package hunt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanWebRootsFindsWebshell(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "uploads")
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	shell := `<?php $k = $_POST['k']; eval(base64_decode($k));`
	if err := os.WriteFile(filepath.Join(up, "shell.php"), []byte(shell), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := `<?php function x($a) { return htmlspecialchars($a); }`
	if err := os.WriteFile(filepath.Join(up, "clean.php"), []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, ".user.ini"), []byte("auto_prepend_file = /var/www/uploads/shell.php\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, warnings := ScanWebRoots([]string{root}, time.Time{}, true, 6)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	var shellFound, prependFound bool
	for _, f := range findings {
		switch f.ID {
		case "P2S-HUNT-012":
			if filepath.Base(f.Target) == "shell.php" {
				shellFound = true
			}
			if filepath.Base(f.Target) == "clean.php" {
				t.Errorf("clean file was flagged: %s", f.Detail)
			}
		case "P2S-HUNT-013":
			prependFound = true
		}
	}
	if !shellFound {
		t.Fatalf("webshell not found in %d findings", len(findings))
	}
	if !prependFound {
		t.Fatal("auto_prepend persistence not found")
	}
}

func TestScanSessionsIgnoresBenignProgress(t *testing.T) {
	dir := t.TempDir()
	benign := `upload_progress_1|a:5:{s:10:"start_time";i:1760667236;s:14:"content_length";i:3145728;}`
	if err := os.WriteFile(filepath.Join(dir, "sess_benign"), []byte(benign), 0o600); err != nil {
		t.Fatal(err)
	}
	malicious := benign + "\n<?php system($_GET['c']); ?>"
	if err := os.WriteFile(filepath.Join(dir, "sess_bad"), []byte(malicious), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, warnings := ScanSessions([]string{dir}, time.Time{}, true)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Target != filepath.Join(dir, "sess_bad") {
		t.Fatalf("wrong file flagged: %s", findings[0].Target)
	}
	if findings[0].Severity < 4 {
		t.Fatalf("PHP in session should be critical, got %s", findings[0].Severity)
	}
}

func TestScoreFile(t *testing.T) {
	high := []byte(`<?php eval($_POST['x']);`)
	if score := len(scoreFile("x.php", high)); score == 0 {
		t.Fatal("expected signals for an obvious webshell")
	}
	low := []byte(`<?php echo "hello";`)
	if sigs := scoreFile("x.php", low); len(sigs) != 0 {
		t.Fatalf("unexpected signals: %+v", sigs)
	}
}
