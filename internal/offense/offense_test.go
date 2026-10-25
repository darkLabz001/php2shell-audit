package offense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

func withVersion(version string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/"+version)
		next(w, r)
	}
}

func hasFinding(res *Result, id string) *model.Finding {
	for i := range res.Findings {
		if res.Findings[i].ID == id {
			return &res.Findings[i]
		}
	}
	return nil
}

func testOptions(scope *Scope, target string, probes []string, oom int64) Options {
	return Options{
		Scope:                 scope,
		Targets:               []string{target},
		Timeout:               3 * time.Second,
		OOMBody:               oom,
		AcknowledgeDisruption: oom > 0,
		Probes:                probes,
		AuditPath:             filepath.Join(os.TempDir(), "p2s-offense-test-audit.jsonl"),
	}
}

func TestPressureProbeSurvives(t *testing.T) {
	var got int64
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			got = r.ContentLength
			_, _ = io.Copy(io.Discard, r.Body)
			fmt.Fprint(w, "ok")
			return
		}
		fmt.Fprint(w, "PHP version: 8.4.26\nSAPI: apache2handler\n")
	}))
	defer srv.Close()

	scope := validScope(srv.URL)
	scope.AcknowledgeDisruption = true
	opts := testOptions(scope, srv.URL, []string{"109618"}, 2048)
	opts.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != 2048 {
		t.Fatalf("server saw %d body bytes, want 2048", got)
	}
	f := hasFinding(res, "P2S-OFF-001")
	if f == nil {
		t.Fatalf("no survived finding; findings=%v", ids(res.Findings))
	}
	if f.Severity != model.Info {
		t.Errorf("severity = %v, want info", f.Severity)
	}
	if data, err := os.ReadFile(opts.AuditPath); err != nil || !strings.Contains(string(data), `"probe":"109618"`) {
		t.Fatalf("audit log missing 109618 entry (err=%v)", err)
	}
}

func TestPressureProbeConnectionDrop(t *testing.T) {
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fmt.Fprint(w, "phpinfo PHP version 8.4.26")
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer srv.Close()

	scope := validScope(srv.URL)
	scope.AcknowledgeDisruption = true
	res, err := Run(context.Background(), testOptions(scope, srv.URL, []string{"109618"}, 4096))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFinding(res, "P2S-OFF-002") == nil {
		t.Fatalf("no connection-drop finding; findings=%v", ids(res.Findings))
	}
}

func TestPressureProbeGuardrails(t *testing.T) {
	scope := validScope("http://127.0.0.1:1/")
	scope.AcknowledgeDisruption = false
	if _, err := Run(context.Background(), testOptions(scope, "http://127.0.0.1:1/", []string{"109618"}, 4096)); err == nil {
		t.Fatal("pressure probe ran without acknowledgement")
	}
	scope.AcknowledgeDisruption = true
	opts := testOptions(scope, "http://127.0.0.1:1/", []string{"109618"}, MaxOOMBody+1)
	if _, err := Run(context.Background(), opts); err == nil {
		t.Fatal("oversized pressure body accepted")
	}
}

func TestFixedBuildSkipsProbes(t *testing.T) {
	srv := httptest.NewServer(withVersion("8.4.27", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "PHP version: 8.4.27\n")
	}))
	defer srv.Close()

	scope := validScope(srv.URL)
	scope.AcknowledgeDisruption = true
	res, err := Run(context.Background(), testOptions(scope, srv.URL, []string{"109618", "109619"}, 4096))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFinding(res, "P2S-OFF-001") != nil || hasFinding(res, "P2S-OFF-010") != nil {
		t.Fatalf("patched target produced validation findings: %v", ids(res.Findings))
	}
	found := false
	for _, note := range res.Notes {
		if strings.Contains(note, "skipped because the build is patched") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no patched-skip note in %v", res.Notes)
	}
}

func TestSafeRunReportsPressureSkip(t *testing.T) {
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	res, err := Run(context.Background(), testOptions(validScope(srv.URL), srv.URL, []string{"109618"}, 0))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFinding(res, "P2S-OFF-008") == nil {
		t.Fatalf("safe run did not explain the skipped pressure probe: %v", ids(res.Findings))
	}
}

func TestUploadProgressCrossRequestSignal(t *testing.T) {
	var mu sync.Mutex
	progress := map[string][]string{}
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("PHPSESSID")
		sid := ""
		if err == nil {
			sid = cookie.Value
		}
		if r.Method == http.MethodPost {
			_ = r.ParseMultipartForm(1 << 20)
			canary := r.FormValue("PHP_SESSION_UPLOAD_PROGRESS")
			if sid != "" && canary != "" {
				mu.Lock()
				progress[sid] = append(progress[sid], canary)
				mu.Unlock()
			}
			fmt.Fprint(w, "uploaded")
			return
		}
		mu.Lock()
		values := append([]string(nil), progress[sid]...)
		mu.Unlock()
		for _, v := range values {
			fmt.Fprintln(w, v)
		}
	}))
	defer srv.Close()

	res, err := Run(context.Background(), testOptions(validScope(srv.URL), srv.URL, []string{"109619"}, 0))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFinding(res, "P2S-OFF-010") == nil {
		t.Fatalf("no cross-request finding; findings=%v", ids(res.Findings))
	}
}

func TestUploadProgressNoSignal(t *testing.T) {
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain response without state")
	}))
	defer srv.Close()

	res, err := Run(context.Background(), testOptions(validScope(srv.URL), srv.URL, []string{"109619"}, 0))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFinding(res, "P2S-OFF-012") == nil {
		t.Fatalf("no no-signal finding; findings=%v", ids(res.Findings))
	}
}

func TestAuditLogRecordsScope(t *testing.T) {
	srv := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	scope := validScope(srv.URL)
	opts := testOptions(scope, srv.URL, []string{"109619"}, 0)
	opts.AuditPath = path
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected preflight and probe audit lines, got %d", len(lines))
	}
	var entry auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("audit line is not JSON: %v", err)
	}
	if entry.CaseID != scope.CaseID || entry.Operator != scope.Operator {
		t.Fatalf("audit entry lost scope metadata: %+v", entry)
	}
}

func TestRedirectCannotEscapeScope(t *testing.T) {
	var escaped int
	other := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		escaped++
		fmt.Fprint(w, "out of scope")
	}))
	defer other.Close()

	redirector := httptest.NewServer(withVersion("8.4.26", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer redirector.Close()

	res, err := Run(context.Background(), testOptions(validScope(redirector.URL), redirector.URL, []string{"109619"}, 0))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if escaped != 0 {
		t.Fatalf("offense followed a redirect outside the scope %d time(s)", escaped)
	}
	if res == nil {
		t.Fatal("nil result")
	}
}

func ids(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}
