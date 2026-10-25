package hunt

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// fileSignal is a weighted indicator found in a PHP file.
type fileSignal struct {
	token  string
	weight int
	line   string
}

var fileSignals = []struct {
	re     *regexp.Regexp
	token  string
	weight int
}{
	{regexp.MustCompile(`(?i)\beval\s*\(`), "eval(", 5},
	{regexp.MustCompile(`(?i)\bbase64_decode\s*\(`), "base64_decode(", 4},
	{regexp.MustCompile(`(?i)\bgzinflate\s*\(|\bgzuncompress\s*\(|\bstr_rot13\s*\(`), "compressed/rot13 payload", 4},
	{regexp.MustCompile(`(?i)\bassert\s*\(`), "assert(", 4},
	{regexp.MustCompile(`(?i)\bcreate_function\s*\(`), "create_function(", 4},
	{regexp.MustCompile(`(?i)\bsystem\s*\(`), "system(", 5},
	{regexp.MustCompile(`(?i)\bshell_exec\s*\(`), "shell_exec(", 5},
	{regexp.MustCompile(`(?i)\bpassthru\s*\(`), "passthru(", 5},
	{regexp.MustCompile(`(?i)\bpopen\s*\(`), "popen(", 4},
	{regexp.MustCompile(`(?i)\bproc_open\s*\(`), "proc_open(", 4},
	{regexp.MustCompile(`(?i)\bpcntl_exec\s*\(`), "pcntl_exec(", 6},
	{regexp.MustCompile(`(?i)\bpreg_replace\s*\([^;]{0,120}/e['"\s,)]`), "preg_replace /e", 4},
	{regexp.MustCompile(`(?i)\bmove_uploaded_file\s*\(`), "move_uploaded_file(", 2},
	{regexp.MustCompile(`(?i)\bfile_get_contents\s*\(\s*['"]https?:`), "remote file read", 4},
	{regexp.MustCompile(`(?i)\bcurl_exec\s*\(`), "curl_exec(", 2},
	{regexp.MustCompile(`(?i)\bfsockopen\s*\(`), "fsockopen(", 3},
	{regexp.MustCompile(`(?i)\bchmod\s*\([^;]{0,80}0777`), "chmod 0777", 3},
	{regexp.MustCompile(`(?i)(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`), "include from request", 6},
	{regexp.MustCompile(`\$_(?:REQUEST|POST|GET|COOKIE)\s*\[[^\]]+\]\s*\(`), "request variable call", 5},
	{regexp.MustCompile(`(?i)\b(?:extract|parse_str)\s*\(`), "extract/parse_str", 2},
	{regexp.MustCompile(`(?i)\b(?:gethostbyname|gethostbyaddr)\s*\(`), "dns lookup", 1},
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`), "hex-encoded payload", 3},
	{regexp.MustCompile(`[A-Za-z0-9+/]{300,}={0,2}`), "long base64 blob", 3},
	{regexp.MustCompile(`(?i)\b(?:set_time_limit|ini_set)\s*\(\s*['"]display_errors`), "hides errors", 2},
}

var phpExt = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".php6": true,
	".php7": true, ".php8": true, ".phtml": true, ".phar": true, ".inc": true,
	".module": true, ".theme": true,
}

// ScanWebRoots looks for PHP files modified inside the lookback window that
// contain webshell-like constructs, and for auto_prepend/auto_append
// persistence in .htaccess and .user.ini.
func ScanWebRoots(roots []string, since time.Time, allFiles bool, minScore int) ([]model.Finding, []string) {
	if minScore <= 0 {
		minScore = 6
	}
	var findings []model.Finding
	var warnings []string
	seen := map[string]bool{}

	for _, root := range roots {
		fi, err := os.Stat(root)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", root, err))
			continue
		}
		if !fi.IsDir() {
			warnings = append(warnings, fmt.Sprintf("%s: not a directory", root))
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", ".cache", ".svn", "vendor":
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			base := strings.ToLower(d.Name())
			ext := strings.ToLower(filepath.Ext(base))

			if base == ".htaccess" || base == ".user.ini" {
				if f, ok := inspectAutoPrepend(path); ok {
					findings = append(findings, f)
				}
				return nil
			}
			if !phpExt[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if !allFiles && !since.IsZero() && info.ModTime().Before(since) {
				return nil
			}
			if info.Size() > 2*1024*1024 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			signals := scoreFile(path, data)
			score := 0
			var tokens []string
			var snippet string
			for _, s := range signals {
				score += s.weight
				tokens = append(tokens, s.token)
				if snippet == "" {
					snippet = s.line
				}
			}
			lowerPath := strings.ToLower(path)
			for _, dir := range []string{"/uploads/", "/upload/", "/tmp/", "/temp/", "/cache/", "/files/", "/images/"} {
				if strings.Contains(lowerPath, dir) {
					score += 4
					break
				}
			}
			if score < minScore || seen[path] {
				return nil
			}
			seen[path] = true

			sev := model.Medium
			if score >= 14 {
				sev = model.Critical
			} else if score >= 9 {
				sev = model.High
			}
			findings = append(findings, model.Finding{
				ID: "P2S-HUNT-012", Title: "Suspicious PHP file (possible webshell)", Severity: sev,
				Category: "compromise", Surface: "host", Target: path, Confidence: confidenceFor(score),
				Detail: fmt.Sprintf("The file matches %d weighted webshell indicators (score %d). Review it before deleting anything: it may be a legitimate but unusual application file.", len(tokens), score),
				Evidence: []string{
					"path: " + path,
					"modified: " + info.ModTime().UTC().Format(time.RFC3339),
					"score: " + fmt.Sprint(score) + " tokens: " + strings.Join(uniqueStrings(tokens), ", "),
					"snippet: " + snippet,
				},
				Remediation: "Quarantine the file, compare against the deployed revision, review access logs for requests to it, and rotate secrets if it executed.",
				Meta:        map[string]string{"score": fmt.Sprint(score)},
			})
			return nil
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Severity > findings[j].Severity })
	return findings, warnings
}

func scoreFile(path string, data []byte) []fileSignal {
	text := string(data)
	var out []fileSignal
	for _, sig := range fileSignals {
		if sig.re.MatchString(text) {
			out = append(out, fileSignal{token: sig.token, weight: sig.weight, line: firstMatchLine(text, sig.re)})
		}
	}
	if len(data) > 512*1024 {
		out = append(out, fileSignal{token: "oversized php file", weight: 1})
	}
	return out
}

func firstMatchLine(text string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	start := strings.LastIndexByte(text[:loc[0]], '\n') + 1
	end := strings.IndexByte(text[loc[1]:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += loc[1]
	}
	line := strings.TrimSpace(text[start:end])
	if len(line) > 220 {
		line = line[:217] + "..."
	}
	return line
}

func confidenceFor(score int) string {
	switch {
	case score >= 14:
		return "high"
	case score >= 9:
		return "medium"
	default:
		return "low"
	}
}

var autoPrependRE = regexp.MustCompile(`(?i)auto_(?:prepend|append)_file\s*=?\s*["']?([^"'\s]+)`)

func inspectAutoPrepend(path string) (model.Finding, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Finding{}, false
	}
	m := autoPrependRE.FindStringSubmatch(string(data))
	if m == nil {
		return model.Finding{}, false
	}
	info, _ := os.Stat(path)
	modified := ""
	if info != nil {
		modified = info.ModTime().UTC().Format(time.RFC3339)
	}
	return model.Finding{
		ID: "P2S-HUNT-013", Title: "auto_prepend_file/auto_append_file injected via " + filepath.Base(path),
		Severity: model.Critical, Category: "persistence", Surface: "host", Target: path, Confidence: "high",
		Detail:      "A per-directory configuration file sets auto_prepend_file or auto_append_file. The confirmed php2shell RCE chain redirects this exact directive; on a clean host it is also a common webshell persistence trick.",
		Evidence:    []string{"path: " + path, "modified: " + modified, "directive: " + strings.TrimSpace(m[0])},
		Remediation: "Inspect and remove the directive, restore the file from a trusted revision, and treat the host as compromised until proven otherwise.",
		Refs:        []string{model.GHSA109618},
		CVEs:        []string{model.CVE109618},
	}, true
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
