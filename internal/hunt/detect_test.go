package hunt

import (
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

const (
	oomLine   = `[Thu Oct 17 02:13:57.120411 2026] [php7:error] [pid 4411:tid 1] [client 203.0.113.44:51234] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 35651584 bytes) in Unknown on line 0`
	crashLine = `[Thu Oct 17 02:13:57.220411 2026] [core:error] [pid 4411:tid 1] [client 203.0.113.44:51234] AH00052: child pid 4412 exit signal Segmentation fault (11)`
)

func TestParseAccessLine(t *testing.T) {
	rec := parseLine(`203.0.113.44 - alice [17/Oct/2026:02:13:58 +0000] "POST /index.php HTTP/1.1" 500 1024 "-" "curl/8.5.0"`, "access.log", 7, 2026)
	if rec.Kind != "access" {
		t.Fatalf("kind = %q", rec.Kind)
	}
	if rec.IP != "203.0.113.44" || rec.Method != "POST" || rec.Path != "/index.php" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.Time.IsZero() || rec.Time.Year() != 2026 {
		t.Fatalf("time = %v", rec.Time)
	}
	if rec.Status != 500 || rec.UserAgent != "curl/8.5.0" {
		t.Fatalf("status/ua = %d/%q", rec.Status, rec.UserAgent)
	}
}

func TestParseApacheError(t *testing.T) {
	rec := parseLine(oomLine, "error.log", 1, 2026)
	if rec.Kind != "apache-error" {
		t.Fatalf("kind = %q", rec.Kind)
	}
	if rec.IP != "203.0.113.44" {
		t.Fatalf("ip = %q", rec.IP)
	}
	if !strings.Contains(rec.Message, "Unknown on line 0") {
		t.Fatalf("message = %q", rec.Message)
	}
	if rec.Time.IsZero() {
		t.Fatal("time not parsed")
	}
}

func TestParseJSONRecord(t *testing.T) {
	line := `{"time":"2026-10-17T02:13:56Z","client":"203.0.113.44","method":"POST","path":"/index.php","status":500,"content_length":35651584,"set_cookie":"PHPSESSID=abc"}`
	rec := parseLine(line, "requests.jsonl", 1, 2026)
	if rec.Kind != "json" {
		t.Fatalf("kind = %q", rec.Kind)
	}
	if rec.IP != "203.0.113.44" || rec.Method != "POST" || rec.ContentLength != 35651584 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.SetCookie != "PHPSESSID=abc" {
		t.Fatalf("set-cookie = %q", rec.SetCookie)
	}
}

func TestAnalyzeDetectsStartupOOMAndCorrelation(t *testing.T) {
	now := time.Date(2026, 10, 17, 2, 14, 0, 0, time.UTC)
	records := []Record{
		parseLine(oomLine, "error.log", 1, 2026),
		parseLine(crashLine, "error.log", 2, 2026),
		parseLine(`{"time":"2026-10-17T02:13:56Z","client":"203.0.113.44","method":"POST","path":"/index.php","content_length":35651584,"set_cookie":"PHPSESSID=AbCdEf0123456789%00%ff%fe%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e%4f%50%51%52%53%54"}`, "requests.jsonl", 1, 2026),
	}
	opts := Options{Since: now.Add(-time.Hour), Until: now.Add(time.Hour), LargeBody: 2 << 20}
	findings, events := Analyze(records, opts)
	if len(events) < 4 {
		t.Fatalf("expected at least 4 events (oom, crash, large body, cookie), got %d", len(events))
	}
	ids := map[string]int{}
	for _, f := range findings {
		ids[f.ID]++
	}
	if ids["P2S-HUNT-001"] != 1 {
		t.Errorf("startup OOM finding missing or duplicated: %v", ids)
	}
	if ids["P2S-HUNT-002"] != 1 {
		t.Errorf("crash finding missing: %v", ids)
	}
	if ids["P2S-HUNT-003"] != 1 {
		t.Errorf("large body finding missing: %v", ids)
	}
	if ids["P2S-HUNT-005"] != 1 {
		t.Errorf("session leak finding missing: %v", ids)
	}
	if ids["P2S-HUNT-007"] == 0 {
		t.Errorf("correlation finding missing: %v", ids)
	}
	for _, f := range findings {
		if f.ID == "P2S-HUNT-001" && f.Target != "203.0.113.44" {
			t.Errorf("OOM target = %q", f.Target)
		}
		if f.Severity >= model.High && f.Category == "" {
			t.Errorf("finding %s has no category", f.ID)
		}
	}
}

func TestAnalyzeRespectsWindow(t *testing.T) {
	records := []Record{parseLine(oomLine, "error.log", 1, 2026)}
	opts := Options{Since: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}
	findings, events := Analyze(records, opts)
	if len(findings) != 0 || len(events) != 0 {
		t.Fatalf("expected no findings after the window, got %d/%d", len(findings), len(events))
	}
}

func TestAnalyzeInScriptOOMIsNoiseByDefault(t *testing.T) {
	line := `[Thu Oct 17 02:14:05 2026] [php7:error] [pid 1] [client 198.51.100.9] PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted (tried to allocate 4194304 bytes) in /var/www/html/index.php on line 412`
	findings, events := Analyze([]Record{parseLine(line, "error.log", 1, 2026)}, Options{})
	if len(findings) != 0 || len(events) != 0 {
		t.Fatalf("in-script OOM should be suppressed by default, got %d findings", len(findings))
	}
	_, events = Analyze([]Record{parseLine(line, "error.log", 1, 2026)}, Options{IncludeNoise: true})
	if len(events) != 1 {
		t.Fatalf("in-script OOM should appear with IncludeNoise, got %d", len(events))
	}
}
