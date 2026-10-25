package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

func report() *model.Report {
	f := model.Finding{
		ID: "P2S-EXP-001", Title: "PHP 8.4.26 is vulnerable to php2shell",
		Severity: model.Critical, Category: "exposure", Target: "/usr/bin/php",
		Detail: "test detail", CVEs: []string{model.CVE109618},
	}
	f.SetLevel()
	return &model.Report{
		Tool: "php2shell-audit", Version: "test",
		GeneratedAt: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC),
		Findings:    []model.Finding{f},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	r := report()
	if err := Write(&buf, r, "json", false); err != nil {
		t.Fatal(err)
	}
	var out model.Report
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Stats.Critical != 1 || out.Stats.Total != 1 {
		t.Fatalf("stats = %+v", out.Stats)
	}
	if out.Findings[0].Level != "critical" {
		t.Fatalf("level = %q", out.Findings[0].Level)
	}
}

func TestWriteJSONL(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, report(), "jsonl", false); err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(buf.String()), "\n") != 0 {
		t.Fatalf("expected one JSONL record, got %q", buf.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, report(), "sarif", false); err != nil {
		t.Fatal(err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF: %+v", doc)
	}
	if doc.Runs[0].Results[0].Level != "error" {
		t.Fatalf("critical should map to SARIF error, got %q", doc.Runs[0].Results[0].Level)
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, report(), "text", false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SUMMARY", "CRITICAL", "PHP 8.4.26 is vulnerable"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, report(), "xml", false); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}
