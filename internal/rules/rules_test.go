package rules

import (
	"strings"
	"testing"
)

func TestGenerateAll(t *testing.T) {
	files := Generate("all")
	for _, want := range []string{
		"sigma/php2shell_startup_oom.yml",
		"modsecurity/php2shell.conf",
		"nginx/php2shell.conf",
		"yara/php2shell_webshell.yar",
		"siem/php2shell.kql",
		"siem/php2shell.spl",
	} {
		if files[want] == "" {
			t.Errorf("missing generated file %q", want)
		}
	}
	if !strings.Contains(files["sigma/php2shell_startup_oom.yml"], "CVE-2026-109618") && !strings.Contains(files["sigma/php2shell_startup_oom.yml"], "cve.2026.109618") {
		t.Error("sigma OOM rule does not reference the CVE")
	}
}

func TestGenerateFilters(t *testing.T) {
	sigma := Generate("sigma")
	if len(sigma) != 5 {
		t.Fatalf("expected 5 sigma rules, got %d", len(sigma))
	}
	for name := range sigma {
		if !strings.HasPrefix(name, "sigma/") {
			t.Errorf("unexpected file in sigma filter: %s", name)
		}
	}
	if got := Generate("nope"); len(got) != 0 {
		t.Errorf("unknown format should be empty, got %d", len(got))
	}
}

func TestRuleContentIsNotEmpty(t *testing.T) {
	for name, body := range Generate("all") {
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
