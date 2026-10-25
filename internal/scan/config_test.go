package scan

import (
	"strings"
	"testing"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/phpver"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"128M", 128 << 20, true},
		{"8m", 8 << 20, true},
		{"1G", 1 << 30, true},
		{"512K", 512 << 10, true},
		{"8388608", 8388608, true},
		{"-1", -1, true},
		{"0", 0, true},
		{`"32M"`, 32 << 20, true},
		{"", 0, false},
		{"lots", 0, false},
	}
	for _, tt := range tests {
		got, ok := ParseSize(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("ParseSize(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFormatSize(t *testing.T) {
	if got := FormatSize(128 << 20); got != "128M" {
		t.Fatalf("FormatSize = %q", got)
	}
	if got := FormatSize(-1); got != "unlimited" {
		t.Fatalf("FormatSize(-1) = %q", got)
	}
}

func TestPosturePrecedence(t *testing.T) {
	p := newPosture()
	p.Values["memory_limit"] = "64M"
	p.Values["value.memory_limit"] = "128M"
	p.Values["admin.memory_limit"] = "256M"
	p.Values["session.upload_progress.enabled"] = "1"
	p.Values["post_max_size"] = "64M"

	if got := p.Get("memory_limit"); got != "256M" {
		t.Fatalf("admin value did not win: %q", got)
	}
	if !p.AdminLevel("memory_limit") {
		t.Fatal("AdminLevel should be true")
	}
	if on, known := p.Bool("session.upload_progress.enabled"); !on || !known {
		t.Fatal("upload_progress should parse as enabled")
	}
	if n, ok := p.Size("post_max_size"); !ok || n != 64<<20 {
		t.Fatalf("post_max_size = %d, %v", n, ok)
	}
}

func TestParseINIReader(t *testing.T) {
	in := `
; comment
[PHP]
memory_limit = 128M
display_errors = On
post_max_size = 8M ; trailing comment

[Session]
session.upload_progress.enabled = 0

[PATH=/var/www]
php_admin_value[memory_limit] = -1
`
	p := newPosture()
	vals, err := parseINIReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	p.mergeINI(vals, "test.ini")
	if got := p.Get("display_errors"); got != "On" {
		t.Fatalf("display_errors = %q", got)
	}
	if got := p.Get("post_max_size"); got != "8M" {
		t.Fatalf("post_max_size = %q", got)
	}
	if v, known := p.Bool("session.upload_progress.enabled"); v || !known {
		t.Fatal("upload_progress should be disabled")
	}
	if !p.AdminLevel("memory_limit") {
		t.Fatal("php_admin_value not recorded")
	}
	if got := p.Get("memory_limit"); got != "-1" {
		t.Fatalf("memory_limit = %q", got)
	}
}

func TestConfigFindingsVulnerable(t *testing.T) {
	p := newPosture()
	p.Values["memory_limit"] = "128M"
	p.Values["post_max_size"] = "64M"
	p.Values["session.upload_progress.enabled"] = "1"
	limits := &RLimits{AddressSpace: "268435456", DataSize: "unlimited"}

	fs := ConfigFindings("host:test", "8.4.26", phpver.StatusVulnerable, "fpm-fcgi", p, limits)
	ids := map[string]model.Severity{}
	for _, f := range fs {
		ids[f.ID] = f.Severity
	}
	for _, want := range []string{"P2S-CFG-001", "P2S-CFG-002", "P2S-CFG-004", "P2S-CFG-006"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	if ids["P2S-CFG-002"] != model.High {
		t.Errorf("upload_progress finding should be high on a vulnerable build, got %s", ids["P2S-CFG-002"])
	}
}

func TestConfigFindingsPatchedDowngrades(t *testing.T) {
	p := newPosture()
	p.Values["memory_limit"] = "128M"
	p.Values["session.upload_progress.enabled"] = "1"
	fs := ConfigFindings("host:test", "8.4.27", phpver.StatusFixed, "fpm-fcgi", p, nil)
	for _, f := range fs {
		if f.ID == "P2S-CFG-002" && f.Severity > model.Medium {
			t.Fatalf("patched build should reduce upload_progress severity, got %s", f.Severity)
		}
	}
}

func TestConcretePkgVersion(t *testing.T) {
	cases := map[string]bool{
		"2:8.4+96":         false,
		"8.4.26-1~deb13u1": true,
		"8.4.27":           true,
		"8.3.26-r0":        true,
		"2:8.4.26-1":       true,
		"1:8.4":            false,
		"2:96":             false,
	}
	for in, want := range cases {
		if got := concretePkgVersion(in); got != want {
			t.Errorf("concretePkgVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLooksLikePHPBinary(t *testing.T) {
	yes := []string{"php", "php8.4", "php-fpm", "php-fpm8.4", "php8.4-fpm", "php-cgi", "php8.4-zts"}
	no := []string{"phpenmod", "phpquery", "phpize", "php-config", "phpunit", "phpcs", "phpdbg"}
	for _, b := range yes {
		if !looksLikePHPBinary(b) {
			t.Errorf("expected %q to look like a PHP binary", b)
		}
	}
	for _, b := range no {
		if looksLikePHPBinary(b) {
			t.Errorf("expected %q NOT to look like a PHP binary", b)
		}
	}
}
