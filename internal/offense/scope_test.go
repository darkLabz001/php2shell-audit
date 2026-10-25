package offense

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validScope(targets ...string) *Scope {
	return &Scope{
		CaseID:   "LAB-2026-001",
		Operator: "tester",
		Expires:  time.Now().UTC().Add(24 * time.Hour),
		Targets:  targets,
	}
}

func TestScopeAllows(t *testing.T) {
	s := validScope("http://127.0.0.1:8081/base")
	cases := map[string]bool{
		"http://127.0.0.1:8081/":         false,
		"http://127.0.0.1:8081/base":     true,
		"http://127.0.0.1:8081/base/x":   true,
		"http://127.0.0.1:8081/base?q=1": true,
		"http://127.0.0.1:8082/base":     false,
		"https://127.0.0.1:8081/base":    false,
		"http://localhost:8081/base":     false,
		"http://127.0.0.1:8081/baseevil": false,
	}
	for target, want := range cases {
		if got := s.Allows(target); got != want {
			t.Errorf("Allows(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestScopeValidation(t *testing.T) {
	if err := validScope("http://127.0.0.1/").Validate(time.Now().UTC()); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	expired := validScope("http://127.0.0.1/")
	expired.Expires = time.Now().UTC().Add(-time.Minute)
	if err := expired.Validate(time.Now().UTC()); err == nil {
		t.Fatal("expired scope accepted")
	}
	missing := validScope("http://127.0.0.1/")
	missing.CaseID = ""
	if err := missing.Validate(time.Now().UTC()); err == nil {
		t.Fatal("scope without a case id accepted")
	}
	if err := validScope("ftp://127.0.0.1/").Validate(time.Now().UTC()); err == nil {
		t.Fatal("non-HTTP scope target accepted")
	}
}

func TestLoadScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	data, _ := json.Marshal(validScope("http://127.0.0.1:8081/"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	scope, err := LoadScope(path)
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	if scope.CaseID != "LAB-2026-001" {
		t.Fatalf("case = %q", scope.CaseID)
	}
	if _, err := LoadScope(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing scope file accepted")
	}
}

func TestHostIsPublic(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":   false,
		"10.0.0.5":    false,
		"192.168.1.9": false,
		"172.16.0.1":  false,
		"::1":         false,
		"8.8.8.8":     true,
		"1.1.1.1":     true,
	}
	for host, want := range cases {
		got, err := HostIsPublic(context.Background(), net.JoinHostPort(host, "443"))
		if err != nil {
			t.Errorf("%s: %v", host, err)
			continue
		}
		if got != want {
			t.Errorf("%s public=%v, want %v", host, got, want)
		}
	}
}

func TestAuthorizeTargetsPublicPolicy(t *testing.T) {
	ctx := context.Background()
	if err := AuthorizeTargets(ctx, validScope("http://8.8.8.8/"), []string{"http://8.8.8.8/"}, false); err == nil {
		t.Fatal("public target accepted without authorisation")
	}
	s := validScope("http://8.8.8.8/")
	s.AllowPublic = true
	if err := AuthorizeTargets(ctx, s, []string{"http://8.8.8.8/"}, true); err != nil {
		t.Fatalf("explicitly authorised public target refused: %v", err)
	}
	if err := AuthorizeTargets(ctx, validScope("http://127.0.0.1/"), []string{"http://127.0.0.1:8080/"}, false); err == nil {
		t.Fatal("out-of-scope target accepted")
	}
}

func TestNormalizeProbes(t *testing.T) {
	p, err := NormalizeProbes([]string{"109618,109619"})
	if err != nil || !p["109618"] || !p["109619"] {
		t.Fatalf("probes = %v, err=%v", p, err)
	}
	if _, err := NormalizeProbes([]string{"rce"}); err == nil {
		t.Fatal("unknown probe accepted")
	}
}
