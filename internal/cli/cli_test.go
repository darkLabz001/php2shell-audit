package cli

import (
	"testing"
	"time"
)

func TestParseWhen(t *testing.T) {
	fallback := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"":                     fallback,
		"2026-10-21":           time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		"2026-10-21T13:45:00Z": time.Date(2026, 10, 21, 13, 45, 0, 0, time.UTC),
		"2026-10-21 13:45:00":  time.Date(2026, 10, 21, 13, 45, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := parseWhen(in, fallback)
		if err != nil {
			t.Errorf("parseWhen(%q): %v", in, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("parseWhen(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := parseWhen("not-a-date", fallback); err == nil {
		t.Error("expected an error for an invalid timestamp")
	}
}

func TestParseAge(t *testing.T) {
	cases := map[string]time.Duration{
		"72h": 72 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"1w":  7 * 24 * time.Hour,
		"2m":  60 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, ok := parseAge(in)
		if !ok || got != want {
			t.Errorf("parseAge(%q) = (%v, %v), want %v", in, got, ok, want)
		}
	}
	if _, ok := parseAge("soon"); ok {
		t.Error("expected parseAge to reject a non-duration")
	}
}

func TestStringList(t *testing.T) {
	var l stringList
	if err := l.Set("a, b,,c"); err != nil {
		t.Fatal(err)
	}
	if len(l) != 3 || l[0] != "a" || l[1] != "b" || l[2] != "c" {
		t.Fatalf("unexpected list: %v", l)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := Run([]string{"frobnicate"}); code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
}

func TestRunVersion(t *testing.T) {
	if code := Run([]string{"version"}); code != ExitOK {
		t.Fatalf("version exit code = %d", code)
	}
}
