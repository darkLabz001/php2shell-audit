package phpver

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"PHP 8.2.35 (cli) (built: Oct 21 2026)", "8.2.35", true},
		{"8.5.12", "8.5.12", true},
		{"PHP/8.1.2-1ubuntu2.14", "8.1.2", true},
		{"8.2.29-1+deb12u1", "8.2.29", true},
		{"8.6.0RC3", "8.6.0rc3", true},
		{"PHP 5.4.16", "5.4.16", true},
		{"no version here", "", false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok {
			t.Fatalf("Parse(%q) ok=%v want %v", c.in, ok, c.ok)
		}
		if ok && got.String() != c.want {
			t.Errorf("Parse(%q) = %q want %q", c.in, got.String(), c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	must := func(s string) Version {
		v, ok := Parse(s)
		if !ok {
			t.Fatalf("parse %s", s)
		}
		return v
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"8.2.34", "8.2.35", -1},
		{"8.2.35", "8.2.35", 0},
		{"8.3.0", "8.2.99", 1},
		{"8.5.11", "8.5.12", -1},
		{"8.6.0rc3", "8.6.0", -1},
		{"8.6.0", "8.6.0rc3", 1},
		{"8.6.0beta2", "8.6.0rc1", -1},
	}
	for _, c := range cases {
		if got := Compare(must(c.a), must(c.b)); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssess(t *testing.T) {
	cases := []struct {
		v      string
		status string
		fixed  string
	}{
		{"8.5.11", StatusVulnerable, "8.5.12"},
		{"8.5.12", StatusFixed, "8.5.12"},
		{"8.5.13", StatusFixed, "8.5.12"},
		{"8.4.26", StatusVulnerable, "8.4.27"},
		{"8.4.27", StatusFixed, "8.4.27"},
		{"8.3.35", StatusVulnerable, "8.3.36"},
		{"8.2.34", StatusVulnerable, "8.2.35"},
		{"8.2.35", StatusFixed, "8.2.35"},
		{"8.1.31", StatusEOL, ""},
		{"7.4.33", StatusEOL, ""},
		{"5.4.16", StatusEOL, ""},
		{"8.6.0rc3", StatusUnknown, ""},
		{"9.0.0", StatusUnknown, ""},
	}
	for _, c := range cases {
		v, ok := Parse(c.v)
		if !ok {
			t.Fatalf("parse %s", c.v)
		}
		a := Assess(v)
		if a.Status != c.status {
			t.Errorf("Assess(%s).Status=%s want %s", c.v, a.Status, c.status)
		}
		if a.FixedIn != c.fixed {
			t.Errorf("Assess(%s).FixedIn=%s want %s", c.v, a.FixedIn, c.fixed)
		}
	}
}

func TestSeverityFor(t *testing.T) {
	if got := SeverityFor(StatusVulnerable, "apache2handler"); got != "critical" {
		t.Errorf("mod_php severity = %s", got)
	}
	if got := SeverityFor(StatusVulnerable, "fpm-fcgi"); got != "critical" {
		t.Errorf("fpm severity = %s", got)
	}
	if got := SeverityFor(StatusFixed, "fpm-fcgi"); got != "info" {
		t.Errorf("fixed severity = %s", got)
	}
}
