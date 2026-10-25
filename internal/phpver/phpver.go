// Package phpver parses PHP version strings and decides whether a build is
// affected by CVE-2026-109618 and CVE-2026-109619.
package phpver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Status values used by Assessment.
const (
	StatusFixed        = "fixed"
	StatusVulnerable   = "vulnerable"
	StatusEOL          = "eol"
	StatusUnknown      = "unknown"
	StatusVendorPached = "vendor-patched"
)

// Version is a parsed PHP version. Pre is empty for final releases and holds a
// lower-cased qualifier such as "rc", "beta", "alpha" or "dev" otherwise.
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string // e.g. "rc", "beta", "alpha", "dev"
	PreNo int
	Raw   string
}

var versionRE = regexp.MustCompile(`(?i)(\d+)\.(\d+)(?:\.(\d+))?(?:[.\-_+ ]?(alpha|a|beta|b|rc|dev|pre|pl)(\d*))?`)

// Parse extracts the first PHP-looking version from s. It accepts bare
// versions ("8.2.35"), banners ("PHP 8.2.29 (cli)") and distribution versions
// ("8.2.29-1+deb12u1").
func Parse(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	v := Version{Raw: m[0]}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.Patch, _ = strconv.Atoi(m[3])
	}
	if m[4] != "" {
		v.Pre = normalisePre(m[4])
		if m[5] != "" {
			v.PreNo, _ = strconv.Atoi(m[5])
		}
	}
	return v, true
}

func normalisePre(p string) string {
	switch strings.ToLower(p) {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "pl":
		return "pl"
	default:
		return strings.ToLower(p)
	}
}

// String renders the normalised version.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += v.Pre + strconv.Itoa(v.PreNo)
	}
	return s
}

// Branch returns "8.2" style branch names.
func (v Version) Branch() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

func preRank(p string) int {
	switch p {
	case "dev":
		return 0
	case "alpha":
		return 1
	case "beta":
		return 2
	case "rc":
		return 3
	case "pl":
		return 5
	default:
		return 0
	}
}

// Compare returns -1, 0 or 1 as a is older than, equal to or newer than b.
// Pre-releases sort before the corresponding final release.
func Compare(a, b Version) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpInt(a.Patch, b.Patch); c != 0 {
		return c
	}
	// A final release beats any pre-release of the same number.
	ar, br := preRank(a.Pre), preRank(b.Pre)
	if a.Pre == "" {
		ar = 4
	}
	if b.Pre == "" {
		br = 4
	}
	if c := cmpInt(ar, br); c != 0 {
		return c
	}
	return cmpInt(a.PreNo, b.PreNo)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// fixedFor maps a supported branch to the first release that contains the fix.
var fixedFor = map[string]Version{
	"8.2": {Major: 8, Minor: 2, Patch: 35},
	"8.3": {Major: 8, Minor: 3, Patch: 36},
	"8.4": {Major: 8, Minor: 4, Patch: 27},
	"8.5": {Major: 8, Minor: 5, Patch: 12},
}

// Assessment is the result of classifying one version.
type Assessment struct {
	Status  string
	FixedIn string
	Notes   []string
}

// Affected reports whether v is in the affected range before any vendor
// backport is taken into account.
func (v Version) Affected() bool {
	return v.Major >= 5 && (v.Major < 8 || (v.Major == 8 && v.Minor <= 5))
}

// Assess classifies v against the published advisory. It deliberately returns
// Unknown rather than a false "safe" for versions the advisory does not cover.
func Assess(v Version) Assessment {
	a := Assessment{}
	switch {
	case v.Major < 5:
		a.Status = StatusUnknown
		a.Notes = append(a.Notes, "Version predates the affected range stated by the advisory; verify manually.")
		return a
	case v.Major > 8 || (v.Major == 8 && v.Minor > 5):
		a.Status = StatusUnknown
		a.Notes = append(a.Notes, "No published assessment for this branch; treat as unverified until the vendor confirms.")
		return a
	}

	fixed, supported := fixedFor[v.Branch()]
	if !supported {
		a.Status = StatusEOL
		a.Notes = append(a.Notes,
			"No official fix: PHP 8.1 and older are end-of-life.",
			"Some distributions and LTS vendors ship backports; check the package changelog for CVE-2026-109618 and CVE-2026-109619.",
			"Minimal source backports exist for PHP 7.4, 8.0 and 8.1 but are not official releases.",
		)
		return a
	}

	a.FixedIn = fixed.String()
	if Compare(v, fixed) >= 0 {
		a.Status = StatusFixed
		return a
	}
	a.Status = StatusVulnerable
	a.Notes = append(a.Notes, "Upgrade to "+fixed.String()+" or later on this branch.")
	return a
}

// SeverityFor suggests an exposure severity for an affected installation.
// mod_php has the strongest public demonstration and is ranked highest.
func SeverityFor(status, sapi string) string {
	s := strings.ToLower(sapi)
	switch status {
	case StatusFixed:
		return "info"
	case StatusVendorPached:
		return "info"
	case StatusVulnerable:
		switch {
		case strings.Contains(s, "apache") || strings.Contains(s, "mod_php"):
			return "critical"
		case strings.Contains(s, "fpm"):
			return "critical"
		case strings.Contains(s, "cgi"), strings.Contains(s, "frankenphp"), strings.Contains(s, "litespeed"):
			return "high"
		case s == "" || s == "unknown":
			return "high"
		default:
			return "high"
		}
	case StatusEOL:
		return "high"
	default:
		return "medium"
	}
}
