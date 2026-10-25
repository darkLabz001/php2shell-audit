// Package model holds the data types shared by the scanner, the hunter and the
// reporting layer.
package model

import (
	"sort"
	"strings"
	"time"
)

// Severity is ordered from least to most urgent.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity accepts a name, case insensitively.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, true
	case "low":
		return Low, true
	case "medium", "moderate":
		return Medium, true
	case "high":
		return High, true
	case "critical":
		return Critical, true
	}
	return Info, false
}

// AtLeast reports whether s is at least as severe as floor.
func (s Severity) AtLeast(floor Severity) bool { return s >= floor }

// Target is one PHP installation, container or remote endpoint that was
// inspected.
type Target struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"` // binary, process, package, container, remote
	SAPI     string            `json:"sapi,omitempty"`
	Version  string            `json:"version,omitempty"`
	Status   string            `json:"status,omitempty"` // fixed, vulnerable, eol, unknown, vendor-patched
	FixedIn  string            `json:"fixed_in,omitempty"`
	Loaded   bool              `json:"loaded"` // true when the version came from a running worker
	Source   string            `json:"source,omitempty"`
	Config   map[string]string `json:"config,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
	Findings int               `json:"findings"`
	Worst    string            `json:"worst,omitempty"`
	Uptime   string            `json:"uptime,omitempty"`
	Image    string            `json:"image,omitempty"`
}

// Finding is a single actionable result. The same struct is used for scan
// results, log detections and host artefacts so that every output format can
// render them uniformly.
type Finding struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"-"`
	Level      string     `json:"severity"`
	Category   string     `json:"category"`          // exposure, config, attempt, compromise, persistence, intel
	Surface    string     `json:"surface,omitempty"` // local, remote, container, logs, host
	Target     string     `json:"target,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Evidence   []string   `json:"evidence,omitempty"`
	Refs       []string   `json:"refs,omitempty"`
	CVEs       []string   `json:"cves,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	Count      int        `json:"count,omitempty"`
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	Version    string     `json:"version,omitempty"`
	SAPI       string     `json:"sapi,omitempty"`
	Status     string     `json:"status,omitempty"`
	FixedIn    string     `json:"fixed_in,omitempty"`
	// Remediation is a short, operator-facing next step.
	Remediation string            `json:"remediation,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// SetLevel keeps the serialised severity in sync with the numeric value.
func (f *Finding) SetLevel() { f.Level = f.Severity.String() }

// Stats aggregates findings by severity.
type Stats struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

// Add counts one finding.
func (s *Stats) Add(f Severity) {
	switch f {
	case Info:
		s.Info++
	case Low:
		s.Low++
	case Medium:
		s.Medium++
	case High:
		s.High++
	case Critical:
		s.Critical++
	}
	s.Total++
}

// Report is the top level document written by every command.
type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Mode        string    `json:"mode"`
	Since       string    `json:"since,omitempty"`
	Findings    []Finding `json:"findings"`
	Targets     []Target  `json:"targets,omitempty"`
	Stats       Stats     `json:"stats"`
	Notes       []string  `json:"notes,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	Summary     string    `json:"summary,omitempty"`
}

// Finish normalises levels, sorts findings by severity then title and computes
// the statistics. It is safe to call more than once.
func (r *Report) Finish() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity > r.Findings[j].Severity
		}
		return r.Findings[i].Title < r.Findings[j].Title
	})
	r.Stats = Stats{}
	for i := range r.Findings {
		r.Findings[i].SetLevel()
		r.Stats.Add(r.Findings[i].Severity)
	}
	for i := range r.Targets {
		worst := Info
		count := 0
		for _, f := range r.Findings {
			if f.Target != r.Targets[i].Name {
				continue
			}
			count++
			if f.Severity > worst {
				worst = f.Severity
			}
		}
		r.Targets[i].Findings = count
		if count > 0 {
			r.Targets[i].Worst = worst.String()
		}
	}
}

// MaxSeverity returns the most severe finding, or Info when there are none.
func (r *Report) MaxSeverity() Severity {
	worst := Info
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

// DefaultSince is the first day exploitation attempts were publicly reported.
// It is shared by the CLI and the interactive console.
var DefaultSince = time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)

// Refs shared by findings. Kept here so every command cites the same sources.
var (
	AdvisoryURL = "https://www.php.net/archive/2026.php#2026-10-21-5"
	GHSA109618  = "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"
	GHSA109619  = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
)

// CVE identifiers.
const (
	CVE109618 = "CVE-2026-109618"
	CVE109619 = "CVE-2026-109619"
)
