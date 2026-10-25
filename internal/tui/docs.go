package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// findingDocument renders one finding as a scrollable plain-text dossier.
func findingDocument(f model.Finding) []string {
	lines := []string{
		strings.ToUpper(sanitize(firstNonEmpty(f.Title, "Unclassified finding"))),
		strings.Repeat("─", 64),
	}
	add := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		lines = append(lines, fmt.Sprintf("%-11s %s", label, sanitize(value)))
	}
	add("RULE", firstNonEmpty(f.ID, "-"))
	add("SEVERITY", strings.ToUpper(f.Severity.String()))
	add("CATEGORY", f.Category)
	add("TARGET", f.Target)
	add("SURFACE", f.Surface)
	add("CONFIDENCE", f.Confidence)
	if f.Count > 0 {
		add("EVENTS", fmt.Sprintf("%d", f.Count))
	}
	if f.Version != "" || f.Status != "" || f.FixedIn != "" {
		add("PHP", fmt.Sprintf("version=%s  status=%s  fixed_in=%s",
			orDash(f.Version), orDash(f.Status), orDash(f.FixedIn)))
	}
	if f.FirstSeen != nil || f.LastSeen != nil {
		add("WINDOW", stamp(f.FirstSeen)+" .. "+stamp(f.LastSeen))
	}
	if len(f.CVEs) > 0 {
		add("CVE", strings.Join(f.CVEs, ", "))
	}
	if f.Detail != "" {
		lines = append(lines, "", "DETAIL")
		lines = append(lines, sanitize(f.Detail))
	}
	if len(f.Evidence) > 0 {
		lines = append(lines, "", "EVIDENCE")
		for _, e := range f.Evidence {
			lines = append(lines, "  • "+sanitize(e))
		}
	}
	if f.Remediation != "" {
		lines = append(lines, "", "NEXT")
		lines = append(lines, sanitize(f.Remediation))
	}
	if len(f.Refs) > 0 {
		lines = append(lines, "", "REFERENCES")
		for _, ref := range f.Refs {
			lines = append(lines, "  "+ref)
		}
	}
	lines = append(lines, "")
	return lines
}

// helpDocument is the built-in manual.
func helpDocument(version, host string) []string {
	return []string{
		"PHP2SHELL // NEON GRID — OPERATOR MANUAL",
		strings.Repeat("═", 58),
		"",
		fmt.Sprintf("BUILD      php2shell-audit %s", version),
		"ADVISORY   PHP 5.4 through 8.5.11 affected",
		"CVE        CVE-2026-109618 · memory corruption / OOM longjmp",
		"CVE        CVE-2026-109619 · stale cross-request worker state",
		fmt.Sprintf("OPERATOR   %s", host),
		"",
		"FIXED RELEASES",
		"  8.5.12     8.4.27     8.3.36     8.2.35",
		"  PHP 8.1 and older have no official fix; distro backports vary.",
		"",
		"CONTROLS",
		"  ↑ ↓ / j k    move through the menu or a findings list",
		"  enter        execute the selected operation / open a dossier",
		"  tab          cycle findings, targets and notes",
		"  page up/down scroll a long document",
		"  e            export the current report as JSON",
		"  esc          abort a prompt or return to the menu",
		"  ?            open this manual",
		"  q            quit",
		"",
		"TEMPORARY HARDENING (UNTIL PATCHED)",
		"  memory_limit = -1",
		"  post_max_size = 8M",
		"  session.upload_progress.enabled = 0",
		"  fatal_error_backtraces = 0",
		"  expose_php = Off",
		"  display_errors = Off",
		"  log_errors = On",
		"  Restart every worker; a reload is not always enough. Never use",
		"  RLIMIT_AS or RLIMIT_DATA as the memory boundary.",
		"",
		"SAFETY BOUNDARY",
		"  Remote probes are passive GET requests with a descriptive user",
		"  agent. This console never sends exploit payloads, oversized",
		"  bodies, reverse shells or persistence. Only probe systems you",
		"  own or are explicitly authorised to assess.",
		"",
		"  A clean hunt is not proof of safety: engine-level exploitation",
		"  can leave no application-visible trace. Patch regardless.",
		"",
		"[esc] return    [q] quit",
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func stamp(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
