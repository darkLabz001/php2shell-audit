package hunt

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// Options configures a hunt.
type Options struct {
	Paths        []string
	Since        time.Time
	Until        time.Time
	Live         bool
	WebRoots     []string
	SessionPaths []string
	AllFiles     bool
	MinFileScore int
	MaxEvents    int
	LargeBody    int64
	BurstCount   int
	BurstWindow  time.Duration
	IncludeNoise bool
	// EvidenceDir, when set, receives a case directory containing the findings,
	// raw events and a SHA-256 manifest.
	EvidenceDir string
}

// Event is one detector hit, kept for correlation before it is aggregated into
// a finding.
type Event struct {
	Kind     string
	Severity model.Severity
	Time     time.Time
	Target   string
	Detail   string
	Evidence string
	Rec      Record
}

var (
	oomRE        = regexp.MustCompile(`(?i)Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\)`)
	unknownLine  = regexp.MustCompile(`(?i)in Unknown on line 0`)
	crashRE      = regexp.MustCompile(`(?i)(AH00052: child pid \d+ exit signal (?:Segmentation fault|Aborted)|exited on signal (?:11|6)|signal (?:11|6) \(SIG(?:SEGV|ABRT)\)|Segmentation fault \(11\)|SIGSEGV|SIGABRT)`)
	sessCookieRE = regexp.MustCompile(`(?i)PHPSESSID=([^;\s,]+)`)
	progressRE   = regexp.MustCompile(`(?i)PHP_SESSION_UPLOAD_PROGRESS`)
	multipartRE  = regexp.MustCompile(`(?i)multipart/form-data`)
)

// Analyze runs the log detectors. It returns findings and the raw events used
// for correlation.
func Analyze(records []Record, opts Options) ([]model.Finding, []Event) {
	if opts.LargeBody <= 0 {
		opts.LargeBody = 2 * 1024 * 1024
	}
	if opts.BurstCount <= 0 {
		opts.BurstCount = 10
	}
	if opts.BurstWindow <= 0 {
		opts.BurstWindow = 5 * time.Minute
	}

	var events []Event
	largeByIP := map[string][]time.Time{}
	oomByIP := map[string][]time.Time{}

	for _, rec := range records {
		if !opts.Since.IsZero() && !rec.Time.IsZero() && rec.Time.Before(opts.Since) {
			continue
		}
		if !opts.Until.IsZero() && !rec.Time.IsZero() && rec.Time.After(opts.Until) {
			continue
		}
		text := rec.Message
		if text == "" {
			text = rec.Raw
		}
		ev := baseEvent(rec)
		matchedOOM := false

		if m := oomRE.FindStringSubmatch(text); m != nil {
			preInit := unknownLine.MatchString(text) || unknownLine.MatchString(rec.Raw)
			ev.Kind = "oom-inscript"
			ev.Severity = model.Low
			ev.Detail = fmt.Sprintf("memory_limit exhausted (tried to allocate %s)", m[2])
			if preInit {
				ev.Kind = "oom-startup"
				ev.Severity = model.High
				ev.Detail = "memory_limit exhausted during request initialization (in Unknown on line 0)"
				if !rec.Time.IsZero() {
					oomByIP[ev.Target] = append(oomByIP[ev.Target], rec.Time)
				}
			}
			ev.Evidence = formatEvidence(rec)
			if preInit || opts.IncludeNoise {
				events = append(events, ev)
			}
			matchedOOM = preInit
		}

		// A single request can carry several independent signals (for example a
		// 35 MB body that also leaks an anomalous session cookie). Record all of
		// them instead of stopping at the first match.
		if !matchedOOM && crashRE.MatchString(text) && rec.Kind != "access" {
			ev.Kind = "worker-crash"
			ev.Severity = model.Medium
			ev.Detail = "PHP worker terminated abnormally (failed exploit attempts commonly crash the worker)"
			ev.Evidence = formatEvidence(rec)
			events = append(events, ev)
		}

		if progressRE.MatchString(rec.Raw) || progressRE.MatchString(rec.SetCookie) || progressRE.MatchString(strings.Join(fieldValues(rec, "request_body", "body", "payload"), " ")) {
			ev.Kind = "upload-progress"
			ev.Severity = model.Medium
			ev.Detail = "request references PHP_SESSION_UPLOAD_PROGRESS, the session upload-progress trigger for CVE-2026-109619"
			ev.Evidence = formatEvidence(rec)
			events = append(events, ev)
		}

		if rec.SetCookie != "" {
			if m := sessCookieRE.FindStringSubmatch(rec.SetCookie); m != nil {
				val := m[1]
				if len(val) > 256 || strings.Count(val, "%") >= 8 {
					ev.Kind = "session-leak"
					ev.Severity = model.High
					ev.Detail = fmt.Sprintf("PHPSESSID is %d bytes with %d percent escapes; the CVE-2026-109618 leak URL-encodes worker memory into this cookie", len(val), strings.Count(val, "%"))
					ev.Evidence = formatEvidence(rec)
					events = append(events, ev)
				}
			}
		}

		if isWriteMethod(rec.Method) && rec.ContentLength >= opts.LargeBody {
			ev.Kind = "large-body"
			ev.Severity = model.Medium
			ev.Detail = fmt.Sprintf("%s with a %s request body", rec.Method, humanBytes(rec.ContentLength))
			if ct := recordField(rec, "content_type", "content-type"); multipartRE.MatchString(ct) {
				ev.Detail += " (multipart/form-data)"
			}
			ev.Evidence = formatEvidence(rec)
			events = append(events, ev)
			if !rec.Time.IsZero() {
				largeByIP[ev.Target] = append(largeByIP[ev.Target], rec.Time)
			}
		}
	}

	findings := aggregateAttempts(events)
	findings = append(findings, burstFindings(records, opts.BurstCount, opts.BurstWindow)...)
	findings = append(findings, correlationFindings(events, largeByIP, oomByIP)...)
	return findings, events
}

func baseEvent(rec Record) Event {
	target := rec.IP
	if target == "" {
		target = rec.Fields["host"]
	}
	return Event{Time: rec.Time, Target: target, Rec: rec}
}

func isWriteMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

func fieldValues(rec Record, keys ...string) []string {
	var out []string
	for _, k := range keys {
		for fk, fv := range rec.Fields {
			if strings.EqualFold(fk, k) && fv != "" {
				out = append(out, fv)
			}
		}
	}
	return out
}

func recordField(rec Record, keys ...string) string {
	vals := fieldValues(rec, keys...)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// aggregateAttempts groups events by kind and source into findings.
func aggregateAttempts(events []Event) []model.Finding {
	specs := []struct {
		kind       string
		id         string
		title      string
		category   string
		confidence string
		detail     string
		next       string
	}{
		{"oom-startup", "P2S-HUNT-001", "PHP memory exhaustion during request startup", "attempt", "high",
			"A fatal OOM before any application code runs is the signature of the CVE-2026-109618 trigger. A clean application log does not rule this out.",
			"Patch PHP; correlate with the source IP's other requests, oversized bodies and worker crashes."},
		{"worker-crash", "P2S-HUNT-002", "PHP worker crashed with SIGSEGV/SIGABRT", "attempt", "medium",
			"Use-after-free attempts that miss the target layout usually crash the worker. Legitimate bugs can also do this, so correlate with request and error-log signals.",
			"Identify the request served immediately before each crash and preserve the worker core dump if available."},
		{"large-body", "P2S-HUNT-003", "Oversized write request reached a PHP endpoint", "attempt", "medium",
			"Multi-megabyte form bodies are the delivery vehicle for the confirmed CVE-2026-109618 chains. Normal application traffic may include uploads, so baseline before alerting.",
			"Enforce decoded-body and field/part limits at the proxy; check the matching PHP error log for startup OOMs."},
		{"upload-progress", "P2S-HUNT-004", "Request used the session upload-progress trigger", "attempt", "high",
			"PHP_SESSION_UPLOAD_PROGRESS is parsed before application code and is one of the two confirmed CVE-2026-109619 triggers. It is not needed by most applications.",
			"Disable session.upload_progress.enabled, restart workers, and inspect the full request if a WAF body capture exists."},
		{"session-leak", "P2S-HUNT-005", "Anomalous PHPSESSID response cookie", "attempt", "high",
			"The CVE-2026-109618 memory-disclosure primitive URL-encodes leaked worker memory into Set-Cookie: PHPSESSID. This can expose credentials and tokens even without code execution.",
			"Preserve the cookie value and the matching request, patch immediately, and rotate every secret the PHP process could read."},
	}

	var out []model.Finding
	for _, spec := range specs {
		groups := map[string][]Event{}
		for _, ev := range events {
			if ev.Kind != spec.kind {
				continue
			}
			key := ev.Target
			if key == "" {
				key = "(unknown source)"
			}
			groups[key] = append(groups[key], ev)
		}
		targets := make([]string, 0, len(groups))
		for t := range groups {
			targets = append(targets, t)
		}
		sort.Slice(targets, func(i, j int) bool { return len(groups[targets[i]]) > len(groups[targets[j]]) })

		for i, target := range targets {
			if i >= 10 {
				break
			}
			out = append(out, buildFinding(groups[target], spec.id, spec.title, spec.category, spec.confidence, spec.detail, spec.next))
		}
		if len(targets) > 10 {
			merged := buildFinding(eventsOfKind(events, spec.kind), spec.id, spec.title, spec.category, spec.confidence,
				spec.detail+fmt.Sprintf(" Showing the top 10 of %d sources.", len(targets)), spec.next)
			merged.Target = fmt.Sprintf("%d sources", len(targets))
			out = append(out, merged)
		}
	}
	return out
}

func eventsOfKind(events []Event, kind string) []Event {
	var out []Event
	for _, ev := range events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func buildFinding(events []Event, id, title, category, confidence, detail, next string) model.Finding {
	if len(events) == 0 {
		return model.Finding{}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	f := model.Finding{
		ID: id, Title: title, Category: category, Confidence: confidence,
		Detail: detail, Remediation: next, Surface: "logs",
		CVEs:  []string{model.CVE109618, model.CVE109619},
		Refs:  []string{model.AdvisoryURL, model.GHSA109618, model.GHSA109619},
		Count: len(events),
	}
	if events[0].Target != "" {
		f.Target = events[0].Target
	}
	if !events[0].Time.IsZero() {
		t := events[0].Time
		f.FirstSeen = &t
	}
	if !events[len(events)-1].Time.IsZero() {
		t := events[len(events)-1].Time
		f.LastSeen = &t
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.Evidence != "" && !seen[ev.Evidence] {
			seen[ev.Evidence] = true
			f.Evidence = append(f.Evidence, ev.Evidence)
		}
		if len(f.Evidence) >= 8 {
			break
		}
	}
	if f.Severity == 0 {
		f.Severity = events[0].Severity
	}
	for _, ev := range events {
		if ev.Severity > f.Severity {
			f.Severity = ev.Severity
		}
	}
	f.SetLevel()
	return f
}

// burstFindings detects repeated 5xx responses from one source.
func burstFindings(records []Record, threshold int, window time.Duration) []model.Finding {
	type hit struct {
		time time.Time
		rec  Record
	}
	byIP := map[string][]hit{}
	for _, rec := range records {
		if rec.Kind != "access" || rec.Status < 500 || rec.IP == "" || rec.Time.IsZero() {
			continue
		}
		byIP[rec.IP] = append(byIP[rec.IP], hit{rec.Time, rec})
	}
	var out []model.Finding
	for ip, hits := range byIP {
		sort.Slice(hits, func(i, j int) bool { return hits[i].time.Before(hits[j].time) })
		var bursts [][]hit
		i := 0
		for i < len(hits) {
			j := i
			for j < len(hits) && hits[j].time.Sub(hits[i].time) <= window {
				j++
			}
			if j-i >= threshold {
				bursts = append(bursts, hits[i:j])
				i = j
			} else {
				i++
			}
		}
		if len(bursts) == 0 {
			continue
		}
		var evs []Event
		for _, b := range bursts {
			evs = append(evs, Event{
				Kind: "burst", Severity: model.High, Time: b[0].time, Target: ip,
				Detail:   fmt.Sprintf("%d 5xx responses in %s", len(b), window),
				Evidence: formatEvidence(b[0].rec),
			})
		}
		f := buildFinding(evs, "P2S-HUNT-006", "Burst of 5xx responses from one source", "attempt", "medium",
			fmt.Sprintf("%d burst(s) of at least %d server errors within %s. Exploit attempts need repeated attempts to adapt to the target's memory layout.", len(bursts), threshold, window),
			"Correlate with startup OOMs, worker crashes and oversized POSTs from the same source.")
		out = append(out, f)
	}
	return out
}

// correlationFindings raises severity when independent exploit signals share a
// source.
func correlationFindings(events []Event, largeByIP, oomByIP map[string][]time.Time) []model.Finding {
	kindsByIP := map[string]map[string]bool{}
	evsByIP := map[string][]Event{}
	for _, ev := range events {
		if ev.Target == "" {
			continue
		}
		if kindsByIP[ev.Target] == nil {
			kindsByIP[ev.Target] = map[string]bool{}
		}
		kindsByIP[ev.Target][ev.Kind] = true
		evsByIP[ev.Target] = append(evsByIP[ev.Target], ev)
	}

	var out []model.Finding
	for ip, kinds := range kindsByIP {
		// Require at least two independent signal families.
		if len(kinds) < 2 {
			continue
		}
		important := kinds["oom-startup"] || kinds["session-leak"] || kinds["worker-crash"]
		if !important && len(kinds) < 3 {
			continue
		}
		f := buildFinding(evsByIP[ip], "P2S-HUNT-007", "Multiple php2shell exploitation signals from one source", "attempt", "high",
			"Independent indicators (startup OOM, worker crash, oversized request, upload-progress use or leaked session data) share this source within the analysed window. This is the correlation pattern of an active exploitation attempt.",
			"Treat the source as hostile, preserve evidence, patch now, and rotate secrets if any memory-disclosure signal is present.")
		f.Severity = model.Critical
		f.Target = ip
		f.SetLevel()
		f.Meta = map[string]string{"signals": strings.Join(sortedKeys(kinds), ",")}
		out = append(out, f)
	}

	// Same-source OOM and large body within two minutes is the strongest
	// log-only pairing for CVE-2026-109618.
	for ip, ooms := range oomByIP {
		for _, ot := range ooms {
			for _, lt := range largeByIP[ip] {
				if absDuration(ot.Sub(lt)) <= 2*time.Minute {
					var evs []Event
					for _, ev := range evsByIP[ip] {
						if ev.Kind == "oom-startup" || ev.Kind == "large-body" {
							evs = append(evs, ev)
						}
					}
					if len(evs) == 0 {
						continue
					}
					f := buildFinding(evs, "P2S-HUNT-008", "Startup OOM paired with an oversized request", "attempt", "high",
						"An OOM during request initialization occurred within two minutes of a multi-megabyte write request from the same source. This is the request shape of the CVE-2026-109618 trigger.",
						"Capture the full request body if a proxy retained it, check for worker crashes, and patch immediately.")
					f.Target = ip
					f.Severity = model.High
					f.SetLevel()
					out = append(out, f)
					goto next
				}
			}
		}
	next:
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
