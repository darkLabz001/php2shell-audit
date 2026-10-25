package scan

import (
	"fmt"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/phpver"
)

// Result is what every scan mode returns.
type Result struct {
	Targets  []model.Target
	Findings []model.Finding
	Warnings []string
}

func (r *Result) add(f model.Finding) {
	if f.Target != "" {
		for i := range r.Targets {
			if r.Targets[i].Name == f.Target {
				r.Targets[i].Findings++
				if model.Severity(f.Severity) > 0 {
					r.Targets[i].Worst = f.Severity.String()
				}
			}
		}
	}
	r.Findings = append(r.Findings, f)
}

func (r *Result) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// addTarget appends a target and returns its index.
func (r *Result) addTarget(t model.Target) int {
	r.Targets = append(r.Targets, t)
	return len(r.Targets) - 1
}

func (r *Result) setTarget(i int, t model.Target) {
	if i >= 0 && i < len(r.Targets) {
		r.Targets[i] = t
	}
}

// RLimits captures the per-process limits that make the OOM path reachable.
type RLimits struct {
	AddressSpace string
	DataSize     string
}

// ConfigFindings turns an effective configuration into findings. Severity is
// scaled: on a patched build the same items are hardening advice, on a
// vulnerable build they are live exposure.
func ConfigFindings(target, version, status, sapi string, p *Posture, limits *RLimits) []model.Finding {
	if p == nil {
		return nil
	}
	var out []model.Finding
	patched := status == phpver.StatusFixed || status == phpver.StatusVendorPached
	scale := func(vuln, patchedSev model.Severity) model.Severity {
		if patched {
			return patchedSev
		}
		return vuln
	}
	add := func(f model.Finding) {
		f.Target = target
		f.Surface = "local"
		f.SetLevel()
		out = append(out, f)
	}

	// --- CVE-2026-109618: the out-of-memory trigger -------------------------
	if p.Has("memory_limit") {
		if n, ok := p.Size("memory_limit"); ok {
			if n < 0 {
				add(model.Finding{
					ID: "P2S-CFG-001", Title: "memory_limit is unlimited (partial php2shell mitigation)",
					Severity: model.Info, Category: "config", Confidence: "high",
					Detail:      "A finite memory_limit is required for the confirmed CVE-2026-109618 path. Unlimited memory removes that trigger, but an underlying allocation failure can still reach the vulnerable code.",
					Evidence:    []string{"memory_limit=" + p.Get("memory_limit")},
					CVEs:        []string{model.CVE109618},
					Remediation: "Keep memory_limit=-1 pinned with php_admin_value and bound the container/cgroup instead. Never use RLIMIT_AS or RLIMIT_DATA.",
				})
			} else {
				admin := p.AdminLevel("memory_limit")
				detail := fmt.Sprintf("memory_limit is %s (%s). A request that exhausts it takes the longjmp()/OOM path that CVE-2026-109618 turns into memory corruption.", p.Get("memory_limit"), FormatSize(n))
				remed := "Pin memory_limit=-1 with php_admin_value (FPM pool or Apache), lower post_max_size to 8M (32M with uploads), and add container memory limits."
				if !admin {
					detail += " It is not pinned at administrator level, so application code or .user.ini can change it."
				}
				add(model.Finding{
					ID: "P2S-CFG-001", Title: "Finite memory_limit keeps the php2shell OOM trigger reachable",
					Severity: scale(model.High, model.Low), Category: "config", Confidence: "high",
					Detail: detail, Evidence: []string{"memory_limit=" + p.Get("memory_limit")},
					CVEs: []string{model.CVE109618}, Remediation: remed,
				})
			}
		}
	} else {
		add(model.Finding{
			ID: "P2S-CFG-001", Title: "memory_limit could not be determined from configuration files",
			Severity: scale(model.Medium, model.Info), Category: "config", Confidence: "low",
			Detail:      "The effective value may be set by a pool, container entrypoint or per-request override. Read it from the web SAPI, not the CLI.",
			CVEs:        []string{model.CVE109618},
			Remediation: "Run phpinfo() through the web server, or scan every FPM pool and Apache vhost.",
		})
	}

	if p.Has("post_max_size") {
		if n, ok := p.Size("post_max_size"); ok {
			if n <= 0 || n > 32*1024*1024 {
				add(model.Finding{
					ID: "P2S-CFG-004", Title: "post_max_size allows oversized request bodies",
					Severity: scale(model.Medium, model.Low), Category: "config", Confidence: "high",
					Detail:      fmt.Sprintf("post_max_size is %s. Multi-megabyte form bodies are the delivery vehicle for the confirmed CVE-2026-109618 chains.", p.Get("post_max_size")),
					Evidence:    []string{"post_max_size=" + p.Get("post_max_size")},
					CVEs:        []string{model.CVE109618},
					Remediation: "Set post_max_size=8M where uploads are not needed, 32M at most otherwise, and enforce decoded-body, part-count and field-count limits at the proxy.",
				})
			}
		}
	}

	// --- CVE-2026-109619: stale cross-request state ------------------------
	if v, known := p.Bool("session.upload_progress.enabled"); known {
		if v {
			add(model.Finding{
				ID: "P2S-CFG-002", Title: "session.upload_progress is enabled",
				Severity: scale(model.High, model.Medium), Category: "config", Confidence: "high",
				Detail:      "Upload progress tracking runs during request startup, before application code, and is one of the two confirmed CVE-2026-109619 triggers. It is enabled by default and works even when the application never calls session_start().",
				Evidence:    []string{"session.upload_progress.enabled=" + p.Get("session.upload_progress.enabled")},
				CVEs:        []string{model.CVE109619},
				Remediation: "Set session.upload_progress.enabled=0 in php.ini or the FPM pool, then restart every worker. Do not rely on ini_set() or .user.ini.",
			})
		} else {
			add(model.Finding{
				ID: "P2S-CFG-002", Title: "session.upload_progress is disabled (blocks the confirmed upload path)",
				Severity: model.Info, Category: "config", Confidence: "high",
				Evidence: []string{"session.upload_progress.enabled=" + p.Get("session.upload_progress.enabled")},
				CVEs:     []string{model.CVE109619},
			})
		}
	} else {
		add(model.Finding{
			ID: "P2S-CFG-002", Title: "session.upload_progress state could not be determined",
			Severity: scale(model.Medium, model.Info), Category: "config", Confidence: "low",
			Detail:      "If unset, PHP's default is enabled. Verify the effective value from the web SAPI.",
			CVEs:        []string{model.CVE109619},
			Remediation: "Set session.upload_progress.enabled=0 explicitly and restart all workers.",
		})
	}

	if v, ok := phpver.Parse(version); ok && v.Major == 8 && v.Minor >= 5 {
		if on, known := p.Bool("fatal_error_backtraces"); known {
			if on {
				add(model.Finding{
					ID: "P2S-CFG-003", Title: "fatal_error_backtraces is enabled",
					Severity: scale(model.High, model.Medium), Category: "config", Confidence: "high",
					Detail:      "On PHP 8.5 this retains fatal-error backtrace state across requests, the confirmed CVE-2026-109619 backtrace path.",
					Evidence:    []string{"fatal_error_backtraces=" + p.Get("fatal_error_backtraces")},
					CVEs:        []string{model.CVE109619},
					Remediation: "Set fatal_error_backtraces=0 on PHP 8.5 and restart every worker.",
				})
			}
		} else {
			add(model.Finding{
				ID: "P2S-CFG-003", Title: "fatal_error_backtraces state could not be determined",
				Severity: scale(model.Low, model.Info), Category: "config", Confidence: "low",
				CVEs:        []string{model.CVE109619},
				Remediation: "On PHP 8.5, set fatal_error_backtraces=0 explicitly.",
			})
		}
	}

	if strings.Contains(strings.ToLower(sapi), "fpm") {
		req := p.Get("pm.max_requests")
		if req == "1" {
			add(model.Finding{
				ID: "P2S-CFG-005", Title: "FPM recycles every worker after one request",
				Severity: model.Info, Category: "config", Confidence: "high",
				Detail:   "pm.max_requests=1 breaks the same-worker requirement for the cross-request CVE-2026-109619 chains.",
				Evidence: []string{"pm.max_requests=1"}, CVEs: []string{model.CVE109619},
			})
		} else {
			add(model.Finding{
				ID: "P2S-CFG-005", Title: "FPM worker reuse enables cross-request stale state",
				Severity: scale(model.Low, model.Info), Category: "config", Confidence: "medium",
				Detail:      "A worker serves many requests. pm.max_requests is " + orUnknown(req) + "; recycling after each request removes the same-worker condition (at a throughput cost).",
				Evidence:    []string{"pm.max_requests=" + orUnknown(req)},
				CVEs:        []string{model.CVE109619},
				Remediation: "While unpatched, set pm.max_requests=1 if capacity allows, or set it low to bound the window.",
			})
		}
		if kids := p.Get("pm.max_children"); kids != "" {
			add(model.Finding{
				ID: "P2S-CFG-010", Title: "FPM pool size affects exploit reliability",
				Severity: model.Info, Category: "config", Confidence: "medium",
				Detail:   "pm.max_children=" + kids + ". A larger pool lowers the success rate per request but does not remove the vulnerability.",
				Evidence: []string{"pm.max_children=" + kids},
			})
		}
	}

	if limits != nil {
		if limits.AddressSpace != "" || limits.DataSize != "" {
			add(model.Finding{
				ID: "P2S-CFG-006", Title: "Process address-space limits can force the vulnerable allocation failure",
				Severity: scale(model.High, model.Medium), Category: "config", Confidence: "high",
				Detail:      "The running worker has non-unlimited RLIMIT_AS/RLIMIT_DATA. The advisory explicitly warns not to use these as the memory boundary for CVE-2026-109618.",
				Evidence:    compact([]string{"RLIMIT_AS=" + orDash(limits.AddressSpace), "RLIMIT_DATA=" + orDash(limits.DataSize)}),
				CVEs:        []string{model.CVE109618},
				Remediation: "Remove RLIMIT_AS/RLIMIT_DATA and use a container/cgroup memory limit instead.",
			})
		}
	}

	if v, known := p.Bool("display_errors"); known && v {
		add(model.Finding{
			ID: "P2S-CFG-007", Title: "display_errors is enabled in a served configuration",
			Severity: model.Low, Category: "config", Confidence: "medium",
			Detail:      "Exploit attempts frequently produce startup fatals and warnings. Displaying them leaks build and memory details to an attacker.",
			Evidence:    []string{"display_errors=" + p.Get("display_errors")},
			Remediation: "Set display_errors=0 and log_errors=1 in production, then restart workers.",
		})
	}
	if v, known := p.Bool("opcache.enable"); known && v {
		add(model.Finding{
			ID: "P2S-CFG-008", Title: "OPcache is enabled (shared-state primitive present)",
			Severity: model.Info, Category: "config", Confidence: "high",
			Detail:   "The OPcache type-confusion primitive behind one CVE-2026-109619 chain requires OPcache shared memory. This is informational; it is not a vulnerability on a patched build.",
			Evidence: []string{"opcache.enable=" + p.Get("opcache.enable")},
			CVEs:     []string{model.CVE109619},
		})
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "(default)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func compact(in []string) []string {
	var out []string
	for _, s := range in {
		if !strings.HasSuffix(s, "=-") {
			out = append(out, s)
		}
	}
	return out
}

// ExposureFinding reports the version assessment for one target.
func ExposureFinding(target, surface, sapi, version string, a phpver.Assessment, source string) model.Finding {
	f := model.Finding{
		ID:      "P2S-EXP-001",
		Target:  target,
		Surface: surface,
		Version: version,
		SAPI:    sapi,
		Status:  a.Status,
		FixedIn: a.FixedIn,
		Refs:    []string{model.AdvisoryURL, model.GHSA109618, model.GHSA109619},
		CVEs:    []string{model.CVE109618, model.CVE109619},
		Meta:    map[string]string{"source": source},
	}
	switch a.Status {
	case phpver.StatusFixed:
		f.Title = "PHP " + version + " is patched for php2shell"
		f.Severity = model.Info
		f.Confidence = "high"
		f.Detail = "This build is at or above the fixed release for its branch."
		f.Remediation = "No action. Keep workers restarted on the patched build and retain the temporary hardening."
	case phpver.StatusVendorPached:
		f.Title = "PHP " + version + " carries a vendor backport for php2shell"
		f.Severity = model.Info
		f.Confidence = "medium"
		f.Detail = "The upstream version is in the affected range, but the package changelog references both CVE IDs. Verify the running worker was restarted after the package update."
		f.Remediation = "Confirm the loaded module/binary matches the patched package, then restart the web server or FPM pool."
	case phpver.StatusEOL:
		f.Title = "PHP " + version + " is end-of-life and has no official php2shell fix"
		f.Severity = model.High
		f.Confidence = "high"
		f.Detail = "PHP 8.1 and older no longer receive upstream security releases. Distribution backports may exist; otherwise this installation is permanently exposed."
		f.Remediation = "Upgrade to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or a vendor backport), and restart every worker."
	case phpver.StatusVulnerable:
		f.Severity = severityFromString(phpver.SeverityFor(a.Status, sapi))
		f.Confidence = "high"
		f.Title = "PHP " + version + " is vulnerable to php2shell"
		f.Detail = "Affected by CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global state). The bugs are in the PHP engine, below application code, so CMS patches and application hardening do not help."
		if strings.Contains(strings.ToLower(sapi), "apache") || strings.Contains(strings.ToLower(sapi), "mod_php") || strings.Contains(strings.ToLower(sapi), "handler") {
			f.Detail += " mod_php is the highest-risk SAPI: the demonstrated chain runs before any application code."
		}
		f.Remediation = "Upgrade to " + a.FixedIn + " or later and restart the web server/FPM workers. Until then isolate the service or apply the partial runtime mitigations."
	default:
		f.Title = "PHP " + version + " has an unverified php2shell status"
		f.Severity = model.Medium
		f.Confidence = "low"
		f.Detail = "The branch is not covered by the published fixed-version table. Treat it as vulnerable until the vendor confirms."
		f.Remediation = "Confirm support status with the vendor or the PHP release notes."
	}
	if len(a.Notes) > 0 {
		f.Detail += " " + strings.Join(a.Notes, " ")
	}
	f.SetLevel()
	return f
}

func severityFromString(s string) model.Severity {
	v, ok := model.ParseSeverity(s)
	if !ok {
		return model.Medium
	}
	return v
}

// NewReport assembles the shared report shell.
func NewReport(mode, version string) *model.Report {
	return &model.Report{
		Tool:        "php2shell-audit",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Mode:        mode,
	}
}

// Summarise describes the target inventory in one operator-facing sentence.
// It is shared by the CLI and the interactive console so both report the same
// patch posture.
func Summarise(r *model.Report) string {
	var vulnerable, eol, fixed, unknown int
	for _, t := range r.Targets {
		switch t.Status {
		case "vulnerable":
			vulnerable++
		case "eol":
			eol++
		case "fixed", "vendor-patched":
			fixed++
		default:
			unknown++
		}
	}
	if len(r.Targets) == 0 {
		return "No PHP installation was found. If PHP runs in a container or on another host, use --docker or --target."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Inspected %d PHP target(s): %d vulnerable, %d end-of-life, %d patched, %d unverified.",
		len(r.Targets), vulnerable, eol, fixed, unknown)
	if vulnerable > 0 || eol > 0 {
		b.WriteString(" Upgrade to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a vendor backport) and restart every worker. Do not rely on application-level patches.")
	}
	return b.String()
}
