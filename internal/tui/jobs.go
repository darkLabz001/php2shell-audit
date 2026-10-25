package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/hunt"
	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/offense"
	"github.com/darkLabz001/php2shell-audit/internal/rules"
	"github.com/darkLabz001/php2shell-audit/internal/scan"
)

// job describes one background operation and the hints shown while it runs.
type job struct {
	label  string
	verb   string
	phases []string
	fn     func(context.Context) (*model.Report, string, error)
	export func(*App) (string, error)
	wrap   bool
}

const (
	opTimeout   = 10 * time.Second
	maxEvents   = 500000
	largeBody   = 2 * 1024 * 1024
	minWebScore = 6
)

func (a *App) openPrompt(p *promptState) {
	a.prompt = p
	a.screen = screenPrompt
}

func (a *App) menuLocal() {
	a.startJob(&job{
		label: "LOCAL INVENTORY",
		verb:  "mapping this host for vulnerable PHP builds and loose configuration",
		phases: []string{
			"enumerating php binaries and loaded workers",
			"reading process command lines and SAPIs",
			"querying dpkg / rpm / apk package databases",
			"evaluating php.ini, FPM pools and .user.ini overrides",
			"correlating exposure with runtime posture",
		},
		fn: func(ctx context.Context) (*model.Report, string, error) {
			res := scan.Local(ctx, scan.Options{
				Timeout:   opTimeout,
				Processes: true,
				Packages:  true,
			})
			return reportFrom(a.version, "scan", res), "", nil
		},
	})
}

func (a *App) menuRemote() {
	a.openPrompt(&promptState{
		title: "REMOTE PROBE",
		label: "TARGET URL",
		hint:  "passive GET only · example: https://staging.example.com",
		submit: func(value string) error {
			if !strings.Contains(value, "://") {
				value = "https://" + value
			}
			if !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://"), ".") {
				return fmt.Errorf("not a host: %s", value)
			}
			a.startJob(&job{
				label: "REMOTE PROBE",
				verb:  "reading version headers from " + value,
				phases: []string{
					"resolving endpoint and TLS",
					"requesting the landing page passively",
					"parsing version-bearing headers and body",
					"assessing the patch level",
				},
				fn: func(ctx context.Context) (*model.Report, string, error) {
					res := scan.Remote(ctx, value, scan.RemoteOptions{Timeout: opTimeout})
					return reportFrom(a.version, "scan", res), "", nil
				},
			})
			return nil
		},
	})
}

func (a *App) menuDocker() {
	a.startJob(&job{
		label: "CONTAINER SWEEP",
		verb:  "inspecting running containers through the Docker socket",
		phases: []string{
			"listing containers and pinned/floating tags",
			"inspecting PHP images and entrypoints",
			"comparing observed builds with fixed releases",
		},
		fn: func(ctx context.Context) (*model.Report, string, error) {
			res := scan.Docker(ctx, opTimeout)
			return reportFrom(a.version, "scan", res), "", nil
		},
	})
}

func (a *App) menuLogs() {
	a.openPrompt(&promptState{
		title: "LOG HUNT",
		label: "LOG FILE OR DIRECTORY",
		hint:  "comma-separated · example: /var/log, testdata/logs",
		submit: func(value string) error {
			paths, err := existingPaths(value)
			if err != nil {
				return err
			}
			a.startJob(&job{
				label: "LOG HUNT",
				verb:  "mining telemetry for php2shell exploitation",
				phases: []string{
					"reading access, error and JSON logs",
					"filtering the analysis window",
					"scoring OOM, crash and oversized-body signals",
					"correlating sources and session anomalies",
				},
				fn: func(ctx context.Context) (*model.Report, string, error) {
					res := hunt.Run(hunt.Options{
						Paths:       paths,
						Since:       model.DefaultSince,
						MaxEvents:   maxEvents,
						LargeBody:   largeBody,
						BurstCount:  10,
						BurstWindow: 5 * time.Minute,
					})
					return reportFromHunt(a.version, res), "", nil
				},
			})
			return nil
		},
	})
}

func (a *App) menuLive() {
	a.startJob(&job{
		label: "LIVE RESPONSE",
		verb:  "sweeping processes, sockets, cron, systemd and session stores",
		phases: []string{
			"walking the process tree for shell children",
			"inspecting outbound sockets owned by workers",
			"checking cron, systemd, rc.local and ld.so.preload",
			"reviewing authorized_keys and session files",
		},
		fn: func(ctx context.Context) (*model.Report, string, error) {
			res := hunt.Run(hunt.Options{
				Live:         true,
				Since:        model.DefaultSince,
				AllFiles:     true,
				MinFileScore: minWebScore,
			})
			return reportFromHunt(a.version, res), "", nil
		},
	})
}

func (a *App) menuWebRoot() {
	a.openPrompt(&promptState{
		title: "WEBSHELL SWEEP",
		label: "WEB ROOT",
		hint:  "comma-separated · example: /var/www/html",
		submit: func(value string) error {
			paths, err := existingPaths(value)
			if err != nil {
				return err
			}
			a.startJob(&job{
				label: "WEBSHELL SWEEP",
				verb:  "scoring PHP files and session artefacts",
				phases: []string{
					"walking the web root",
					"scoring webshell heuristics",
					"inspecting .user.ini and .htaccess",
					"triaging session files",
				},
				fn: func(ctx context.Context) (*model.Report, string, error) {
					res := hunt.Run(hunt.Options{
						WebRoots:     paths,
						Since:        model.DefaultSince,
						AllFiles:     true,
						MinFileScore: minWebScore,
					})
					return reportFromHunt(a.version, res), "", nil
				},
			})
			return nil
		},
	})
}

func (a *App) menuRules() {
	a.startJob(&job{
		label: "SIGNATURE FORGE",
		verb:  "compiling detection content for the SOC",
		phases: []string{
			"assembling Sigma rules",
			"binding ModSecurity and nginx request limits",
			"forging YARA, KQL and SPL hunting queries",
		},
		fn: func(ctx context.Context) (*model.Report, string, error) {
			return nil, rulesText(rules.Generate("all")), nil
		},
		export: func(*App) (string, error) {
			files := rules.Generate("all")
			dir := filepath.Join("out", "detections")
			for name, data := range files {
				path := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return "", err
				}
				if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
					return "", err
				}
			}
			return fmt.Sprintf("FORGED %d FILES -> %s", len(files), dir), nil
		},
	})
}

func (a *App) menuOffense() {
	a.openPrompt(&promptState{
		title: "OFFENSE RANGE",
		label: "AUTHORIZATION FILE",
		hint:  "JSON scope · example: docs/authorization.example.json",
		submit: func(path string) error {
			scope, err := offense.LoadScope(path)
			if err != nil {
				return err
			}
			a.openPrompt(&promptState{
				title: "OFFENSE RANGE",
				label: "TARGET URL",
				hint:  "must be listed in case " + scope.CaseID,
				submit: func(target string) error {
					if !strings.Contains(target, "://") {
						target = "https://" + target
					}
					if !scope.Allows(target) {
						return fmt.Errorf("%s is not listed in case %s", target, scope.CaseID)
					}
					a.openPrompt(&promptState{
						title: "OFFENSE RANGE",
						label: "TYPE AUTHORIZE",
						hint:  "case " + scope.CaseID + " · safe validation only · no payloads",
						submit: func(confirm string) error {
							if !strings.EqualFold(strings.TrimSpace(confirm), "AUTHORIZE") {
								return fmt.Errorf("type AUTHORIZE to confirm")
							}
							a.startJob(a.offenseJob(scope, target))
							return nil
						},
					})
					return nil
				},
			})
			return nil
		},
	})
}

func (a *App) offenseJob(scope *offense.Scope, target string) *job {
	return &job{
		label: "OFFENSE RANGE",
		verb:  "authorized validation of CVE-2026-109618 / CVE-2026-109619",
		phases: []string{
			"verifying case scope and target policy",
			"running passive version preflight",
			"checking the bounded OOM pressure path",
			"probing upload-progress state with safe canaries",
			"recording the audit trail",
		},
		fn: func(ctx context.Context) (*model.Report, string, error) {
			res, err := offense.Run(ctx, offense.Options{
				Scope:     scope,
				Targets:   []string{target},
				Timeout:   15 * time.Second,
				Probes:    []string{"109618", "109619"},
				AuditPath: offense.DefaultAudit,
			})
			if err != nil {
				return nil, "", err
			}
			rep := scan.NewReport("offense", a.version)
			rep.Findings = res.Findings
			rep.Targets = res.Targets
			rep.Warnings = res.Warnings
			rep.Notes = res.Notes
			rep.Summary = res.Summary
			return rep, "", nil
		},
	}
}

func (a *App) menuHelp() {
	a.viewer = &viewerState{
		title: "MANUAL // ADVISORY AND CONTROLS",
		body:  helpDocument(a.version, a.host),
		wrap:  true,
		back:  screenMenu,
	}
	a.screen = screenViewer
}

// reportFrom wraps a scan result in the shared report shell.
func reportFrom(version, mode string, res *scan.Result) *model.Report {
	rep := scan.NewReport(mode, version)
	if res == nil {
		rep.Summary = "The scan produced no result."
		return rep
	}
	rep.Findings = res.Findings
	rep.Targets = res.Targets
	rep.Warnings = res.Warnings
	rep.Summary = scan.Summarise(rep)
	return rep
}

// reportFromHunt wraps a hunt result in the shared report shell.
func reportFromHunt(version string, res *hunt.Result) *model.Report {
	rep := scan.NewReport("hunt", version)
	rep.Since = model.DefaultSince.Format(time.RFC3339)
	if res == nil {
		rep.Summary = "The hunt produced no result."
		return rep
	}
	rep.Findings = res.Findings
	rep.Warnings = res.Warnings
	rep.Notes = res.Notes
	rep.Summary = res.Summary
	return rep
}

func existingPaths(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := os.Stat(part); err != nil {
			return nil, fmt.Errorf("no such path: %s", part)
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one path is required")
	}
	return out, nil
}

func rulesText(files map[string]string) string {
	names := make([]string, 0, len(files))
	total := 0
	for name, body := range files {
		names = append(names, name)
		total += len(body)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("DETECTION CONTENT COMPILED\n\n")
	fmt.Fprintf(&b, "%d files · %d bytes\n\n", len(files), total)
	for _, name := range names {
		fmt.Fprintf(&b, "  %-44s %7d B\n", name, len(files[name]))
	}
	b.WriteString("\n[e] write them under out/detections\n")
	b.WriteString("[esc] return to the operations menu\n\n")
	b.WriteString("These rules are starting points. Tune thresholds to your traffic,\n")
	b.WriteString("run in detect mode first, and remember that proxy rules are partial\n")
	b.WriteString("mitigations, not a fix.\n")
	return b.String()
}
