// Package cli implements the php2shell-audit command line interface.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/buildinfo"
	"github.com/darkLabz001/php2shell-audit/internal/hunt"
	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/offense"
	"github.com/darkLabz001/php2shell-audit/internal/output"
	"github.com/darkLabz001/php2shell-audit/internal/rules"
	"github.com/darkLabz001/php2shell-audit/internal/scan"
	"github.com/darkLabz001/php2shell-audit/internal/tui"
)

// Exit codes. 2 means "the requested severity threshold was met", which makes
// the tool usable as a CI or cron gate without parsing output.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitFindings = 2
)

// DefaultSince is the first day exploitation attempts were publicly reported.
// It is shared by the CLI and the interactive console.
var DefaultSince = model.DefaultSince

// Run executes the command line and returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		if tui.IsTerminal(os.Stdin) && tui.IsTerminal(os.Stdout) {
			return runTUI()
		}
		usage(os.Stderr)
		return ExitError
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "hunt":
		return runHunt(args[1:])
	case "rules":
		return runRules(args[1:])
	case "offense", "offence":
		return runOffense(args[1:])
	case "tui", "ui", "console":
		return runTUI()
	case "version", "--version", "-v":
		return runVersion(args[1:])
	case "help", "--help", "-h":
		usage(os.Stdout)
		return ExitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return ExitError
	}
}

// runTUI starts the interactive console. It requires a real terminal; scripts
// and pipes should use scan, hunt or rules instead.
func runTUI() int {
	if err := tui.Run(tui.Config{Version: buildinfo.Version}); err != nil {
		fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `php2shell-audit %s - exposure scanner and threat hunter for the
October 2026 PHP "php2shell" vulnerabilities (CVE-2026-109618 / CVE-2026-109619).

USAGE
  p2s tui                     open the interactive cyberpunk console
  p2s scan   [options]        inventory PHP and verify patch status
  p2s hunt   [options]        hunt logs, web roots and hosts for exploitation
  p2s rules  [options]        emit Sigma/ModSecurity/nginx/YARA/KQL/SPL content
  p2s offense [options]       authorized CVE-2026-109618/9 validation
  p2s version                 print build information

TUI
  p2s tui                     interactive menu, findings browser and export
  Aliased to "php" by "make install-alias" for quick access.

SCAN
  p2s scan --local                          scan this host (default)
  p2s scan --target https://site.example    passive remote check
  p2s scan --targets-file targets.txt       one URL per line
  p2s scan --docker                         inventory running containers
  p2s scan --local --web-root /var/www --ini /etc/php/8.4/fpm/php.ini

  --local                 inventory binaries, processes and packages (default)
  --target URL            passive check of a remote endpoint (repeatable)
  --targets-file FILE     read remote targets, one per line
  --docker                inspect running containers through the docker CLI
  --web-root DIR          web root to search for .user.ini/.htaccess (repeatable)
  --ini FILE              php.ini or FPM pool file to read (repeatable)
  --path PATH             extra path to GET on each remote target (repeatable,
                          e.g. /phpinfo.php on an operator-owned host)
  --timeout DURATION      per-operation timeout (default 8s)
  --insecure              skip TLS verification for remote targets

HUNT
  p2s hunt --logs /var/log --web-root /var/www --live
  p2s hunt --logs today.log --since 2026-10-17T00:00:00Z --evidence ./case-1

  --logs PATH             log file or directory (repeatable)
  --web-root DIR          web root to scan for webshells (repeatable)
  --session-path DIR      session save_path to inspect (repeatable)
  --live                  inspect the running host: processes, sockets,
                          cron/systemd/authorized_keys
  --since TIME            start of the window (default %s)
  --until TIME            end of the window
  --all-files             scan files older than --since too
  --min-file-score N      webshell score threshold (default 6)
  --max-events N          cap parsed log records (default 500000)
  --large-body BYTES      oversized-request threshold (default 2 MiB)
  --evidence DIR          write findings, events and a SHA-256 manifest

OFFENSE (authorized validation)
  p2s offense --authorize scope.json --target http://127.0.0.1:8081/
  p2s offense --authorize scope.json --target http://127.0.0.1:8081/ \
      --oom-body 8MiB --acknowledge-disruption

  --authorize FILE         JSON authorization scope (required)
  --target URL             endpoint listed in the scope (repeatable)
  --probe LIST             109618, 109619 or both (default both)
  --oom-body SIZE          opt-in CVE-2026-109618 pressure body (default 0)
  --acknowledge-disruption required for --oom-body; may disrupt a worker
  --allow-public           permit a public target explicitly allowed by scope
  --audit FILE             JSONL audit log (default out/offense-audit.jsonl)
  --insecure               skip TLS verification
  --timeout DURATION       per-request timeout (default 15s)

  Offense stops at validation. It never runs code, writes a webshell or
  installs persistence, and the pressure probe is capped at 64 MiB.

COMMON
  --format FORMAT         text, json, jsonl or sarif (default text)
  --output FILE           write the report to FILE instead of stdout
  --fail-on SEVERITY      exit 2 when a finding is at least this severe
  --no-color              disable ANSI colour

RULES
  p2s rules --format all --output ./detections
  p2s rules --format sigma              # print to stdout

  --format FORMAT         all, sigma, modsecurity, nginx, yara, kql, splunk
  --output DIR            write files under DIR; "-" prints to stdout
  --list                  list the files that would be written

Scan and hunt remote checks are passive GET requests. Offense mode sends only
the bounded validation probes described above. The tool never sends exploit
payloads, opens reverse shells, writes webshells or installs persistence.
`, buildinfo.Version, DefaultSince.Format(time.RFC3339))
}

// --- flags -----------------------------------------------------------------

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func newFlagSet(name, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", summary)
		fs.PrintDefaults()
	}
	return fs
}

type commonFlags struct {
	format  string
	output  string
	failOn  string
	noColor bool
}

func addCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.format, "format", "text", "output format: text, json, jsonl or sarif")
	fs.StringVar(&c.output, "output", "", "write the report to this file instead of stdout")
	fs.StringVar(&c.failOn, "fail-on", "", "exit 2 when a finding is at least this severe (info, low, medium, high, critical)")
	fs.BoolVar(&c.noColor, "no-color", false, "disable ANSI colour")
}

// emit writes the report and returns the process exit code.
func emit(r *model.Report, c commonFlags) int {
	colour := !c.noColor && c.output == "" && isTerminal(os.Stdout)
	var w io.Writer = os.Stdout
	var file *os.File
	if c.output != "" && c.output != "-" {
		if err := os.MkdirAll(filepath.Dir(c.output), 0o755); err != nil && filepath.Dir(c.output) != "." {
			fmt.Fprintf(os.Stderr, "p2s: create output directory: %v\n", err)
			return ExitError
		}
		f, err := os.Create(c.output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "p2s: create output: %v\n", err)
			return ExitError
		}
		defer f.Close()
		file = f
		w = f
	}
	if err := output.Write(w, r, c.format, colour); err != nil {
		fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
		return ExitError
	}
	if file != nil {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "p2s: write output: %v\n", err)
			return ExitError
		}
	}
	if c.failOn != "" {
		floor, ok := model.ParseSeverity(c.failOn)
		if !ok {
			fmt.Fprintf(os.Stderr, "p2s: unknown --fail-on severity %q\n", c.failOn)
			return ExitError
		}
		if r.MaxSeverity().AtLeast(floor) {
			return ExitFindings
		}
	}
	return ExitOK
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// --- scan ------------------------------------------------------------------

func runScan(args []string) int {
	fs := newFlagSet("scan", "Inventory PHP installations, verify patch status and assess exposure.")
	var (
		local       bool
		docker      bool
		targets     stringList
		targetsFile string
		webRoots    stringList
		iniPaths    stringList
		paths       stringList
		timeout     time.Duration
		insecure    bool
		common      commonFlags
	)
	fs.BoolVar(&local, "local", false, "inventory this host (default when no other mode is selected)")
	fs.BoolVar(&docker, "docker", false, "inspect running containers")
	fs.Var(&targets, "target", "remote URL to check passively (repeatable)")
	fs.StringVar(&targetsFile, "targets-file", "", "file containing remote targets, one per line")
	fs.Var(&webRoots, "web-root", "web root used to find per-directory PHP config (repeatable)")
	fs.Var(&iniPaths, "ini", "php.ini or FPM pool file to read (repeatable)")
	fs.Var(&paths, "path", "extra path to GET on remote targets (repeatable)")
	fs.DurationVar(&timeout, "timeout", 8*time.Second, "per-operation timeout")
	fs.BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	addCommon(fs, &common)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if fs.NArg() > 0 {
		// Accept bare URLs for convenience: p2s scan https://example.com
		for _, a := range fs.Args() {
			if strings.Contains(a, "://") || strings.HasPrefix(a, "http") {
				targets = append(targets, a)
			} else {
				fmt.Fprintf(os.Stderr, "p2s: unexpected argument %q\n", a)
				return ExitError
			}
		}
	}
	if targetsFile != "" {
		fromFile, err := readTargetsFile(targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
			return ExitError
		}
		targets = append(targets, fromFile...)
	}
	if !local && !docker && len(targets) == 0 {
		local = true
	}
	if timeout <= 0 {
		fmt.Fprintln(os.Stderr, "p2s: --timeout must be positive")
		return ExitError
	}
	if insecure && len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "p2s: --insecure only applies to --target")
	}

	ctx := context.Background()
	report := scan.NewReport("scan", buildinfo.Version)
	var warnings []string

	if local {
		res := scan.Local(ctx, scan.Options{
			WebRoots:  webRoots,
			IniPaths:  iniPaths,
			Timeout:   timeout,
			Processes: true,
			Packages:  true,
		})
		merge(report, res)
	}
	if docker {
		res := scan.Docker(ctx, timeout)
		merge(report, res)
	}
	for _, target := range targets {
		res := scan.Remote(ctx, target, scan.RemoteOptions{
			Timeout:  timeout,
			Insecure: insecure,
			Paths:    paths,
		})
		merge(report, res)
	}
	report.Warnings = append(report.Warnings, warnings...)
	report.Summary = scanSummary(report)
	return emit(report, common)
}

func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contains no targets", path)
	}
	return out, nil
}

func merge(report *model.Report, res *scan.Result) {
	report.Findings = append(report.Findings, res.Findings...)
	report.Targets = append(report.Targets, res.Targets...)
	report.Warnings = append(report.Warnings, res.Warnings...)
}

func scanSummary(r *model.Report) string {
	return scan.Summarise(r)
}

// --- hunt ------------------------------------------------------------------

func runHunt(args []string) int {
	fs := newFlagSet("hunt", "Hunt logs, web roots, session files and the live host for php2shell exploitation.")
	var (
		logs         stringList
		webRoots     stringList
		sessionPaths stringList
		live         bool
		allFiles     bool
		evidence     string
		sinceRaw     string
		untilRaw     string
		minScore     int
		maxEvents    int
		largeBody    int64
		burst        int
		burstWindow  time.Duration
		common       commonFlags
	)
	fs.Var(&logs, "logs", "log file or directory to analyse (repeatable)")
	fs.Var(&webRoots, "web-root", "web root to scan for webshells (repeatable)")
	fs.Var(&sessionPaths, "session-path", "PHP session save_path to inspect (repeatable)")
	fs.BoolVar(&live, "live", false, "inspect the running host")
	fs.StringVar(&sinceRaw, "since", DefaultSince.Format(time.RFC3339), "start of the analysis window")
	fs.StringVar(&untilRaw, "until", "", "end of the analysis window")
	fs.BoolVar(&allFiles, "all-files", false, "scan files regardless of modification time")
	fs.IntVar(&minScore, "min-file-score", 6, "webshell score threshold")
	fs.IntVar(&maxEvents, "max-events", 500000, "maximum parsed log records")
	fs.Int64Var(&largeBody, "large-body", 2*1024*1024, "oversized request-body threshold in bytes")
	fs.IntVar(&burst, "burst", 10, "requests from one source that constitute a burst")
	fs.DurationVar(&burstWindow, "burst-window", 5*time.Minute, "burst observation window")
	fs.StringVar(&evidence, "evidence", "", "directory for evidence export")
	addCommon(fs, &common)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "p2s: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return ExitError
	}

	since, err := parseWhen(sinceRaw, DefaultSince)
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2s: --since: %v\n", err)
		return ExitError
	}
	var until time.Time
	if untilRaw != "" {
		until, err = parseWhen(untilRaw, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "p2s: --until: %v\n", err)
			return ExitError
		}
		if until.Before(since) {
			fmt.Fprintln(os.Stderr, "p2s: --until is before --since")
			return ExitError
		}
	}
	if minScore < 1 {
		fmt.Fprintln(os.Stderr, "p2s: --min-file-score must be at least 1")
		return ExitError
	}
	if maxEvents < 1 {
		fmt.Fprintln(os.Stderr, "p2s: --max-events must be at least 1")
		return ExitError
	}

	res := hunt.Run(hunt.Options{
		Paths:        logs,
		Since:        since,
		Until:        until,
		Live:         live,
		WebRoots:     webRoots,
		SessionPaths: sessionPaths,
		AllFiles:     allFiles,
		MinFileScore: minScore,
		MaxEvents:    maxEvents,
		LargeBody:    largeBody,
		BurstCount:   burst,
		BurstWindow:  burstWindow,
		EvidenceDir:  evidence,
	})

	report := scan.NewReport("hunt", buildinfo.Version)
	report.Since = since.Format(time.RFC3339)
	if !until.IsZero() {
		report.Since += " .. " + until.Format(time.RFC3339)
	}
	report.Findings = res.Findings
	report.Warnings = res.Warnings
	report.Notes = res.Notes
	report.Summary = res.Summary
	return emit(report, common)
}

func parseWhen(s string, fallback time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback, nil
	}
	switch strings.ToLower(s) {
	case "today":
		now := time.Now().UTC()
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC), nil
	case "yesterday":
		now := time.Now().UTC().AddDate(0, 0, -1)
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC), nil
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	// Also accept relative durations such as 72h or 7d.
	if d, ok := parseAge(s); ok {
		return time.Now().UTC().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse %q (use RFC3339, YYYY-MM-DD, today, yesterday, 72h or 7d)", s)
}

func parseAge(s string) (time.Duration, bool) {
	if len(s) < 2 {
		return 0, false
	}
	unit := s[len(s)-1]
	n, err := time.ParseDuration(s[:len(s)-1] + "h")
	if err != nil {
		return 0, false
	}
	switch unit {
	case 'h':
		return n, true
	case 'd':
		return n * 24, true
	case 'w':
		return n * 24 * 7, true
	case 'm':
		return n * 24 * 30, true
	}
	return 0, false
}

// --- offense ---------------------------------------------------------------

func runOffense(args []string) int {
	fs := newFlagSet("offense", "Authorized, bounded validation of CVE-2026-109618 / CVE-2026-109619.")
	var (
		authorize   string
		targets     stringList
		probeRaw    string
		oomRaw      string
		audit       string
		allowPublic bool
		ackDisrupt  bool
		insecure    bool
		timeout     time.Duration
		common      commonFlags
	)
	fs.StringVar(&authorize, "authorize", "", "JSON authorization scope (required)")
	fs.Var(&targets, "target", "endpoint listed in the scope (repeatable)")
	fs.StringVar(&probeRaw, "probe", "109618,109619", "109618, 109619 or both")
	fs.StringVar(&oomRaw, "oom-body", "0", "opt-in CVE-2026-109618 pressure body (for example 8MiB)")
	fs.StringVar(&audit, "audit", offense.DefaultAudit, `JSONL audit log; "-" disables`)
	fs.BoolVar(&allowPublic, "allow-public", false, "permit a public target explicitly allowed by the scope")
	fs.BoolVar(&ackDisrupt, "acknowledge-disruption", false, "acknowledge that the pressure probe may disrupt a worker")
	fs.BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request timeout")
	addCommon(fs, &common)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "p2s: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return ExitError
	}
	if timeout <= 0 {
		fmt.Fprintln(os.Stderr, "p2s: --timeout must be positive")
		return ExitError
	}
	scope, err := offense.LoadScope(authorize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
		return ExitError
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "p2s: offense needs at least one --target listed in the scope")
		return ExitError
	}
	probes, err := offense.NormalizeProbes([]string{probeRaw})
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
		return ExitError
	}
	oomBody, err := parseByteSize(oomRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2s: --oom-body: %v\n", err)
		return ExitError
	}
	if oomBody > 0 && !probes["109618"] {
		fmt.Fprintln(os.Stderr, "p2s: --oom-body ignored because --probe does not include 109618")
		oomBody = 0
	}
	if oomBody > 0 {
		if !ackDisrupt || !scope.AcknowledgeDisruption {
			fmt.Fprintln(os.Stderr, "p2s: the pressure probe can disrupt a worker; set acknowledge_disruption in the scope and pass --acknowledge-disruption")
			return ExitError
		}
		if oomBody < offense.MinOOMBody || oomBody > offense.MaxOOMBody {
			fmt.Fprintf(os.Stderr, "p2s: --oom-body must be between %d and %d bytes\n", offense.MinOOMBody, offense.MaxOOMBody)
			return ExitError
		}
	}

	ctx := context.Background()
	if err := offense.AuthorizeTargets(ctx, scope, targets, allowPublic); err != nil {
		fmt.Fprintf(os.Stderr, "p2s: authorization refused: %v\n", err)
		return ExitError
	}
	res, err := offense.Run(ctx, offense.Options{
		Scope:                 scope,
		Targets:               targets,
		Timeout:               timeout,
		Insecure:              insecure,
		OOMBody:               oomBody,
		AllowPublic:           allowPublic,
		AcknowledgeDisruption: ackDisrupt,
		Probes:                []string{probeRaw},
		AuditPath:             audit,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
		return ExitError
	}

	report := scan.NewReport("offense", buildinfo.Version)
	report.Findings = res.Findings
	report.Targets = res.Targets
	report.Warnings = res.Warnings
	report.Notes = res.Notes
	report.Summary = res.Summary
	return emit(report, common)
}

// parseByteSize accepts plain bytes or a binary/decimal suffix such as 8MiB.
func parseByteSize(raw string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || s == "0" {
		return 0, nil
	}
	suffixes := []struct {
		name string
		mult int64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30},
		{"kb", 1000}, {"mb", 1000 * 1000}, {"gb", 1000 * 1000 * 1000},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30},
		{"b", 1},
	}
	for _, suffix := range suffixes {
		if !strings.HasSuffix(s, suffix.name) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(s, suffix.name))
		n, err := strconv.ParseInt(number, 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid size %q", raw)
		}
		if n > math.MaxInt64/suffix.mult {
			return 0, fmt.Errorf("size %q is too large", raw)
		}
		return n * suffix.mult, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q (use bytes, KiB, MiB or GiB)", raw)
	}
	return n, nil
}

// --- rules -----------------------------------------------------------------

func runRules(args []string) int {
	fs := newFlagSet("rules", "Emit detection content for php2shell.")
	var (
		format string
		out    string
		list   bool
	)
	fs.StringVar(&format, "format", "all", "all, sigma, modsecurity, nginx, yara, kql or splunk")
	fs.StringVar(&out, "output", "-", `output directory, or "-" for stdout`)
	fs.BoolVar(&list, "list", false, "list the generated files")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	files := rules.Generate(format)
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "p2s: unknown format %q (want all, sigma, modsecurity, nginx, yara, kql or splunk)\n", format)
		return ExitError
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	if list {
		for _, name := range names {
			fmt.Fprintln(os.Stdout, name)
		}
		return ExitOK
	}
	if out == "" || out == "-" {
		w := bufio.NewWriter(os.Stdout)
		for i, name := range names {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "# ===== %s =====\n", name)
			fmt.Fprint(w, files[name])
			if !strings.HasSuffix(files[name], "\n") {
				fmt.Fprintln(w)
			}
		}
		if err := w.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	for _, name := range names {
		path := filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
			return ExitError
		}
		if err := os.WriteFile(path, []byte(files[name]), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "p2s: %v\n", err)
			return ExitError
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d file(s) to %s\n", len(files), out)
	return ExitOK
}

// --- version ---------------------------------------------------------------

func runVersion(args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "p2s: version takes no arguments\n")
		return ExitError
	}
	fmt.Printf("php2shell-audit %s\n", buildinfo.Version)
	fmt.Printf("commit:     %s\n", buildinfo.Commit)
	fmt.Printf("built:      %s\n", buildinfo.Date)
	fmt.Printf("go:         %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("advisory:   %s\n", model.AdvisoryURL)
	fmt.Printf("cves:       %s, %s\n", model.CVE109618, model.CVE109619)
	fmt.Printf("fixed:      PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35\n")
	fmt.Printf("lookback:   attempts reported from %s\n", DefaultSince.Format("2006-01-02"))
	return ExitOK
}
