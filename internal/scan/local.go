package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/phpver"
)

// Options configures a local scan.
type Options struct {
	WebRoots  []string
	IniPaths  []string
	Timeout   time.Duration
	Docker    bool
	Processes bool
	Packages  bool
}

// Local inventories the host: installed binaries, running workers, packages
// and containers. It never sends traffic.
func Local(ctx context.Context, opts Options) *Result {
	res := &Result{}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	host, _ := os.Hostname()
	hostTarget := "host:" + host

	binPaths := discoverBinaries()
	infos := make([]binaryInfo, 0, len(binPaths))
	for _, p := range binPaths {
		infos = append(infos, inspectBinary(ctx, p, timeout))
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Path < infos[j].Path })

	// Exposed, version-aware view per binary.
	for _, b := range infos {
		name := "binary:" + b.Path
		t := model.Target{
			Name: name, Kind: "binary", Source: b.Path, SAPI: b.SAPI,
			Config: b.Config, Notes: b.Notes,
		}
		if b.Version != nil {
			a := phpver.Assess(*b.Version)
			t.Version = b.Version.Raw
			t.Status = a.Status
			t.FixedIn = a.FixedIn
			res.addTarget(t)
			res.add(ExposureFinding(name, "local", b.SAPI, b.Version.Raw, a, b.Path))
		} else {
			t.Status = phpver.StatusUnknown
			if b.Err != "" {
				t.Notes = append(t.Notes, b.Err)
			}
			res.addTarget(t)
			res.add(model.Finding{
				ID: "P2S-EXP-003", Target: name, Surface: "local",
				Title: "PHP binary version could not be determined", Severity: model.Medium,
				Category: "exposure", Confidence: "high", SAPI: b.SAPI, Status: phpver.StatusUnknown,
				Detail: b.Err, Remediation: "Run the binary with -v manually and compare against the fixed-version table.",
				Refs: []string{model.AdvisoryURL}, CVEs: []string{model.CVE109618, model.CVE109619},
			})
		}
	}

	// Running workers: the only version that actually matters for exposure.
	var procs []procInfo
	if opts.Processes {
		procs = readPHPProcesses(ctx, timeout)
	}
	procFindings := processFindings(procs, infos, timeout)
	res.Findings = append(res.Findings, procFindings...)
	for _, p := range procs {
		t := model.Target{
			Name: p.TargetName, Kind: "process", SAPI: p.SAPI, Loaded: true,
			Source: p.Source, Uptime: p.Uptime,
		}
		if p.Version != nil {
			a := phpver.Assess(*p.Version)
			t.Version = p.Version.Raw
			t.Status = a.Status
			t.FixedIn = a.FixedIn
			res.addTarget(t)
			res.add(ExposureFinding(p.TargetName, "local", p.SAPI, p.Version.Raw, a, p.Source))
		} else {
			t.Status = phpver.StatusUnknown
			t.Notes = append(t.Notes, "running build could not be versioned")
			res.addTarget(t)
		}
	}

	// Distro packages provide the on-disk patch level and backport evidence.
	// Packages are grouped by branch and status: a typical Debian host has a
	// dozen php8.4-* packages that all describe the same engine build.
	var pkgs []pkgInfo
	if opts.Packages {
		pkgs = readPackages(ctx, timeout)
	}
	type pkgGroup struct {
		branch  string
		status  string
		version *phpver.Version
		names   []string
		notes   []string
		source  string
	}
	groups := map[string]*pkgGroup{}
	var groupOrder []string
	for _, pkg := range pkgs {
		if pkg.Version == nil {
			continue
		}
		a := phpver.Assess(*pkg.Version)
		status, evidence := pkg.Status, ""
		if a.Status == phpver.StatusVulnerable || a.Status == phpver.StatusEOL {
			patched, ev, _ := vendorBackport(ctx, pkg.Name, timeout)
			if patched > 0 {
				evidence = ev
				if patched >= 2 {
					status = phpver.StatusVendorPached
				} else {
					a.Notes = append(a.Notes, "The package changelog references only one of the two CVE IDs; verify the backport manually.")
				}
			}
		}
		key := pkg.Version.Branch() + "|" + status
		g := groups[key]
		if g == nil {
			g = &pkgGroup{
				branch: pkg.Version.Branch(), status: status,
				version: pkg.Version, source: pkg.Source,
			}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		}
		g.names = append(g.names, pkg.Name)
		if evidence != "" {
			g.notes = append(g.notes, pkg.Name+": "+evidence)
		}
		g.notes = append(g.notes, pkg.Notes...)
		if phpver.Compare(*pkg.Version, *g.version) > 0 {
			g.version = pkg.Version
		}
		// Keep the notes that explain the assessment for the whole group.
		for _, n := range a.Notes {
			if !containsString(g.notes, n) {
				g.notes = append(g.notes, n)
			}
		}
	}
	sort.Strings(groupOrder)
	for _, key := range groupOrder {
		g := groups[key]
		sort.Strings(g.names)
		label := g.names[0]
		if len(g.names) > 1 {
			label = fmt.Sprintf("%s +%d more", g.names[0], len(g.names)-1)
		}
		name := fmt.Sprintf("packages: %s %s (%s)", label, g.version.Raw, plural(len(g.names), "package"))
		t := model.Target{
			Name: name, Kind: "package", Version: g.version.Raw, Status: g.status,
			Source: g.source, Notes: g.notes,
		}
		a := phpver.Assess(*g.version)
		a.Status = g.status
		res.addTarget(t)
		res.add(ExposureFinding(name, "local", "", g.version.Raw, a, g.source))
	}

	// Host-level configuration posture. Pool-specific overrides are merged;
	// the warning makes that limitation explicit.
	if opts.Processes || opts.Packages || len(infos) > 0 {
		posture := loadPosture(collectINI(infos), opts.WebRoots, opts.IniPaths)
		sapi := "mixed"
		ver := ""
		for _, p := range procs {
			if p.SAPI != "" {
				sapi = p.SAPI
			}
			if p.Version != nil && (ver == "" || phpver.Compare(*p.Version, mustVersion(ver)) > 0) {
				ver = p.Version.Raw
			}
		}
		if ver == "" {
			for _, b := range infos {
				if b.Version != nil {
					ver = b.Version.Raw
					break
				}
			}
		}
		status := ""
		if v, ok := phpver.Parse(ver); ok {
			status = phpver.Assess(v).Status
		}
		limits := mergeLimits(procs)
		if len(posture.Values) > 0 || limits != nil {
			res.addTarget(model.Target{
				Name: hostTarget, Kind: "host", SAPI: sapi, Version: ver, Status: status,
			})
			for _, f := range ConfigFindings(hostTarget, ver, status, sapi, posture, limits) {
				res.add(f)
			}
			if hasMultiplePools() {
				res.warn("FPM pool configuration was merged into one posture; pools can differ. Check each pool's php_admin_value entries individually.")
			}
			if posture.Get("memory_limit") != "" && !posture.AdminLevel("memory_limit") {
				res.warn("memory_limit is not pinned at administrator level; a per-request override can restore the vulnerable path.")
			}
		}
	}

	if opts.Docker {
		d := Docker(ctx, timeout)
		res.Findings = append(res.Findings, d.Findings...)
		res.Targets = append(res.Targets, d.Targets...)
		res.Warnings = append(res.Warnings, d.Warnings...)
	}

	if len(res.Targets) == 0 {
		res.warn("No PHP binaries, running workers or packages were found. If PHP is present, pass explicit paths or run as root.")
	}
	return res
}

func mustVersion(s string) phpver.Version {
	v, _ := phpver.Parse(s)
	return v
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func collectINI(infos []binaryInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range infos {
		for _, p := range b.IniPaths {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func mergeLimits(procs []procInfo) *RLimits {
	out := &RLimits{}
	for _, p := range procs {
		if p.Limits.AddressSpace != "" && out.AddressSpace == "" {
			out.AddressSpace = p.Limits.AddressSpace
		}
		if p.Limits.DataSize != "" && out.DataSize == "" {
			out.DataSize = p.Limits.DataSize
		}
	}
	if out.AddressSpace == "" && out.DataSize == "" {
		return nil
	}
	return out
}

func hasMultiplePools() bool {
	matches, _ := filepath.Glob("/etc/php/*/fpm/pool.d/*.conf")
	return len(matches) > 1
}

// --- binaries --------------------------------------------------------------

type binaryInfo struct {
	Path     string
	Version  *phpver.Version
	SAPI     string
	Config   map[string]string
	IniPaths []string
	Notes    []string
	Err      string
}

var versionBannerRE = regexp.MustCompile(`(?i)\bPHP\s+(\d+\.\d+\.\d+[^\s()]*)`)

func inspectBinary(ctx context.Context, path string, timeout time.Duration) binaryInfo {
	b := binaryInfo{Path: path, SAPI: sapiFromName(path), Config: map[string]string{}}
	out, err := runCmd(ctx, timeout, path, "-v")
	if err != nil && strings.TrimSpace(out) == "" {
		b.Err = fmt.Sprintf("%s -v failed: %v", path, err)
		return b
	}
	if m := versionBannerRE.FindStringSubmatch(out); m != nil {
		if v, ok := phpver.Parse(m[1]); ok {
			b.Version = &v
		}
	} else if v, ok := phpver.Parse(out); ok {
		b.Version = &v
	}
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "fpm-fcgi"):
		b.SAPI = "fpm-fcgi"
	case strings.Contains(lower, "cgi-fcgi"):
		b.SAPI = "cgi-fcgi"
	case strings.Contains(lower, "cli"):
		b.SAPI = "cli"
	}

	// The CLI probe reports the view of the CLI SAPI only; it is still the most
	// reliable way to discover ini paths and defaults without serving a page.
	if !strings.Contains(b.SAPI, "fpm") {
		if cfg, ini, perr := probePHP(ctx, path, timeout); perr == nil {
			b.Config = cfg
			b.IniPaths = ini
		} else {
			b.Notes = append(b.Notes, "configuration probe failed: "+perr.Error())
		}
	}

	// FPM can dump its effective configuration without starting workers.
	if strings.Contains(b.SAPI, "fpm") || strings.Contains(filepath.Base(path), "fpm") {
		if dump, err := runCmd(ctx, timeout, path, "-tt"); err == nil && strings.Contains(dump, "php_admin_value") {
			if vals, err := parseINIReader(strings.NewReader(dump)); err == nil {
				for k, v := range vals {
					b.Config[k] = v
				}
			}
		}
	}
	return b
}

const probeCode = `$k=["memory_limit","post_max_size","upload_max_filesize","max_input_vars","max_input_nesting_level","session.upload_progress.enabled","fatal_error_backtraces","session.save_path","opcache.enable","display_errors","log_errors","error_reporting","max_execution_time"];foreach($k as $x){echo "cfg\t",$x,"\t",base64_encode((string)ini_get($x)),"\n";}echo "sapi\t",base64_encode(PHP_SAPI),"\n";echo "ini\t",base64_encode((string)php_ini_loaded_file()),"\n";foreach(explode(",",(string)php_ini_scanned_files()) as $f){$f=trim($f);if($f!=="")echo "scan\t",base64_encode($f),"\n";}`

func probePHP(ctx context.Context, path string, timeout time.Duration) (map[string]string, []string, error) {
	out, err := runCmd(ctx, timeout, path, "-r", probeCode)
	if err != nil {
		return nil, nil, err
	}
	cfg := map[string]string{}
	var ini []string
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		raw, decErr := decodeBase64(parts[2])
		if decErr != nil {
			continue
		}
		switch parts[0] {
		case "cfg":
			cfg[parts[1]] = raw
			if parts[1] == "memory_limit" {
				cfg["memory_limit"] = raw
			}
		case "ini":
			if raw != "" {
				ini = append(ini, raw)
			}
		case "scan":
			if raw != "" {
				ini = append(ini, raw)
			}
		}
	}
	return cfg, ini, nil
}

func decodeBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return string(b), err
}

func sapiFromName(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "fpm"):
		return "fpm-fcgi"
	case strings.Contains(base, "cgi"):
		return "cgi-fcgi"
	default:
		return "cli"
	}
}

func discoverBinaries() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			return
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if seen[real] {
			return
		}
		seen[real] = true
		out = append(out, real)
	}

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "php*"))
		for _, m := range matches {
			if looksLikePHPBinary(filepath.Base(m)) {
				add(m)
			}
		}
	}
	for _, pattern := range []string{
		"/usr/bin/php*", "/usr/sbin/php*", "/usr/local/bin/php*",
		"/usr/local/sbin/php*", "/opt/*/bin/php*", "/opt/*/sbin/php*",
		"/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php*",
		"/usr/local/etc/php*/bin/php*",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if looksLikePHPBinary(filepath.Base(m)) {
				add(m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func looksLikePHPBinary(base string) bool {
	base = strings.ToLower(base)
	if !strings.HasPrefix(base, "php") {
		return false
	}
	for _, bad := range []string{"phpize", "php-config", "phpcs", "phpcbf", "phpstan", "phpunit", "phpdoc", "phpdbg"} {
		if strings.HasPrefix(base, bad) {
			return false
		}
	}
	// php, php8.2, php-fpm, php-fpm8.2, php-cgi, php8.2-fpm
	rest := strings.TrimPrefix(base, "php")
	rest = strings.TrimPrefix(rest, "-")
	for _, token := range []string{"fpm", "cgi", "dbg", "embed", "zts"} {
		rest = strings.ReplaceAll(rest, token, "")
	}
	rest = strings.Trim(rest, "-_")
	if rest == "" {
		return true
	}
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' {
			continue
		}
		return false
	}
	return true
}

// --- processes -------------------------------------------------------------

type procInfo struct {
	PID        int
	PPID       int
	Comm       string
	Exe        string
	Source     string
	SAPI       string
	Version    *phpver.Version
	TargetName string
	Uptime     string
	Started    time.Time
	Limits     RLimits
	Count      int
}

var webComms = map[string]bool{
	"apache2": true, "httpd": true, "php-fpm": true, "php-fpm8.2": true,
	"php-cgi": true, "frankenphp": true, "litespeed": true, "lshttpd": true,
	"openlitespeed": true, "nginx": true,
}

func readPHPProcesses(ctx context.Context, timeout time.Duration) []procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	boot := bootTime()
	now := time.Now()
	var procs []procInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(readFileString(fmt.Sprintf("/proc/%d/comm", pid)))
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if !webComms[comm] && !strings.HasPrefix(filepath.Base(exe), "php") && !strings.Contains(exe, "frankenphp") {
			continue
		}
		lib := findLibPHP(pid)
		if lib == "" && !strings.HasPrefix(filepath.Base(exe), "php") && !strings.Contains(exe, "frankenphp") {
			continue
		}

		p := procInfo{PID: pid, Comm: comm, Exe: exe}
		p.PPID = readPPID(pid)
		p.Limits = readLimits(pid)
		p.Started, p.Uptime = processStart(pid, boot, now)
		p.Source = exe
		if lib != "" {
			p.Source = lib
		}

		switch {
		case strings.Contains(comm, "fpm") || strings.Contains(filepath.Base(exe), "fpm"):
			p.SAPI = "fpm-fcgi"
		case strings.Contains(comm, "cgi") || strings.Contains(filepath.Base(exe), "cgi"):
			p.SAPI = "cgi-fcgi"
		case strings.Contains(strings.ToLower(comm), "litespeed") || strings.Contains(strings.ToLower(comm), "lshttpd"):
			p.SAPI = "litespeed"
		case strings.Contains(strings.ToLower(exe), "frankenphp"):
			p.SAPI = "frankenphp"
		case lib != "":
			p.SAPI = "apache2handler"
		default:
			p.SAPI = "cli"
		}

		if v := versionForProcess(ctx, p, timeout); v != nil {
			p.Version = v
		}
		p.TargetName = fmt.Sprintf("process: %s (%s)", filepath.Base(p.Source), p.SAPI)
		procs = append(procs, p)
	}
	// Group identical worker types so a 200-process Apache pool produces one row.
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].TargetName != procs[j].TargetName {
			return procs[i].TargetName < procs[j].TargetName
		}
		return procs[i].PID < procs[j].PID
	})
	var grouped []procInfo
	for _, p := range procs {
		found := false
		for i := range grouped {
			g := &grouped[i]
			if g.TargetName == p.TargetName && sameVersion(g.Version, p.Version) && g.SAPI == p.SAPI {
				g.Count++
				found = true
				break
			}
		}
		if !found {
			p.Count = 1
			grouped = append(grouped, p)
		}
	}
	return grouped
}

func sameVersion(a, b *phpver.Version) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func processFindings(procs []procInfo, bins []binaryInfo, timeout time.Duration) []model.Finding {
	var out []model.Finding
	bestByBranch := map[string]phpver.Version{}
	for _, b := range bins {
		if b.Version == nil || strings.Contains(b.SAPI, "fpm") {
			continue
		}
		br := b.Version.Branch()
		if cur, ok := bestByBranch[br]; !ok || phpver.Compare(*b.Version, cur) > 0 {
			bestByBranch[br] = *b.Version
		}
	}
	for _, p := range procs {
		if p.Version == nil {
			continue
		}
		a := phpver.Assess(*p.Version)
		best, ok := bestByBranch[p.Version.Branch()]
		if ok && phpver.Compare(*p.Version, best) < 0 && a.Status == phpver.StatusVulnerable {
			out = append(out, model.Finding{
				ID: "P2S-EXP-004", Target: p.TargetName, Surface: "local",
				Title:    "Running worker is older than the installed PHP build",
				Severity: model.Critical, Category: "exposure", Confidence: "high",
				Version: p.Version.Raw, Status: a.Status, FixedIn: best.Raw, SAPI: p.SAPI,
				Detail: fmt.Sprintf("The worker loaded %s but %s is installed on disk. The patched code is not active until the web server or FPM pool is restarted.", p.Version.Raw, best.Raw),
				Evidence: []string{
					"running: " + p.Version.Raw + " (" + p.Source + ")",
					"installed: " + best.Raw,
					"started: " + p.Started.UTC().Format(time.RFC3339) + " (uptime " + p.Uptime + ")",
				},
				CVEs:        []string{model.CVE109618, model.CVE109619},
				Refs:        []string{model.AdvisoryURL},
				Remediation: "Restart Apache/PHP-FPM, then confirm the new PID's loaded version.",
			})
		}
	}
	return out
}

func versionForProcess(ctx context.Context, p procInfo, timeout time.Duration) *phpver.Version {
	// Prefer asking the executable; it is exact and cheap.
	if strings.HasPrefix(filepath.Base(p.Exe), "php") {
		if out, err := runCmd(ctx, timeout, p.Exe, "-v"); err == nil {
			if m := versionBannerRE.FindStringSubmatch(out); m != nil {
				if v, ok := phpver.Parse(m[1]); ok {
					return &v
				}
			}
		}
	}
	// libphp.so: look for an embedded version string, then fall back to the
	// package that owns the module.
	if v := versionFromModule(ctx, p.Source, timeout); v != nil {
		return v
	}
	if v := versionFromOwner(ctx, p.Source, timeout); v != nil {
		return v
	}
	return nil
}

var moduleVersionRE = regexp.MustCompile(`(?i)(?:PHP|php)[ /_-]?(\d+\.\d+\.\d+)`)

func versionFromModule(ctx context.Context, path string, timeout time.Duration) *phpver.Version {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 128*1024*1024 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 8*1024*1024)
	n, _ := io.ReadFull(f, buf)
	if m := moduleVersionRE.FindSubmatch(buf[:n]); m != nil {
		if v, ok := phpver.Parse(string(m[1])); ok {
			return &v
		}
	}
	return nil
}

func versionFromOwner(ctx context.Context, path string, timeout time.Duration) *phpver.Version {
	if path == "" {
		return nil
	}
	if out, err := runCmd(ctx, timeout, "dpkg-query", "-S", path); err == nil {
		if i := strings.Index(out, ": "); i > 0 {
			pkg := strings.TrimSpace(out[:i])
			if vout, err := runCmd(ctx, timeout, "dpkg-query", "-W", "-f=${Version}", pkg); err == nil {
				if v, ok := phpver.Parse(vout); ok {
					return &v
				}
			}
		}
	}
	if out, err := runCmd(ctx, timeout, "rpm", "-qf", path); err == nil {
		pkg := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
		if pkg != "" {
			if vout, err := runCmd(ctx, timeout, "rpm", "-q", "--qf", "%{VERSION}", pkg); err == nil {
				if v, ok := phpver.Parse(vout); ok {
					return &v
				}
			}
		}
	}
	return nil
}

func findLibPHP(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		path := line[i:]
		if strings.Contains(path, "libphp") && strings.HasSuffix(path, ".so") {
			return path
		}
	}
	return ""
}

func readPPID(pid int) int {
	data := readFileString(fmt.Sprintf("/proc/%d/stat", pid))
	i := strings.LastIndexByte(data, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(data[i+1:])
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}

func readLimits(pid int) RLimits {
	f, err := os.Open(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		return RLimits{}
	}
	defer f.Close()
	var out RLimits
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		soft := fields[len(fields)-3]
		if soft == "unlimited" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Max address space"):
			out.AddressSpace = soft
		case strings.HasPrefix(line, "Max data size"):
			out.DataSize = soft
		}
	}
	return out
}

func bootTime() time.Time {
	data := readFileString("/proc/stat")
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "btime ") {
			n, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			if n > 0 {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Now()
}

func processStart(pid int, boot, now time.Time) (time.Time, string) {
	data := readFileString(fmt.Sprintf("/proc/%d/stat", pid))
	i := strings.LastIndexByte(data, ')')
	if i < 0 {
		return time.Time{}, ""
	}
	fields := strings.Fields(data[i+1:])
	if len(fields) < 20 {
		return time.Time{}, ""
	}
	ticks, _ := strconv.ParseInt(fields[19], 10, 64)
	start := boot.Add(time.Duration(ticks) * (time.Second / 100))
	d := now.Sub(start)
	if d < 0 {
		d = 0
	}
	return start, d.Round(time.Second).String()
}

func readFileString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// --- packages --------------------------------------------------------------

var concretePkgRE = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// concretePkgVersion reports whether a distribution version names a concrete
// PHP release (X.Y.Z) rather than a metapackage branch (X.Y+NN).
func concretePkgVersion(v string) bool {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i > 0 && i < 5 {
		v = v[i+1:]
	}
	return concretePkgRE.MatchString(v)
}

type pkgInfo struct {
	Name    string
	Version *phpver.Version
	Status  string
	Source  string
	Notes   []string
}

func readPackages(ctx context.Context, timeout time.Duration) []pkgInfo {
	var out []pkgInfo
	seen := map[string]bool{}
	add := func(name, version, source string) {
		if name == "" || seen[name+"|"+version] {
			return
		}
		seen[name+"|"+version] = true
		p := pkgInfo{Name: name, Source: source}
		if v, ok := phpver.Parse(version); ok {
			// Distribution metapackages such as Debian's php-bcmath
			// (version 2:8.4+96) carry a branch number, not an engine patch
			// level. The concrete php8.4-* package is reported instead.
			if !concretePkgVersion(version) {
				return
			}
			p.Version = &v
			p.Status = phpver.Assess(v).Status
		} else {
			return
		}
		out = append(out, p)
	}

	if out, err := runCmd(ctx, timeout, "dpkg-query", "-W", "-f=${Package}\t${Version}\n"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 && strings.Contains(strings.ToLower(parts[0]), "php") {
				add(parts[0], parts[1], "dpkg")
			}
		}
	}
	if out, err := runCmd(ctx, timeout, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 && strings.Contains(strings.ToLower(parts[0]), "php") {
				add(parts[0], parts[1], "rpm")
			}
		}
	}
	if out, err := runCmd(ctx, timeout, "apk", "info", "-v"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if i := strings.LastIndex(line, "-"); i > 0 && strings.Contains(strings.ToLower(line), "php") {
				add(line[:i], line[i+1:], "apk")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// vendorBackport looks for the CVE identifiers in package changelogs. It
// returns how many of the two CVEs were found, plus a short evidence string.
func vendorBackport(ctx context.Context, pkg string, timeout time.Duration) (int, string, []string) {
	var texts []string
	for _, suffix := range []string{"changelog.Debian.gz", "changelog.gz"} {
		path := filepath.Join("/usr/share/doc", pkg, suffix)
		if data, err := readGzip(path, 8*1024*1024); err == nil {
			texts = append(texts, data)
			break
		}
	}
	if data, err := os.ReadFile(filepath.Join("/usr/share/doc", pkg, "changelog.Debian")); err == nil {
		texts = append(texts, string(limitBytes(data, 8*1024*1024)))
	}
	if out, err := runCmd(ctx, timeout, "rpm", "-q", "--changelog", pkg); err == nil {
		texts = append(texts, out)
	}
	if len(texts) == 0 {
		return 0, "", nil
	}
	joined := strings.Join(texts, "\n")
	found := 0
	for _, cve := range []string{model.CVE109618, model.CVE109619} {
		if strings.Contains(joined, cve) {
			found++
		}
	}
	if found == 0 {
		return 0, "", nil
	}
	return found, fmt.Sprintf("package changelog references %d/2 CVE IDs", found), nil
}

func readGzip(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, int64(max)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func limitBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// --- command helpers -------------------------------------------------------

func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return buf.String(), fmt.Errorf("timeout after %s", timeout)
	}
	return buf.String(), err
}
