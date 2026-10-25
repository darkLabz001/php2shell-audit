package hunt

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

var webProcessNames = map[string]bool{
	"apache2": true, "httpd": true, "php-fpm": true, "php-fpm8.2": true,
	"php-cgi": true, "frankenphp": true, "litespeed": true, "lshttpd": true,
	"openlitespeed": true, "nginx": true,
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true, "busybox": true,
}

var toolNames = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
	"netcat": true, "python": true, "python3": true, "perl": true, "ruby": true,
	"ssh": true, "scp": true, "sftp": true, "base64": true, "openssl": true,
}

type hostProc struct {
	PID   int
	PPID  int
	Comm  string
	Exe   string
	Cmd   string
	Start string
}

// Host inspects live processes and persistence locations. It is read-only.
func Host(opts Options) ([]model.Finding, []string) {
	var findings []model.Finding
	var warnings []string
	procs, err := readHostProcs()
	if err != nil {
		return nil, []string{"process inventory failed: " + err.Error()}
	}
	byPID := map[int]hostProc{}
	children := map[int][]int{}
	var roots []hostProc
	for _, p := range procs {
		byPID[p.PID] = p
		children[p.PPID] = append(children[p.PPID], p.PID)
		if webProcessNames[p.Comm] || strings.HasPrefix(filepath.Base(p.Exe), "php-fpm") {
			roots = append(roots, p)
		}
	}
	if len(roots) == 0 {
		warnings = append(warnings, "no webserver or PHP-FPM processes found; process and network checks were skipped")
	}

	relevant := map[int]bool{}
	var descendants []hostProc
	for _, root := range roots {
		queue := append([]int(nil), children[root.PID]...)
		for len(queue) > 0 {
			pid := queue[0]
			queue = queue[1:]
			if relevant[pid] {
				continue
			}
			relevant[pid] = true
			p, ok := byPID[pid]
			if !ok {
				continue
			}
			descendants = append(descendants, p)
			queue = append(queue, children[pid]...)
		}
	}

	// 1. Web worker spawned a shell or a tool.
	seenChild := map[string]bool{}
	for _, p := range descendants {
		kind := ""
		sev := model.Medium
		switch {
		case shellNames[p.Comm]:
			kind = "shell"
			sev = model.Critical
		case toolNames[p.Comm]:
			kind = "tool"
			sev = model.High
		default:
			continue
		}
		parent := byPID[p.PPID]
		key := fmt.Sprintf("%d|%s", parent.PID, p.Comm)
		if seenChild[key] {
			continue
		}
		seenChild[key] = true
		findings = append(findings, model.Finding{
			ID: "P2S-HUNT-010", Title: "Web worker spawned " + kind + ": " + p.Comm,
			Severity: sev, Category: "compromise", Surface: "host",
			Target:     fmt.Sprintf("%s[%d] -> %s[%d]", parent.Comm, parent.PID, p.Comm, p.PID),
			Confidence: "high",
			Detail:     "A webserver/PHP worker process has a child that is an interactive shell or a data-transfer tool. Web servers do not normally do this; it is the most direct evidence of post-exploitation command execution.",
			Evidence: []string{
				"parent: " + procLine(parent),
				"child:  " + procLine(p),
				"started: " + p.Start,
			},
			Remediation: "Treat the host as compromised. Isolate it, capture memory and the process tree, then rebuild from trusted images and rotate all secrets the PHP worker could read.",
			Refs:        []string{model.AdvisoryURL},
			CVEs:        []string{model.CVE109618, model.CVE109619},
		})
	}

	// 2. Outbound connections from workers or their children.
	if len(relevant) > 0 {
		findings = append(findings, outboundFindings(relevant, byPID)...)
	}

	// 3. Persistence: cron, systemd, authorized_keys.
	findings = append(findings, persistenceFindings(opts.Since)...)

	if os.Geteuid() != 0 {
		warnings = append(warnings, "not running as root: some /proc entries and persistence paths may be unreadable")
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Severity > findings[j].Severity })
	return findings, warnings
}

func readHostProcs() ([]hostProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []hostProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(readSmall(fmt.Sprintf("/proc/%d/comm", pid)))
		if comm == "" {
			continue
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		ppid := procPPID(pid)
		out = append(out, hostProc{
			PID: pid, PPID: ppid, Comm: comm, Exe: exe,
			Cmd: readCmdline(pid), Start: procStartTime(pid),
		})
	}
	return out, nil
}

func procLine(p hostProc) string {
	line := fmt.Sprintf("%s[%d] ppid=%d", p.Comm, p.PID, p.PPID)
	if p.Exe != "" {
		line += " exe=" + p.Exe
	}
	if p.Cmd != "" {
		line += " cmd=" + truncateStr(p.Cmd, 240)
	}
	return line
}

func readSmall(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func readCmdline(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func procPPID(pid int) int {
	data := readSmall(fmt.Sprintf("/proc/%d/stat", pid))
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

func procStartTime(pid int) string {
	data := readSmall(fmt.Sprintf("/proc/%d/stat", pid))
	i := strings.LastIndexByte(data, ')')
	if i < 0 {
		return "unknown"
	}
	fields := strings.Fields(data[i+1:])
	if len(fields) < 20 {
		return "unknown"
	}
	ticks, _ := strconv.ParseInt(fields[19], 10, 64)
	boot := int64(0)
	for _, line := range strings.Split(readSmall("/proc/stat"), "\n") {
		if strings.HasPrefix(line, "btime ") {
			boot, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			break
		}
	}
	if boot == 0 {
		return "unknown"
	}
	t := time.Unix(boot, 0).Add(time.Duration(ticks) * (time.Second / 100))
	return t.UTC().Format(time.RFC3339)
}

// --- network ---------------------------------------------------------------

type conn struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	Inode      string
	Proto      string
}

func outboundFindings(relevant map[int]bool, byPID map[int]hostProc) []model.Finding {
	inodeToPID := map[string]int{}
	for pid := range relevant {
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodeToPID[inode] = pid
		}
	}
	if len(inodeToPID) == 0 {
		return nil
	}
	var findout []model.Finding
	seen := map[string]bool{}
	for _, table := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
	} {
		f, err := os.Open(table.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || fields[3] != "01" {
				continue
			}
			inode := fields[9]
			pid, ok := inodeToPID[inode]
			if !ok {
				continue
			}
			localIP, localPort, ok1 := parseProcAddr(fields[1])
			remoteIP, remotePort, ok2 := parseProcAddr(fields[2])
			if !ok1 || !ok2 || remoteIP == "0.0.0.0" || remoteIP == "::" {
				continue
			}
			ip := net.ParseIP(remoteIP)
			if ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
				continue
			}
			p := byPID[pid]
			suspicious := shellNames[p.Comm] || p.Comm == "nc" || p.Comm == "ncat" || p.Comm == "socat"
			if !suspicious && normalEgressPort(remotePort) {
				continue
			}
			key := fmt.Sprintf("%d|%s|%d", pid, remoteIP, remotePort)
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := model.Medium
			conf := "low"
			if suspicious {
				sev = model.High
				conf = "high"
			}
			findout = append(findout, model.Finding{
				ID: "P2S-HUNT-011", Title: "Outbound connection from a web worker or child",
				Severity: sev, Category: "compromise", Surface: "host",
				Target:     fmt.Sprintf("%s[%d] -> %s:%d", p.Comm, pid, remoteIP, remotePort),
				Confidence: conf,
				Detail:     "An established outbound connection belongs to a webserver/PHP process or one of its children. Compare it with the application's expected egress; reverse shells and C2 channels often appear here.",
				Evidence: []string{
					procLine(p),
					fmt.Sprintf("%s %s:%d -> %s:%d", table.proto, localIP, localPort, remoteIP, remotePort),
				},
				Remediation: "Identify the remote endpoint, capture the socket owner and process tree, then block egress and investigate the request that spawned it.",
			})
		}
		f.Close()
	}
	return findout
}

func normalEgressPort(port int) bool {
	switch port {
	case 25, 53, 80, 443, 465, 587, 3306, 5432, 6379, 11211, 9200, 27017:
		return true
	}
	return false
}

func parseProcAddr(s string) (string, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, false
	}
	switch len(raw) {
	case 4:
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), int(port64), true
	case 16:
		for i := 0; i < 16; i += 4 {
			raw[i], raw[i+3] = raw[i+3], raw[i]
			raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
		}
		ip := net.IP(raw)
		return ip.String(), int(port64), true
	}
	return "", 0, false
}

// --- persistence -----------------------------------------------------------

var persistenceTokens = []string{
	"curl ", "wget ", "base64", "/dev/tcp", "nc ", "ncat ", "socat ",
	"bash -c", "sh -c", "php -r", "python -c", "perl -e",
}

func persistenceFindings(since time.Time) []model.Finding {
	var out []model.Finding
	seen := map[string]bool{}

	check := func(path, category string) {
		if seen[path] {
			return
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return
		}
		if !since.IsZero() && info.ModTime().Before(since) {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 1024*1024 {
			return
		}
		text := string(data)
		var hits []string
		for _, tok := range persistenceTokens {
			if strings.Contains(text, tok) {
				hits = append(hits, strings.TrimSpace(tok))
			}
		}
		if len(hits) == 0 {
			return
		}
		seen[path] = true
		sev := model.Medium
		for _, h := range hits {
			if h != "php -r" {
				sev = model.High
				break
			}
		}
		out = append(out, model.Finding{
			ID: "P2S-HUNT-015", Title: "New or modified persistence entry references a downloader or shell",
			Severity: sev, Category: "persistence", Surface: "host", Target: path, Confidence: "medium",
			Detail: fmt.Sprintf("A %s file modified inside the lookback window contains: %s. This is a common persistence mechanism after webshell or RCE exploitation.", category, strings.Join(hits, ", ")),
			Evidence: []string{
				"path: " + path,
				"modified: " + info.ModTime().UTC().Format(time.RFC3339),
				"tokens: " + strings.Join(hits, ", "),
			},
			Remediation: "Compare with the configuration management baseline, remove unauthorised entries, and review what the referenced command does before deleting evidence.",
		})
	}

	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/var/spool/cron", "/var/spool/cron/crontabs"} {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				check(path, "cron")
			}
			return nil
		})
	}
	check("/etc/crontab", "cron")
	check("/etc/rc.local", "startup")
	check("/etc/ld.so.preload", "loader")
	for _, pattern := range []string{
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
		"/root/.config/systemd/user/*.service", "/home/*/.config/systemd/user/*.service",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			check(m, "systemd")
		}
	}
	for _, pattern := range []string{
		"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys", "/var/www/.ssh/authorized_keys",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || (!since.IsZero() && info.ModTime().Before(since)) {
				continue
			}
			out = append(out, model.Finding{
				ID: "P2S-HUNT-016", Title: "SSH authorized_keys modified inside the lookback window",
				Severity: model.Medium, Category: "persistence", Surface: "host", Target: m, Confidence: "low",
				Detail:      "An authorized_keys file was modified recently. This can be legitimate administration, but it is also a standard persistence step after host compromise.",
				Evidence:    []string{"path: " + m, "modified: " + info.ModTime().UTC().Format(time.RFC3339)},
				Remediation: "Verify every key against your access inventory and remove unknown keys.",
			})
		}
	}

	// A non-empty ld.so.preload is rare on a normal server and loads a library
	// into every process; it does not need shell tokens to be worth reporting.
	if !seen["/etc/ld.so.preload"] {
		if info, err := os.Stat("/etc/ld.so.preload"); err == nil && !info.IsDir() &&
			(since.IsZero() || !info.ModTime().Before(since)) {
			if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil && strings.TrimSpace(string(data)) != "" {
				out = append(out, model.Finding{
					ID: "P2S-HUNT-017", Title: "ld.so.preload is present on the host",
					Severity: model.High, Category: "persistence", Surface: "host", Target: "/etc/ld.so.preload",
					Confidence:  "medium",
					Detail:      "ld.so.preload forces a shared library into every dynamically linked process. It is a known rootkit mechanism and is almost never required on a web server.",
					Evidence:    []string{"path: /etc/ld.so.preload", "content: " + truncateStr(strings.TrimSpace(string(data)), 200)},
					Remediation: "Verify the referenced library against the package manager. If it is unknown, preserve the file and the library, then isolate the host.",
				})
			}
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
