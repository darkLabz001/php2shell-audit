package scan

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Posture is the effective PHP configuration relevant to the two CVEs. Values
// are stored verbatim (for example "128M") together with the file they were
// read from.
type Posture struct {
	Values  map[string]string
	Sources map[string]string
}

func newPosture() *Posture {
	return &Posture{Values: map[string]string{}, Sources: map[string]string{}}
}

// Get returns the effective value for a directive. Administrator level values
// (php_admin_value) win over per-directory values (php_value) which win over
// plain ini entries.
func (p *Posture) Get(key string) string {
	if p == nil {
		return ""
	}
	for _, prefix := range []string{"admin.", "value.", ""} {
		if v, ok := p.Values[prefix+key]; ok && v != "" {
			return v
		}
	}
	return ""
}

// Has reports whether any level defines key.
func (p *Posture) Has(key string) bool {
	if p == nil {
		return false
	}
	_, a := p.Values["admin."+key]
	_, b := p.Values["value."+key]
	_, c := p.Values[key]
	return a || b || c
}

// AdminLevel reports whether key was pinned with php_admin_value/php_admin_flag.
func (p *Posture) AdminLevel(key string) bool {
	if p == nil {
		return false
	}
	_, ok := p.Values["admin."+key]
	return ok
}

// Bool interprets a php.ini boolean. The second result is false when the
// directive is unset or unintelligible.
func (p *Posture) Bool(key string) (value, known bool) {
	v := strings.ToLower(strings.Trim(strings.TrimSpace(p.Get(key)), `"'`))
	switch v {
	case "1", "on", "true", "yes", "enabled":
		return true, true
	case "0", "off", "false", "no", "disabled", "":
		if v == "" {
			return false, false
		}
		return false, true
	}
	return false, false
}

// Size returns a php.ini size in bytes. -1 means unlimited, 0 means "no limit"
// for post_max_size but is treated as unlimited by callers. The second result
// is false when the value cannot be parsed.
func (p *Posture) Size(key string) (int64, bool) {
	return ParseSize(p.Get(key))
}

// ParseSize parses values such as "128M", "1G", "8388608" and "-1".
func ParseSize(s string) (int64, bool) {
	s = strings.Trim(strings.TrimSpace(s), `"'`)
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	last := s[len(s)-1]
	switch last {
	case 'k', 'K':
		mult = 1024
		s = s[:len(s)-1]
	case 'm', 'M':
		mult = 1024 * 1024
		s = s[:len(s)-1]
	case 'g', 'G':
		mult = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	if n < 0 {
		return -1, true
	}
	return n * mult, true
}

// FormatSize renders a byte count using the largest sensible binary unit.
func FormatSize(n int64) string {
	if n < 0 {
		return "unlimited"
	}
	switch {
	case n >= 1024*1024*1024 && n%(1024*1024*1024) == 0:
		return strconv.FormatInt(n/(1024*1024*1024), 10) + "G"
	case n >= 1024*1024 && n%(1024*1024) == 0:
		return strconv.FormatInt(n/(1024*1024), 10) + "M"
	case n >= 1024 && n%1024 == 0:
		return strconv.FormatInt(n/1024, 10) + "K"
	default:
		return strconv.FormatInt(n, 10)
	}
}

var sectionRE = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
var indexedKeyRE = regexp.MustCompile(`^(php_admin_value|php_admin_flag|php_value|php_flag)\[([^\]]+)\]$`)

// parseINI reads an ini-style file and records plain, admin-level and
// per-directory values. All three levels are kept so that the evaluator can
// tell whether a safety setting was pinned where the application cannot
// override it.
func parseINI(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseINIReader(f)
}

func parseINIReader(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if sectionRE.MatchString(line) {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(stripInlineComment(line[eq+1:]))
		val = strings.Trim(val, `"'`)

		if m := indexedKeyRE.FindStringSubmatch(key); m != nil {
			level := "value."
			if strings.HasPrefix(m[1], "php_admin_") {
				level = "admin."
			}
			out[level+m[2]] = val
			continue
		}
		out[key] = val
	}
	return out, sc.Err()
}

func stripInlineComment(s string) string {
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == ';' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

var (
	apacheValueRE = regexp.MustCompile(`(?i)^\s*(php_admin_value|php_admin_flag|php_value|php_flag)\s+([A-Za-z0-9_.]+)\s+(.+?)\s*$`)
	apacheIniRE   = regexp.MustCompile(`(?i)^\s*(php_admin_value|php_value)\[([^\]]+)\]\s*=\s*(.+?)\s*$`)
)

// parseApacheConfig records php_value/php_admin_value directives. It is
// intentionally line based: Apache configuration is too complex to model here
// and the directives we care about are single-line.
func parseApacheConfig(path string, into *Posture) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := apacheIniRE.FindStringSubmatch(line); m != nil {
			level := "value."
			if strings.Contains(m[1], "admin") {
				level = "admin."
			}
			into.Values[level+m[2]] = strings.Trim(m[3], `"'`)
			into.Sources[level+m[2]] = path
			continue
		}
		if m := apacheValueRE.FindStringSubmatch(line); m != nil {
			level := "value."
			if strings.Contains(m[1], "admin") {
				level = "admin."
			}
			into.Values[level+m[2]] = strings.Trim(m[3], `"'`)
			into.Sources[level+m[2]] = path
		}
	}
	return sc.Err()
}

// mergeINI copies values from src into p, recording src as the source.
func (p *Posture) mergeINI(src map[string]string, path string) {
	for k, v := range src {
		p.Values[k] = v
		p.Sources[k] = path
	}
}

// loadPosture builds the effective configuration view for a host. It reads the
// ini files the PHP binary reports, the usual distribution locations and
// (optionally) FPM pool and Apache configuration.
func loadPosture(iniPaths []string, webRoots []string, extra []string) *Posture {
	p := newPosture()

	seen := map[string]bool{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		vals, err := parseINI(path)
		if err == nil {
			p.mergeINI(vals, path)
		}
	}

	for _, path := range iniPaths {
		add(path)
	}
	// Distribution defaults. Later files override earlier ones, mirroring the
	// order PHP itself uses closely enough for a triage tool.
	for _, pattern := range []string{
		"/etc/php.ini",
		"/etc/php/*/php.ini",
		"/etc/php/*/fpm/php.ini",
		"/etc/php/*/apache2/php.ini",
		"/etc/php/*/cgi/php.ini",
		"/etc/php/*/cli/php.ini",
		"/usr/local/etc/php.ini",
		"/usr/local/etc/php/*.ini",
		"/opt/*/etc/php.ini",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			add(m)
		}
	}
	for _, path := range extra {
		add(path)
	}

	// FPM pools override php.ini for the workers.
	for _, pattern := range []string{
		"/etc/php/*/fpm/pool.d/*.conf",
		"/usr/local/etc/php-fpm.d/*.conf",
		"/etc/php-fpm.d/*.conf",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			vals, err := parseINI(m)
			if err != nil {
				continue
			}
			p.mergeINI(vals, m)
		}
	}

	// Apache mod_php directives, including per-directory .htaccess files.
	for _, pattern := range []string{
		"/etc/apache2/apache2.conf",
		"/etc/apache2/conf-enabled/*.conf",
		"/etc/apache2/sites-enabled/*.conf",
		"/etc/httpd/conf/httpd.conf",
		"/etc/httpd/conf.d/*.conf",
		"/usr/local/apache2/conf/httpd.conf",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			_ = parseApacheConfig(m, p)
		}
	}
	for _, root := range webRoots {
		_ = parseApacheConfig(filepath.Join(root, ".htaccess"), p)
		add(filepath.Join(root, ".user.ini"))
	}
	return p
}

// iniPathsFromPHP parses the output of `php --ini`.
func iniPathsFromPHP(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Loaded Configuration File:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Loaded Configuration File:"))
			if v != "" && v != "(none)" {
				paths = append(paths, v)
			}
		case strings.HasPrefix(line, "Additional .ini files parsed:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Additional .ini files parsed:"))
			if v != "" && v != "(none)" {
				for _, p := range strings.Split(v, ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						paths = append(paths, p)
					}
				}
			}
		}
	}
	return paths
}
