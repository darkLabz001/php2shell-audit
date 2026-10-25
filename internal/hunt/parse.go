// Package hunt analyses webserver, PHP and host telemetry for exploitation
// and post-exploitation evidence relating to the php2shell vulnerabilities.
package hunt

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Record is one normalised log line.
type Record struct {
	Time          time.Time
	Kind          string // access, apache-error, nginx-error, php-error, syslog, json
	File          string
	Line          int
	Raw           string
	IP            string
	Method        string
	Path          string
	Status        int
	Bytes         int64
	ContentLength int64
	UserAgent     string
	Referer       string
	Message       string
	SetCookie     string
	Cookie        string
	Fields        map[string]string
}

var (
	accessRE    = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Za-z]+|-)\s+(\S+)(?:\s+[^"]*)?" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)
	apacheErrRE = regexp.MustCompile(`^\[([^\]]+)\]\s+(.*)$`)
	nginxErrRE  = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[[^\]]+\] (?:\d+#\d+: )?(?:\*\d+ )?(.*)$`)
	syslogRE    = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:]+):\s*(.*)$`)
	phpErrRE    = regexp.MustCompile(`^\[([^\]]+)\]\s+(.*)$`)
	clientRE    = regexp.MustCompile(`\[client ([^\]:]+)(?::\d+)?\]`)
)

var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z0700",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"Mon Jan _2 15:04:05.000000 2006",
	"Mon Jan _2 15:04:05 2006",
	"Mon Jan 02 15:04:05.000000 2006",
	"2006/01/02 15:04:05",
	"02-Jan-2006 15:04:05 MST",
	"02-Jan-2006 15:04:05",
	"Jan _2 15:04:05",
	"2006-01-02",
}

func parseTimeAny(s string, yearHint int) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return fromUnix(n), true
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if strings.HasPrefix(layout, "Jan ") && yearHint > 0 {
				t = t.AddDate(yearHint, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

func fromUnix(n int64) time.Time {
	if n > 1e15 { // microseconds
		return time.Unix(0, n*1000).UTC()
	}
	if n > 1e12 { // milliseconds
		return time.Unix(0, n*int64(time.Millisecond)).UTC()
	}
	return time.Unix(n, 0).UTC()
}

// parseLine turns a raw line into a Record. It is deliberately tolerant:
// unknown formats still produce a Record so the regex detectors can run on Raw.
func parseLine(line, file string, lineNo int, yearHint int) Record {
	rec := Record{File: file, Line: lineNo, Raw: line, Fields: map[string]string{}}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return rec
	}

	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]any
		if json.Unmarshal([]byte(trimmed), &obj) == nil {
			rec.Kind = "json"
			parseJSONRecord(&rec, obj, yearHint)
			return rec
		}
	}

	if m := accessRE.FindStringSubmatch(trimmed); m != nil {
		rec.Kind = "access"
		if t, ok := parseTimeAny(m[2], yearHint); ok {
			rec.Time = t
		}
		rec.IP = m[1]
		rec.Method = m[3]
		rec.Path = m[4]
		rec.Status, _ = strconv.Atoi(m[5])
		rec.Bytes = parseBytes(m[6])
		if len(m) > 7 {
			rec.Referer = m[7]
			rec.UserAgent = m[8]
		}
		return rec
	}

	if m := nginxErrRE.FindStringSubmatch(trimmed); m != nil {
		rec.Kind = "nginx-error"
		if t, ok := parseTimeAny(m[1], yearHint); ok {
			rec.Time = t
		}
		rec.Message = m[2]
		rec.IP = extractClient(trimmed)
		if rec.IP == "" {
			rec.IP = extractNginxClient(m[2])
		}
		return rec
	}

	if m := phpErrRE.FindStringSubmatch(trimmed); m != nil {
		if t, err := time.Parse("02-Jan-2006 15:04:05 MST", m[1]); err == nil {
			rec.Time = t
			rec.Kind = "php-error"
			rec.Message = m[2]
			rec.IP = extractClient(m[2])
			return rec
		}
	}

	if m := apacheErrRE.FindStringSubmatch(trimmed); m != nil {
		if t, ok := parseTimeAny(m[1], yearHint); ok {
			rec.Time = t
			rec.Kind = "apache-error"
			rec.Message = m[2]
			rec.IP = extractClient(m[2])
			return rec
		}
	}

	if m := syslogRE.FindStringSubmatch(trimmed); m != nil {
		if t, ok := parseTimeAny(m[1], yearHint); ok {
			rec.Time = t
			rec.Kind = "syslog"
			rec.Fields["host"] = m[2]
			rec.Fields["program"] = m[3]
			rec.Message = m[4]
			rec.IP = extractClient(m[4])
			return rec
		}
	}

	// Unknown prefix: keep an RFC3339 or syslog timestamp if one is present at
	// the start, otherwise leave the time zero.
	if i := strings.IndexByte(trimmed, ' '); i > 0 {
		if t, ok := parseTimeAny(trimmed[:i], yearHint); ok {
			rec.Time = t
		}
	}
	if rec.Kind == "" {
		rec.Kind = "unknown"
	}
	rec.Message = trimmed
	rec.IP = extractClient(trimmed)
	return rec
}

func parseJSONRecord(rec *Record, obj map[string]any, yearHint int) {
	for k, v := range obj {
		switch strings.ToLower(k) {
		case "timestamp", "time", "edgestarttimestamp", "eventtime", "@timestamp", "ts":
			rec.Time = jsonTime(v, yearHint)
		case "remote_addr", "remote_ip", "client_ip", "clientip", "client", "c_ip", "ip", "src_ip", "src", "source.ip", "source_ip":
			rec.IP = stringVal(v)
		case "method", "request_method", "http_method", "clientrequestmethod":
			rec.Method = strings.ToUpper(stringVal(v))
		case "request_uri", "uri", "path", "url", "clientrequesturi", "cs-uri-stem":
			rec.Path = stringVal(v)
		case "status", "status_code", "edgeresponsestatus", "sc_status":
			rec.Status = intVal(v)
		case "body_bytes_sent", "bytes", "size", "response_size":
			rec.Bytes = int64Val(v)
		case "content_length", "request_length", "request_size", "body_size":
			rec.ContentLength = int64Val(v)
		case "http_user_agent", "user_agent", "useragent", "cs(user-agent)":
			rec.UserAgent = stringVal(v)
		case "http_referer", "referer", "referrer":
			rec.Referer = stringVal(v)
		case "message", "msg", "event", "log":
			rec.Message = stringVal(v)
		case "set_cookie", "set-cookie", "response_set_cookie":
			rec.SetCookie = stringVal(v)
		case "cookie", "http_cookie", "request_cookie":
			rec.Cookie = stringVal(v)
		}
		rec.Fields[strings.ToLower(k)] = stringVal(v)
	}
	if rec.Message == "" {
		rec.Message = rec.Raw
	}
}

func jsonTime(v any, yearHint int) time.Time {
	switch x := v.(type) {
	case string:
		if t, ok := parseTimeAny(x, yearHint); ok {
			return t
		}
	case float64:
		return fromUnix(int64(x))
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return fromUnix(n)
		}
	case int64:
		return fromUnix(x)
	}
	return time.Time{}
}

func stringVal(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func intVal(v any) int {
	n := int64Val(v)
	return int(n)
}

func int64Val(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case int64:
		return x
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	}
	return 0
}

func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func extractClient(s string) string {
	if m := clientRE.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

var nginxClientRE = regexp.MustCompile(`client: ([0-9a-fA-F:.]+)`)

func extractNginxClient(s string) string {
	if m := nginxClientRE.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// readRecords walks paths and returns parsed records plus the files that were
// read. Directories are traversed; binary files are skipped.
func readRecords(paths []string, since time.Time, maxEvents int, warn func(string, ...any)) ([]Record, []string) {
	var records []Record
	var files []string
	yearHint := 0
	if !since.IsZero() {
		yearHint = since.Year()
	}
	for _, root := range paths {
		fi, err := os.Stat(root)
		if err != nil {
			warn("%s: %v", root, err)
			continue
		}
		if fi.IsDir() {
			_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					base := info.Name()
					if base == ".git" || base == "node_modules" || base == ".cache" || base == "proc" || base == "sys" {
						return filepath.SkipDir
					}
					return nil
				}
				if !info.Mode().IsRegular() || info.Size() > 2*1024*1024*1024 {
					return nil
				}
				r, ok := readFileRecords(path, yearHint, since, maxEvents-len(records), warn)
				if ok {
					files = append(files, path)
					records = append(records, r...)
				}
				if maxEvents > 0 && len(records) >= maxEvents {
					warn("event cap of %d records reached; increase --max-events to read more", maxEvents)
					return filepath.SkipAll
				}
				return nil
			})
			continue
		}
		r, ok := readFileRecords(root, yearHint, since, maxEvents-len(records), warn)
		if ok {
			files = append(files, root)
			records = append(records, r...)
		}
	}
	return records, files
}

func readFileRecords(path string, yearHint int, since time.Time, remaining int, warn func(string, ...any)) ([]Record, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	head := make([]byte, 8192)
	n, _ := f.Read(head)
	if n > 0 && isBinary(head[:n]) {
		return nil, false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false
	}

	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		reader = zr
	}

	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	var out []Record
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		rec := parseLine(line, path, lineNo, yearHint)
		if !since.IsZero() && !rec.Time.IsZero() && rec.Time.Before(since) {
			continue
		}
		out = append(out, rec)
		if remaining > 0 && len(out) >= remaining {
			break
		}
	}
	if err := sc.Err(); err != nil {
		warn("%s: %v", path, err)
	}
	return out, true
}

func isBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// formatEvidence produces "file:line: raw" trimmed for report output.
func formatEvidence(r Record) string {
	raw := strings.ReplaceAll(strings.TrimSpace(r.Raw), "\n", " ")
	if len(raw) > 300 {
		raw = raw[:297] + "..."
	}
	if r.File == "" {
		return raw
	}
	return fmt.Sprintf("%s:%d: %s", r.File, r.Line, raw)
}
