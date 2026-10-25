package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/phpver"
)

// RemoteOptions configures passive remote assessment.
type RemoteOptions struct {
	Timeout   time.Duration
	Insecure  bool
	Paths     []string
	UserAgent string
	// NoRedirect keeps the request on the authorized host. Offense mode sets
	// it so a redirect cannot move a probe outside the scope file.
	NoRedirect bool
}

const defaultUA = "php2shell-audit/0.1 (defensive exposure check; +https://github.com/darkLabz001/php2shell-audit)"

var (
	headerVersionRE  = regexp.MustCompile(`(?i)\bphp[/ ]v?(\d+\.\d+\.\d+)`)
	phpinfoVersionRE = regexp.MustCompile(`(?is)PHP Version\s*</td>\s*<td[^>]*>\s*([0-9][^<\s]*)`)
	phpinfoAPIRE     = regexp.MustCompile(`(?is)Server API\s*</td>\s*<td[^>]*>\s*([^<]+)`)
	phpinfoRowRE     = regexp.MustCompile(`(?is)<tr[^>]*>\s*<td[^>]*class="e"[^>]*>(.*?)</td>\s*<td[^>]*class="v"[^>]*>(.*?)</td>`)
	tagRE            = regexp.MustCompile(`(?s)<[^>]+>`)
)

// Remote performs a passive check: one GET (plus optional operator-supplied
// paths) and header/body inspection. It never sends exploit-shaped requests.
func Remote(ctx context.Context, rawURL string, opts RemoteOptions) *Result {
	res := &Result{}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUA
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opts.NoRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec // explicit operator choice
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
		},
	}

	target, body, resp, err := fetch(ctx, client, rawURL, ua, opts.Insecure)
	if err != nil {
		res.warn("%s: %v", rawURL, err)
		res.add(model.Finding{
			ID: "P2S-REM-004", Target: rawURL, Surface: "remote",
			Title: "Remote target could not be checked", Severity: model.Low,
			Category: "error", Confidence: "high",
			Detail:      err.Error(),
			Remediation: "Verify DNS, routing, TLS and the URL. An unchecked target is not a safe target; check it from another vantage point or run the local scan on the host.",
			Refs:        []string{model.AdvisoryURL},
		})
		return res
	}
	name := target.String()
	t := model.Target{Name: name, Kind: "remote", Source: name}
	if resp != nil {
		t.Config = map[string]string{"http_status": resp.Status}
	}
	res.addTarget(t)
	idx := len(res.Targets) - 1

	var evidence []string
	if resp != nil {
		for _, h := range []string{"X-Powered-By", "X-PHP-Version", "Server", "X-Generator", "Via"} {
			if v := resp.Header.Get(h); v != "" {
				evidence = append(evidence, h+": "+v)
			}
		}
	}

	version, sapi := detectRemoteVersion(resp, body)
	if version != nil {
		a := phpver.Assess(*version)
		t.Version = version.Raw
		t.Status = a.Status
		t.FixedIn = a.FixedIn
		t.SAPI = sapi
		res.setTarget(idx, t)
		res.add(ExposureFinding(name, "remote", sapi, version.Raw, a, "http"))
		evidence = append(evidence, "detected PHP "+version.Raw)
	} else {
		t.Status = phpver.StatusUnknown
		res.setTarget(idx, t)
		res.add(model.Finding{
			ID: "P2S-REM-001", Target: name, Surface: "remote",
			Title: "PHP version is not disclosed; remote exposure is unverified", Severity: model.Medium,
			Category: "exposure", Confidence: "high", Status: phpver.StatusUnknown,
			Detail:      "The site did not reveal a PHP version in headers, cookies or the response body. This does not mean it is safe: version hiding is common and the bugs are below application code.",
			Evidence:    evidence,
			Refs:        []string{model.AdvisoryURL},
			CVEs:        []string{model.CVE109618, model.CVE109619},
			Remediation: "Run `php2shell-audit scan --local` on the host, or read the version from the served SAPI (phpinfo behind auth) and compare with the fixed table.",
		})
	}

	// Memory-disclosure heuristic: the confirmed leak URL-encodes heap bytes
	// into PHPSESSID. Long or percent-encoded session cookies are suspicious.
	if resp != nil {
		for _, c := range resp.Cookies() {
			if !strings.EqualFold(c.Name, "PHPSESSID") && !strings.HasPrefix(strings.ToUpper(c.Name), "PHPSESSID") {
				continue
			}
			if len(c.Value) > 256 || strings.Count(c.Value, "%") >= 8 {
				res.add(model.Finding{
					ID: "P2S-REM-002", Target: name, Surface: "remote",
					Title: "PHPSESSID has an anomalous length or encoding", Severity: model.High,
					Category: "attempt", Confidence: "medium",
					Detail:      fmt.Sprintf("A PHPSESSID of %d bytes with %d percent escapes was returned. The CVE-2026-109618 memory-disclosure primitive URL-encodes leaked worker memory into this cookie. Legitimate session IDs are 22-256 characters and normally do not look like encoded binary.", len(c.Value), strings.Count(c.Value, "%")),
					Evidence:    []string{"Set-Cookie: " + c.Name + "=" + truncateForEvidence(c.Value, 160)},
					CVEs:        []string{model.CVE109618},
					Refs:        []string{model.GHSA109618},
					Remediation: "Correlate with webserver logs and worker crashes; patch and rotate secrets if the host was unpatched. Do not treat this heuristic alone as proof of compromise.",
				})
			}
		}
	}

	// Optional operator-supplied paths (typically a phpinfo page they own).
	for _, path := range opts.Paths {
		probeURL := joinURL(target, path)
		_, pbody, presp, perr := fetch(ctx, client, probeURL.String(), ua, opts.Insecure)
		if perr != nil {
			res.warn("%s: %v", probeURL, perr)
			continue
		}
		info := parsePHPInfo(pbody)
		if len(info) == 0 {
			continue
		}
		ver := info["PHP Version"]
		api := info["Server API"]
		if ver == "" {
			ver = stripTags(info["PHP Version"])
		}
		res.add(model.Finding{
			ID: "P2S-REM-003", Target: name, Surface: "remote",
			Title: "phpinfo() is reachable without authentication", Severity: model.High,
			Category: "exposure", Confidence: "high",
			Detail:      "The probe returned a phpinfo page. It exposes the exact build, SAPI, ini paths and configuration to anyone who requests it, and it gave this scanner the effective configuration below.",
			Evidence:    []string{probeURL.String()},
			Remediation: "Remove the phpinfo file or put it behind authentication and an IP allowlist. Review the exposed secrets in the page.",
		})
		if v, ok := phpver.Parse(ver); ok {
			a := phpver.Assess(v)
			surfaceTarget := name + " " + path
			res.addTarget(model.Target{
				Name: surfaceTarget, Kind: "remote-phpinfo", SAPI: api,
				Version: v.Raw, Status: a.Status, FixedIn: a.FixedIn, Source: probeURL.String(),
			})
			res.add(ExposureFinding(surfaceTarget, "remote", api, v.Raw, a, probeURL.String()))
			posture := postureFromPHPInfo(info)
			for _, f := range ConfigFindings(surfaceTarget, v.Raw, a.Status, api, posture, nil) {
				f.Surface = "remote"
				res.add(f)
			}
		} else if ver != "" {
			res.warn("%s: phpinfo reported an unparseable version %q", probeURL, ver)
		}
		_ = presp
	}

	// Context that helps an operator prioritise: CDN/WAF in front, or a CMS
	// that is very likely to be backed by PHP.
	var notes []string
	if waf := detectWAF(resp); waf != "" {
		notes = append(notes, "edge/WAF: "+waf)
	}
	if cms := detectCMS(resp, body); cms != "" {
		notes = append(notes, "application: "+cms)
	}
	if len(notes) > 0 {
		t = res.Targets[idx]
		t.Notes = append(t.Notes, notes...)
		res.setTarget(idx, t)
	}
	return res
}

func fetch(ctx context.Context, client *http.Client, rawURL, ua string, insecure bool) (*url.URL, string, *http.Response, error) {
	candidates := []string{rawURL}
	if !strings.Contains(rawURL, "://") {
		candidates = []string{"https://" + rawURL, "http://" + rawURL}
	}
	var lastErr error
	for _, candidate := range candidates {
		u, err := url.Parse(candidate)
		if err != nil {
			return nil, "", nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, "", nil, err
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			lastErr = err
			continue
		}
		return u, string(body), resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable URL")
	}
	return nil, "", nil, lastErr
}

func detectRemoteVersion(resp *http.Response, body string) (*phpver.Version, string) {
	if resp != nil {
		for _, h := range []string{"X-Powered-By", "X-PHP-Version", "Server", "X-Generator"} {
			if m := headerVersionRE.FindStringSubmatch(resp.Header.Get(h)); m != nil {
				if v, ok := phpver.Parse(m[1]); ok {
					return &v, sapiHint(resp)
				}
			}
		}
	}
	if info := parsePHPInfo(body); len(info) > 0 {
		if v, ok := phpver.Parse(info["PHP Version"]); ok {
			return &v, strings.TrimSpace(stripTags(info["Server API"]))
		}
	}
	if m := headerVersionRE.FindStringSubmatch(body); m != nil {
		// Only trust a body match when the page looks like phpinfo or a debug
		// banner; arbitrary page text mentioning PHP is too noisy.
		if strings.Contains(strings.ToLower(body), "php version") || strings.Contains(strings.ToLower(body), "server api") {
			if v, ok := phpver.Parse(m[1]); ok {
				return &v, ""
			}
		}
	}
	return nil, ""
}

func sapiHint(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	server := strings.ToLower(resp.Header.Get("Server"))
	switch {
	case strings.Contains(server, "apache"):
		return "apache2handler"
	case strings.Contains(server, "litespeed"):
		return "litespeed"
	case strings.Contains(server, "nginx") || strings.Contains(server, "cloudflare"):
		return "unknown (nginx/front proxy; PHP SAPI not disclosed)"
	case strings.Contains(server, "frankenphp"):
		return "frankenphp"
	}
	return ""
}

func parsePHPInfo(body string) map[string]string {
	out := map[string]string{}
	for _, m := range phpinfoRowRE.FindAllStringSubmatch(body, -1) {
		key := strings.TrimSpace(stripTags(m[1]))
		val := strings.TrimSpace(stripTags(m[2]))
		if key != "" {
			out[key] = val
		}
	}
	if v := phpinfoVersionRE.FindStringSubmatch(body); v != nil {
		if _, ok := out["PHP Version"]; !ok {
			out["PHP Version"] = strings.TrimSpace(v[1])
		}
	}
	if a := phpinfoAPIRE.FindStringSubmatch(body); a != nil {
		if _, ok := out["Server API"]; !ok {
			out["Server API"] = strings.TrimSpace(stripTags(a[1]))
		}
	}
	return out
}

func postureFromPHPInfo(info map[string]string) *Posture {
	p := newPosture()
	keys := []string{
		"memory_limit", "post_max_size", "upload_max_filesize",
		"max_input_vars", "max_input_nesting_level",
		"session.upload_progress.enabled", "fatal_error_backtraces",
		"session.save_path", "opcache.enable", "display_errors",
		"log_errors", "pm.max_requests", "pm.max_children",
	}
	for _, k := range keys {
		if v, ok := info[k]; ok && v != "" {
			p.Values[k] = v
			p.Sources[k] = "phpinfo"
		}
	}
	return p
}

func detectWAF(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	switch {
	case resp.Header.Get("CF-Ray") != "":
		return "Cloudflare"
	case resp.Header.Get("X-Sucuri-ID") != "":
		return "Sucuri"
	case resp.Header.Get("X-Akamai-Transformed") != "":
		return "Akamai"
	case resp.Header.Get("X-Azure-Ref") != "":
		return "Azure Front Door"
	case resp.Header.Get("X-Goog-Generation") != "":
		return "Google Cloud"
	}
	return ""
}

func detectCMS(resp *http.Response, body string) string {
	lower := strings.ToLower(body)
	var hints []string
	if strings.Contains(lower, "wp-content/") || strings.Contains(lower, "wp-includes/") {
		hints = append(hints, "WordPress")
	}
	if strings.Contains(lower, "drupal") || strings.Contains(lower, "sites/default/files") {
		hints = append(hints, "Drupal")
	}
	if strings.Contains(lower, "/media/system/js/") || strings.Contains(lower, "joomla") {
		hints = append(hints, "Joomla")
	}
	if strings.Contains(lower, "magento") || strings.Contains(lower, "mage/cookies") {
		hints = append(hints, "Magento")
	}
	if resp != nil {
		if strings.Contains(strings.ToLower(resp.Header.Get("X-Powered-By")), "laravel") ||
			strings.Contains(lower, "laravel_session") {
			hints = append(hints, "Laravel")
		}
		if strings.Contains(lower, "/typo3/") {
			hints = append(hints, "TYPO3")
		}
		if strings.Contains(lower, "nextcloud") {
			hints = append(hints, "Nextcloud")
		}
	}
	return strings.Join(hints, ", ")
}

func joinURL(base *url.URL, path string) *url.URL {
	if path == "" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := *base
	u.Path = path
	u.RawQuery = ""
	return &u
}

func stripTags(s string) string {
	return tagRE.ReplaceAllString(s, "")
}

func truncateForEvidence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
