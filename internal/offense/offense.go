package offense

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/scan"
)

// Hard ceiling for the disruptive CVE-2026-109618 pressure probe. It is kept
// deliberately small: this is a validation tool, not a stress tester.
const (
	MaxOOMBody      = 64 << 20
	MinOOMBody      = 1024
	DefaultAudit    = "out/offense-audit.jsonl"
	maxResponseRead = 64 << 10
)

// Options configures one authorized validation run.
type Options struct {
	Scope                 *Scope
	Targets               []string
	Timeout               time.Duration
	Insecure              bool
	OOMBody               int64
	AllowPublic           bool
	AcknowledgeDisruption bool
	Probes                []string
	AuditPath             string
	UserAgent             string
}

// Result is the validation report.
type Result struct {
	Targets  []model.Target
	Findings []model.Finding
	Warnings []string
	Notes    []string
	Summary  string
}

type probeOutcome struct {
	Findings []model.Finding
	Notes    []string
	Outcome  string
	Detail   string
}

type auditEntry struct {
	At         time.Time      `json:"at"`
	CaseID     string         `json:"case_id"`
	Operator   string         `json:"operator"`
	Target     string         `json:"target"`
	Probe      string         `json:"probe"`
	Outcome    string         `json:"outcome"`
	Detail     string         `json:"detail,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	Params     map[string]any `json:"params,omitempty"`
}

// Run performs the authorization pre-flight and then the selected probes.
// Authorization failures are returned as errors before any request is sent.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.Scope.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	if len(opts.Targets) == 0 {
		return nil, errors.New("at least one --target is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	probes, err := NormalizeProbes(opts.Probes)
	if err != nil {
		return nil, err
	}
	if opts.OOMBody > 0 {
		if !opts.AcknowledgeDisruption || !opts.Scope.AcknowledgeDisruption {
			return nil, errors.New("the CVE-2026-109618 pressure probe can disrupt a worker; set acknowledge_disruption in the scope and pass --acknowledge-disruption")
		}
		if opts.OOMBody < MinOOMBody || opts.OOMBody > MaxOOMBody {
			return nil, fmt.Errorf("--oom-body must be between %d and %d bytes", MinOOMBody, MaxOOMBody)
		}
	}
	if err := AuthorizeTargets(ctx, opts.Scope, opts.Targets, opts.AllowPublic); err != nil {
		return nil, err
	}

	res := &Result{}
	res.Notes = append(res.Notes,
		fmt.Sprintf("AUTHORIZED VALIDATION · case %s · operator %s · expires %s",
			opts.Scope.CaseID, opts.Scope.Operator, opts.Scope.Expires.UTC().Format(time.RFC3339)),
		"Validation only: no exploit payload, code execution, reverse shell, webshell, credential theft or persistence is attempted.",
	)
	if probes["109618"] && opts.OOMBody <= 0 {
		res.Notes = append(res.Notes, "CVE-2026-109618 pressure probe is disabled; pass --oom-body and --acknowledge-disruption to run it against an isolated target.")
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "php2shell-audit/offense (authorized validation; case " + opts.Scope.CaseID + ")"
	}
	client := newClient(opts)
	auditWarned := false
	audit := func(e auditEntry) {
		if opts.AuditPath == "" || opts.AuditPath == "-" {
			return
		}
		e.At = time.Now().UTC()
		e.CaseID = opts.Scope.CaseID
		e.Operator = opts.Scope.Operator
		if err := appendAudit(opts.AuditPath, e); err != nil && !auditWarned {
			res.Warnings = append(res.Warnings, "offense audit log: "+err.Error())
			auditWarned = true
		}
	}

	signals := 0
	for _, target := range opts.Targets {
		start := time.Now()
		sr := scan.Remote(ctx, target, scan.RemoteOptions{
			Timeout:    opts.Timeout,
			Insecure:   opts.Insecure,
			UserAgent:  ua,
			NoRedirect: true,
		})
		res.Findings = append(res.Findings, sr.Findings...)
		res.Targets = append(res.Targets, sr.Targets...)
		res.Warnings = append(res.Warnings, sr.Warnings...)

		version, status, sapi := targetInfo(sr)
		audit(auditEntry{
			Target: target, Probe: "preflight", Outcome: "complete",
			Detail:     fmt.Sprintf("version=%s status=%s sapi=%s", orDash(version), orDash(status), orDash(sapi)),
			DurationMS: time.Since(start).Milliseconds(),
		})

		if status == "fixed" || status == "vendor-patched" {
			note := fmt.Sprintf("%s reports %s (%s); offensive validation skipped because the build is patched.", target, orDash(version), status)
			res.Notes = append(res.Notes, note)
			audit(auditEntry{Target: target, Probe: "all", Outcome: "skipped", Detail: note})
			continue
		}

		if probes["109618"] {
			var out probeOutcome
			switch {
			case opts.OOMBody <= 0:
				out = probeOutcome{
					Outcome: "skipped", Detail: "pressure probe disabled (--oom-body 0)",
					Findings: []model.Finding{offenseFinding("P2S-OFF-008", target,
						"CVE-2026-109618 pressure probe not run (policy)", model.Info, "high",
						"remote", "The pressure probe is opt-in because it can disrupt a worker. The passive preflight ran; no pressure request was sent. Use the CLI with --oom-body and --acknowledge-disruption against an isolated target.",
						[]string{"pressure request: not sent", "no code execution attempted"})},
				}
			case status != "vulnerable" && status != "eol":
				reason := fmt.Sprintf("build status %q is not confirmed affected", orDash(status))
				out = probeOutcome{
					Outcome: "skipped", Detail: reason + "; refusing the disruptive probe",
					Notes: []string{target + ": pressure probe skipped because the build is not confirmed vulnerable."},
					Findings: []model.Finding{offenseFinding("P2S-OFF-008", target,
						"CVE-2026-109618 pressure probe skipped", model.Info, "high",
						"remote", "The build was not confirmed vulnerable, so the disruptive pressure request was not sent.",
						[]string{"reason: " + reason, "pressure request: not sent"})},
				}
			default:
				out = runOOMProbe(ctx, client, opts, target, version, ua)
			}
			res.Findings = append(res.Findings, out.Findings...)
			res.Notes = append(res.Notes, out.Notes...)
			signals += countSignals(out.Findings)
			audit(auditEntry{
				Target: target, Probe: "109618", Outcome: out.Outcome, Detail: out.Detail,
				Params: map[string]any{"oom_body": opts.OOMBody},
			})
		}
		if probes["109619"] {
			out := runUploadProbe(ctx, client, opts, target, status, version, ua)
			res.Findings = append(res.Findings, out.Findings...)
			res.Notes = append(res.Notes, out.Notes...)
			signals += countSignals(out.Findings)
			audit(auditEntry{Target: target, Probe: "109619", Outcome: out.Outcome, Detail: out.Detail})
		}
	}

	if opts.AuditPath != "" && opts.AuditPath != "-" {
		res.Notes = append(res.Notes, "Audit trail: "+opts.AuditPath)
	}
	res.Summary = fmt.Sprintf(
		"Authorized validation for case %s completed against %d target(s): %d validation signal(s). No code execution was attempted.",
		opts.Scope.CaseID, len(opts.Targets), signals,
	)
	dedupe(&res.Warnings)
	return res, nil
}

// NormalizeProbes accepts both names, a comma-separated list or "all".
func NormalizeProbes(values []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(values) == 0 {
		values = []string{"109618", "109619"}
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			switch part {
			case "", "all", "both":
				out["109618"] = true
				out["109619"] = true
			case "109618", "cve-2026-109618":
				out["109618"] = true
			case "109619", "cve-2026-109619":
				out["109619"] = true
			default:
				return nil, fmt.Errorf("unknown probe %q (want 109618 or 109619)", part)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no probes selected")
	}
	return out, nil
}

func newClient(opts Options) *http.Client {
	return &http.Client{
		Timeout: opts.Timeout * 2,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.Insecure}, //nolint:gosec // explicit operator flag
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: opts.Timeout,
			Proxy:                 nil,
		},
	}
}

func targetInfo(res *scan.Result) (version, status, sapi string) {
	if res == nil || len(res.Targets) == 0 {
		return "", "", ""
	}
	t := res.Targets[0]
	return t.Version, t.Status, t.SAPI
}

// --- CVE-2026-109618: bounded OOM pressure --------------------------------

type repeatReader struct {
	ch        byte
	remaining int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = r.ch
	}
	r.remaining -= n
	return int(n), nil
}

func runOOMProbe(ctx context.Context, client *http.Client, opts Options, target, version, ua string) probeOutcome {
	bodyLen := opts.OOMBody
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, io.NopCloser(io.MultiReader(
		strings.NewReader("pad="),
		&repeatReader{ch: 'A', remaining: bodyLen - 4},
	)))
	if err != nil {
		return probeOutcome{
			Findings: []model.Finding{offenseFinding("P2S-OFF-004", target,
				"CVE-2026-109618 pressure probe could not be constructed", model.Low, "low",
				"http", err.Error(), nil)},
			Outcome: "error", Detail: err.Error(),
		}
	}
	req.ContentLength = bodyLen
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Connection", "close")
	req.Header.Set("X-P2S-Probe", "109618-pressure")
	req.Header.Set("X-P2S-Case", opts.Scope.CaseID)

	resp, err := client.Do(req)
	elapsed := time.Since(start)
	out := probeOutcome{}
	evidence := []string{
		fmt.Sprintf("request body bytes=%d (single request)", bodyLen),
		fmt.Sprintf("target version=%s", orDash(version)),
		fmt.Sprintf("duration=%s", elapsed.Round(time.Millisecond)),
	}
	if err != nil {
		detail := err.Error()
		switch {
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
			strings.Contains(strings.ToLower(detail), "connection reset"),
			strings.Contains(strings.ToLower(detail), "unexpected eof"):
			out.Findings = append(out.Findings, offenseFinding("P2S-OFF-002", target,
				"Connection dropped during bounded CVE-2026-109618 pressure probe", model.High, "medium",
				"remote", "The worker stopped responding while parsing a bounded body. That is consistent with the OOM longjmp path but is not proof of code execution.",
				append(evidence, "error: "+detail)))
			out.Outcome, out.Detail = "connection-dropped", detail
		case isTimeout(err):
			out.Findings = append(out.Findings, offenseFinding("P2S-OFF-003", target,
				"CVE-2026-109618 pressure probe timed out", model.Medium, "low",
				"remote", "No response arrived before the per-request deadline. Inspect worker logs before repeating; a timeout can be load, a crash or a stalled parser.",
				append(evidence, "error: "+detail)))
			out.Outcome, out.Detail = "timeout", detail
		default:
			out.Findings = append(out.Findings, offenseFinding("P2S-OFF-004", target,
				"CVE-2026-109618 pressure probe failed", model.Low, "low",
				"remote", "The request could not be completed. This does not validate the primitive.",
				append(evidence, "error: "+detail)))
			out.Outcome, out.Detail = "error", detail
		}
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseRead))
	low := strings.ToLower(string(body))
	evidence = append(evidence, "HTTP "+resp.Status)
	if snippet := responseSnippet(body); snippet != "" {
		evidence = append(evidence, "response: "+snippet)
	}
	switch {
	case strings.Contains(low, "allowed memory size") || strings.Contains(low, "out of memory") || strings.Contains(low, "memory exhausted"):
		out.Findings = append(out.Findings, offenseFinding("P2S-OFF-005", target,
			"OOM signature returned by the CVE-2026-109618 pressure probe", model.High, "medium",
			"remote", "The response contains a PHP memory-exhaustion signature after a bounded body. Correlate the timestamp with the worker and error logs.",
			evidence))
		out.Outcome, out.Detail = "oom-signature", resp.Status
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		out.Findings = append(out.Findings, offenseFinding("P2S-OFF-007", target,
			"Pressure body was rejected before the OOM path", model.Info, "high",
			"remote", "The server rejected the body (413). The configured request-size limit prevents this probe from reaching the memory path.",
			evidence))
		out.Outcome, out.Detail = "body-rejected", resp.Status
	case resp.StatusCode >= 500:
		out.Findings = append(out.Findings, offenseFinding("P2S-OFF-006", target,
			"Server error after bounded CVE-2026-109618 pressure probe", model.Medium, "medium",
			"remote", "The server returned a 5xx after the pressure request. This can be an application error or a damaged worker; correlate with the PHP error log.",
			evidence))
		out.Outcome, out.Detail = "server-error", resp.Status
	default:
		out.Findings = append(out.Findings, offenseFinding("P2S-OFF-001", target,
			"Worker remained responsive to bounded CVE-2026-109618 pressure", model.Info, "medium",
			"remote", "The request completed without a crash-like signal. This does not prove the build is safe: the body may be below the effective memory limit or the OOM path may need a different shape.",
			evidence))
		out.Outcome, out.Detail = "survived", resp.Status
	}
	return out
}

// --- CVE-2026-109619: upload-progress canary -------------------------------

func runUploadProbe(ctx context.Context, client *http.Client, opts Options, target, status, version, ua string) probeOutcome {
	if status == "fixed" || status == "vendor-patched" {
		return probeOutcome{Outcome: "skipped", Detail: "build is patched"}
	}
	canaries := []string{canaryValue(), canaryValue()}
	sid := canaryValue()
	statuses := make([]string, 0, len(canaries))
	start := time.Now()
	for _, c := range canaries {
		st, _, err := uploadOnce(ctx, client, target, sid, c, ua, opts.Scope.CaseID)
		if err != nil {
			return probeOutcome{
				Findings: []model.Finding{offenseFinding("P2S-OFF-013", target,
					"CVE-2026-109619 upload-progress probe failed", model.Low, "low",
					"remote", "The multipart canary request could not be completed; no state conclusion is possible.",
					[]string{fmt.Sprintf("error: %v", err), "single retry not attempted"})},
				Outcome: "error", Detail: err.Error(),
			}
		}
		statuses = append(statuses, st)
	}

	body, headers, followStatus, err := followUp(ctx, client, target, sid, ua, opts.Scope.CaseID)
	elapsed := time.Since(start)
	evidence := []string{
		"upload statuses: " + strings.Join(statuses, ", "),
		"follow-up: " + followStatus,
		fmt.Sprintf("session canary=%s…", sid[:6]),
		fmt.Sprintf("duration=%s", elapsed.Round(time.Millisecond)),
		"no code execution attempted",
	}
	if err != nil {
		evidence = append(evidence, "follow-up error: "+err.Error())
		return probeOutcome{
			Findings: []model.Finding{offenseFinding("P2S-OFF-013", target,
				"CVE-2026-109619 follow-up request failed", model.Low, "low",
				"remote", "The uploads completed but the follow-up request failed, so cross-request state could not be assessed.", evidence)},
			Outcome: "error", Detail: err.Error(),
		}
	}

	haystack := body + "\n" + headers
	found := make([]string, 0, len(canaries))
	for _, c := range canaries {
		if strings.Contains(haystack, c) {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 2:
		return probeOutcome{
			Findings: []model.Finding{offenseFinding("P2S-OFF-010", target,
				"Upload-progress state persisted across worker requests", model.High, "medium",
				"remote", "Both independent progress canaries were visible in a later response on the same PHPSESSID. That is a cross-request state signal consistent with CVE-2026-109619; it is not proof of code execution.",
				append(evidence, "both canaries observed"))},
			Outcome: "cross-request-state", Detail: "both canaries observed",
		}
	case 1:
		return probeOutcome{
			Findings: []model.Finding{offenseFinding("P2S-OFF-011", target,
				"Upload-progress canary was reflected across requests", model.Medium, "medium",
				"remote", "One progress canary appeared in a later response on the same session. Review how the application exposes session progress before treating this as a stale-state finding.",
				append(evidence, "one canary observed"))},
			Outcome: "canary-reflected", Detail: "one canary observed",
		}
	}
	return probeOutcome{
		Findings: []model.Finding{offenseFinding("P2S-OFF-012", target,
			"Upload-progress canary was not observed", model.Info, "medium",
			"remote", "The uploads were accepted but the canary did not surface in the follow-up response. session.upload_progress may be disabled or the endpoint may not report progress; the precondition is not confirmed.",
			evidence)},
		Outcome: "canary-not-observed", Detail: "no canary in follow-up",
	}
}

func uploadOnce(ctx context.Context, client *http.Client, target, sid, canary, ua, caseID string) (string, string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("PHP_SESSION_UPLOAD_PROGRESS", canary); err != nil {
		return "", "", err
	}
	part, err := mw.CreateFormFile("file", "p2s-canary.txt")
	if err != nil {
		return "", "", err
	}
	if _, err := fmt.Fprintf(part, "authorized validation canary %s\n", canary); err != nil {
		return "", "", err
	}
	if err := mw.Close(); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body.Bytes()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Cookie", "PHPSESSID="+sid)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-P2S-Probe", "109619-upload-progress")
	req.Header.Set("X-P2S-Case", caseID)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseRead))
	return resp.Status, string(data), nil
}

func followUp(ctx context.Context, client *http.Client, target, sid, ua, caseID string) (body, headers, status string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Cookie", "PHPSESSID="+sid)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-P2S-Probe", "109619-follow-up")
	req.Header.Set("X-P2S-Case", caseID)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseRead))
	var h strings.Builder
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(&h, "%s: %s\n", key, value)
		}
	}
	return string(data), h.String(), resp.Status, nil
}

// --- helpers ---------------------------------------------------------------

func offenseFinding(id, target, title string, severity model.Severity, confidence, surface, detail string, evidence []string) model.Finding {
	cves := []string{model.CVE109618}
	if strings.HasPrefix(id, "P2S-OFF-01") {
		cves = []string{model.CVE109619}
	}
	return model.Finding{
		ID: id, Title: title, Severity: severity, Category: "validation",
		Surface: surface, Target: target, Detail: detail, Evidence: evidence,
		Confidence: confidence, CVEs: cves,
		Refs:        []string{model.AdvisoryURL},
		Remediation: "Correlate the timestamp with PHP, Apache and FPM logs. Validation is not proof of exploitability; do not repeat a disruptive probe against production.",
	}
}

func countSignals(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Category == "validation" && f.Severity >= model.Medium {
			n++
		}
	}
	return n
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	type timeout interface{ Timeout() bool }
	var t timeout
	return errors.As(err, &t) && t.Timeout()
}

func responseSnippet(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func canaryValue() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("p2s-%d", time.Now().UnixNano())
	}
	return "p2s-" + hex.EncodeToString(b[:])
}

func appendAudit(path string, e auditEntry) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(e)
}

func dedupe(values *[]string) {
	seen := map[string]bool{}
	out := (*values)[:0]
	for _, v := range *values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	*values = out
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
