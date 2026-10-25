package hunt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// Result is the output of a hunt run.
type Result struct {
	Findings []model.Finding
	Warnings []string
	Notes    []string
	Files    []string
	Events   []Event
	Summary  string
}

// Run executes a hunt against logs and, when requested, the live host.
func Run(opts Options) *Result {
	res := &Result{}
	if len(opts.Paths) == 0 && !opts.Live && len(opts.WebRoots) == 0 {
		res.Warnings = append(res.Warnings, "nothing to analyse: pass --logs, --web-root or --live")
	}

	if len(opts.Paths) > 0 {
		records, files := readRecords(opts.Paths, opts.Since, opts.MaxEvents, func(f string, a ...any) {
			res.Warnings = append(res.Warnings, fmt.Sprintf(f, a...))
		})
		res.Files = files
		findings, events := Analyze(records, opts)
		res.Findings = append(res.Findings, findings...)
		res.Events = append(res.Events, events...)
		if len(records) == 0 {
			res.Warnings = append(res.Warnings, "no readable log lines matched the requested window")
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("analysed %d log line(s) from %d file(s)", len(records), len(files)))
		}
	}

	if opts.Live {
		findings, warnings := Host(opts)
		res.Findings = append(res.Findings, findings...)
		res.Warnings = append(res.Warnings, warnings...)
	}

	if len(opts.WebRoots) > 0 {
		findings, warnings := ScanWebRoots(opts.WebRoots, opts.Since, opts.AllFiles, opts.MinFileScore)
		res.Findings = append(res.Findings, findings...)
		res.Warnings = append(res.Warnings, warnings...)
	}

	if len(opts.SessionPaths) > 0 || opts.Live {
		findings, warnings := ScanSessions(opts.SessionPaths, opts.Since, opts.AllFiles)
		res.Findings = append(res.Findings, findings...)
		res.Warnings = append(res.Warnings, warnings...)
	}

	res.Summary = summarise(res.Findings)
	if opts.EvidenceDir != "" && (len(res.Findings) > 0 || len(res.Events) > 0) {
		if paths, err := writeEvidence(opts.EvidenceDir, res); err != nil {
			res.Warnings = append(res.Warnings, "evidence export failed: "+err.Error())
		} else {
			res.Notes = append(res.Notes, "evidence written to "+strings.Join(paths, ", "))
		}
	}
	return res
}

func summarise(findings []model.Finding) string {
	var compromise, persistence, attempts int
	for _, f := range findings {
		switch f.Category {
		case "compromise":
			compromise++
		case "persistence":
			persistence++
		case "attempt":
			attempts++
		}
	}
	switch {
	case compromise > 0 || persistence > 0:
		return fmt.Sprintf("Indicators of compromise or persistence were found (%d compromise, %d persistence, %d attempt signals). Isolate affected hosts before remediating.", compromise, persistence, attempts)
	case attempts > 0:
		return fmt.Sprintf("Exploitation attempts were detected (%d signal groups) but no confirmed post-exploitation artefact was found. Patch exposed PHP now and preserve the evidence.", attempts)
	default:
		return "No php2shell-specific signals were found in the supplied telemetry. Absence of signals is not proof of safety: the engine exploits can run below application logging. Patch regardless."
	}
}

func writeEvidence(dir string, res *Result) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var written []string
	write := func(name string, data []byte) error {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		written = append(written, path)
		return nil
	}

	var events strings.Builder
	enc := json.NewEncoder(&events)
	for _, ev := range res.Events {
		_ = enc.Encode(ev)
	}
	if err := write("events.jsonl", []byte(events.String())); err != nil {
		return written, err
	}

	findingsJSON, _ := json.MarshalIndent(map[string]any{
		"generated_at": time.Now().UTC(),
		"summary":      res.Summary,
		"findings":     res.Findings,
		"warnings":     res.Warnings,
	}, "", "  ")
	if err := write("findings.json", findingsJSON); err != nil {
		return written, err
	}

	var matches strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&matches, "## [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title)
		if f.Target != "" {
			fmt.Fprintf(&matches, "target: %s\n", f.Target)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(&matches, "  %s\n", e)
		}
		matches.WriteString("\n")
	}
	if err := write("matches.log", []byte(matches.String())); err != nil {
		return written, err
	}

	manifest := map[string]string{}
	for _, path := range written {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		manifest[filepath.Base(path)] = hex.EncodeToString(sum[:])
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if err := write("manifest.json", manifestJSON); err != nil {
		return written, err
	}
	return written, nil
}
