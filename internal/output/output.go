// Package output renders reports as human readable text, JSON or SARIF.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// Format names accepted by Write.
const (
	FormatText  = "text"
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatSARIF = "sarif"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiBRed   = "\x1b[91m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
)

func colourSeverity(s model.Severity, on bool) string {
	label := strings.ToUpper(s.String())
	if !on {
		return label
	}
	switch s {
	case model.Critical:
		return ansiBRed + ansiBold + label + ansiReset
	case model.High:
		return ansiRed + label + ansiReset
	case model.Medium:
		return ansiYellow + label + ansiReset
	case model.Low:
		return ansiCyan + label + ansiReset
	default:
		return ansiDim + label + ansiReset
	}
}

// Write serialises r in the requested format. colour is ignored for machine
// readable formats.
func Write(w io.Writer, r *model.Report, format string, colour bool) error {
	r.Finish()
	switch strings.ToLower(format) {
	case "", FormatText:
		return writeText(w, r, colour)
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case FormatJSONL:
		enc := json.NewEncoder(w)
		for _, f := range r.Findings {
			if err := enc.Encode(f); err != nil {
				return err
			}
		}
		return nil
	case FormatSARIF:
		return writeSARIF(w, r)
	default:
		return fmt.Errorf("unknown output format %q (want text, json, jsonl or sarif)", format)
	}
}

func writeText(w io.Writer, r *model.Report, colour bool) error {
	bold := func(s string) string {
		if !colour {
			return s
		}
		return ansiBold + s + ansiReset
	}
	dim := func(s string) string {
		if !colour {
			return s
		}
		return ansiDim + s + ansiReset
	}

	fmt.Fprintf(w, "%s %s  %s\n", bold("php2shell-audit"), r.Version, dim(r.GeneratedAt.Format(time.RFC3339)))
	if r.Mode != "" {
		fmt.Fprintf(w, "mode: %s", r.Mode)
		if r.Since != "" {
			fmt.Fprintf(w, "   since: %s", r.Since)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s: %s\n\n", bold("SUMMARY"), summaryLine(&r.Stats, colour))

	if r.Summary != "" {
		fmt.Fprintln(w, r.Summary)
		fmt.Fprintln(w)
	}

	if len(r.Targets) > 0 {
		fmt.Fprintln(w, bold("TARGETS"))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tKIND\tSAPI\tVERSION\tSTATUS\tLOADED\tFINDINGS")
		for _, t := range r.Targets {
			name := t.Name
			if len(name) > 56 {
				name = name[:53] + "..."
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%d\n",
				name, orDash(t.Kind), orDash(t.SAPI), orDash(t.Version),
				statusCell(t.Status, t.Worst, colour), yesNo(t.Loaded), t.Findings)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	if len(r.Findings) == 0 {
		if colour {
			fmt.Fprintln(w, ansiGreen+"No findings."+ansiReset)
		} else {
			fmt.Fprintln(w, "No findings.")
		}
	} else {
		fmt.Fprintf(w, "%s\n", bold("FINDINGS"))
		for i, f := range r.Findings {
			fmt.Fprintf(w, "  %s %s\n", colourSeverity(f.Severity, colour), bold(f.Title))
			if f.Target != "" {
				fmt.Fprintf(w, "      target: %s", f.Target)
				if f.Surface != "" {
					fmt.Fprintf(w, "  (%s)", f.Surface)
				}
				fmt.Fprintln(w)
			}
			if f.ID != "" {
				fmt.Fprintf(w, "      rule:   %s\n", f.ID)
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "      detail: %s\n", f.Detail)
			}
			if f.Version != "" || f.Status != "" || f.FixedIn != "" {
				fmt.Fprintf(w, "      php:    version=%s status=%s fixed_in=%s\n",
					orDash(f.Version), orDash(f.Status), orDash(f.FixedIn))
			}
			if f.Confidence != "" {
				fmt.Fprintf(w, "      confidence: %s", f.Confidence)
				if f.Count > 0 {
					fmt.Fprintf(w, "  events: %d", f.Count)
				}
				fmt.Fprintln(w)
			}
			if f.FirstSeen != nil || f.LastSeen != nil {
				fmt.Fprintf(w, "      window: %s .. %s\n", ts(f.FirstSeen), ts(f.LastSeen))
			}
			maxEvidence := 6
			for j, e := range f.Evidence {
				if j >= maxEvidence {
					fmt.Fprintf(w, "      ... %d more\n", len(f.Evidence)-maxEvidence)
					break
				}
				fmt.Fprintf(w, "      evidence: %s\n", truncate(e, 240))
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "      next:   %s\n", f.Remediation)
			}
			if len(f.CVEs) > 0 {
				fmt.Fprintf(w, "      cve:    %s\n", strings.Join(f.CVEs, ", "))
			}
			if len(f.Refs) > 0 {
				fmt.Fprintf(w, "      ref:    %s\n", f.Refs[0])
			}
			if i != len(r.Findings)-1 {
				fmt.Fprintln(w)
			}
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("NOTES"))
		for _, note := range r.Notes {
			fmt.Fprintf(w, "  - %s\n", note)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("WARNINGS"))
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "  - %s\n", warn)
		}
	}
	return nil
}

func summaryLine(s *model.Stats, colour bool) string {
	parts := []struct {
		n int
		s model.Severity
	}{
		{s.Critical, model.Critical},
		{s.High, model.High},
		{s.Medium, model.Medium},
		{s.Low, model.Low},
		{s.Info, model.Info},
	}
	var out []string
	for _, p := range parts {
		out = append(out, fmt.Sprintf("%d %s", p.n, strings.ToLower(colourSeverity(p.s, colour))))
	}
	return strings.Join(out, "  ") + fmt.Sprintf("   (%d total)", s.Total)
}

func statusCell(status, worst string, colour bool) string {
	if status == "" {
		status = "unknown"
	}
	if colour {
		switch status {
		case "vulnerable", "eol":
			return ansiRed + status + ansiReset
		case "fixed", "vendor-patched":
			return ansiGreen + status + ansiReset
		}
	}
	return status
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// --- SARIF 2.1.0 -----------------------------------------------------------

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Props     map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name string `json:"name"`
}

func writeSARIF(w io.Writer, r *model.Report) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := rules[f.ID]; !ok {
			rules[f.ID] = sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  &sarifText{Text: f.Detail},
				DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
				Properties:       map[string]any{"tags": tagsFor(f)},
			}
			if len(f.Refs) > 0 {
				rules[f.ID] = withHelp(rules[f.ID], f.Refs[0])
			}
		}
		msg := f.Title
		if f.Detail != "" {
			msg += ": " + f.Detail
		}
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: truncate(msg, 900)},
			Props: map[string]any{
				"target":     f.Target,
				"surface":    f.Surface,
				"confidence": f.Confidence,
			},
		}
		if f.Target != "" && (strings.HasPrefix(f.Target, "/") || strings.Contains(f.Target, "://")) {
			res.Locations = []sarifLocation{{
				PhysicalLocation: &sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Target}},
			}}
		}
		results = append(results, res)
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, rr := range rules {
		ruleList = append(ruleList, rr)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "php2shell-audit",
				InformationURI: "https://github.com/darkLabz001/php2shell-audit",
				Version:        r.Version,
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func withHelp(r sarifRule, uri string) sarifRule {
	r.HelpURI = uri
	return r
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}

func tagsFor(f model.Finding) []string {
	tags := []string{f.Category}
	tags = append(tags, f.CVEs...)
	return tags
}
