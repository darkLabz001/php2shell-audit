package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

func testApp(t *testing.T, w, h int) (*App, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	a := newApp(Config{Version: "test", Width: w, Height: h, Out: &buf})
	a.out = &buf
	a.fixed = true
	a.theme = theme{enabled: true}
	a.screen = screenMenu
	return a, &buf
}

func frameLines(t *testing.T, out string) []string {
	t.Helper()
	if out == "" {
		t.Fatal("empty frame")
	}
	return strings.Split(out, "\r\n")
}

func TestKeyReaderSequences(t *testing.T) {
	cases := []struct {
		in   string
		kind keyKind
		r    rune
	}{
		{"a", keyRune, 'a'},
		{"é", keyRune, 'é'},
		{"\r", keyEnter, 0},
		{"\t", keyTab, 0},
		{"\x7f", keyBackspace, 0},
		{"\x03", keyCtrlC, 0},
		{"\x1b", keyEsc, 0},
		{"\x1b[A", keyUp, 0},
		{"\x1b[B", keyDown, 0},
		{"\x1b[C", keyRight, 0},
		{"\x1b[D", keyLeft, 0},
		{"\x1b[H", keyHome, 0},
		{"\x1b[F", keyEnd, 0},
		{"\x1b[5~", keyPageUp, 0},
		{"\x1b[6~", keyPageDown, 0},
		{"\x1b[3~", keyDelete, 0},
	}
	for _, tc := range cases {
		kr := newKeyReader(strings.NewReader(tc.in), nil)
		got, err := kr.read()
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got.kind != tc.kind || (tc.kind == keyRune && got.r != tc.r) {
			t.Errorf("%q decoded as (%v, %q), want (%v, %q)", tc.in, got.kind, got.r, tc.kind, tc.r)
		}
	}
}

func TestWidthHelpers(t *testing.T) {
	styled := "\x1b[38;5;198mabcdef\x1b[0m"
	if got := displayWidth(styled); got != 6 {
		t.Fatalf("displayWidth = %d, want 6", got)
	}
	clipped := clip(styled, 3)
	if got := displayWidth(clipped); got != 3 {
		t.Fatalf("clipped width = %d, want 3", got)
	}
	if !strings.Contains(clipped, "abc") {
		t.Fatalf("clip lost content: %q", clipped)
	}
	if got := padRight("ab", 5); got != "ab   " {
		t.Fatalf("padRight = %q", got)
	}
	if got := displayWidth("█▓░⣾"); got != 4 {
		t.Fatalf("glyph width = %d, want 4", got)
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three", 7)
	if len(got) != 2 || got[0] != "one two" || got[1] != "three" {
		t.Fatalf("wrap = %#v", got)
	}
	long := wrap(strings.Repeat("x", 12), 5)
	for _, line := range long {
		if displayWidth(line) > 5 {
			t.Fatalf("line %q wider than 5", line)
		}
	}
}

func TestMenuNavigation(t *testing.T) {
	a, _ := testApp(t, 100, 32)
	down := key{kind: keyDown}
	for i := 0; i < 2; i++ {
		a.handle(down)
	}
	if a.cursor != 2 {
		t.Fatalf("cursor = %d, want 2", a.cursor)
	}
	a.handle(key{kind: keyUp})
	if a.cursor != 1 {
		t.Fatalf("cursor after up = %d, want 1", a.cursor)
	}
	a.handle(key{kind: keyUp})
	a.handle(key{kind: keyUp})
	if a.cursor != len(a.menu)-1 {
		t.Fatalf("cursor should wrap to the last entry, got %d", a.cursor)
	}
	a.handle(key{kind: keyHome})
	if a.cursor != 0 {
		t.Fatalf("home = %d, want 0", a.cursor)
	}
	a.handle(key{kind: keyRune, r: '?'})
	if a.screen != screenViewer {
		t.Fatalf("manual did not open, screen = %v", a.screen)
	}
	a.handle(key{kind: keyEsc})
	if a.screen != screenMenu {
		t.Fatalf("esc did not return to menu, screen = %v", a.screen)
	}
	a.handle(key{kind: keyRune, r: 'q'})
	if !a.quit {
		t.Fatal("q did not quit")
	}
}

func TestPromptEditing(t *testing.T) {
	a, _ := testApp(t, 90, 28)
	var got string
	a.openPrompt(&promptState{
		title: "LOG HUNT",
		label: "PATH",
		submit: func(v string) error {
			got = v
			return nil
		},
	})
	if a.screen != screenPrompt {
		t.Fatal("prompt did not open")
	}
	for _, r := range "abc" {
		a.handle(key{kind: keyRune, r: r})
	}
	a.handle(key{kind: keyBackspace})
	a.handle(key{kind: keyEnter})
	if got != "ab" {
		t.Fatalf("submitted %q, want %q", got, "ab")
	}
	a.handle(key{kind: keyEsc})
	if a.screen != screenMenu || a.prompt != nil {
		t.Fatalf("esc did not close the prompt (screen=%v)", a.screen)
	}
}

func TestRenderFrames(t *testing.T) {
	for _, size := range [][2]int{{120, 36}, {80, 24}, {40, 16}} {
		a, buf := testApp(t, size[0], size[1])
		screens := []screen{screenSplash, screenMenu, screenPrompt, screenRunning, screenResults, screenViewer}

		a.prompt = &promptState{title: "REMOTE PROBE", label: "TARGET URL", hint: "https://example.com"}
		a.job = &jobState{job: &job{label: "LOCAL INVENTORY", verb: "checking", phases: []string{"a", "b"}}}
		a.results = &resultsState{report: sampleReport()}
		a.viewer = &viewerState{title: "MANUAL", body: helpDocument("test", "operator@host"), wrap: true}

		for _, s := range screens {
			a.screen = s
			a.tick++
			buf.Reset()
			a.draw()
			if buf.Len() == 0 {
				t.Fatalf("size %v screen %v produced no output", size, s)
			}
			lines := frameLines(t, buf.String())
			if len(lines) != size[1] {
				t.Fatalf("size %v screen %v drew %d lines, want %d", size, s, len(lines), size[1])
			}
		}
	}
}

func TestMenuAndResultsContent(t *testing.T) {
	a, buf := testApp(t, 110, 34)
	a.draw()
	out := buf.String()
	for _, want := range []string{"PHP2SHELL", "LOCAL INVENTORY", "LIVE INTEL", "CVE-2026-109618"} {
		if !strings.Contains(out, want) {
			t.Errorf("menu frame missing %q", want)
		}
	}

	a.results = &resultsState{report: sampleReport()}
	a.screen = screenResults
	buf.Reset()
	a.draw()
	out = buf.String()
	for _, want := range []string{"FINDINGS", "P2S-CFG-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("results frame missing %q", want)
		}
	}

	a.results.tab = 1
	buf.Reset()
	a.draw()
	if !strings.Contains(buf.String(), "TARGET INVENTORY") {
		t.Error("targets tab did not render")
	}
}

func TestNoColorOutput(t *testing.T) {
	a, buf := testApp(t, 100, 30)
	a.theme = theme{enabled: false}
	a.draw()
	out := buf.String()
	if strings.Contains(out, "\x1b[38;5;") || strings.Contains(out, "\x1b[48;5;") {
		t.Error("NO_COLOR frame still contains 256-colour escapes")
	}
	if !strings.Contains(out, "LOCAL INVENTORY") {
		t.Error("NO_COLOR frame lost its content")
	}
}

func TestSmallMenuKeepsAllOperations(t *testing.T) {
	a, buf := testApp(t, 60, 20)
	a.draw()
	out := buf.String()
	for _, label := range []string{"LOCAL INVENTORY", "SIGNATURE FORGE", "JACK OUT"} {
		if !strings.Contains(out, label) {
			t.Errorf("small menu missing %q", label)
		}
	}
}

func TestResultsTabsWithoutTargets(t *testing.T) {
	a, buf := testApp(t, 100, 30)
	rep := &model.Report{
		Tool:    "php2shell-audit",
		Mode:    "hunt",
		Summary: "No php2shell-specific signals were found.",
		Findings: []model.Finding{{
			ID: "P2S-HUNT-012", Title: "Webshell score", Severity: model.High, Category: "compromise",
		}},
	}
	rep.Finish()
	a.results = &resultsState{report: rep}
	a.screen = screenResults
	if got := a.results.tabCount(); got != 2 {
		t.Fatalf("tabCount = %d, want 2", got)
	}
	if kind := a.results.tabKind(1); kind != "notes" {
		t.Fatalf("tab 1 = %q, want notes", kind)
	}
	a.results.tab = 1
	buf.Reset()
	a.draw()
	out := buf.String()
	if strings.Contains(out, "TARGET INVENTORY") {
		t.Error("notes tab rendered an empty target inventory")
	}
	if !strings.Contains(out, "NOTES") {
		t.Error("notes tab not rendered")
	}
}

func TestHelpAndFindingDocument(t *testing.T) {
	help := strings.Join(helpDocument("0.1.0", "op@host"), "\n")
	for _, want := range []string{"CVE-2026-109618", "8.5.12", "SAFETY BOUNDARY", "CONTROLS"} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q", want)
		}
	}
	f := model.Finding{
		ID:          "P2S-HUNT-012",
		Title:       "Webshell score",
		Severity:    model.High,
		Category:    "compromise",
		Target:      "/var/www/a.php",
		Detail:      "weighted score 9",
		Evidence:    []string{"eval(", "base64_decode("},
		Remediation: "quarantine the file",
	}
	doc := strings.Join(findingDocument(f), "\n")
	for _, want := range []string{"P2S-HUNT-012", "HIGH", "EVIDENCE", "quarantine the file"} {
		if !strings.Contains(doc, want) {
			t.Errorf("finding document missing %q", want)
		}
	}
}

func sampleReport() *model.Report {
	rep := &model.Report{
		Tool:    "php2shell-audit",
		Version: "test",
		Mode:    "scan",
		Summary: "Inspected 1 PHP target: 1 vulnerable.",
		Targets: []model.Target{
			{Name: "binary:/usr/bin/php8.4", Kind: "binary", Version: "8.4.26", Status: "vulnerable", Findings: 1},
		},
		Findings: []model.Finding{{
			ID:       "P2S-CFG-001",
			Title:    "Finite memory_limit keeps the OOM trigger reachable",
			Severity: model.High,
			Category: "config",
			Target:   "binary:/usr/bin/php8.4",
			Detail:   "memory_limit=128M",
		}},
	}
	rep.Finish()
	return rep
}
