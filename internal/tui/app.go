// Package tui implements the interactive, cyberpunk-themed console for
// php2shell-audit. It uses only the standard library and raw ANSI escapes so
// the binary keeps its zero-dependency footprint.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/output"
)

// screen identifies the active view.
type screen int

const (
	screenSplash screen = iota
	screenMenu
	screenPrompt
	screenRunning
	screenResults
	screenViewer
)

// Config configures a TUI run. Width and Height are test hooks; when they are
// zero the real terminal size is used.
type Config struct {
	Version string
	In      io.Reader
	Out     io.Writer
	Width   int
	Height  int
}

// menuEntry is one operation in the main menu.
type menuEntry struct {
	label string
	blurb string
	run   func(*App)
}

// promptState is a single-line modal input.
type promptState struct {
	title  string
	label  string
	hint   string
	value  string
	err    string
	submit func(string) error
}

// jobState tracks a background operation.
type jobState struct {
	job     *job
	started time.Time
	cancel  context.CancelFunc
}

// jobResult is delivered when a background operation finishes.
type jobResult struct {
	report *model.Report
	text   string
	err    error
	export func(*App) (string, error)
}

// resultsState is the report browser.
type resultsState struct {
	report *model.Report
	err    error
	tab    int
	cursor int
	offset int
}

// viewerState is a scrollable document (finding detail, rules or help).
type viewerState struct {
	title  string
	body   []string
	wrap   bool
	offset int
	back   screen
	export func(*App) (string, error)
}

// App owns all interactive state.
type App struct {
	version string
	theme   theme
	inFile  *os.File
	out     io.Writer
	w, h    int
	fixed   bool

	screen  screen
	menu    []menuEntry
	cursor  int
	prompt  *promptState
	job     *jobState
	jobCh   chan jobResult
	results *resultsState
	viewer  *viewerState
	last    *model.Report

	tick        int
	started     time.Time
	splashUntil time.Time
	lastSecond  int
	quit        bool

	flash      string
	flashUntil time.Time

	host string
}

// IsTerminal reports whether f is attached to a terminal. It deliberately
// does not require the window size to be known: some pty wrappers report 0x0.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return isTTY(f)
}

// Run starts the interactive console and blocks until the operator exits.
func Run(cfg Config) error {
	if cfg.In == nil {
		cfg.In = os.Stdin
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	inFile, ok := cfg.In.(*os.File)
	if !ok {
		return errors.New("tui: stdin is not a terminal")
	}
	if outFile, ok := cfg.Out.(*os.File); ok && !IsTerminal(outFile) {
		return errors.New("tui: stdout is not a terminal; use scan, hunt or rules for non-interactive runs")
	}
	state, err := makeRaw(inFile)
	if err != nil {
		return fmt.Errorf("tui: this console needs an interactive terminal: %w", err)
	}
	defer restoreRaw(inFile, state)

	if cfg.Width <= 0 || cfg.Height <= 0 {
		if w, h, ok := terminalSize(inFile); ok {
			cfg.Width, cfg.Height = w, h
		} else {
			cfg.Width, cfg.Height = 100, 32
		}
	}

	a := newApp(cfg)
	a.inFile = inFile
	a.fixed = false

	fmt.Fprint(a.out, "\x1b]0;PHP2SHELL // NEON GRID\x07")
	fmt.Fprint(a.out, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")
	defer func() {
		fmt.Fprint(a.out, ansiReset+"\x1b[?25h\x1b[?1049l")
	}()

	keys := make(chan key, 32)
	go func() {
		kr := newKeyReader(inFile, inFile.SetReadDeadline)
		for {
			k, err := kr.read()
			if err != nil {
				close(keys)
				return
			}
			keys <- k
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(90 * time.Millisecond)
	defer ticker.Stop()

	a.draw()
	for !a.quit {
		select {
		case k, ok := <-keys:
			if !ok {
				a.quit = true
				break
			}
			a.handle(k)
			a.draw()
		case <-sigCh:
			a.quit = true
		case res := <-a.jobCh:
			a.completeJob(res)
			a.draw()
		case <-ticker.C:
			prev := a.lastSecond
			a.lastSecond = time.Now().Second()
			a.tick++
			prevW, prevH := a.w, a.h
			a.size()
			if a.screen == screenSplash && time.Now().After(a.splashUntil) {
				a.screen = screenMenu
			}
			if a.animate() || prev != a.lastSecond || prevW != a.w || prevH != a.h {
				a.draw()
			}
		}
	}
	return nil
}

func newApp(cfg Config) *App {
	th := theme{enabled: colorEnabled()}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "operator"
	}
	a := &App{
		version: sanitize(cfg.Version),
		theme:   th,
		out:     cfg.Out,
		w:       cfg.Width,
		h:       cfg.Height,
		fixed:   cfg.Width > 0 && cfg.Height > 0,
		screen:  screenSplash,
		host:    sanitize(user + "@" + host),
	}
	a.started = time.Now()
	a.splashUntil = a.started.Add(1200 * time.Millisecond)
	a.lastSecond = a.started.Second()
	a.menu = []menuEntry{
		{"LOCAL INVENTORY", "audit this host", (*App).menuLocal},
		{"REMOTE PROBE", "passive endpoint check", (*App).menuRemote},
		{"CONTAINER SWEEP", "running containers", (*App).menuDocker},
		{"LOG HUNT", "access / error / JSON logs", (*App).menuLogs},
		{"LIVE RESPONSE", "processes · sockets · cron", (*App).menuLive},
		{"WEBSHELL SWEEP", "score web root files", (*App).menuWebRoot},
		{"SIGNATURE FORGE", "Sigma / YARA / nginx content", (*App).menuRules},
		{"INTEL / MANUAL", "advisory + controls", (*App).menuHelp},
		{"JACK OUT", "leave the grid", func(app *App) { app.quit = true }},
	}
	return a
}

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := os.Getenv("TERM")
	return term != "" && term != "dumb"
}

// --- input dispatch --------------------------------------------------------

func (a *App) handle(k key) {
	if k.kind == keyCtrlC {
		a.quit = true
		return
	}
	switch a.screen {
	case screenSplash:
		if k.kind == keyRune && (k.r == 'q' || k.r == 'Q') {
			a.quit = true
			return
		}
		a.screen = screenMenu
	case screenMenu:
		a.handleMenu(k)
	case screenPrompt:
		a.handlePrompt(k)
	case screenRunning:
		a.handleRunning(k)
	case screenResults:
		a.handleResults(k)
	case screenViewer:
		a.handleViewer(k)
	}
}

func (a *App) handleMenu(k key) {
	switch k.kind {
	case keyUp:
		a.moveCursor(-1)
	case keyDown:
		a.moveCursor(1)
	case keyHome:
		a.cursor = 0
	case keyEnd:
		a.cursor = len(a.menu) - 1
	case keyEnter:
		if a.cursor >= 0 && a.cursor < len(a.menu) {
			a.menu[a.cursor].run(a)
		}
	case keyRune:
		switch k.r {
		case 'k', 'K':
			a.moveCursor(-1)
		case 'j', 'J':
			a.moveCursor(1)
		case 'q', 'Q':
			a.quit = true
		case '?', 'h', 'H':
			a.menuHelp()
		default:
			if k.r >= '1' && k.r <= '9' {
				idx := int(k.r - '1')
				if idx < len(a.menu) {
					a.cursor = idx
					a.menu[idx].run(a)
				}
			}
		}
	}
}

func (a *App) moveCursor(delta int) {
	if len(a.menu) == 0 {
		return
	}
	a.cursor = (a.cursor + delta + len(a.menu)) % len(a.menu)
}

func (a *App) handlePrompt(k key) {
	if a.prompt == nil {
		a.screen = screenMenu
		return
	}
	switch k.kind {
	case keyEsc:
		a.prompt = nil
		a.screen = screenMenu
	case keyEnter:
		if strings.TrimSpace(a.prompt.value) == "" {
			a.prompt.err = "value required"
			return
		}
		if err := a.prompt.submit(strings.TrimSpace(a.prompt.value)); err != nil {
			a.prompt.err = err.Error()
		}
	case keyBackspace:
		runes := []rune(a.prompt.value)
		if len(runes) > 0 {
			a.prompt.value = string(runes[:len(runes)-1])
		}
		a.prompt.err = ""
	case keyCtrlU:
		a.prompt.value = ""
		a.prompt.err = ""
	case keyRune:
		if len(a.prompt.value) < 512 && k.r >= 32 {
			a.prompt.value += string(k.r)
			a.prompt.err = ""
		}
	}
}

func (a *App) handleRunning(k key) {
	switch k.kind {
	case keyEsc:
		if a.job != nil {
			a.job.cancel()
			a.job = nil
		}
		a.jobCh = nil
		a.screen = screenMenu
		a.flashFor("operation aborted", 2*time.Second)
	case keyRune:
		if k.r == 'q' || k.r == 'Q' {
			a.quit = true
		}
	}
}

func (a *App) handleResults(k key) {
	r := a.results
	if r == nil {
		a.screen = screenMenu
		return
	}
	tabs := r.tabCount()
	switch k.kind {
	case keyEsc:
		a.screen = screenMenu
	case keyTab, keyRight:
		r.tab = (r.tab + 1) % tabs
	case keyLeft:
		r.tab = (r.tab - 1 + tabs) % tabs
	case keyUp:
		a.resultsMove(-1)
	case keyDown:
		a.resultsMove(1)
	case keyHome:
		r.cursor, r.offset = 0, 0
	case keyEnd:
		if r.report != nil {
			r.cursor = len(r.report.Findings) - 1
			r.offset = maxInt(0, r.cursor-3)
		}
	case keyPageUp:
		a.resultsMove(-8)
	case keyPageDown:
		a.resultsMove(8)
	case keyEnter:
		a.openFinding()
	case keyRune:
		switch k.r {
		case 'j', 'J':
			a.resultsMove(1)
		case 'k', 'K':
			a.resultsMove(-1)
		case 'e', 'E':
			a.exportCurrent()
		case 'q', 'Q':
			a.quit = true
		case '?', 'h', 'H':
			a.resultsHelp()
		case 'l', 'L':
			r.tab = (r.tab + 1) % tabs
		case 't', 'T':
			if tabs > 1 {
				r.tab = 1
			}
		}
	}
}

func (a *App) resultsMove(delta int) {
	r := a.results
	if r == nil || r.report == nil || r.tab != 0 {
		return
	}
	n := len(r.report.Findings)
	if n == 0 {
		return
	}
	r.cursor += delta
	if r.cursor < 0 {
		r.cursor = 0
	}
	if r.cursor >= n {
		r.cursor = n - 1
	}
	visible := a.resultsListHeight()
	if visible < 3 {
		visible = 3
	}
	if r.cursor < r.offset {
		r.offset = r.cursor
	}
	if r.cursor >= r.offset+visible {
		r.offset = r.cursor - visible + 1
	}
	if r.offset < 0 {
		r.offset = 0
	}
}

func (a *App) openFinding() {
	r := a.results
	if r == nil || r.report == nil || r.tab != 0 || len(r.report.Findings) == 0 {
		return
	}
	if r.cursor < 0 || r.cursor >= len(r.report.Findings) {
		return
	}
	f := r.report.Findings[r.cursor]
	a.viewer = &viewerState{
		title: "FINDING // " + firstNonEmpty(f.ID, "UNCLASSIFIED"),
		body:  findingDocument(f),
		wrap:  true,
		back:  screenResults,
	}
	a.screen = screenViewer
}

func (a *App) handleViewer(k key) {
	v := a.viewer
	if v == nil {
		a.screen = screenMenu
		return
	}
	page := maxInt(3, a.h-8)
	switch k.kind {
	case keyEsc, keyBackspace:
		a.closeViewer()
	case keyUp:
		v.offset = maxInt(0, v.offset-1)
	case keyDown:
		v.offset++
	case keyPageUp:
		v.offset = maxInt(0, v.offset-page)
	case keyPageDown:
		v.offset += page
	case keyHome:
		v.offset = 0
	case keyEnd:
		v.offset = 1 << 30
	case keyRune:
		switch k.r {
		case 'j', 'J':
			v.offset++
		case 'k', 'K':
			v.offset = maxInt(0, v.offset-1)
		case 'g':
			v.offset = 0
		case 'G':
			v.offset = 1 << 30
		case ' ':
			v.offset += page
		case 'b', 'B':
			v.offset = maxInt(0, v.offset-page)
		case 'e', 'E':
			if v.export != nil {
				a.runExport(v.export)
			}
		case 'q', 'Q':
			a.quit = true
		}
	}
}

func (a *App) closeViewer() {
	back := screenMenu
	if a.viewer != nil {
		back = a.viewer.back
	}
	a.viewer = nil
	a.screen = back
}

func (a *App) resultsHelp() {
	a.viewer = &viewerState{
		title: "MANUAL // KEYBINDS AND ADVISORY",
		body:  helpDocument(a.version, a.host),
		wrap:  true,
		back:  screenResults,
	}
	a.screen = screenViewer
}

// --- jobs ------------------------------------------------------------------

func (a *App) startJob(j *job) {
	if j == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.job = &jobState{job: j, started: time.Now(), cancel: cancel}
	ch := make(chan jobResult, 1)
	a.jobCh = ch
	a.screen = screenRunning
	go func() {
		report, text, err := j.fn(ctx)
		ch <- jobResult{report: report, text: text, err: err, export: j.export}
	}()
}

func (a *App) completeJob(res jobResult) {
	if a.screen != screenRunning || a.job == nil {
		return
	}
	current := a.job
	a.job = nil
	a.jobCh = nil

	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			a.screen = screenMenu
			return
		}
		a.results = &resultsState{err: res.err}
		a.screen = screenResults
		return
	}
	if res.report != nil {
		res.report.Finish()
		a.last = res.report
		a.results = &resultsState{report: res.report}
		a.screen = screenResults
		return
	}
	a.viewer = &viewerState{
		title:  current.job.label,
		body:   strings.Split(strings.TrimRight(res.text, "\n"), "\n"),
		wrap:   current.job.wrap,
		back:   screenMenu,
		export: res.export,
	}
	a.screen = screenViewer
}

// --- export ----------------------------------------------------------------

func (a *App) exportCurrent() {
	r := a.results
	if r == nil || r.report == nil {
		return
	}
	a.runExport(func(app *App) (string, error) { return app.exportReport(r.report) })
}

func (a *App) runExport(fn func(*App) (string, error)) {
	msg, err := fn(a)
	if err != nil {
		a.flashFor("EXPORT FAILED: "+err.Error(), 5*time.Second)
		return
	}
	a.flashFor(msg, 5*time.Second)
}

func (a *App) exportReport(r *model.Report) (string, error) {
	if err := os.MkdirAll("out", 0o755); err != nil {
		return "", err
	}
	mode := strings.ToLower(firstNonEmpty(r.Mode, "report"))
	path := fmt.Sprintf("out/tui-%s-%s.json", mode, time.Now().Format("20060102-150405"))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	if err := output.Write(f, r, output.FormatJSON, false); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return "SAVED " + path, nil
}

func (a *App) flashFor(msg string, d time.Duration) {
	a.flash = msg
	a.flashUntil = time.Now().Add(d)
}

func (a *App) animate() bool {
	if a.flashUntil.After(time.Now()) {
		return true
	}
	return a.screen == screenSplash || a.screen == screenRunning
}

// --- rendering loop --------------------------------------------------------

func (a *App) size() (int, int) {
	if !a.fixed && a.inFile != nil {
		if w, h, ok := terminalSize(a.inFile); ok {
			if w != a.w || h != a.h {
				a.w, a.h = w, h
				fmt.Fprint(a.out, "\x1b[2J")
			}
		}
	}
	if a.w < 20 {
		a.w = 20
	}
	if a.h < 8 {
		a.h = 8
	}
	return a.w, a.h
}

func (a *App) draw() {
	a.size()
	var lines []string
	switch a.screen {
	case screenSplash:
		lines = a.viewSplash()
	case screenMenu:
		lines = a.viewMenu()
	case screenPrompt:
		lines = a.viewPrompt()
	case screenRunning:
		lines = a.viewRunning()
	case screenResults:
		lines = a.viewResults()
	case screenViewer:
		lines = a.viewViewer()
	}
	a.emit(lines)
}

func (a *App) emit(lines []string) {
	var b strings.Builder
	bg := ""
	if a.theme.enabled {
		bg = colBg
	}
	b.WriteString("\x1b[H")
	b.WriteString(bg)
	limit := a.h
	for i := 0; i < limit; i++ {
		var line string
		if i < len(lines) {
			line = clip(lines[i], a.w)
		}
		b.WriteString(line)
		if n := a.w - displayWidth(line); n > 0 {
			b.WriteString(strings.Repeat(" ", n))
		}
		b.WriteString(ansiReset)
		b.WriteString(bg)
		if i < limit-1 {
			b.WriteString("\r\n")
		}
	}
	fmt.Fprint(a.out, b.String())
}

// --- small helpers ---------------------------------------------------------

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runtimeLabel() string {
	return runtime.GOOS + "/" + runtime.GOARCH + " · " + runtime.Version()
}
