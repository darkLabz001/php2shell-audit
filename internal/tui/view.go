package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

type hint struct {
	key   string
	label string
}

func (a *App) hintLine(hints []hint) string {
	return a.hintLineWithin(hints, 0)
} // hintLineWithin joins as many hints as fit in maxWidth. A zero limit means
// no limit.
func (a *App) hintLineWithin(hints []hint, maxWidth int) string {
	th := a.theme
	parts := make([]string, 0, len(hints))
	width := 0
	for _, h := range hints {
		piece := th.paint("["+h.key+"]", colCyan, ansiBold) + " " + th.paint(h.label, colDim)
		add := displayWidth(piece)
		if len(parts) > 0 {
			add += 3
		}
		if maxWidth > 0 && width+add > maxWidth {
			break
		}
		parts = append(parts, piece)
		width += add
	}
	return strings.Join(parts, "   ")
}

func (a *App) footer(hints []hint, right string) []string {
	th := a.theme
	flashing := a.flash != "" && a.flashUntil.After(time.Now())
	if flashing {
		right = th.paint(a.flash, colYellow, ansiBold)
	} else if right != "" {
		right = th.paint(right, colFaint)
	}
	left := " " + a.hintLine(hints)
	room := a.w - 1

	// Drop the decorative note before crowding the key hints; a flash message
	// is important, so in that case trim the hints instead.
	if right != "" && !flashing && displayWidth(left)+displayWidth(right)+3 > room {
		right = ""
	}
	rw := displayWidth(right)
	if rw > room {
		right = clip(right, room)
		rw = displayWidth(right)
	}
	reserve := 0
	if rw > 0 {
		reserve = rw + 3
	}
	left = " " + a.hintLineWithin(hints, maxInt(1, room-reserve))
	gap := room - displayWidth(left) - rw
	if gap < 1 {
		gap = 1
	}
	line := clip(left+strings.Repeat(" ", gap)+right, a.w)
	return []string{th.rule(a.w), line}
}

// pinFooter pads the body so the footer sits on the last two rows of the
// viewport, keeping the key hints in a stable place across screens.
func (a *App) pinFooter(body, footer []string) []string {
	out := append([]string{}, body...)
	if pad := a.h - len(out) - len(footer); pad > 0 {
		out = append(out, make([]string, pad)...)
	}
	return append(out, footer...)
}

func (a *App) header(left, right string) []string {
	th := a.theme
	inner := a.w - 2
	if inner < 1 {
		inner = 1
	}
	room := a.w - 4
	lw, rw := displayWidth(left), displayWidth(right)
	if lw+rw > room {
		if rw >= room {
			right, rw = "", 0
		}
		left = clip(left, maxInt(0, room-rw-1))
		lw = displayWidth(left)
	}
	gap := room - lw - rw
	if gap < 1 {
		gap = 1
	}
	return []string{
		th.paint("╔"+strings.Repeat("═", inner)+"╗", colMagenta),
		th.paint("║", colMagenta) + " " + left + strings.Repeat(" ", gap) + right + " " + th.paint("║", colMagenta),
		th.paint("╚"+strings.Repeat("═", inner)+"╝", colMagenta),
	}
}

func (a *App) clock() string {
	th := a.theme
	blink := "●"
	if a.tick/6%2 == 0 {
		blink = "○"
	}
	return th.paint(blink, colPink, ansiBold) + " " +
		th.paint(time.Now().UTC().Format("2006-01-02 15:04:05")+" UTC", colDim)
}

func (a *App) panel(title string, body []string, width, height int) []string {
	if width < 8 {
		return nil
	}
	th := a.theme
	inner := width - 4
	top := "┌─[ " + title + " ]"
	fill := width - displayWidth(top) - 1
	if fill < 0 {
		top = clip(top, width-1)
		fill = 0
	}
	out := []string{
		th.paint("┌─[ ", colMagenta) + th.paint(title, colPink, ansiBold) +
			th.paint(" ]", colMagenta) + th.paint(strings.Repeat("─", fill)+"┐", colMagenta),
	}
	if height <= 0 {
		height = len(body) + 2
	}
	rows := height - 2
	for i := 0; i < rows; i++ {
		var line string
		if i < len(body) {
			line = body[i]
		}
		line = padRight(clip(line, inner), inner)
		out = append(out, th.paint("│", colMagenta)+" "+line+" "+th.paint("│", colMagenta))
	}
	out = append(out, th.paint("└"+strings.Repeat("─", width-2)+"┘", colMagenta))
	return out
}

func (a *App) intelBody(width int) []string {
	th := a.theme
	lines := []string{
		th.paint("HOST  ", colDim) + th.paint(a.host, colWhite),
		th.paint("GRID  ", colDim) + th.paint(runtimeLabel(), colFaint),
		"",
		th.paint("▓ CVE-2026-109618", colPink, ansiBold),
		th.paint("  engine RCE · memory disclosure", colDim),
		th.paint("▓ CVE-2026-109619", colPink, ansiBold),
		th.paint("  stale cross-request worker state", colDim),
		"",
		th.paint("FIXED RELEASES", colCyan),
		th.paint("  8.5.12 · 8.4.27 · 8.3.36 · 8.2.35", colWhite),
	}
	if a.last != nil {
		st := a.last.Stats
		lines = append(lines, "",
			th.paint("LAST RUN", colCyan)+"  "+th.paint(strings.ToUpper(a.last.Mode), colWhite)+" · "+
				fmt.Sprintf("%d findings", st.Total),
			fmt.Sprintf("  %s  %s  %s",
				th.severityColour(model.Critical, fmt.Sprintf("%d crit", st.Critical)),
				th.severityColour(model.High, fmt.Sprintf("%d high", st.High)),
				th.severityColour(model.Medium, fmt.Sprintf("%d med", st.Medium))),
		)
	} else {
		lines = append(lines, "",
			th.paint("LAST RUN", colCyan)+"  "+th.paint("no scan yet", colDim))
	}
	barWidth := minInt(18, maxInt(6, width-24))
	lines = append(lines, "",
		th.progressBar(barWidth, a.tick)+" "+th.paint("awaiting operator", colDim))
	return lines
}

func (a *App) compactTitle(glitch bool) string {
	th := a.theme
	title := "▓▒░ PHP2SHELL // NEON GRID ░▒▓"
	if a.w < 46 {
		title = "PHP2SHELL // NEON GRID"
	}
	if glitch {
		return th.glitch(title, a.tick)
	}
	return title
}

func (a *App) splashBanner() []string {
	if a.w >= 94 {
		return a.theme.logoLines()
	}
	th := a.theme
	return []string{th.paint(a.compactTitle(true), colPink, ansiBold)}
}

// --- splash ----------------------------------------------------------------

func (a *App) viewSplash() []string {
	th := a.theme
	elapsed := time.Since(a.started)
	banner := a.splashBanner()

	boot := []string{
		"mount /dev/neon",
		"load advisory CVE-2026-109618 / 619",
		"arm passive probes",
		"calibrate severity matrix",
		"synchronise session keys",
	}
	shown := int(elapsed/(160*time.Millisecond)) + 1
	if shown > len(boot) {
		shown = len(boot)
	}

	content := make([]string, 0, 24)
	for _, line := range banner {
		content = append(content, centerIn(line, a.w))
	}
	content = append(content, "")
	content = append(content, centerIn(th.paint("PHP ENGINE EXPOSURE RESPONSE CONSOLE", colCyan, ansiBold), a.w))
	content = append(content, centerIn(th.paint(versionLabel(a.version)+"  ·  CVE-2026-109618 / CVE-2026-109619", colDim), a.w))
	content = append(content, "")

	for i, b := range boot {
		var line string
		switch {
		case i < shown-1:
			line = th.paint("[ OK ]", colGreen, ansiBold) + " " + th.paint(b, colWhite)
		case i == shown-1:
			line = a.theme.spinner(a.tick) + th.paint(" [ .. ]", colCyan) + " " + th.paint(b, colDim)
		default:
			line = th.paint("[    ]", colFaint) + " " + th.paint(b, colFaint)
		}
		content = append(content, "   "+line)
	}

	barWidth := minInt(46, maxInt(10, a.w-24))
	content = append(content, "")
	content = append(content, "   "+th.progressBar(barWidth, a.tick))
	content = append(content, "")
	content = append(content, centerIn(th.paint("press any key to jack in", colDim)+th.paint("█", colPink), a.w))

	top := maxInt(0, (a.h-len(content))/2)
	out := make([]string, 0, a.h)
	for i := 0; i < top; i++ {
		out = append(out, "")
	}
	out = append(out, content...)
	return out
}

// --- menu ------------------------------------------------------------------

func (a *App) menuRow(index int, selected bool, width int) string {
	th := a.theme
	if width < 12 {
		width = 12
	}
	entry := a.menu[index]
	prefix := "  "
	if selected {
		prefix = "▸ "
	}
	head := fmt.Sprintf("%s%02d  %s", prefix, index+1, entry.label)
	blurb := ""
	room := width - displayWidth(head) - 3
	if room >= 10 {
		blurb = clipEllipsis(entry.blurb, room)
		head += "  " + blurb
	}
	if selected {
		return th.paint(padRight(head, width), colBgSelect, colBlack, ansiBold)
	}
	line := th.paint(prefix, colPink) + th.paint(fmt.Sprintf("%02d", index+1), colDim) +
		"  " + th.paint(entry.label, colWhite)
	if blurb != "" {
		line += "  " + th.paint(blurb, colFaint)
	}
	return padRight(line, width)
}

func (a *App) viewMenu() []string {
	th := a.theme
	left := a.header(
		th.paint("▓▒░ PHP2SHELL", colPink, ansiBold)+th.paint(" // NEON GRID", colCyan),
		a.clock(),
	)

	content := []string{""}
	if a.w >= 94 && a.h >= 30 {
		for _, line := range th.logoLines() {
			content = append(content, centerIn(line, a.w))
		}
		content = append(content, "")
	} else {
		content = append(content, centerIn(th.paint(a.compactTitle(false), colPink, ansiBold), a.w))
	}
	content = append(content,
		centerIn(
			th.paint("PHP ENGINE EXPOSURE RESPONSE CONSOLE", colCyan)+
				th.paint("  ·  ", colFaint)+th.paint("CVE-2026-109618 / 619", colDim)+
				th.paint("  ·  "+versionLabel(a.version), colFaint),
			a.w),
		"")

	// Build the menu body, then decide whether the intel column fits.
	leftW := minInt(52, maxInt(34, a.w*44/100))
	if a.w < 78 {
		leftW = a.w - 4
	}
	menuBody := make([]string, 0, len(a.menu))
	for i := range a.menu {
		menuBody = append(menuBody, a.menuRow(i, i == a.cursor, leftW-4))
	}

	footer := a.footer([]hint{
		{"↑↓", "move"},
		{"enter", "run"},
		{"1-9", "jump"},
		{"?", "help"},
		{"q", "quit"},
	}, "PASSIVE // NO PAYLOADS")

	budget := a.h - len(left) - len(footer) - 1
	if budget-len(content)-1 < len(menuBody)+2 {
		// Small viewport: drop the banner so every operation stays visible.
		content = []string{""}
	}
	panelBudget := budget - len(content) - 1
	if panelBudget < 6 {
		panelBudget = 6
	}

	block := a.panel("OPERATIONS", menuBody, leftW, minInt(len(menuBody)+2, panelBudget))
	if a.w >= 78 {
		rightW := a.w - leftW - 3
		intel := a.intelBody(rightW - 4)
		height := maxInt(len(menuBody), len(intel)) + 2
		if height > panelBudget {
			height = panelBudget
		}
		block = joinColumns(
			a.panel("OPERATIONS", menuBody, leftW, height),
			a.panel("LIVE INTEL", intel, rightW, height),
			2,
		)
	}

	content = append(content, block...)
	content = append(content, "")

	budget = a.h - len(left) - len(footer) - 1
	if budget < 1 {
		budget = 1
	}
	if len(content) > budget {
		content = content[:budget]
	}
	out := append([]string{}, left...)
	out = append(out, content...)
	return a.pinFooter(out, footer)
}

// --- prompt ----------------------------------------------------------------

func (a *App) viewPrompt() []string {
	th := a.theme
	p := a.prompt
	if p == nil {
		return a.viewMenu()
	}
	header := a.header(
		th.paint("▓▒░ INPUT REQUIRED", colPink, ansiBold)+th.paint(" // "+p.title, colCyan),
		a.clock(),
	)

	cursor := "█"
	if a.tick/5%2 == 0 {
		cursor = " "
	}
	body := []string{
		th.paint(strings.ToUpper(p.label), colCyan, ansiBold),
		"",
		th.paint("> ", colPink) + th.paint(p.value, colWhite) + th.paint(cursor, colPink),
		"",
		th.paint(p.hint, colFaint),
	}
	if p.err != "" {
		body = append(body, "", th.paint("✖ "+p.err, colRed, ansiBold))
	}
	body = append(body, "", th.paint("[enter] execute   [esc] abort", colDim))

	width := minInt(72, a.w-6)
	box := a.panel(p.title, body, width, 0)
	top := maxInt(1, (a.h-len(box)-len(header))/4)

	out := append([]string{}, header...)
	out = append(out, make([]string, top)...)
	left := maxInt(0, (a.w-width)/2)
	for _, line := range box {
		out = append(out, strings.Repeat(" ", left)+line)
	}
	footer := a.footer([]hint{
		{"enter", "execute"},
		{"esc", "abort"},
		{"ctrl-u", "clear"},
	}, "OPERATOR INPUT")
	return a.pinFooter(out, footer)
}

// --- running ---------------------------------------------------------------

func (a *App) viewRunning() []string {
	th := a.theme
	j := a.job
	if j == nil {
		return a.viewMenu()
	}
	elapsed := time.Since(j.started)
	if j.started.IsZero() {
		elapsed = 0
	}
	header := a.header(
		th.paint("▓▒░ EXECUTING", colPink, ansiBold)+th.paint(" // "+j.job.label, colCyan),
		th.spinner(a.tick)+" "+th.paint(elapsed.Round(time.Second).String(), colDim),
	)

	barWidth := minInt(58, maxInt(12, a.w-16))
	phase := int(elapsed / (900 * time.Millisecond))
	if phase >= len(j.job.phases) {
		phase = len(j.job.phases) - 1
	}

	content := []string{
		"",
		"  " + th.spinner(a.tick) + " " + th.paint(j.job.label, colPink, ansiBold),
		"    " + th.paint(j.job.verb, colDim),
		"",
		"    " + th.progressBar(barWidth, a.tick),
		"    " + th.paint("elapsed "+elapsed.Round(time.Second).String(), colDim) +
			th.paint("   ·   esc abort", colFaint),
		"",
		"  " + th.paint("PHASE TRACE", colCyan, ansiBold),
	}
	for i, p := range j.job.phases {
		switch {
		case i < phase:
			content = append(content, "    "+th.paint("✓ ", colGreen, ansiBold)+th.paint(p, colDim))
		case i == phase:
			content = append(content, "    "+th.paint("▸ ", colPink, ansiBold)+th.paint(p, colWhite, ansiBold))
		default:
			content = append(content, "    "+th.paint("· ", colFaint)+th.paint(p, colFaint))
		}
	}
	content = append(content, "",
		"  "+th.paint("PASSIVE CHECKS ONLY // NO PAYLOADS SENT", colFaint))

	out := append([]string{}, header...)
	out = append(out, content...)
	footer := a.footer([]hint{
		{"esc", "abort"},
		{"q", "quit"},
	}, "SCANNING")
	return a.pinFooter(out, footer)
}

// --- results ---------------------------------------------------------------

func (r *resultsState) tabCount() int {
	if r.report == nil {
		return 1
	}
	n := 1
	if len(r.report.Targets) > 0 {
		n++
	}
	if r.report.Summary != "" || len(r.report.Notes) > 0 || len(r.report.Warnings) > 0 {
		n++
	}
	return n
}

// tabKind maps a tab index to its content. Targets are only present when the
// report actually contains a target inventory; otherwise notes take its place.
func (r *resultsState) tabKind(i int) string {
	if i == 0 || r.report == nil {
		return "findings"
	}
	if len(r.report.Targets) > 0 && i == 1 {
		return "targets"
	}
	return "notes"
}

func (r *resultsState) tabNames() []string {
	if r.report == nil {
		return []string{"ERROR"}
	}
	names := []string{fmt.Sprintf("FINDINGS %d", len(r.report.Findings))}
	if len(r.report.Targets) > 0 {
		names = append(names, fmt.Sprintf("TARGETS %d", len(r.report.Targets)))
	}
	if r.tabCount() > len(names) {
		names = append(names, "NOTES")
	}
	return names
}

func (a *App) resultsListHeight() int {
	// header(3) + blank + summary + tabs + blank + panel borders + blank +
	// footer(2) leaves this many content rows.
	h := a.h - 12
	if h < 3 {
		h = 3
	}
	return h
}

func (a *App) summaryLine(r *model.Report) string {
	th := a.theme
	st := r.Stats
	parts := []string{
		th.severityColour(model.Critical, fmt.Sprintf("%d CRIT", st.Critical)),
		th.severityColour(model.High, fmt.Sprintf("%d HIGH", st.High)),
		th.severityColour(model.Medium, fmt.Sprintf("%d MED", st.Medium)),
		th.severityColour(model.Low, fmt.Sprintf("%d LOW", st.Low)),
		th.paint(fmt.Sprintf("%d INFO", st.Info), colDim),
	}
	return th.paint("SUMMARY ", colCyan, ansiBold) + strings.Join(parts, th.paint("  ·  ", colFaint)) +
		th.paint(fmt.Sprintf("   (%d total)", st.Total), colFaint)
}

func (a *App) tabsLine(r *resultsState) string {
	th := a.theme
	names := r.tabNames()
	parts := make([]string, 0, len(names))
	for i, name := range names {
		if i == r.tab {
			parts = append(parts, th.paint(" "+name+" ", colBgSelect, colBlack, ansiBold))
		} else {
			parts = append(parts, th.paint(" "+name+" ", colDim))
		}
	}
	return " " + strings.Join(parts, th.paint("│", colFaint))
}

func (a *App) viewResults() []string {
	th := a.theme
	r := a.results
	if r == nil {
		return a.viewMenu()
	}
	if r.err != nil {
		return a.viewError(r.err)
	}
	header := a.header(
		th.paint("▓▒░ RESULT", colPink, ansiBold)+th.paint(" // "+strings.ToUpper(r.report.Mode), colCyan),
		a.clock(),
	)
	out := append([]string{}, header...)
	out = append(out, "", " "+a.summaryLine(r.report), a.tabsLine(r), "")

	var block []string
	switch r.tabKind(r.tab) {
	case "findings":
		block = a.resultsFindings(r)
	case "targets":
		block = a.resultsTargets(r)
	default:
		block = a.resultsNotes(r)
	}
	out = append(out, block...)
	hints := []hint{
		{"tab", "switch"},
		{"e", "export"},
		{"esc", "menu"},
		{"q", "quit"},
	}
	if r.tab == 0 && len(r.report.Findings) > 0 {
		hints = append([]hint{{"↑↓", "move"}, {"enter", "open"}}, hints...)
	}
	footer := a.footer(hints, "PASSIVE // NO PAYLOADS")
	return a.pinFooter(out, footer)
}

func (a *App) resultsFindings(r *resultsState) []string {
	th := a.theme
	if len(r.report.Findings) == 0 {
		body := []string{
			"",
			"  " + th.green("No findings in this run."),
			"",
			"  " + th.paint(r.report.Summary, colDim),
			"",
			"  " + th.paint("Absence of signals is not proof of safety.", colFaint),
		}
		return a.panel("FINDINGS", body, a.w-2, a.resultsListHeight()+2)
	}

	split := a.w >= 78
	leftW := a.w - 2
	if split {
		leftW = minInt(58, maxInt(40, a.w*45/100))
	}
	inner := leftW - 4
	visible := a.resultsListHeight()
	if visible < 1 {
		visible = 1
	}
	if r.offset > len(r.report.Findings)-1 {
		r.offset = maxInt(0, len(r.report.Findings)-1)
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

	body := make([]string, 0, visible)
	for i := r.offset; i < len(r.report.Findings) && len(body) < visible; i++ {
		f := r.report.Findings[i]
		tag := th.severityTag(f.Severity)
		titleRoom := inner - displayWidth(tag) - 3
		title := clipEllipsis(sanitize(f.Title), maxInt(4, titleRoom))
		var row string
		if i == r.cursor {
			// Keep the highlight continuous on both sides of the severity chip.
			row = th.paint("▸ ", colBgRow, colPink, ansiBold) +
				tag +
				th.paint(" "+padRight(title, maxInt(1, inner-9)), colBgRow, colWhite)
		} else {
			row = "  " + tag + " " + th.paint(padRight(title, maxInt(1, inner-9)), colWhite)
		}
		body = append(body, row)
	}
	list := a.panel("FINDINGS", body, leftW, visible+2)
	if !split {
		return list
	}

	rightW := a.w - leftW - 3
	dossier := a.findingPreview(r.report.Findings[r.cursor], rightW-4, visible)
	return joinColumns(list, a.panel("DOSSIER", dossier, rightW, visible+2), 2)
}

func (a *App) findingPreview(f model.Finding, width, height int) []string {
	th := a.theme
	lines := []string{
		th.paint(strings.ToUpper(sanitize(clip(f.Title, width))), colWhite, ansiBold),
		"",
	}
	add := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		lines = append(lines, th.paint(fmt.Sprintf("%-10s", label), colDim)+" "+th.paint(clip(sanitize(value), width-11), colWhite))
	}
	add("ID", firstNonEmpty(f.ID, "-"))
	add("CATEGORY", f.Category)
	add("TARGET", f.Target)
	add("SURFACE", f.Surface)
	add("CONFIDENCE", f.Confidence)
	if f.Count > 0 {
		add("EVENTS", fmt.Sprintf("%d", f.Count))
	}
	if f.Status != "" {
		add("STATUS", f.Status)
	}
	if f.FirstSeen != nil || f.LastSeen != nil {
		add("WINDOW", stamp(f.FirstSeen)+" .. "+stamp(f.LastSeen))
	}
	if f.Detail != "" {
		lines = append(lines, "")
		for _, line := range wrap(sanitize(f.Detail), width) {
			lines = append(lines, th.paint(line, colDim))
		}
	}
	if len(f.Evidence) > 0 {
		lines = append(lines, "", th.paint("EVIDENCE", colCyan))
		for _, e := range f.Evidence {
			for _, line := range wrap("• "+sanitize(e), width) {
				lines = append(lines, th.paint(line, colWhite))
			}
		}
	}
	if f.Remediation != "" && len(lines)+3 < height {
		lines = append(lines, "", th.paint("NEXT", colCyan))
		for _, line := range wrap(sanitize(f.Remediation), width) {
			lines = append(lines, th.paint(line, colGreen))
		}
	}
	lines = append(lines, "", th.paint("[enter] full dossier", colFaint))
	if height > 0 && len(lines) > height {
		lines = lines[:height]
	}
	return lines
}

func (a *App) resultsTargets(r *resultsState) []string {
	th := a.theme
	inner := a.w - 6
	const fixedCols = 9 + 6 + 10 + 10 + 5
	nameW := inner - fixedCols - 5
	if nameW < 12 {
		nameW = 12
	}
	head := padRight(th.paint("NAME", colCyan), nameW) + " " +
		padRight(th.paint("KIND", colCyan), 9) + " " +
		padRight(th.paint("SAPI", colCyan), 6) + " " +
		padRight(th.paint("VERSION", colCyan), 10) + " " +
		padRight(th.paint("STATUS", colCyan), 10) + " " +
		rightAlign(th.paint("FIND", colCyan), 4)
	body := []string{head, th.rule(inner)}
	for _, t := range r.report.Targets {
		row := padRight(th.paint(clipEllipsis(sanitize(t.Name), nameW), colWhite), nameW) + " " +
			padRight(th.paint(clip(orDash(t.Kind), 9), colDim), 9) + " " +
			padRight(th.paint(clip(orDash(t.SAPI), 6), colDim), 6) + " " +
			padRight(th.paint(clip(orDash(t.Version), 10), colWhite), 10) + " " +
			padRight(th.statusColour(t.Status), 10) + " " +
			rightAlign(th.paint(fmt.Sprintf("%d", t.Findings), colDim), 4)
		body = append(body, row)
		if len(body) > a.resultsListHeight()+2 {
			break
		}
	}
	return a.panel("TARGET INVENTORY", body, a.w-2, a.resultsListHeight()+2)
}

func (a *App) resultsNotes(r *resultsState) []string {
	th := a.theme
	body := []string{}
	if r.report.Summary != "" {
		for _, line := range wrap(r.report.Summary, a.w-8) {
			body = append(body, th.paint(line, colWhite))
		}
	}
	if len(r.report.Notes) > 0 {
		body = append(body, "", th.paint("NOTES", colCyan, ansiBold))
		for _, note := range r.report.Notes {
			for _, line := range wrap("• "+sanitize(note), a.w-8) {
				body = append(body, th.paint(line, colDim))
			}
		}
	}
	if len(r.report.Warnings) > 0 {
		body = append(body, "", th.paint("WARNINGS", colOrange, ansiBold))
		for _, warn := range r.report.Warnings {
			for _, line := range wrap("! "+sanitize(warn), a.w-8) {
				body = append(body, th.paint(line, colOrange))
			}
		}
	}
	if len(body) == 0 {
		body = []string{th.paint("Nothing to report.", colDim)}
	}
	return a.panel("NOTES", body, a.w-2, a.resultsListHeight()+2)
}

func (a *App) viewError(err error) []string {
	th := a.theme
	header := a.header(
		th.paint("▓▒░ OPERATION FAILED", colRed, ansiBold),
		a.clock(),
	)
	body := []string{
		"",
		th.paint("The operation could not complete.", colWhite, ansiBold),
		"",
	}
	for _, line := range wrap(sanitize(err.Error()), a.w-14) {
		body = append(body, th.paint(line, colRed))
	}
	body = append(body, "", th.paint("Check the path, permissions or target and try again.", colDim))

	width := minInt(76, a.w-6)
	box := a.panel("ERROR", body, width, 0)
	out := append([]string{}, header...)
	out = append(out, "")
	out = append(out, centerBlock(box, a.w)...)
	footer := a.footer([]hint{{"esc", "menu"}, {"q", "quit"}}, "FAULT")
	return a.pinFooter(out, footer)
}

// --- viewer ----------------------------------------------------------------

func (a *App) viewViewer() []string {
	th := a.theme
	v := a.viewer
	if v == nil {
		return a.viewMenu()
	}
	header := a.header(
		th.paint("▓▒░ "+clip(v.title, a.w-30), colPink, ansiBold),
		a.clock(),
	)
	inner := maxInt(10, a.w-6)
	var rendered []string
	for _, line := range v.body {
		if v.wrap {
			rendered = append(rendered, wrap(line, inner)...)
		} else {
			rendered = append(rendered, sanitize(line))
		}
	}
	visible := a.h - len(header) - 3 - 2
	if visible < 3 {
		visible = 3
	}
	maxOffset := maxInt(0, len(rendered)-visible)
	if v.offset > maxOffset {
		v.offset = maxOffset
	}
	if v.offset < 0 {
		v.offset = 0
	}

	out := append([]string{}, header...)
	out = append(out, "")
	for i := v.offset; i < len(rendered) && i < v.offset+visible; i++ {
		line := rendered[i]
		if !v.wrap {
			out = append(out, "   "+th.paint(clip(line, inner), colDim))
			continue
		}
		switch {
		case i == 0:
			out = append(out, "   "+th.paint(line, colWhite, ansiBold))
		case strings.HasPrefix(line, "──"):
			out = append(out, "   "+th.paint(line, colFaint))
		case strings.HasPrefix(line, "  • ") || strings.HasPrefix(line, "  "):
			out = append(out, "   "+th.paint(line, colWhite))
		case isDocHeading(line):
			out = append(out, "   "+th.paint(line, colCyan, ansiBold))
		default:
			if label, value, ok := splitDocLine(line); ok {
				out = append(out, "   "+th.paint(label, colDim)+"  "+th.paint(value, colWhite))
				continue
			}
			out = append(out, "   "+th.paint(line, colDim))
		}
	}
	out = append(out, "")
	pct := 0
	if len(rendered) > 0 {
		pct = (v.offset + visible) * 100 / len(rendered)
		if pct > 100 {
			pct = 100
		}
	}
	hints := []hint{{"↑↓", "scroll"}, {"space", "page"}, {"esc", "back"}}
	if v.export != nil {
		hints = append(hints, hint{"e", "export"})
	}
	hints = append(hints, hint{"q", "quit"})
	footer := a.footer(hints, fmt.Sprintf("%d%%  ·  %d lines", pct, len(rendered)))
	return a.pinFooter(out, footer)
}

func centerBlock(lines []string, width int) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, centerIn(line, width))
	}
	return out
}

func rightAlign(s string, width int) string {
	n := width - displayWidth(s)
	if n <= 0 {
		return s
	}
	return strings.Repeat(" ", n) + s
}

// splitDocLine recognises "LABEL  value" rows in the manual and dossiers so
// the label and value can be coloured separately.
func splitDocLine(line string) (label, value string, ok bool) {
	if len(line) < 4 || line[0] == ' ' {
		return "", "", false
	}
	idx := strings.Index(line, "  ")
	if idx <= 0 || idx > 16 {
		return "", "", false
	}
	label = strings.TrimRight(line[:idx], " ")
	value = strings.TrimLeft(line[idx:], " ")
	if value == "" || strings.ContainsAny(label, "•") {
		return "", "", false
	}
	return label, value, true
}

// isDocHeading reports whether a line looks like an all-caps section title.
func isDocHeading(line string) bool {
	if len(line) < 4 || len(line) > 64 || strings.Contains(line, "  ") {
		return false
	}
	letters := 0
	for _, r := range line {
		switch {
		case r >= 'A' && r <= 'Z':
			letters++
		case r >= 'a' && r <= 'z':
			return false
		}
	}
	return letters > 2
}
