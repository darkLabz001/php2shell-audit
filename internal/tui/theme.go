package tui

import (
	"fmt"
	"strings"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

// ANSI building blocks. The palette is deliberately 256-colour rather than
// truecolour so the theme survives a plain SSH session or a 16-colour profile.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRev   = "\x1b[7m"
)

const (
	colBg       = "\x1b[48;5;232m"
	colBgPanel  = "\x1b[48;5;234m"
	colBgRow    = "\x1b[48;5;237m"
	colBgSelect = "\x1b[48;5;198m"
	colBgCrit   = "\x1b[48;5;160m"
	colBgHigh   = "\x1b[48;5;202m"
	colBgMed    = "\x1b[48;5;178m"
	colBgLow    = "\x1b[48;5;31m"
	colBgInfo   = "\x1b[48;5;240m"

	colFg      = "\x1b[38;5;252m"
	colWhite   = "\x1b[38;5;231m"
	colBlack   = "\x1b[38;5;16m"
	colDim     = "\x1b[38;5;243m"
	colFaint   = "\x1b[38;5;238m"
	colPink    = "\x1b[38;5;213m"
	colMagenta = "\x1b[38;5;198m"
	colPurple  = "\x1b[38;5;99m"
	colCyan    = "\x1b[38;5;51m"
	colTeal    = "\x1b[38;5;44m"
	colYellow  = "\x1b[38;5;226m"
	colOrange  = "\x1b[38;5;214m"
	colRed     = "\x1b[38;5;203m"
	colGreen   = "\x1b[38;5;48m"
)

// theme centralises styling so --no-color or a dumb terminal can switch every
// call to plain text without touching the layout code.
type theme struct {
	enabled bool
}

func (t theme) paint(s string, codes ...string) string {
	if !t.enabled || s == "" || len(codes) == 0 {
		return s
	}
	return strings.Join(codes, "") + s + ansiReset
}

func (t theme) bold(s string) string    { return t.paint(s, ansiBold) }
func (t theme) dim(s string) string     { return t.paint(s, colDim) }
func (t theme) faint(s string) string   { return t.paint(s, colFaint) }
func (t theme) cyan(s string) string    { return t.paint(s, colCyan) }
func (t theme) pink(s string) string    { return t.paint(s, colPink) }
func (t theme) magenta(s string) string { return t.paint(s, colMagenta) }
func (t theme) yellow(s string) string  { return t.paint(s, colYellow) }
func (t theme) red(s string) string     { return t.paint(s, colRed) }
func (t theme) green(s string) string   { return t.paint(s, colGreen) }

// severityTag renders a fixed-width chip used in lists and headers.
func (t theme) severityTag(s model.Severity) string {
	bg, fg, label := colBgInfo, colWhite, "INFO"
	switch s {
	case model.Critical:
		bg, fg, label = colBgCrit, colWhite, "CRIT"
	case model.High:
		bg, fg, label = colBgHigh, colBlack, "HIGH"
	case model.Medium:
		bg, fg, label = colBgMed, colBlack, "MED"
	case model.Low:
		bg, fg, label = colBgLow, colWhite, "LOW"
	}
	return t.paint(fmt.Sprintf(" %-4s ", label), bg, fg, ansiBold)
}

// severityColour paints text in the colour associated with a severity.
func (t theme) severityColour(s model.Severity, text string) string {
	switch s {
	case model.Critical:
		return t.paint(text, colRed, ansiBold)
	case model.High:
		return t.paint(text, colOrange, ansiBold)
	case model.Medium:
		return t.paint(text, colYellow)
	case model.Low:
		return t.paint(text, colCyan)
	default:
		return t.paint(text, colDim)
	}
}

// statusColour highlights patch status words.
func (t theme) statusColour(status string) string {
	switch strings.ToLower(status) {
	case "vulnerable", "eol", "end-of-life":
		return t.paint(strings.ToUpper(status), colRed, ansiBold)
	case "fixed", "vendor-patched":
		return t.paint(strings.ToUpper(status), colGreen, ansiBold)
	case "unknown", "":
		return t.paint("UNKNOWN", colDim)
	default:
		return t.paint(strings.ToUpper(status), colYellow)
	}
}

const (
	fullLogo = `██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝ ██╔══██║██╔═══╝  ╚═══██╗╚════██║██╔══██║██╔══╝  ██║     ██║
██║     ██║  ██║██║     ██████╔╝███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝`
)

// logoLines returns the banner with a vertical neon gradient.
func (t theme) logoLines() []string {
	rows := strings.Split(fullLogo, "\n")
	gradient := []string{colPink, colMagenta, colPurple, colPurple, colCyan, colCyan}
	width := 0
	for _, row := range rows {
		if w := displayWidth(row); w > width {
			width = w
		}
	}
	out := make([]string, 0, len(rows))
	for i, row := range rows {
		out = append(out, t.paint(padRight(row, width), gradient[i%len(gradient)], ansiBold))
	}
	return out
}

var spinnerFrames = []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}

func (t theme) spinner(frame int) string {
	return t.paint(spinnerFrames[frame%len(spinnerFrames)], colCyan, ansiBold)
}

// progressBar renders a moving lit segment. It is intentionally indeterminate:
// the scanners do not report intermediate percentages.
func (t theme) progressBar(width, frame int) string {
	if width < 4 {
		width = 4
	}
	head := frame % (width + 8)
	var b strings.Builder
	b.WriteString(t.paint("[", colDim))
	for i := 0; i < width; i++ {
		d := i - (head - 8)
		switch {
		case d >= 0 && d < 3:
			b.WriteString(t.paint("█", colPink, ansiBold))
		case d >= 3 && d < 7:
			b.WriteString(t.paint("▓", colMagenta))
		case d >= 7 && d < 10:
			b.WriteString(t.paint("▒", colPurple))
		default:
			b.WriteString(t.paint("░", colFaint))
		}
	}
	b.WriteString(t.paint("]", colDim))
	return b.String()
}

// glitch applies a deterministic, low-frequency corruption to a title so the
// splash and menu feel alive without becoming unreadable.
func (t theme) glitch(s string, frame int) string {
	if !t.enabled || frame%23 != 0 {
		return s
	}
	glyphs := []rune("▓▒░#%&@")
	out := []rune(s)
	for i := 0; i < len(out); i++ {
		if (i*7+frame)%19 == 0 && string(out[i]) != " " {
			out[i] = glyphs[(i+frame)%len(glyphs)]
		}
	}
	return string(out)
}

func (t theme) rule(width int) string {
	if width < 1 {
		width = 1
	}
	return t.paint(strings.Repeat("─", width), colFaint)
}
