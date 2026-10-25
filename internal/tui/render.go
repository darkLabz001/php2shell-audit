package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// escapeLen returns the byte length of the ANSI/OSC sequence starting at s[0],
// or 0 when s does not start with an escape.
func escapeLen(s string) int {
	if len(s) < 2 || s[0] != 0x1b {
		return 0
	}
	switch s[1] {
	case '[':
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return len(s)
	case ']':
		for i := 2; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	default:
		return 2
	}
}

// displayWidth counts printable terminal cells, ignoring escape sequences.
func displayWidth(s string) int {
	width := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			n := escapeLen(s[i:])
			if n == 0 {
				n = 1
			}
			i += n
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		width += runeWidth(r)
		i += size
	}
	return width
}

// clip truncates styled text to width cells. Escape sequences are preserved so
// colour does not bleed into the padding that follows.
func clip(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	used := 0
	truncated := false
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			n := escapeLen(s[i:])
			if n == 0 {
				n = 1
			}
			b.WriteString(s[i : i+n])
			i += n
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		w := runeWidth(r)
		if used+w > width {
			truncated = true
			break
		}
		b.WriteString(s[i : i+size])
		used += w
		i += size
	}
	if truncated {
		b.WriteString(ansiReset)
	}
	return b.String()
}

// clipEllipsis truncates to width cells and marks the cut with an ellipsis.
func clipEllipsis(s string, width int) string {
	if displayWidth(s) <= width {
		return s
	}
	if width < 2 {
		return clip(s, width)
	}
	return clip(s, width-1) + "…"
}

// padRight appends spaces until s is exactly width cells wide.
func padRight(s string, width int) string {
	n := width - displayWidth(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

// centerIn centres styled text inside width cells.
func centerIn(s string, width int) string {
	n := width - displayWidth(s)
	if n <= 0 {
		return clip(s, width)
	}
	left := n / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", n-left)
}

// wrap breaks plain text into lines no wider than width cells. Styled text is
// not expected here; callers wrap first and paint afterwards.
func wrap(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" {
			out = append(out, "")
			continue
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " "))]
		if displayWidth(indent) > width-4 {
			indent = ""
		}
		current := ""
		for _, word := range strings.Split(raw, " ") {
			if word == "" {
				if current == "" {
					current = indent
				}
				continue
			}
			candidate := word
			if current != "" {
				candidate = current + " " + word
			}
			if displayWidth(candidate) <= width || current == "" {
				if displayWidth(candidate) > width {
					// A single oversized token: hard-split it.
					rest := []rune(word)
					for len(rest) > 0 {
						take := 0
						used := 0
						for take < len(rest) && used+runeWidth(rest[take]) <= width {
							used += runeWidth(rest[take])
							take++
						}
						if take == 0 {
							take = 1
						}
						out = append(out, string(rest[:take]))
						rest = rest[take:]
					}
					current = ""
					continue
				}
				current = candidate
				continue
			}
			out = append(out, current)
			current = indent + word
		}
		if current != "" {
			out = append(out, current)
		}
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}

// runeWidth approximates wcwidth for the glyphs used by the interface.
func runeWidth(r rune) int {
	switch {
	case r == 0:
		return 0
	case r < 32 || (r >= 0x7f && r < 0xa0):
		return 0
	case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r):
		return 0
	case r >= 0x1100 && (r <= 0x115f ||
		r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1f64f) ||
		(r >= 0x1f900 && r <= 0x1f9ff) ||
		(r >= 0x20000 && r <= 0x3fffd)):
		return 2
	}
	return 1
}

// sanitize strips control characters from data that may come from logs or
// package metadata before it is written to the terminal.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// joinColumns stitches two rendered columns together with a gap.
func joinColumns(left, right []string, gap int) []string {
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	out := make([]string, 0, n)
	spacer := strings.Repeat(" ", gap)
	for i := 0; i < n; i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if r == "" {
			out = append(out, l)
			continue
		}
		out = append(out, l+spacer+r)
	}
	return out
}
