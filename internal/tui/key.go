package tui

import (
	"bufio"
	"io"
	"strconv"
	"time"
	"unicode/utf8"
)

// keyKind identifies a decoded key press.
type keyKind int

const (
	keyUnknown keyKind = iota
	keyRune
	keyEnter
	keyEsc
	keyTab
	keyBackspace
	keyUp
	keyDown
	keyLeft
	keyRight
	keyPageUp
	keyPageDown
	keyHome
	keyEnd
	keyDelete
	keyCtrlC
	keyCtrlD
	keyCtrlU
)

// key is one decoded input event.
type key struct {
	kind keyKind
	r    rune
}

// keyReader decodes a byte stream into key events. The optional deadline hook
// is used to distinguish a lone ESC from the start of a control sequence.
type keyReader struct {
	br          *bufio.Reader
	setDeadline func(time.Time) error
}

func newKeyReader(r io.Reader, deadline func(time.Time) error) *keyReader {
	return &keyReader{br: bufio.NewReaderSize(r, 256), setDeadline: deadline}
}

func (kr *keyReader) read() (key, error) {
	b, err := kr.br.ReadByte()
	if err != nil {
		return key{}, err
	}
	switch b {
	case 3:
		return key{kind: keyCtrlC}, nil
	case 4:
		return key{kind: keyCtrlD}, nil
	case 21:
		return key{kind: keyCtrlU}, nil
	case '\r', '\n':
		return key{kind: keyEnter}, nil
	case '\t':
		return key{kind: keyTab}, nil
	case 0x7f, 0x08:
		return key{kind: keyBackspace}, nil
	case 0x1b:
		return kr.readEscape()
	}
	if b < 0x20 {
		return key{kind: keyUnknown}, nil
	}
	if err := kr.br.UnreadByte(); err != nil {
		return key{kind: keyUnknown}, nil
	}
	r, _, err := kr.br.ReadRune()
	if err != nil {
		return key{}, err
	}
	return key{kind: keyRune, r: r}, nil
}

func (kr *keyReader) readEscape() (key, error) {
	if kr.br.Buffered() == 0 && kr.setDeadline != nil {
		// Give a sequence such as ESC [ A a moment to arrive; a bare ESC is
		// otherwise interpreted immediately.
		if err := kr.setDeadline(time.Now().Add(25 * time.Millisecond)); err == nil {
			_, err := kr.br.Peek(1)
			_ = kr.setDeadline(time.Time{})
			if err != nil {
				return key{kind: keyEsc}, nil
			}
		}
	}
	if kr.br.Buffered() == 0 {
		return key{kind: keyEsc}, nil
	}

	first, err := kr.br.ReadByte()
	if err != nil {
		return key{kind: keyEsc}, nil
	}
	if first != '[' && first != 'O' {
		if utf8.FullRune([]byte{first}) {
			return key{kind: keyRune, r: rune(first)}, nil
		}
		return key{kind: keyEsc}, nil
	}

	var params []byte
	for {
		b, err := kr.br.ReadByte()
		if err != nil {
			return key{kind: keyEsc}, nil
		}
		if b >= 0x40 && b <= 0x7e {
			return sequenceKey(params, b)
		}
		params = append(params, b)
		if len(params) > 16 {
			return key{kind: keyUnknown}, nil
		}
	}
}

func sequenceKey(params []byte, final byte) (key, error) {
	switch final {
	case 'A':
		return key{kind: keyUp}, nil
	case 'B':
		return key{kind: keyDown}, nil
	case 'C':
		return key{kind: keyRight}, nil
	case 'D':
		return key{kind: keyLeft}, nil
	case 'H':
		return key{kind: keyHome}, nil
	case 'F':
		return key{kind: keyEnd}, nil
	case 'Z':
		return key{kind: keyTab}, nil // shift-tab; treated as tab-cycle
	case '~':
		n, _ := strconv.Atoi(string(params))
		switch n {
		case 1, 7:
			return key{kind: keyHome}, nil
		case 3:
			return key{kind: keyDelete}, nil
		case 4, 8:
			return key{kind: keyEnd}, nil
		case 5:
			return key{kind: keyPageUp}, nil
		case 6:
			return key{kind: keyPageDown}, nil
		}
	}
	return key{kind: keyUnknown}, nil
}
