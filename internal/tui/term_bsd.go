//go:build darwin || freebsd || netbsd || openbsd

package tui

import (
	"os"
	"syscall"
	"unsafe"
)

// rawState holds the terminal attributes so they can be restored on exit.
type rawState struct {
	termios syscall.Termios
}

func ioctl(f *os.File, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), request, uintptr(arg), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// makeRaw switches f into cbreak/raw mode and disables echo and signal keys.
func makeRaw(f *os.File) (*rawState, error) {
	var t syscall.Termios
	if err := ioctl(f, syscall.TIOCGETA, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	saved := t
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := ioctl(f, syscall.TIOCSETA, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &rawState{termios: saved}, nil
}

func restoreRaw(f *os.File, st *rawState) error {
	if st == nil {
		return nil
	}
	return ioctl(f, syscall.TIOCSETA, unsafe.Pointer(&st.termios))
}

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// terminalSize returns the usable window size in cells.
func terminalSize(f *os.File) (width, height int, ok bool) {
	var ws winsize
	if err := ioctl(f, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, false
	}
	if ws.Col == 0 || ws.Row == 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}

// isTTY reports whether the descriptor is a terminal, even when the pty has
// not been given a window size.
func isTTY(f *os.File) bool {
	var ws winsize
	return ioctl(f, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)) == nil
}
