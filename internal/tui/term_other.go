//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package tui

import (
	"errors"
	"os"
)

type rawState struct{}

var errUnsupportedTerminal = errors.New("interactive TUI is not supported on this platform")

func makeRaw(*os.File) (*rawState, error) { return nil, errUnsupportedTerminal }

func restoreRaw(*os.File, *rawState) error { return nil }

func terminalSize(*os.File) (int, int, bool) { return 0, 0, false }

func isTTY(*os.File) bool { return false }
