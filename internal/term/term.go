// Package term is the small part of terminal handling GoPassGen needs: telling
// a real terminal from any other file, and reading a phrase without echoing it.
//
// It exists so the tool can stay free of the large golang.org/x/sys dependency.
// Platforms without an implementation report "not a terminal", which is the
// safe answer: no colour, and stdin is read like a pipe.
package term

import "errors"

// ErrUnsupported is returned when echo cannot be controlled on this platform.
var ErrUnsupported = errors.New("terminal control is not supported on this platform")

// IsTerminal reports whether fd refers to a terminal. Character devices that
// are not terminals, such as /dev/null, are not terminals.
func IsTerminal(fd uintptr) bool {
	return isTerminal(fd)
}

// DisableEcho stops the terminal from displaying typed characters. Line editing
// and Ctrl-C keep working. The returned function restores the previous settings
// and must be called even when reading fails.
func DisableEcho(fd uintptr) (restore func() error, err error) {
	return disableEcho(fd)
}
