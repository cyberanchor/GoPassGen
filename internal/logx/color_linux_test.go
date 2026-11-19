package logx

import (
	"os"
	"syscall"
	"testing"
)

func TestColorOnRealTerminal(t *testing.T) {
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	defer pty.Close()

	t.Setenv("NO_COLOR", "")
	if !ColorEnabled(pty, false) {
		t.Error("an empty NO_COLOR must not disable colour on a terminal")
	}
	if ColorEnabled(pty, true) {
		t.Error("-no-color must disable colour")
	}
	os.Unsetenv("NO_COLOR")
	if !ColorEnabled(pty, false) {
		t.Error("a terminal should get colour")
	}
	t.Setenv("NO_COLOR", "1")
	if ColorEnabled(pty, false) {
		t.Error("NO_COLOR with a value must disable colour")
	}
}
