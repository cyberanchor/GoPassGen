package term

import (
	"os"
	"syscall"
	"testing"
)

// openPTY returns the master side of a new pseudo-terminal. Terminal ioctls on
// it act on the terminal itself.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestIsTerminal(t *testing.T) {
	if !IsTerminal(openPTY(t).Fd()) {
		t.Error("a pseudo-terminal was not recognised")
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if IsTerminal(devNull.Fd()) {
		t.Error("the null device is a character device, not a terminal")
	}

	regular, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if IsTerminal(regular.Fd()) {
		t.Error("a regular file is not a terminal")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(r.Fd()) {
		t.Error("a pipe is not a terminal")
	}

	if IsTerminal(^uintptr(0)) {
		t.Error("an invalid descriptor is not a terminal")
	}
}

func TestDisableEchoAndRestore(t *testing.T) {
	pty := openPTY(t)
	fd := pty.Fd()
	before, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag&syscall.ECHO == 0 {
		t.Fatal("a new terminal should echo")
	}

	restore, err := DisableEcho(fd)
	if err != nil {
		t.Fatal(err)
	}
	during, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if during.Lflag&syscall.ECHO != 0 {
		t.Error("echo is still on")
	}
	for name, bit := range map[string]uint32{"ECHONL": syscall.ECHONL, "ICANON": syscall.ICANON, "ISIG": syscall.ISIG} {
		if during.Lflag&bit == 0 {
			t.Errorf("%s must stay on: Enter and Ctrl-C have to keep working", name)
		}
	}

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	after, err := getTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if *after != *before {
		t.Error("terminal settings were not restored")
	}
}

func TestDisableEchoRejectsNonTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := DisableEcho(r.Fd()); err == nil {
		t.Error("expected an error for a pipe")
	}
}
