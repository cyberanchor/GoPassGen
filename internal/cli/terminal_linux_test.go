package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openTerminal returns both sides of a new pseudo-terminal.
func openTerminal(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { master.Close() })

	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Skipf("unlocking the terminal: %v", errno)
	}
	var number uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		t.Skipf("finding the terminal: %v", errno)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("opening the terminal: %v", err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func echoEnabled(t *testing.T, f *os.File) bool {
	t.Helper()
	var state syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state))); errno != 0 {
		t.Fatal(errno)
	}
	return state.Lflag&syscall.ECHO != 0
}

// TestTerminalInputEndsAtEnterAndIsHidden types a phrase the way a person would.
func TestTerminalInputEndsAtEnterAndIsHidden(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	master, slave := openTerminal(t)

	echoed := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, master) // ends with EIO when the other side closes
		echoed <- b.String()
	}()

	var out, errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- RunContext(context.Background(), []string{"-mnemonic-stdin"}, slave, &out, &errb)
	}()

	waitForEchoOff(t, slave)
	if _, err := master.WriteString(validEN + "\n"); err != nil {
		t.Fatal(err)
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, stderr = %s", code, errb.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Enter did not finish the input")
	}
	if got := strings.TrimSpace(out.String()); got != validENPassword12 {
		t.Errorf("password = %q", got)
	}
	if !echoEnabled(t, slave) {
		t.Error("terminal echo was not restored")
	}

	slave.Close()
	select {
	case text := <-echoed:
		if strings.Contains(text, "abandon") {
			t.Errorf("the phrase was shown on the terminal: %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Error("terminal output did not end")
	}
}

func TestInterruptedTerminalInputRestoresEcho(t *testing.T) {
	_, slave := openTerminal(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out, errb bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- RunContext(ctx, []string{"-mnemonic-stdin"}, slave, &out, &errb) }()

	waitForEchoOff(t, slave)
	cancel()
	select {
	case code := <-done:
		if code != 130 {
			t.Errorf("exit = %d, want 130", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancellation was ignored")
	}
	if !echoEnabled(t, slave) {
		t.Error("terminal echo was not restored")
	}
}

func waitForEchoOff(t *testing.T, f *os.File) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); echoEnabled(t, f); {
		if time.Now().After(deadline) {
			t.Fatal("echo was never turned off")
		}
		time.Sleep(time.Millisecond)
	}
}
