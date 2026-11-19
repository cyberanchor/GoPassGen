//go:build linux || darwin || freebsd

package term

import (
	"syscall"
	"unsafe"
)

func getTermios(fd uintptr) (*syscall.Termios, error) {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&t))); errno != 0 {
		return nil, errno
	}
	return &t, nil
}

func setTermios(fd uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}

func isTerminal(fd uintptr) bool {
	_, err := getTermios(fd)
	return err == nil
}

func disableEcho(fd uintptr) (func() error, error) {
	saved, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	hidden := *saved
	hidden.Lflag &^= syscall.ECHO
	// ECHONL keeps the newline visible, so the cursor still moves on after Enter.
	hidden.Lflag |= syscall.ECHONL | syscall.ICANON | syscall.ISIG
	hidden.Iflag |= syscall.ICRNL
	if err := setTermios(fd, &hidden); err != nil {
		return nil, err
	}
	return func() error { return setTermios(fd, saved) }, nil
}
