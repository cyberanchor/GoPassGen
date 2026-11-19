package term

import "syscall"

// Console input modes, from the Windows SDK.
const (
	enableProcessedInput = 0x0001
	enableLineInput      = 0x0002
	enableEchoInput      = 0x0004
)

var procSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func setConsoleMode(fd uintptr, mode uint32) error {
	if ok, _, err := procSetConsoleMode.Call(fd, uintptr(mode)); ok == 0 {
		return err
	}
	return nil
}

func getConsoleMode(fd uintptr) (uint32, error) {
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(fd), &mode)
	return mode, err
}

func isTerminal(fd uintptr) bool {
	_, err := getConsoleMode(fd)
	return err == nil
}

func disableEcho(fd uintptr) (func() error, error) {
	saved, err := getConsoleMode(fd)
	if err != nil {
		return nil, err
	}
	hidden := saved&^enableEchoInput | enableLineInput | enableProcessedInput
	if err := setConsoleMode(fd, hidden); err != nil {
		return nil, err
	}
	return func() error { return setConsoleMode(fd, saved) }, nil
}
