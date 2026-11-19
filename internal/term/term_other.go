//go:build !linux && !darwin && !freebsd && !windows

package term

func isTerminal(uintptr) bool { return false }

func disableEcho(uintptr) (func() error, error) { return nil, ErrUnsupported }
