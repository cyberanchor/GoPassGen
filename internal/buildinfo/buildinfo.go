// Package buildinfo exposes static identification data for the binary.
//
// Everything here is a compile-time constant on purpose: no linker-injected
// git hash, no build timestamp, no VCS stamping. That is what makes release
// builds byte-for-byte reproducible — two people building the same source tree
// with the same Go toolchain must obtain the same SHA-256.
package buildinfo

import (
	"fmt"
	"runtime"
)

const (
	// Name is the executable name used in help and version output.
	Name = "GoPassGen"

	// Version is the release version of this tool.
	Version = "1.4.1"

	// DerivationVersion identifies the password derivation algorithm this
	// build implements. It is NOT the tool version: it is the compatibility
	// contract. Any change to it means previously generated passwords will
	// no longer be reproduced.
	//
	// pypassgen-1.3.5:
	//   seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic", 2048, 64)
	//   key  = PBKDF2-HMAC-SHA512(seed, "0", 1000000, 64)
	//   pw   = rejection-sample(HMAC-SHA512(key, "PyPassGen\x00"||ctr32be)) over 88 chars
	DerivationVersion = "pypassgen-1.3.5"
)

// VersionString returns the multi-line output of --version.
func VersionString() string {
	return fmt.Sprintf(
		"%s %s\nderivation: %s (bit-compatible with PyPassGen 1.3.5)\nruntime:    %s %s/%s",
		Name, Version, DerivationVersion,
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}

// Short returns a one-line identifier, e.g. "GoPassGen 1.4.0".
func Short() string {
	return Name + " " + Version
}
