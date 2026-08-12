// Command gopassgen derives deterministic passwords from BIP-39 mnemonic
// phrases, bit-compatible with PyPassGen 1.3.5.
//
// This file stays intentionally trivial: all behaviour lives in
// internal/cli.Run, which returns an exit code instead of terminating the
// process, so every path is reachable from tests.
package main

import (
	"os"

	"gopassgen/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
