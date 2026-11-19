# Changelog

All notable changes to GoPassGen. Versions follow [Semantic Versioning](https://semver.org/).

The **derivation version** is tracked separately from the tool version. It identifies the
password derivation algorithm and is printed by `-version`. A change to it means previously
generated passwords no longer reproduce, and would require a major release plus an explicit
migration note.

## [Unreleased]

### Security
- `golang.org/x/text` is updated from v0.14.0 to v0.44.0, which fixes
  [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970) (CVE-2026-56852): `unicode/norm` could
  loop forever on invalid UTF-8. GoPassGen 1.5.0 is not affected in practice. It only calls
  `NFKD.String`, which returns even on the input from the upstream fix, while the loop is in
  the NFC and NFKC iterators. govulncheck flags the call anyway, which is why CI failed. The
  update also fixes GO-2026-6629 in `secure/precis`, a package GoPassGen does not use.

### Changed
- Building from source needs Go 1.26 or newer instead of 1.21, because the fixed
  `golang.org/x/text` requires it. Release binaries are still built with Go 1.27.4.
- Built with Go 1.27 or newer, normalisation uses the Unicode 17.0.0 tables instead of
  15.0.0. Every earlier decomposition is unchanged, and none of the 57 characters that
  decompose only under the newer tables, such as outlined Latin letters, decomposes to a
  character of any wordlist. The same phrases are accepted as before, and each gives the
  same password.
- Windows is no longer built or tested: `./build.sh dist`, the release workflow and CI leave
  it out. Nothing was ever published for it.

### Fixed
- The release workflow did not run govulncheck, so 1.5.0 was published although the same
  check had failed in CI. It now runs before the release artefacts are built.

## [1.5.0] - 2026-11-19

### Added
- `-case-sensitive` hides the values you typed (phrases, file names, other arguments) from
  logs and error messages, wherever it stands on the command line.
- `-output` now also works with `-mnemonic` and `-mnemonic-stdin`.
- A CI workflow for pushes and pull requests, and signed build provenance for releases.
- The licenses of Go and `golang.org/x/text` are included in the release archives.
- Release archives contain `CHANGELOG.md`, and the release notes on GitHub are taken from it.

### Changed
- **Output files get ordinary permissions** (`0644` minus the umask) instead of `0600`. An
  existing file keeps its mode.
- An existing output file is replaced after a warning, and only once the run has succeeded:
  data is written to a temporary file and renamed into place. If the directory is not
  writable, the file is overwritten in place at the end instead, and a failure of that last
  write loses the old contents.
- With `-output`, nothing is written to stdout, so `-auto-gen` no longer prints its secrets
  to the terminal as well.
- Numbers are read as plain decimal: `016` is 16, not 14. Negative values, signs and base
  prefixes are rejected in every mode. A password made earlier with a leading zero is
  reproduced with the length it really had: `-password-length 016` gave 14 characters, so
  use `-password-length 14`. All other passwords are unchanged.
- Options without effect in the selected mode are errors, as are `-v` with a different
  `-log-level` and additional work options with `-version` or `-self-test`.
- A usage error prints the reason once and the help once. With `-log-format json` every
  stderr line is JSON, and `-log-level silent` prints nothing.
- On a terminal, `-mnemonic-stdin` hides the input and finishes at Enter.
- PBKDF2 and HMAC-SHA512 are implemented in `internal/derive`, which removes the
  `golang.org/x/crypto` dependency. Derived values are unchanged and are checked against
  the published vectors and the standard library.
- The module path is `github.com/cyberanchor/GoPassGen`, so `go install` works.
- GitHub releases carry a prebuilt binary for Linux x86-64 only, with the source archive and
  `SHA256SUMS`. Every other target is still built by the release workflow as a check; on
  those systems use `go install` or build from source.

### Fixed
- Write errors were ignored: on a full disk the tool could report success and exit 0 with an
  empty or truncated file. Failures on files and on stdout now exit with code 1.
- SIGINT and SIGTERM had no effect while waiting for stdin, a FIFO or a full pipe, during a
  single derivation and during `-self-test`. All of them now exit with code 130.
- A bad `-output` path is detected before any derivation runs.
- `-output` no longer follows symbolic links to files.
- Directories created for `-output` are removed again when the run fails.
- Every wordlist is checked against its SHA-256 digest whenever it is loaded, not only by
  `-self-test`.
- HMAC state and entropy bit arrays are erased after use.
- Colour needs a real terminal: `/dev/null` no longer qualifies. An empty `NO_COLOR` no
  longer disables colour, as no-color.org specifies.
- `./build.sh dist` packages tracked files only, so stray files such as generated phrases
  cannot end up in the source archive.
- Release archives no longer depend on the time zone or umask, and
  `verify-reproducible` really builds in a different environment.
- The release workflow can be started by hand from any branch, does not expand its input
  inside shell scripts, pins Go and all actions exactly, and limits write access to the
  publishing job.

## [1.4.1] - 2026-08-12

### Changed
- Logging moved from a hand-written logger to the standard library's `log/slog`.
  All call sites now emit structured attributes (`count=3 words=24`) instead of
  values formatted into the message text.
- `derive.Stats` implements `slog.LogValuer`, so derivation diagnostics appear as a
  typed group (`stats.blocks`, `stats.rejected`, `stats.rejection_rate`).
- The language is attached once per run with `slog.Logger.With`, so every record
  carries it, including those emitted by `internal/passgen`.

### Added
- `-log-format pretty|json`. JSON output goes through `slog.JSONHandler` and is
  intended for batch runs and log aggregation.
- The pretty handler is verified against `testing/slogtest`, plus a negative test
  proving that conformance suite is not vacuous.

### Fixed
- Release archives are now reproducible, not just the binaries inside them. `zip`
  stored per-file timestamps and directory order, so `SHA256SUMS` changed on every
  packaging run; timestamps are pinned to `SOURCE_DATE_EPOCH` and entries are
  sorted before archiving.

### Notes
- The pretty layout, colour behaviour, level names and CLI flags are unchanged;
  only the message text is now split into message plus attributes.
- Password derivation is untouched: `DerivationVersion` remains `pypassgen-1.3.5`.

## [1.4.0] - 2026-08-12

First production release of the Go port.

### Added
- Multi-package layout: `cmd/gopassgen` plus `internal/{derive,bip39,passgen,cli,logx,buildinfo}`.
- `-self-test`: seven known-answer checks (alphabet, wordlist SHA-256 digests, NFKD, BIP-39
  seed, HMAC stream, KDF, end-to-end) against the reference vectors.
- `-mnemonic-stdin`: reads the phrase from stdin, keeping it out of shell history and `ps`.
- `-log-level silent|error|warn|info|debug`, `-no-color`, `NO_COLOR` support; logs on stderr,
  output on stdout.
- `-jobs`: bounded worker pool for batch generation, with `Ctrl-C` cancellation.
- `-version`: tool version, derivation version and runtime.
- Sentinel errors in every package, matchable with `errors.Is`/`errors.As`.
- Exit codes: `0` success, `1` runtime error, `2` usage error, `130` interrupted.
- Test suite with 22 end-to-end password vectors across all seven languages and lengths
  1/12/16/24/32/100/256, 35 mnemonic vectors, 15 seed vectors, 18 validation edge cases;
  92.4% statement coverage.
- `build.sh` with reproducible static release builds, debug builds, cross-compilation,
  zip packaging and `SHA256SUMS`.

### Security
- Output files are created with mode `0600` instead of the Python original's `0644`.
- Validation errors report the *position* of a bad word, never the word itself.
- Seeds, keys and passwords are handled as `[]byte` and zeroed after use.

### Compatibility
- Derivation version `pypassgen-1.3.5`: byte-identical passwords to PyPassGen 1.3.5.
- Whitespace handling, NFKD normalization and the `-count`/`-phrases` fallback intentionally
  reproduce the reference behaviour, including its quirks.
