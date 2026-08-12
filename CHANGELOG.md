# Changelog

All notable changes to GoPassGen. Versions follow [Semantic Versioning](https://semver.org/).

The **derivation version** is tracked separately from the tool version. It identifies the
password derivation algorithm and is printed by `-version`. A change to it means previously
generated passwords no longer reproduce, and would require a major release plus an explicit
migration note.

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
- `release.sh` verified that the working tree was clean using a command
  substitution inside `[[ ... ]]`, which does not trip `set -e`: outside a git
  repository the check silently passed. The exit status is now captured explicitly.

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
