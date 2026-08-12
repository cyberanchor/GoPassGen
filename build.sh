#!/usr/bin/env bash
#
# build.sh — reproducible static builds and release artefacts for GoPassGen.
#
# Design goals:
#   * release binaries are static, stripped and free of build metadata, so the
#     same source tree plus the same Go toolchain always yields the same
#     SHA-256 on any machine;
#   * debug binaries keep every symbol and disable optimisation and inlining,
#     so delve and perf work properly;
#   * no network access is required: dependencies are vendored.
#
# Usage:
#   ./build.sh                     release build for the host platform
#   ./build.sh release             same, explicitly
#   ./build.sh debug               unstripped build with DWARF, for delve
#   ./build.sh test                full test suite (slow, ~1M PBKDF2 per vector)
#   ./build.sh test --short        fast smoke tests
#   ./build.sh check               gofmt + go vet + short tests
#   ./build.sh dist                cross-compile all targets + zips + SHA256SUMS
#   ./build.sh dist --targets "linux/amd64 darwin/arm64"
#   ./build.sh verify-reproducible builds twice and compares digests
#   ./build.sh clean               remove build/ and dist/
#
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP="gopassgen"
PKG="./cmd/gopassgen"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT}/build"
DIST_DIR="${ROOT}/dist"

# Version is read from the source of truth so the script can never disagree
# with the binary. No git hash, no timestamp: those would break reproducibility.
VERSION="$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${ROOT}/internal/buildinfo/buildinfo.go" | head -n1)"
[[ -n "${VERSION}" ]] || { echo "cannot determine version from internal/buildinfo" >&2; exit 1; }

DEFAULT_TARGETS="linux/amd64 linux/arm64 linux/386 linux/arm \
darwin/amd64 darwin/arm64 \
windows/amd64 windows/arm64 \
freebsd/amd64 openbsd/amd64"

# Archives are made reproducible by pinning every stored timestamp. Without
# this the binaries would be identical but the zips around them would not, and
# SHA256SUMS would change on every packaging run for no reason.
# 315532800 = 1980-01-01, the earliest timestamp the zip format can store.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-315532800}"

# Vendored dependencies make the build hermetic. Fall back to module mode if
# the vendor directory was deliberately removed.
if [[ -d "${ROOT}/vendor" ]]; then
    MOD_FLAG="-mod=vendor"
else
    MOD_FLAG="-mod=mod"
fi

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
#
# -trimpath        strips absolute paths, so two machines produce identical output
# -buildvcs=false  keeps git state (branch, revision, dirty flag) out of the binary
# -buildid=        clears the Go build ID, the last non-deterministic field
# -s               drops the symbol table
# -w               drops DWARF debug information
# CGO_ENABLED=0    pure Go: no dynamic linking against libc, no NSS surprises
#
RELEASE_GOFLAGS=(-trimpath -buildvcs=false "${MOD_FLAG}")
RELEASE_LDFLAGS="-s -w -buildid="

# Debug keeps everything, and disables optimisation/inlining for a usable
# stepping experience. -buildvcs stays off so debug and release differ only in
# symbols, not in embedded metadata.
DEBUG_GOFLAGS=(-buildvcs=false "${MOD_FLAG}" -gcflags "all=-N -l")
DEBUG_LDFLAGS="-buildid="

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_INFO=$'\033[36m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_ERR=""; C_INFO=""; C_OFF=""
fi
readonly C_OK C_ERR C_INFO C_OFF

log()  { printf '%s==>%s %s\n' "${C_INFO}" "${C_OFF}" "$*"; }
ok()   { printf '%s  ok%s %s\n' "${C_OK}" "${C_OFF}" "$*"; }
die()  { printf '%serror%s %s\n' "${C_ERR}" "${C_OFF}" "$*" >&2; exit 1; }

trap 'die "failed at line ${LINENO}"' ERR

require_go() {
    command -v go >/dev/null 2>&1 || die "go toolchain not found in PATH"
    local have want
    have="$(go env GOVERSION)"
    want="go1.21"
    # Lexical comparison is wrong across major versions; compare numerically.
    local hv wv
    hv="$(printf '%s' "${have}" | sed -n 's/^go\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
    wv="$(printf '%s' "${want}" | sed -n 's/^go\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
    # shellcheck disable=SC2086
    set -- ${hv} ${wv}
    if (( $1 < $3 || ( $1 == $3 && $2 < $4 ) )); then
        die "need ${want} or newer, found ${have}"
    fi
}

# normalize_mtimes pins every timestamp under a directory so that zip stores a
# fixed value. GNU touch understands "@epoch"; BSD touch needs -t.
normalize_mtimes() {
    local dir="$1"
    if ! find "${dir}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null; then
        local stamp
        stamp="$(TZ=UTC date -r "${SOURCE_DATE_EPOCH}" +%Y%m%d%H%M.%S 2>/dev/null || echo "198001010000.00")"
        find "${dir}" -exec touch -h -t "${stamp}" {} + \
            || die "cannot normalise timestamps in ${dir}"
    fi
}

# zip_deterministic archives a directory with a fixed file order and no extra
# attributes (-X drops uid/gid and extended timestamps).
zip_deterministic() {
    local zip_path="$1" base_dir="$2" entry="$3"
    ( cd "${base_dir}" \
      && find "${entry}" -print \
         | LC_ALL=C sort \
         | zip -qX -@ "${zip_path}" )
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "neither sha256sum nor shasum is available"
    fi
}

write_checksum_line() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        die "neither sha256sum nor shasum is available"
    fi
}

write_checksums() {
    local dir="$1"
    ( cd "${dir}"
      if command -v sha256sum >/dev/null 2>&1; then
          sha256sum -- * > SHA256SUMS.tmp
      else
          shasum -a 256 -- * > SHA256SUMS.tmp
      fi
      grep -v 'SHA256SUMS' SHA256SUMS.tmp > SHA256SUMS
      rm -f SHA256SUMS.tmp
    )
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build_one() {
    local mode="$1" goos="$2" goarch="$3" outfile="$4"
    local -a flags
    local ldflags

    if [[ "${mode}" == "release" ]]; then
        flags=("${RELEASE_GOFLAGS[@]}"); ldflags="${RELEASE_LDFLAGS}"
    else
        flags=("${DEBUG_GOFLAGS[@]}");   ldflags="${DEBUG_LDFLAGS}"
    fi

    mkdir -p "$(dirname "${outfile}")"

    # SOURCE_DATE_EPOCH is honoured by nothing in a pure-Go build, but setting
    # it documents intent and helps any wrapper tooling.
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" GOFLAGS="" \
        go build "${flags[@]}" -ldflags "${ldflags}" -o "${outfile}" "${PKG}"

    ok "${mode} ${goos}/${goarch} -> ${outfile#"${ROOT}"/} ($(sha256_of "${outfile}" | cut -c1-16)…)"
}

cmd_release() {
    require_go
    log "release build ${APP} ${VERSION} (static, stripped, no build id)"
    build_one release "$(go env GOOS)" "$(go env GOARCH)" "${OUT_DIR}/${APP}"

    if command -v file >/dev/null 2>&1; then
        file -b "${OUT_DIR}/${APP}" | sed 's/^/     /'
    fi
    "${OUT_DIR}/${APP}" -version | sed 's/^/     /'
}

cmd_debug() {
    require_go
    log "debug build ${APP} ${VERSION} (symbols + DWARF, -N -l)"
    build_one debug "$(go env GOOS)" "$(go env GOARCH)" "${OUT_DIR}/${APP}-debug"
    echo "     run: dlv exec ${OUT_DIR#"${ROOT}"/}/${APP}-debug -- -mnemonic-stdin"
}

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

cmd_test() {
    require_go
    local extra=("$@")
    log "go test ${extra[*]:-} (full suite runs ~1M PBKDF2 iterations per vector)"
    go test "${MOD_FLAG}" -timeout 1800s "${extra[@]}" ./...
    ok "tests passed"
}

cmd_check() {
    require_go
    log "gofmt"
    local unformatted
    unformatted="$(gofmt -l . | grep -v '^vendor/' || true)"
    [[ -z "${unformatted}" ]] || die "not gofmt-clean:"$'\n'"${unformatted}"
    ok "gofmt clean"

    log "go vet"
    go vet "${MOD_FLAG}" ./...
    ok "vet clean"

    cmd_test -short
}

cmd_verify_reproducible() {
    require_go
    log "building twice and comparing digests"
    local a b
    a="${OUT_DIR}/repro-a"; b="${OUT_DIR}/repro-b"
    build_one release "$(go env GOOS)" "$(go env GOARCH)" "${a}"
    build_one release "$(go env GOOS)" "$(go env GOARCH)" "${b}"

    local ha hb
    ha="$(sha256_of "${a}")"; hb="$(sha256_of "${b}")"
    rm -f "${a}" "${b}"

    [[ "${ha}" == "${hb}" ]] || die "builds differ: ${ha} vs ${hb}"
    ok "reproducible: ${ha}"
}

# ---------------------------------------------------------------------------
# Distribution
# ---------------------------------------------------------------------------

make_source_zip() {
    local zip_path="${DIST_DIR}/${APP}-v${VERSION}-source.zip"
    local staging="$1"
    local stage="${staging}/${APP}-v${VERSION}-source"

    log "packaging source"
    command -v zip >/dev/null 2>&1 || die "zip is required for 'dist'"

    # The tree is copied out before being archived: normalising timestamps in
    # place would rewrite the working directory. Exclude the git database, not
    # the .github directory — a pattern like '*.git*' silently drops the
    # release workflow too.
    mkdir -p "${stage}"
    ( cd "${ROOT}" && tar cf - \
        --exclude='./.git' --exclude='./dist' --exclude='./build' \
        --exclude='*.DS_Store' --exclude='*.out' --exclude='*.test' \
        . ) | ( cd "${stage}" && tar xf - )

    normalize_mtimes "${stage}"
    zip_deterministic "${zip_path}" "${staging}" "${APP}-v${VERSION}-source"
    ok "source archive -> ${zip_path#"${ROOT}"/}"
}

cmd_dist() {
    require_go
    command -v zip >/dev/null 2>&1 || die "zip is required for 'dist'"

    local targets="${DEFAULT_TARGETS}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --targets) targets="${2:?--targets needs a value}"; shift 2 ;;
            *) die "unknown option for dist: $1" ;;
        esac
    done

    rm -rf "${DIST_DIR}"
    mkdir -p "${DIST_DIR}"

    log "release artefacts for ${APP} ${VERSION}"
    local staging
    staging="$(mktemp -d)"

    local target goos goarch binname stage
    for target in ${targets}; do
        goos="${target%%/*}"; goarch="${target##*/}"
        binname="${APP}"
        [[ "${goos}" == "windows" ]] && binname="${APP}.exe"

        stage="${staging}/${APP}-v${VERSION}-${goos}-${goarch}"
        mkdir -p "${stage}"
        build_one release "${goos}" "${goarch}" "${stage}/${binname}"

        cp "${ROOT}/README.md" "${stage}/" 2>/dev/null || true
        cp "${ROOT}/LICENSE"   "${stage}/" 2>/dev/null || true

        # Per-archive checksum of the raw binary, in the standard
        # "<digest>  <name>" format so that a user who unpacks the zip can run
        # `sha256sum -c gopassgen.sha256` on it directly.
        ( cd "${stage}" && write_checksum_line "${binname}" > "${binname}.sha256" ) \
            || die "checksum failed for ${target}"

        normalize_mtimes "${stage}"
        zip_deterministic \
            "${DIST_DIR}/${APP}-v${VERSION}-${goos}-${goarch}.zip" \
            "${staging}" "${APP}-v${VERSION}-${goos}-${goarch}"
    done

    make_source_zip "${staging}"
    write_checksums "${DIST_DIR}"
    rm -rf "${staging}"

    echo
    log "dist contents"
    ( cd "${DIST_DIR}" && ls -1 && echo && cat SHA256SUMS )
}

cmd_clean() {
    rm -rf "${OUT_DIR}" "${DIST_DIR}"
    ok "removed build/ and dist/"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

usage() {
    sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
    local cmd="${1:-release}"
    [[ $# -gt 0 ]] && shift || true

    case "${cmd}" in
        release)             cmd_release "$@" ;;
        debug)               cmd_debug "$@" ;;
        test)                cmd_test "$@" ;;
        check)               cmd_check "$@" ;;
        dist)                cmd_dist "$@" ;;
        verify-reproducible) cmd_verify_reproducible "$@" ;;
        clean)               cmd_clean "$@" ;;
        -h|--help|help)      usage ;;
        *)                   usage; die "unknown command: ${cmd}" ;;
    esac
}

main "$@"
