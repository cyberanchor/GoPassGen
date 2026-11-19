#!/usr/bin/env bash
#
# build.sh — reproducible static builds and release artefacts for GoPassGen.
#
# Design goals:
#   * release binaries are static, stripped and free of paths, build IDs and VCS
#     stamps, so the same source tree plus the same Go toolchain always yields
#     the same SHA-256 on any machine;
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
#   ./build.sh verify-reproducible rebuilds elsewhere and compares digests
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

# What goes into the source archive when there is no git checkout to ask.
SOURCE_PATHS=".github .gitignore CHANGELOG.md LICENSE README.md build.sh cmd go.mod go.sum internal vendor"

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
    want="go1.26"   # the go line in go.mod
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

# normalize_tree removes everything the environment leaks into an archive: the
# umask through file modes, the clock through timestamps.
normalize_tree() {
    local dir="$1"
    find "${dir}" -type d -exec chmod 755 {} +
    find "${dir}" -type f -perm -u+x -exec chmod 755 {} +
    find "${dir}" -type f ! -perm -u+x -exec chmod 644 {} +
    normalize_mtimes "${dir}"
}

# zip_deterministic archives a directory with a fixed file order and no extra
# attributes (-X drops uid/gid and extended timestamps). zip stores local time,
# so the time zone has to be fixed as well.
zip_deterministic() {
    local zip_path="$1" base_dir="$2" entry="$3"
    ( cd "${base_dir}" \
      && find "${entry}" -print \
         | LC_ALL=C sort \
         | TZ=UTC zip -qX -@ "${zip_path}" )
}

# copy_licenses adds the notices that the BSD licenses of Go and golang.org/x/text
# require for binary redistribution.
copy_licenses() {
    local dest="$1/licenses" goroot text_dir
    goroot="$(go env GOROOT)"
    text_dir="${ROOT}/vendor/golang.org/x/text"
    if [[ ! -d "${text_dir}" ]]; then
        text_dir="$(cd "${ROOT}" && go list -mod=mod -m -f '{{.Dir}}' golang.org/x/text)"
    fi
    mkdir -p "${dest}"
    cp "${goroot}/LICENSE"      "${dest}/go.LICENSE"
    cp "${goroot}/PATENTS"      "${dest}/go.PATENTS"
    cp "${text_dir}/LICENSE"    "${dest}/golang.org-x-text.LICENSE"
    cp "${text_dir}/PATENTS"    "${dest}/golang.org-x-text.PATENTS"
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
    log "go test $* (full suite runs ~1M PBKDF2 iterations per vector)"
    go test "${MOD_FLAG}" -timeout 1800s "$@" ./...
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

# copy_worktree copies the working tree without the git database and build
# output. It serves the reproducibility check only and never reaches an archive.
copy_worktree() {
    local dest="$1"
    ( cd "${ROOT}" && tar cf - --exclude='./.git' --exclude='./dist' --exclude='./build' . ) \
        | ( cd "${dest}" && tar xf - )
}

# The second build differs in everything that must not matter: directory, build
# cache, time zone and umask. The fresh cache makes it slow, and honest.
cmd_verify_reproducible() {
    require_go
    log "building in two different environments and comparing digests"
    local work a b ha hb
    work="$(mktemp -d)"
    a="${work}/repro-a"; b="${work}/repro-b"
    mkdir -p "${work}/elsewhere"
    copy_worktree "${work}/elsewhere"

    build_one release "$(go env GOOS)" "$(go env GOARCH)" "${a}"
    ( cd "${work}/elsewhere" \
      && umask 077 \
      && TZ=Asia/Tokyo GOCACHE="${work}/cache" CGO_ENABLED=0 GOFLAGS="" \
         go build "${RELEASE_GOFLAGS[@]}" -ldflags "${RELEASE_LDFLAGS}" -o "${b}" "${PKG}" )

    ha="$(sha256_of "${a}")"; hb="$(sha256_of "${b}")"
    chmod -R u+w "${work}"
    rm -rf "${work}"

    [[ "${ha}" == "${hb}" ]] || die "builds differ: ${ha} vs ${hb}"
    ok "reproducible: ${ha}"
}

# ---------------------------------------------------------------------------
# Distribution
# ---------------------------------------------------------------------------

in_git_checkout() {
    local prefix
    prefix="$(git -C "${ROOT}" rev-parse --show-prefix 2>/dev/null)" && [[ -z "${prefix}" ]]
}

# copy_source_files copies what belongs in the source archive and nothing else.
# Running the tool in the checkout creates files full of secrets, so whatever
# merely happens to be lying in the working tree must stay out.
copy_source_files() {
    local dest="$1"
    if in_git_checkout; then
        if [[ -n "$(git -C "${ROOT}" status --porcelain)" ]]; then
            log "warning: uncommitted changes; untracked files are not packaged"
        fi
        # A tracked file may have been deleted without committing that yet.
        ( cd "${ROOT}" \
          && git ls-files -z \
             | while IFS= read -r -d '' f; do
                   if [[ -e "${f}" || -L "${f}" ]]; then printf '%s\0' "${f}"; fi
               done \
             | tar --null -T - -cf - ) | ( cd "${dest}" && tar xf - )
    else
        # shellcheck disable=SC2086
        ( cd "${ROOT}" && tar cf - --exclude='*.out' --exclude='*.test' --exclude='.DS_Store' ${SOURCE_PATHS} ) \
            | ( cd "${dest}" && tar xf - )
    fi
}

make_source_zip() {
    local zip_path="${DIST_DIR}/${APP}-v${VERSION}-source.zip"
    local staging="$1"
    local stage="${staging}/${APP}-v${VERSION}-source"

    log "packaging source"
    command -v zip >/dev/null 2>&1 || die "zip is required for 'dist'"

    # The tree is copied out before being archived: normalising timestamps in
    # place would rewrite the working directory.
    mkdir -p "${stage}"
    copy_source_files "${stage}"

    normalize_tree "${stage}"
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

        # The documents belong in every archive: a missing one stops the build.
        cp "${ROOT}/README.md" "${ROOT}/CHANGELOG.md" "${ROOT}/LICENSE" "${stage}/"
        copy_licenses "${stage}"

        # Per-archive checksum of the raw binary, in the standard
        # "<digest>  <name>" format so that a user who unpacks the zip can run
        # `sha256sum -c gopassgen.sha256` on it directly.
        ( cd "${stage}" && write_checksum_line "${binname}" > "${binname}.sha256" ) \
            || die "checksum failed for ${target}"

        normalize_tree "${stage}"
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

# The usage text is the comment block at the top of this file.
usage() {
    awk 'NR > 2 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
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
