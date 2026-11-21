#!/bin/sh
# Run Hearthscan on macOS or Linux without installing it.
#
#   curl -fsSL https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch/run.sh | sh
#
# With arguments:
#
#   curl -fsSL https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch/run.sh | sh -s -- scan --lang tr
#
# It downloads the release binary for this computer and the release's
# SHA256SUMS, checks the binary's SHA-256, runs it from a new temporary folder
# and deletes that folder when the program ends, also after Ctrl+C or an
# error. Nothing is installed and no admin rights are needed.
#
# HEARTHSCAN_VERSION=2.0.0 runs that release instead of the latest one.
# HEARTHSCAN_DOWNLOAD_BASE replaces the download address. It is only meant for
# testing against a local copy of a release.
#
# The work happens in main, called on the last line, so sh has read the whole
# script before anything is downloaded or run, even when it comes through a pipe.

REPO="https://github.com/kalachbeg/Hearthscan"
FROM_SOURCE="uvx --from git+$REPO hearthscan"

tmp=""

say() {
    printf '%s\n' "$*" >&2
}

fail() {
    say "$*"
    exit 1
}

cleanup() {
    if [ -n "$tmp" ] && [ -d "$tmp" ]; then
        rm -rf "$tmp"
    fi
}

# Sets asset to the name of the release file for this computer.
pick_asset() {
    case $(uname -s) in
        Linux) os=linux ;;
        Darwin) os=macos ;;
        *) fail "There is no Hearthscan build for $(uname -s). With uv you can run it from source: $FROM_SOURCE" ;;
    esac
    case $(uname -m) in
        x86_64 | amd64) arch=x64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) fail "There is no Hearthscan build for $os on $(uname -m). With uv you can run it from source: $FROM_SOURCE" ;;
    esac
    # A shell running under Rosetta says x86_64 on an Apple silicon Mac.
    if [ "$os" = macos ] && [ "$arch" = x64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = 1 ]; then
        arch=arm64
    fi
    asset="hearthscan-$os-$arch"
}

# Saves the address $1 to the file $2. Returns 0 when the file was saved, 2
# when the server says there is no such file and 1 on any other failure.
fetch() {
    if [ "$downloader" = curl ]; then
        code=$(curl -sSL --proto-redir =https --retry 2 -w '%{http_code}' -o "$2" "$1") || return 1
        case $code in
            200) return 0 ;;
            404) return 2 ;;
        esac
        say "The server answered with HTTP $code for $1"
        return 1
    fi
    wget -q $hsts -O "$2" "$1"
    case $? in
        0) return 0 ;;
        8) return 2 ;; # GNU wget: the server answered with an error such as 404
    esac
    return 1
}

not_found() {
    if [ -n "$HEARTHSCAN_VERSION" ]; then
        say "Hearthscan $version was not found at $base"
    else
        say "There is no Hearthscan release to download yet."
    fi
    say "You can run it from source with uv instead:"
    say "  $FROM_SOURCE"
    exit 1
}

main() {
    pick_asset

    if command -v curl >/dev/null 2>&1; then
        downloader=curl
    elif command -v wget >/dev/null 2>&1; then
        downloader=wget
        # Without --no-hsts GNU wget keeps a ~/.wget-hsts file. BusyBox wget
        # neither writes one nor knows the option.
        hsts=""
        if wget --help 2>&1 | grep -q -- --no-hsts; then
            hsts="--no-hsts"
        fi
    else
        fail "Neither curl nor wget is installed, so Hearthscan cannot be downloaded."
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        hasher="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        hasher="shasum -a 256"
    else
        fail "Neither sha256sum nor shasum is installed, so the download cannot be checked."
    fi

    if [ -n "$HEARTHSCAN_VERSION" ]; then
        version=${HEARTHSCAN_VERSION#v}
        case $version in
            "" | *[!0-9A-Za-z.+-]*) fail "HEARTHSCAN_VERSION should look like 2.0.0, not '$HEARTHSCAN_VERSION'." ;;
        esac
        base="$REPO/releases/download/v$version"
        release="release $version"
    else
        base="$REPO/releases/latest/download"
        release="the latest release"
    fi
    if [ -n "$HEARTHSCAN_DOWNLOAD_BASE" ]; then
        base=${HEARTHSCAN_DOWNLOAD_BASE%/}
    fi

    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    root=${TMPDIR:-/tmp}
    tmp=$(mktemp -d "${root%/}/hearthscan.XXXXXXXX") || fail "Could not create a temporary folder in $root"

    say "Downloading $asset from $release..."
    fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
    case $? in
        0) ;;
        2) not_found ;;
        *) fail "Could not download $base/SHA256SUMS" ;;
    esac
    expected=$(awk -v name="$asset" '
        { sub(/\r$/, "") }
        ($2 == name || $2 == "*" name) && length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ {
            print tolower($1)
            exit
        }' "$tmp/SHA256SUMS")
    if [ -z "$expected" ]; then
        say "SHA256SUMS has no checksum for $asset, so it will not be run."
        fail "With uv you can run Hearthscan from source instead: $FROM_SOURCE"
    fi

    fetch "$base/$asset" "$tmp/$asset"
    case $? in
        0) ;;
        2) not_found ;;
        *) fail "Could not download $base/$asset" ;;
    esac

    say "Checking the SHA-256 checksum..."
    actual=$($hasher "$tmp/$asset" | awk '{ print tolower($1) }')
    if [ "$actual" != "$expected" ]; then
        fail "The SHA-256 of $asset does not match SHA256SUMS, so it was not run."
    fi
    chmod +x "$tmp/$asset" || fail "Could not make $tmp/$asset executable."

    say "Checksum OK. Starting Hearthscan."
    # From here on Ctrl+C belongs to the program: it reaches the program
    # directly and the program decides how to end and with which status.
    trap : INT
    # The program unpacks itself into a temporary folder of its own. TMPDIR
    # keeps that folder inside this one as well.
    if [ -t 0 ] || ! (: </dev/tty) 2>/dev/null; then
        TMPDIR=$tmp "$tmp/$asset" "$@"
    else
        # Piped into sh, the script itself is on stdin. The program reads the
        # keyboard instead, as it would when started by hand.
        TMPDIR=$tmp "$tmp/$asset" "$@" </dev/tty
    fi
    status=$?
    if [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then
        say "The program could not be started. If $root does not allow running programs, set TMPDIR to a folder that does."
        say "Or run Hearthscan from source with uv: $FROM_SOURCE"
    fi
    exit "$status"
}

main "$@"
