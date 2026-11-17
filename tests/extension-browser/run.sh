#!/bin/sh
# Browser test of the Chrome extension against a hostile origin.
#
# Loads extensions/chrome into a headless Chromium, maps pinchat.io to a
# local server (hostile-server.js) and checks, for a set of tampering cases,
# what the page was able to do and whether the extension warned.
#
# Not part of CI: it needs Chromium, openssl and node. The extension's
# background worker fetches the signed manifest of its pinned release from
# GitHub, so the first run also needs network access and the static/ files in
# the working tree must match that release. Nothing is sent to the real site:
# the host name is remapped to 127.0.0.1.
#
# Usage: tests/extension-browser/run.sh [extension-dir]
# Exit status is non-zero when an expectation marked "must" fails. The case
# marked "known limit" documents behaviour that is wrong but not fixable in
# the content script; it is reported and does not fail the run.

set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXT=${1:-"$HERE/../../extensions/chrome"}
CHROMIUM=${CHROMIUM:-chromium}
WORK=$(mktemp -d)
LOG="$WORK/requests.log"
trap 'kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -subj "/CN=pinchat.io" -addext "subjectAltName=DNS:pinchat.io,DNS:www.pinchat.io" 2>/dev/null
: > "$LOG"
node "$HERE/hostile-server.js" "$WORK" "$LOG" > "$WORK/server.out" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "hostile server did not start:"; cat "$WORK/server.out"; exit 2
fi

ROOM="room=00000000-0000-4000-8000-000000000000"
FAILED=0

# load <url> [ext]   -> DOM after load on stdout
# Every load gets a browser profile of its own: this function runs in a
# command substitution, and a profile reused across cases carries the
# extension's stored state from one case into the next.
load() {
    : > "$LOG"
    if [ "${2:-}" = "ext" ]; then set -- "$1" "--load-extension=$EXT"; else set -- "$1" ""; fi
    # shellcheck disable=SC2086
    timeout 120 "$CHROMIUM" --headless=new --no-sandbox --disable-gpu \
        --user-data-dir="$(mktemp -d -p "$WORK" profile.XXXXXX)" $2 \
        --host-resolver-rules="MAP pinchat.io 127.0.0.1:8443" --ignore-certificate-errors \
        --virtual-time-budget=20000 --dump-dom "$1" 2>/dev/null
}

has() { printf '%s' "$1" | grep -q "$2" && echo yes || echo no; }

# expect <must|limit> <description> <actual> <wanted>
expect() {
    if [ "$3" = "$4" ]; then
        echo "    ok       $2: $3"
    elif [ "$1" = "limit" ]; then
        echo "    LIMIT    $2: $3 (wanted $4, see SECURITY.md)"
    else
        echo "    FAILED   $2: $3 (wanted $4)"
        FAILED=$((FAILED + 1))
    fi
}

echo "$("$CHROMIUM" --version), extension: $EXT"

echo "[1] no extension: the altered page runs the attacker's handler (harness sanity check)"
DOM=$(load "https://pinchat.io/static/chat.html?$ROOM")
expect must "page loaded" "$(has "$DOM" 'PinChat')" yes
expect must "attacker handler ran" "$(has "$DOM" 'data-attacker="handler-ran"')" yes

echo "[2] official origin, HTML altered for the navigation only"
DOM=$(load "https://pinchat.io/static/chat.html?$ROOM" ext)
expect must "altered markup reached the page" "$(has "$DOM" 'missing.png')" yes
expect must "attacker handler ran" "$(has "$DOM" 'data-attacker="handler-ran"')" no
expect limit "extension warned about the altered HTML" "$(has "$DOM" 'pinchat-integrity-warning-host')" yes

echo "[3] same host on another port, HTML altered for the navigation only"
DOM=$(load "https://pinchat.io:8444/static/chat.html?$ROOM" ext)
expect must "attacker handler ran" "$(has "$DOM" 'data-attacker="handler-ran"')" no
expect must "extension warned" "$(has "$DOM" 'pinchat-integrity-warning-host')" yes
expect must "extension fetched files to verify the foreign origin" \
    "$(grep -q 'mode=cors dest=empty' "$LOG" && echo yes || echo no)" no

echo "[4] control: the extension's own fetch sees the altered HTML"
DOM=$(load "https://pinchat.io:8446/static/chat.html?$ROOM" ext)
expect must "extension warned" "$(has "$DOM" 'pinchat-integrity-warning-host')" yes

for POC in rel-exact rel-multi rel-case; do
    echo "[5:$POC] unsigned stylesheet linked from the altered HTML"
    DOM=$(load "https://pinchat.io/static/chat.html?$ROOM&poc=$POC" ext)
    expect must "stylesheet was requested by the page" \
        "$(grep -q 'evil.css mode=no-cors dest=style' "$LOG" && echo yes || echo no)" yes
    expect must "extension warned" "$(has "$DOM" 'pinchat-integrity-warning-host')" yes
done

echo
if [ "$FAILED" -eq 0 ]; then echo "PASSED (known limits are listed above)"; else echo "FAILED: $FAILED expectation(s)"; fi
exit "$FAILED"
