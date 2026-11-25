#!/usr/bin/env bash
#
# Build store-ready packages for the PinChat Integrity Verifier extensions.
#
# The archive is produced with `git archive` from a committed tree rather than
# from the working directory. Three reasons, all of which matter for an
# extension whose only job is to be a trust anchor:
#
#   1. Reproducible. Anyone with the repository can rebuild the exact bytes
#      that were uploaded and compare the SHA-256 printed below.
#   2. No stray files. Chromium writes extensions/*/_metadata/ when the folder
#      is loaded unpacked, and directories beginning with an underscore are
#      reserved in extensions. `git archive` only sees tracked files, so local
#      build artifacts, editor droppings and ignored paths cannot leak into a
#      published package.
#   3. Layout. `HEAD:extensions/<browser>` puts manifest.json at the root of
#      the zip, which is what both stores require.
#
# Usage:
#   extensions/package.sh              # package HEAD
#   extensions/package.sh <git-ref>    # package a specific commit or tag
#
set -euo pipefail

REF="${1:-HEAD}"
ROOT="$(git rev-parse --show-toplevel)"
OUT="$ROOT/dist"
cd "$ROOT"

fail() { echo "ERROR: $*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

git rev-parse --verify "$REF" >/dev/null 2>&1 || fail "unknown git ref: $REF"

# ---------------------------------------------------------------------------
# Release-pin consistency.
#
# The extension fetches its manifest from
#   raw.githubusercontent.com/<repo>/main/hashes.json.signed
# refuses anything below MIN_KNOWN_SEQUENCE, and until it has verified one
# applies the rules.json it was packaged with. Store review takes days, so
# these have to be right *before* submission: a build whose floor is above
# the manifest on main rejects every manifest it can fetch and ships a
# broken verifier, and one whose floor is below the manifest its packaged
# rules come from lets a fresh install accept an older release.
# ---------------------------------------------------------------------------
read_pin() { # <browser> <const-name>
    git show "$REF:extensions/$1/background.js" \
        | sed -n "s/^const $2 = '\{0,1\}\([^';]*\)'\{0,1\};/\1/p" | head -1
}

CHROME_BRANCH="$(read_pin chrome MANIFEST_BRANCH)"
FIREFOX_BRANCH="$(read_pin firefox MANIFEST_BRANCH)"
CHROME_FLOOR="$(read_pin chrome MIN_KNOWN_SEQUENCE)"
FIREFOX_FLOOR="$(read_pin firefox MIN_KNOWN_SEQUENCE)"

[ "$CHROME_BRANCH" = "main" ] && [ "$FIREFOX_BRANCH" = "main" ] \
    || fail "both builds must read the manifest from main: chrome=$CHROME_BRANCH firefox=$FIREFOX_BRANCH"
[ -n "$CHROME_FLOOR" ] || fail "could not read MIN_KNOWN_SEQUENCE from the chrome background script"
[ "$CHROME_FLOOR" = "$FIREFOX_FLOOR" ] \
    || fail "MIN_KNOWN_SEQUENCE differs: chrome=$CHROME_FLOOR firefox=$FIREFOX_FLOOR"

REF_SEQ="$(git show "$REF:hashes.json.signed" | jq -r '.data.sequence')"
[ "$REF_SEQ" != "null" ] || fail "no signed manifest at $REF"
[ "$(git show "$REF:hashes.json.signed" | jq -r '.data.pages | type')" = "array" ] \
    || fail "the manifest at $REF lists no page scripts: this build could verify nothing with it"
[ "$REF_SEQ" = "$CHROME_FLOOR" ] \
    || fail "floor $CHROME_FLOOR is not the sequence $REF_SEQ of the manifest at $REF, which the packaged rules come from: release the extension with finish-release.sh <tag> <version>"

# The build verifies nothing until main carries its floor. Warn, do not
# fail: main may simply not have been pushed yet.
if MAIN_SEQ="$(git show origin/main:hashes.json.signed 2>/dev/null | jq -r '.data.sequence' 2>/dev/null)" \
    && [[ "$MAIN_SEQ" =~ ^[0-9]+$ ]]; then
    if [ "$MAIN_SEQ" -lt "$CHROME_FLOOR" ]; then
        echo "WARNING: origin/main is at sequence $MAIN_SEQ, below the floor $CHROME_FLOOR of this build." >&2
        echo "         Push main before submitting it, or it verifies nothing." >&2
    fi
else
    echo "WARNING: origin/main not available locally; make sure main carries sequence $CHROME_FLOOR before submitting." >&2
fi

# Version parity. Both stores key auto-update off this number and nothing else.
CHROME_VER="$(git show "$REF:extensions/chrome/manifest.json" | jq -r .version)"
FIREFOX_VER="$(git show "$REF:extensions/firefox/manifest.json" | jq -r .version)"
[ "$CHROME_VER" = "$FIREFOX_VER" ] \
    || fail "manifest version differs: chrome=$CHROME_VER firefox=$FIREFOX_VER"

echo "Packaging version $CHROME_VER from $REF"
echo "  manifest from main, floor $CHROME_FLOOR (packaged rules from sequence $REF_SEQ)"
echo

mkdir -p "$OUT"

for BROWSER in chrome firefox; do
    ZIP="$OUT/pinchat-verifier-$BROWSER-$CHROME_VER.zip"
    rm -f "$ZIP"
    git archive --format=zip "$REF:extensions/$BROWSER" -o "$ZIP"

    # manifest.json has to sit at the archive root or both stores reject it.
    unzip -l "$ZIP" | grep -qE '[[:space:]]manifest\.json$' \
        || fail "manifest.json is not at the root of $ZIP"
    # Belt and braces: the reserved _metadata directory must never ship.
    if unzip -l "$ZIP" | grep -q '_metadata'; then
        fail "$ZIP contains _metadata"
    fi

    printf '%s\n' "$ZIP"
    printf '  sha256 %s\n' "$(sha256sum "$ZIP" | cut -d' ' -f1)"
    printf '  files  %s\n\n' "$(unzip -l "$ZIP" | tail -1 | awk '{print $2}')"
done

echo "Record the SHA-256 values above. After uploading, they are what lets you"
echo "confirm the store is serving the bytes you built."
