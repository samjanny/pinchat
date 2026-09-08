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
#   raw.githubusercontent.com/<repo>/<GITHUB_TAG>/hashes.json.signed
# and refuses anything below MIN_KNOWN_SEQUENCE. Store review takes days, so
# these have to be right *before* submission: a build whose tag does not exist
# yet, or whose floor is above the sequence at that tag, rejects every manifest
# it can fetch and ships a permanently broken verifier.
# ---------------------------------------------------------------------------
read_pin() { # <browser> <const-name>
    git show "$REF:extensions/$1/background.js" \
        | sed -n "s/^const $2 = '\{0,1\}\([^';]*\)'\{0,1\};/\1/p" | head -1
}

CHROME_TAG="$(read_pin chrome GITHUB_TAG)"
FIREFOX_TAG="$(read_pin firefox GITHUB_TAG)"
CHROME_FLOOR="$(read_pin chrome MIN_KNOWN_SEQUENCE)"
FIREFOX_FLOOR="$(read_pin firefox MIN_KNOWN_SEQUENCE)"

[ -n "$CHROME_TAG" ] || fail "could not read GITHUB_TAG from the chrome background script"
[ "$CHROME_TAG" = "$FIREFOX_TAG" ] \
    || fail "GITHUB_TAG differs: chrome=$CHROME_TAG firefox=$FIREFOX_TAG"
[ "$CHROME_FLOOR" = "$FIREFOX_FLOOR" ] \
    || fail "MIN_KNOWN_SEQUENCE differs: chrome=$CHROME_FLOOR firefox=$FIREFOX_FLOOR"

git rev-parse --verify "$CHROME_TAG^{commit}" >/dev/null 2>&1 \
    || fail "GITHUB_TAG $CHROME_TAG does not exist locally. Cut and push the release tag first."

TAG_SEQ="$(git show "$CHROME_TAG:hashes.json.signed" | jq -r '.data.sequence')"
[ "$TAG_SEQ" != "null" ] || fail "no signed manifest at $CHROME_TAG"
[ "$TAG_SEQ" -ge "$CHROME_FLOOR" ] \
    || fail "floor $CHROME_FLOOR is above sequence $TAG_SEQ at $CHROME_TAG: this build would reject every manifest it can fetch"

# Version parity. Both stores key auto-update off this number and nothing else.
CHROME_VER="$(git show "$REF:extensions/chrome/manifest.json" | jq -r .version)"
FIREFOX_VER="$(git show "$REF:extensions/firefox/manifest.json" | jq -r .version)"
[ "$CHROME_VER" = "$FIREFOX_VER" ] \
    || fail "manifest version differs: chrome=$CHROME_VER firefox=$FIREFOX_VER"

echo "Packaging version $CHROME_VER from $REF"
echo "  manifest pin: $CHROME_TAG (sequence $TAG_SEQ, floor $CHROME_FLOOR)"
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
