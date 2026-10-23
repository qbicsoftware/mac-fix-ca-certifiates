#!/usr/bin/env bash
# =============================================================================
# install.sh - fetch fix-certificates.sh and make it executable.
#
# Usage:
#   ./install.sh                 # install into the current directory
#   ./install.sh /some/dir       # install into another directory
#   curl -fsSL <raw>/install.sh | bash
#
# Environment overrides:
#   REPO=qbicsoftware/mac-fix-ca-certifiates
#   BRANCH=main
#   GITHUB_RAW=https://raw.githubusercontent.com/<repo>/<branch>
# =============================================================================
set -euo pipefail

REPO="${REPO:-qbicsoftware/mac-fix-ca-certifiates}"
BRANCH="${BRANCH:-main}"
FILE="fix-certificates.sh"
BASE="${GITHUB_RAW:-https://raw.githubusercontent.com/$REPO/$BRANCH}"
URL="$BASE/$FILE"

TARGET_DIR="${1:-$PWD}"

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }

[ -d "$TARGET_DIR" ]  || die "no such directory: $TARGET_DIR"
[ -w "$TARGET_DIR" ]  || die "directory is not writable: $TARGET_DIR"

# --- pick a downloader -------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --max-time 60 "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O - --timeout=60 "$1"; }
else
    die "neither curl nor wget is available"
fi

say "Fetching $URL"
tmp="$(mktemp "${TMPDIR:-/tmp}/fix-certificates.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
fetch "$URL" > "$tmp" || die "download failed"

# --- make sure we really got the script and not an error page ----------------
first_line="$(head -n 1 "$tmp" 2>/dev/null || true)"
case "$first_line" in
    '#!'*) ;;
    *) die "downloaded file is not a shell script (got: ${first_line:-<empty>})" ;;
esac
grep -q 'eMudhra' "$tmp" || die "downloaded file does not look like $FILE"
bash -n "$tmp" 2>/dev/null || die "downloaded script has a syntax error"

# --- install -----------------------------------------------------------------
dest="$TARGET_DIR/$FILE"
if [ -e "$dest" ]; then
    say "Overwriting existing $dest"
fi
cat "$tmp" > "$dest"
chmod +x "$dest"

say "Installed $dest"
if command -v shasum >/dev/null 2>&1; then
    say "sha256: $(shasum -a 256 "$dest" | awk '{print $1}')"
fi

say ""
say "Next steps:"
say "  cd $TARGET_DIR"
say "  ./$FILE assess        # read-only report"
say "  ./$FILE apply         # apply the fixes"
