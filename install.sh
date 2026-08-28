#!/bin/sh
# lanmoon installer
# Usage:
#   ./install.sh                      # local clone, sudo-copies into place
#   curl -fsSL <raw>/install.sh | sudo bash   # one-liner, downloads lanmoon.py
set -e

OWNER="iggdrassilon"
REPO="lanmoon"
BRANCH="main"
RAW="https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/lanmoon.py"

DEST="/usr/local/bin/lanmoon"

# Locate lanmoon.py: next to this script, or download it.
SRC="$(dirname "$0")/lanmoon.py"
if [ ! -f "$SRC" ]; then
    echo "lanmoon.py not found locally, downloading from ${RAW}"
    SRC="$(mktemp -t lanmoon.XXXXXX.py)"
    curl -fsSL "$RAW" -o "$SRC"
    DOWNLOADED=1
fi

# Pick a copy command that can write into /usr/local/bin.
if [ "$(id -u)" -eq 0 ]; then
    CP="cp"
else
    CP="sudo cp"
fi

$CP "$SRC" "$DEST"
chmod 755 "$DEST"

if [ -n "$DOWNLOADED" ]; then
    rm -f "$SRC"
fi

echo "installed: $DEST"
echo "run with:  sudo lanmoon   (or just: lanmoon)"
