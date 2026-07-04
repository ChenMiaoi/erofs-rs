#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# generate-seed-corpus.sh
# Generate a minimal seed corpus for EROFS fuzzing.
#
# Usage:
#   ./scripts/generate-seed-corpus.sh
#
# Output:
#   corpus/seeds/empty.erofs    - empty filesystem
#   corpus/seeds/single.erofs   - single file with "hello"
#   corpus/seeds/tree.erofs     - directory tree with nested files

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
MKFS="${MKFS:-$ROOT_DIR/build/erofs-utils/mkfs/mkfs.erofs}"
SEED_DIR="$ROOT_DIR/corpus/seeds"

if [ ! -x "$MKFS" ]; then
    echo "ERROR: mkfs.erofs not found at $MKFS"
    echo "Build erofs-utils first: make erofs-utils"
    exit 1
fi

mkdir -p "$SEED_DIR"

# 1. Empty filesystem
TMP_EMPTY="$(mktemp -d)"
"$MKFS" "$SEED_DIR/empty.erofs" "$TMP_EMPTY"
rm -rf "$TMP_EMPTY"
echo "Generated: $SEED_DIR/empty.erofs ($(stat -c%s "$SEED_DIR/empty.erofs") bytes)"

# 2. Single file
TMP_SINGLE="$(mktemp -d)"
printf 'hello\n' > "$TMP_SINGLE/a.txt"
"$MKFS" "$SEED_DIR/single.erofs" "$TMP_SINGLE"
rm -rf "$TMP_SINGLE"
echo "Generated: $SEED_DIR/single.erofs ($(stat -c%s "$SEED_DIR/single.erofs") bytes)"

# 3. Directory tree with nested directories and files
TMP_TREE="$(mktemp -d)"
mkdir -p "$TMP_TREE/dir1/subdir"
printf 'root file\n' > "$TMP_TREE/root.txt"
printf 'dir1 file\n' > "$TMP_TREE/dir1/file1.txt"
printf 'subdir file\n' > "$TMP_TREE/dir1/subdir/file2.txt"
mkdir -p "$TMP_TREE/dir2"
printf 'dir2 file\n' > "$TMP_TREE/dir2/file3.txt"
"$MKFS" "$SEED_DIR/tree.erofs" "$TMP_TREE"
rm -rf "$TMP_TREE"
echo "Generated: $SEED_DIR/tree.erofs ($(stat -c%s "$SEED_DIR/tree.erofs") bytes)"

# 4. Copy the existing build rootfs as a reference
if [ -f "$ROOT_DIR/build/rootfs.erofs" ]; then
    cp "$ROOT_DIR/build/rootfs.erofs" "$SEED_DIR/build-rootfs.erofs"
    echo "Copied:    $SEED_DIR/build-rootfs.erofs ($(stat -c%s "$SEED_DIR/build-rootfs.erofs") bytes)"
fi

echo ""
echo "Seed corpus generated in: $SEED_DIR"
echo ""
echo "Verify with dump.erofs:"
echo "  ./build/erofs-utils/dump/dump.erofs $SEED_DIR/single.erofs"
