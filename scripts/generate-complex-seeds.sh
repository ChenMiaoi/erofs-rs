#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# generate-complex-seeds.sh
# Generate more complex EROFS seed images for testing.
#
# Usage:
#   ./scripts/generate-complex-seeds.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
MKFS="${MKFS:-$ROOT_DIR/build/erofs-utils/mkfs/mkfs.erofs}"
SEED_DIR="$ROOT_DIR/corpus/seeds"

if [ ! -x "$MKFS" ]; then
    echo "ERROR: mkfs.erofs not found at $MKFS"
    exit 1
fi

mkdir -p "$SEED_DIR"

# 1. Deep directory tree (5 levels)
TMP_DEEP="$(mktemp -d)"
mkdir -p "$TMP_DEEP/a/b/c/d/e"
printf 'deep file\n' > "$TMP_DEEP/a/b/c/d/e/deep.txt"
printf 'level3\n' > "$TMP_DEEP/a/b/c/level3.txt"
printf 'level1\n' > "$TMP_DEEP/a/level1.txt"
"$MKFS" "$SEED_DIR/deep-tree.erofs" "$TMP_DEEP"
rm -rf "$TMP_DEEP"
echo "Generated: $SEED_DIR/deep-tree.erofs ($(stat -c%s "$SEED_DIR/deep-tree.erofs") bytes)"

# 2. Many small files (100 files)
TMP_MANY="$(mktemp -d)"
for i in $(seq 1 100); do
    printf 'file %d content\n' "$i" > "$TMP_MANY/file$(printf '%03d' $i).txt"
done
"$MKFS" "$SEED_DIR/many-files.erofs" "$TMP_MANY"
rm -rf "$TMP_MANY"
echo "Generated: $SEED_DIR/many-files.erofs ($(stat -c%s "$SEED_DIR/many-files.erofs") bytes)"

# 3. Files with xattrs (extended attributes)
TMP_XATTR="$(mktemp -d)"
printf 'xattr test file\n' > "$TMP_XATTR/xattr-file.txt"
# Set some xattrs using setfattr if available
if command -v setfattr >/dev/null 2>&1; then
    setfattr -n user.test -v "test value" "$TMP_XATTR/xattr-file.txt" 2>/dev/null || true
    setfattr -n user.another -v "another value" "$TMP_XATTR/xattr-file.txt" 2>/dev/null || true
fi
# Also create a file with special characters in name
printf 'special file\n' > "$TMP_XATTR/special- chars.txt"
"$MKFS" "$SEED_DIR/xattr-test.erofs" "$TMP_XATTR"
rm -rf "$TMP_XATTR"
echo "Generated: $SEED_DIR/xattr-test.erofs ($(stat -c%s "$SEED_DIR/xattr-test.erofs") bytes)"

# 4. Mixed content (dirs, files, symlinks, empty files, large files)
TMP_MIXED="$(mktemp -d)"
mkdir -p "$TMP_MIXED/subdir1" "$TMP_MIXED/subdir2/nested"
printf 'regular file\n' > "$TMP_MIXED/regular.txt"
printf '' > "$TMP_MIXED/empty.txt"
# Create a ~16KB file
for i in $(seq 1 1000); do
    printf 'line %d: this is a line of text for testing larger files in erofs\n' "$i"
done > "$TMP_MIXED/large-file.txt"
printf 'nested file\n' > "$TMP_MIXED/subdir2/nested/nested.txt"
# Symlink if supported
if command -v ln >/dev/null 2>&1; then
    ln -s regular.txt "$TMP_MIXED/link-to-regular" 2>/dev/null || true
fi
"$MKFS" "$SEED_DIR/mixed-content.erofs" "$TMP_MIXED"
rm -rf "$TMP_MIXED"
echo "Generated: $SEED_DIR/mixed-content.erofs ($(stat -c%s "$SEED_DIR/mixed-content.erofs") bytes)"

# 5. Unicode filenames
TMP_UNICODE="$(mktemp -d)"
printf 'unicode test\n' > "$TMP_UNICODE/你好.txt"
printf 'emoji test\n' > "$TMP_UNICODE/🎉.txt"
printf 'mixed test\n' > "$TMP_UNICODE/test-日本語.txt"
"$MKFS" "$SEED_DIR/unicode-files.erofs" "$TMP_UNICODE"
rm -rf "$TMP_UNICODE"
echo "Generated: $SEED_DIR/unicode-files.erofs ($(stat -c%s "$SEED_DIR/unicode-files.erofs") bytes)"

echo ""
echo "Complex seed corpus generated in: $SEED_DIR"
echo ""
echo "New seeds:"
ls -la "$SEED_DIR"/*.erofs | grep -v 'empty\|single\|tree\|build-rootfs'
