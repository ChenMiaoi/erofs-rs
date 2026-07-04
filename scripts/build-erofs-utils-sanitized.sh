#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# Build erofs-utils command-line tools with sanitizer instrumentation.
#
# Output:
#   build/erofs-utils-sanitized/mkfs/mkfs.erofs
#   build/erofs-utils-sanitized/fsck/fsck.erofs
#   build/erofs-utils-sanitized/dump/dump.erofs

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EROFS_UTILS="$ROOT_DIR/vendor/erofs-utils"
BUILD_DIR="$ROOT_DIR/build/erofs-utils-sanitized"

if ! command -v clang >/dev/null 2>&1; then
    echo "ERROR: clang is required for sanitizer builds but was not found."
    echo "Install with: sudo apt install clang llvm"
    exit 1
fi

if [ ! -x "$EROFS_UTILS/configure" ]; then
    echo "Running autogen.sh in $EROFS_UTILS..."
    (cd "$EROFS_UTILS" && ./autogen.sh)
fi

if [ -f "$BUILD_DIR/Makefile" ]; then
    echo "Cleaning previous sanitizer build..."
    (cd "$BUILD_DIR" && make distclean 2>/dev/null || true)
fi

mkdir -p "$BUILD_DIR"

SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

echo "Configuring sanitizer build with clang..."
cd "$BUILD_DIR"
CC=clang CFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    "$EROFS_UTILS/configure" --disable-fuse

echo "Building sanitizer-instrumented erofs-utils..."
make -j"$(nproc)"

for tool in mkfs/mkfs.erofs fsck/fsck.erofs dump/dump.erofs; do
    if [ ! -x "$BUILD_DIR/$tool" ]; then
        echo "ERROR: expected sanitizer tool missing: $BUILD_DIR/$tool"
        exit 1
    fi
done

echo "SUCCESS: sanitizer erofs-utils tools built in $BUILD_DIR"
