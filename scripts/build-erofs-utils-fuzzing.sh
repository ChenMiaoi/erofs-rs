#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# build-erofs-utils-fuzzing.sh
# Reproducible script to build erofs-utils with fuzzing enabled.
#
# Usage:
#   ./scripts/build-erofs-utils-fuzzing.sh
#
# Requirements:
#   - clang (GCC does not support -fsanitize=address,fuzzer-no-link)
#   - autoconf, automake, libtool, pkg-config
#
# The fuzzer binary will be at:
#   build/erofs-utils-fuzz/fsck/fuzz_erofsfsck

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EROFS_UTILS="$ROOT_DIR/vendor/erofs-utils"
BUILD_DIR="$ROOT_DIR/build/erofs-utils-fuzz"

# Require clang for fuzzing support
if ! command -v clang >/dev/null 2>&1; then
    echo "ERROR: clang is required for fuzzing build but not found."
    echo "Install with: sudo apt install clang llvm"
    exit 1
fi

CLANG_VERSION="$(clang --version | head -1)"
echo "Using compiler: $CLANG_VERSION"

# Run autogen in the source tree to generate configure
if [ ! -x "$EROFS_UTILS/configure" ]; then
    echo "Running autogen.sh in $EROFS_UTILS..."
    (cd "$EROFS_UTILS" && ./autogen.sh)
fi

# Clean previous build artifacts to avoid autotools state issues
if [ -f "$BUILD_DIR/Makefile" ]; then
    echo "Cleaning previous fuzzing build..."
    (cd "$BUILD_DIR" && make distclean 2>/dev/null || true)
fi

mkdir -p "$BUILD_DIR"

echo "Configuring with --enable-fuzzing (CC=clang)..."
cd "$BUILD_DIR"
CC=clang "$EROFS_UTILS/configure" --disable-fuse --enable-fuzzing

echo "Building..."
make -j"$(nproc)"

FUZZER_PATH="$BUILD_DIR/fsck/fuzz_erofsfsck"
if [ -x "$FUZZER_PATH" ]; then
    echo ""
    echo "SUCCESS: Fuzzer built at: $FUZZER_PATH"
    echo ""
    echo "Quick test:"
    echo "  $FUZZER_PATH -help=1 | head -20"
else
    echo "ERROR: Fuzzer binary not found at $FUZZER_PATH"
    exit 1
fi
