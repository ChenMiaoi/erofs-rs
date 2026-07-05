#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# generate-seed-matrix.sh
# Generate a feature matrix of EROFS seed images for fuzzing.
#
# Usage:
#   ./scripts/generate-seed-matrix.sh
#   ./scripts/generate-seed-matrix.sh --block-size 1024,4096 --compression none,lz4

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
MKFS="${MKFS:-$ROOT_DIR/build/erofs-utils/mkfs/mkfs.erofs}"
OUT_DIR="$ROOT_DIR/corpus/seeds/matrix"
BLOCK_SIZES="512,1024,2048,4096"
COMPRESSIONS="none,lz4,lz4hc,zstd"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --output-dir DIR        Output directory (default: corpus/seeds/matrix)
  --block-size LIST       Comma-separated block sizes (default: 512,1024,2048,4096)
  --compression LIST      Comma-separated compressors (default: none,lz4,lz4hc,zstd)
  -h, --help              Show this help
EOF
}

need_value() {
    local option="$1"
    local value="${2:-}"

    if [ -z "$value" ]; then
        echo "ERROR: $option requires a value" >&2
        usage >&2
        exit 1
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-dir)
            need_value "$1" "${2:-}"
            OUT_DIR="$2"
            shift 2
            ;;
        --block-size)
            need_value "$1" "${2:-}"
            BLOCK_SIZES="$2"
            shift 2
            ;;
        --compression)
            need_value "$1" "${2:-}"
            COMPRESSIONS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ ! -x "$MKFS" ]; then
    echo "ERROR: mkfs.erofs not found at $MKFS" >&2
    echo "Build erofs-utils first: make erofs-utils" >&2
    exit 1
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_array() {
    local first=1
    printf '['
    for item in "$@"; do
        if [ "$first" -eq 0 ]; then
            printf ', '
        fi
        first=0
        printf '"%s"' "$(json_escape "$item")"
    done
    printf ']'
}

mkfs_version() {
    "$MKFS" -V 2>&1 | head -n1
}

git_revision() {
    git -C "$1" rev-parse HEAD 2>/dev/null || true
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

append_manifest() {
    local first_entry="$1"
    local seed="$2"
    local path="$3"
    local sha256="$4"
    local source_profile="$5"
    local requirement="$6"
    local mkfs_command="$7"
    shift 7
    local features=("$@")

    if [ "$first_entry" -eq 0 ]; then
        printf ',\n' >> "$MANIFEST"
    fi
    {
        printf '  {\n'
        printf '    "seed": "%s",\n' "$(json_escape "$seed")"
        printf '    "path": "%s",\n' "$(json_escape "$path")"
        printf '    "sha256": "%s",\n' "$sha256"
        printf '    "source_profile": "%s",\n' "$(json_escape "$source_profile")"
        printf '    "requirement": "%s",\n' "$(json_escape "$requirement")"
        printf '    "mkfs": "%s",\n' "$(json_escape "$mkfs_command")"
        printf '    "mkfs_version": "%s",\n' "$(json_escape "$MKFS_VERSION")"
        printf '    "erofs_utils_git": "%s",\n' "$(json_escape "$EROFS_UTILS_GIT")"
        printf '    "features": '
        json_array "${features[@]}"
        printf '\n'
        printf '  }'
    } >> "$MANIFEST"
}

make_basic_root() {
    local root="$1"
    mkdir -p "$root/bin" "$root/etc" "$root/var/log"
    printf 'hello from seed matrix\n' > "$root/README.txt"
    printf 'PATH=/bin\n' > "$root/etc/profile"
    printf '#!/bin/sh\necho matrix\n' > "$root/bin/matrix.sh"
    chmod 0755 "$root/bin/matrix.sh"
    printf 'log entry\n' > "$root/var/log/boot.log"
}

make_large_dir_root() {
    local root="$1"
    mkdir -p "$root/large"
    for i in $(seq 1 320); do
        printf 'large dir file %03d\n' "$i" > "$root/large/file$(printf '%03d' "$i").txt"
    done
}

make_xattr_root() {
    local root="$1"
    mkdir -p "$root"
    printf 'xattr matrix\n' > "$root/xattr.txt"
    if ! command -v setfattr >/dev/null 2>&1; then
        return 1
    fi
    setfattr -n user.matrix -v "seed-matrix" "$root/xattr.txt" 2>/dev/null
}

make_long_xattr_prefix_root() {
    local root="$1"
    mkdir -p "$root"
    printf 'long prefix xattr matrix\n' > "$root/long-prefix.txt"
    if ! command -v setfattr >/dev/null 2>&1; then
        return 1
    fi
    setfattr -n user.matrix.longprefix.alpha -v "alpha" "$root/long-prefix.txt" \
        2>/dev/null || return 1
    setfattr -n user.matrix.longprefix.beta -v "beta" "$root/long-prefix.txt" \
        2>/dev/null
}

make_shared_xattr_root() {
    local root="$1"
    mkdir -p "$root"
    printf 'shared xattr matrix a\n' > "$root/shared-a.txt"
    printf 'shared xattr matrix b\n' > "$root/shared-b.txt"
    if ! command -v setfattr >/dev/null 2>&1; then
        return 1
    fi
    for file in "$root/shared-a.txt" "$root/shared-b.txt"; do
        setfattr -n user.matrix.shared -v "shared-value" "$file" \
            2>/dev/null || return 1
        setfattr -n user.matrix.shared_prefix -v "shared-prefix-value" "$file" \
            2>/dev/null || return 1
    done
}

make_acl_root() {
    local root="$1"
    mkdir -p "$root"
    printf 'acl matrix\n' > "$root/acl.txt"
    if ! command -v setfacl >/dev/null 2>&1; then
        return 1
    fi
    setfacl -m u:0:r "$root/acl.txt" 2>/dev/null
}

make_special_root() {
    local root="$1"
    mkdir -p "$root"
    printf 'hardlink target\n' > "$root/original.txt"
    ln "$root/original.txt" "$root/hardlink.txt" 2>/dev/null || true
    ln -s original.txt "$root/symlink.txt" 2>/dev/null || true
    mkfifo "$root/fifo" 2>/dev/null || true
}

make_socket_root() {
    local root="$1"
    mkdir -p "$root"
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi
    python3 - "$root/socket" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX)
try:
    sock.bind(sys.argv[1])
finally:
    sock.close()
PY
}

make_device_root() {
    local root="$1"
    mkdir -p "$root"
    if ! command -v mknod >/dev/null 2>&1; then
        return 1
    fi
    mknod "$root/null" c 1 3 2>/dev/null
}

run_mkfs() {
    local seed="$1"
    local source="$2"
    local source_profile="$3"
    local requirement="$4"
    local features_csv="$5"
    shift 5
    local args=("$@")
    local image="$OUT_DIR/$seed.erofs"
    local log="$OUT_DIR/$seed.mkfs.log"
    local cmd=("$MKFS" "${args[@]}" "$image" "$source")

    if "${cmd[@]}" > "$log" 2>&1; then
        local sha
        sha="$(sha256_file "$image")"
        IFS=',' read -r -a features <<< "$features_csv"
        append_manifest "$FIRST_ENTRY" "$seed.erofs" "$image" "$sha" "$source_profile" \
            "$requirement" "$MKFS ${args[*]} $image <source:${source_profile}>" "${features[@]}"
        FIRST_ENTRY=0
        rm -f "$log"
        echo "Generated: $image ($(stat -c%s "$image") bytes)"
    else
        echo "WARN: skipped $seed (mkfs failed; see $log)" >&2
        rm -f "$image"
    fi
}

mkdir -p "$OUT_DIR"
MANIFEST="$OUT_DIR/manifest.json"
MKFS_VERSION="$(mkfs_version)"
EROFS_UTILS_GIT="$(git_revision "$ROOT_DIR/vendor/erofs-utils")"
FIRST_ENTRY=1

printf '[\n' > "$MANIFEST"

IFS=',' read -r -a BLOCK_SIZE_ARRAY <<< "$BLOCK_SIZES"
for block_size in "${BLOCK_SIZE_ARRAY[@]}"; do
    tmp="$(mktemp -d)"
    make_basic_root "$tmp"
    run_mkfs "block-${block_size}-plain" "$tmp" "basic" \
        "required" \
        "block_size:${block_size},compression:none,layout:plain,dir_size:small" \
        "-b${block_size}"
    rm -rf "$tmp"
done

IFS=',' read -r -a COMPRESSION_ARRAY <<< "$COMPRESSIONS"
for compression in "${COMPRESSION_ARRAY[@]}"; do
    [ "$compression" = "none" ] && continue
    tmp="$(mktemp -d)"
    make_basic_root "$tmp"
    run_mkfs "compressed-${compression}-4k" "$tmp" "basic" \
        "required" \
        "block_size:4096,compression:${compression},layout:plain,dir_size:small" \
        "-b4096" "-z${compression}"
    rm -rf "$tmp"
done

tmp="$(mktemp -d)"
make_large_dir_root "$tmp"
run_mkfs "large-dir-multiblock-4k" "$tmp" "large_dir" \
    "required" \
    "block_size:4096,compression:none,layout:plain,dir_size:multiblock" \
    "-b4096"
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_xattr_root "$tmp"; then
    run_mkfs "xattr-user-4k" "$tmp" "xattr_user" \
        "best_effort" \
        "block_size:4096,compression:none,xattrs:user,layout:plain,dir_size:small" \
        "-b4096"
else
    echo "WARN: skipped xattr-user-4k (setfattr unavailable or user xattr failed)" >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_long_xattr_prefix_root "$tmp"; then
    run_mkfs "xattr-long-prefix-4k" "$tmp" "xattr_long_prefix" \
        "best_effort" \
        "block_size:4096,compression:none,xattrs:user,xattrs:long_prefix,layout:plain,dir_size:small" \
        "-b4096" "--xattr-prefix=user.matrix.longprefix."
else
    echo "WARN: skipped xattr-long-prefix-4k (setfattr unavailable or long-prefix xattr failed)" \
        >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_shared_xattr_root "$tmp"; then
    run_mkfs "xattr-shared-4k" "$tmp" "xattr_shared" \
        "best_effort" \
        "block_size:4096,compression:none,xattrs:user,xattrs:shared,layout:plain,dir_size:small" \
        "-b4096"
else
    echo "WARN: skipped xattr-shared-4k (setfattr unavailable or shared xattr failed)" >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_acl_root "$tmp"; then
    run_mkfs "acl-posix-4k" "$tmp" "acl_posix" \
        "best_effort" \
        "block_size:4096,compression:none,acl:posix,layout:plain,dir_size:small" \
        "-b4096"
else
    echo "WARN: skipped acl-posix-4k (setfacl unavailable or POSIX ACL failed)" >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
make_special_root "$tmp"
run_mkfs "hardlink-fifo-symlink-4k" "$tmp" "special_files" \
    "required" \
    "block_size:4096,compression:none,hardlink:true,fifo:true,symlink:true,layout:plain" \
    "-b4096"
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_socket_root "$tmp"; then
    run_mkfs "socket-4k" "$tmp" "socket" \
        "best_effort" \
        "block_size:4096,compression:none,socket:true,layout:plain,dir_size:small" \
        "-b4096"
else
    echo "WARN: skipped socket-4k (python3 unavailable or socket creation failed)" >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
if make_device_root "$tmp"; then
    run_mkfs "device-node-4k" "$tmp" "device_node" \
        "best_effort" \
        "block_size:4096,compression:none,device:char,layout:plain,dir_size:small" \
        "-b4096"
else
    echo "WARN: skipped device-node-4k (mknod unavailable or not permitted)" >&2
fi
rm -rf "$tmp"

tmp="$(mktemp -d)"
make_basic_root "$tmp"
run_mkfs "chunked-4k" "$tmp" "basic" \
    "required" \
    "block_size:4096,compression:none,layout:chunked,chunksize:4096" \
    "-b4096" "--chunksize=4096"
rm -rf "$tmp"

tmp="$(mktemp -d)"
make_basic_root "$tmp"
run_mkfs "fragment-packed-lz4-4k" "$tmp" "basic" \
    "required" \
    "block_size:4096,compression:lz4,layout:fragment,packed_inode:true" \
    "-b4096" "-zlz4" "-Efragments"
rm -rf "$tmp"

printf '\n]\n' >> "$MANIFEST"

echo ""
echo "Seed matrix generated in: $OUT_DIR"
echo "Manifest: $MANIFEST"
