#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
set -euo pipefail

# Exercise erofs-utils against valid and malformed EROFS images.
#
# This is a tool-safety smoke, not a proof of correctness.  Normal non-zero
# exits are allowed for malformed artifacts, while timeouts, signal exits, and
# sanitizer diagnostics fail the run.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

MKFS="${MKFS:-$ROOT_DIR/build/erofs-utils/mkfs/mkfs.erofs}"
FSCK="${FSCK:-$ROOT_DIR/build/erofs-utils/fsck/fsck.erofs}"
DUMP="${DUMP:-$ROOT_DIR/build/erofs-utils/dump/dump.erofs}"
INPUT_DIR="${INPUT_DIR:-$ROOT_DIR/corpus/seeds}"
ARTIFACT_DIRS="${ARTIFACT_DIRS:-}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/build/erofs-utils-safety}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-10s}"
MAX_IMAGES="${MAX_IMAGES:-200}"

for tool in timeout "$MKFS" "$FSCK" "$DUMP"; do
    if ! command -v "$tool" >/dev/null 2>&1 && [ ! -x "$tool" ]; then
        echo "ERROR: required tool not found or executable: $tool"
        exit 1
    fi
done

mkdir -p "$LOG_DIR"

SANITIZER_RE='AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|MemorySanitizer|runtime error:'
LAST_RC=0

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

safe_name() {
    basename "$1" | tr -c 'A-Za-z0-9._-' '_'
}

run_tool() {
    local mode="$1"
    local name="$2"
    local log="$3"
    shift 3

    set +e
    ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1}" \
        timeout "$TOOL_TIMEOUT" "$@" >"$log" 2>&1
    LAST_RC=$?
    set -e

    if [ "$LAST_RC" -eq 124 ]; then
        sed -n '1,80p' "$log" >&2 || true
        fail "$name timed out after $TOOL_TIMEOUT"
    fi

    if [ "$LAST_RC" -ge 128 ]; then
        sed -n '1,120p' "$log" >&2 || true
        fail "$name exited due to signal or sanitizer abort (rc=$LAST_RC)"
    fi

    if grep -Eiq "$SANITIZER_RE" "$log"; then
        sed -n '1,160p' "$log" >&2 || true
        fail "$name produced sanitizer diagnostics"
    fi

    if [ "$mode" = "require_success" ] && [ "$LAST_RC" -ne 0 ]; then
        sed -n '1,120p' "$log" >&2 || true
        fail "$name failed on a valid image (rc=$LAST_RC)"
    fi

    printf '%-36s rc=%s log=%s\n' "$name" "$LAST_RC" "$log"
}

echo "== erofs-utils tool safety smoke =="
echo "mkfs: $MKFS"
echo "fsck: $FSCK"
echo "dump: $DUMP"
echo "timeout: $TOOL_TIMEOUT"
echo "logs: $LOG_DIR"

TMP_SRC="$(mktemp -d)"
trap 'rm -rf "$TMP_SRC"' EXIT

mkdir -p "$TMP_SRC/dir"
printf 'hello from erofs-utils safety smoke\n' >"$TMP_SRC/dir/hello.txt"
printf 'root file\n' >"$TMP_SRC/root.txt"

HEALTH_IMG="$LOG_DIR/health.erofs"
run_tool require_success "mkfs health image" "$LOG_DIR/mkfs-health.log" \
    "$MKFS" "$HEALTH_IMG" "$TMP_SRC"
run_tool require_success "fsck health image" "$LOG_DIR/fsck-health.log" \
    "$FSCK" "$HEALTH_IMG"
run_tool require_success "dump health image" "$LOG_DIR/dump-health.log" \
    "$DUMP" -s "$HEALTH_IMG"

image_count=0
fsck_rejections=0
dump_rejections=0

scan_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo "Skipping missing image directory: $dir"
        return
    fi

    while IFS= read -r -d '' image; do
        if [ "$image_count" -ge "$MAX_IMAGES" ]; then
            return
        fi

        image_count=$((image_count + 1))
        image_id="$(printf '%04d-%s' "$image_count" "$(safe_name "$image")")"

        run_tool allow_failure "fsck artifact $image_id" \
            "$LOG_DIR/fsck-$image_id.log" "$FSCK" "$image"
        if [ "$LAST_RC" -ne 0 ]; then
            fsck_rejections=$((fsck_rejections + 1))
        fi

        run_tool allow_failure "dump artifact $image_id" \
            "$LOG_DIR/dump-$image_id.log" "$DUMP" -s "$image"
        if [ "$LAST_RC" -ne 0 ]; then
            dump_rejections=$((dump_rejections + 1))
        fi
    done < <(find "$dir" -type f -name '*.erofs' -print0 | sort -z)
}

scan_dir "$INPUT_DIR"
for dir in $ARTIFACT_DIRS; do
    scan_dir "$dir"
done

cat >"$LOG_DIR/summary.txt" <<EOF
erofs-utils safety smoke: passed
images checked: $image_count
fsck rejections: $fsck_rejections
dump rejections: $dump_rejections
tool crashes: 0
tool timeouts: 0
sanitizer findings: 0
EOF

cat "$LOG_DIR/summary.txt"
