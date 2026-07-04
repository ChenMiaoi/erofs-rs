## Problem

Explain the bug, missing validation, fuzzing gap, or workflow problem first.

## Approach

Describe the change and why this is the conservative fix for EROFS image,
fsck, corpus, or kernel replay behavior.

## User-visible Behavior

List CLI, report, manifest, fixture, CI, or documentation changes. Write "None"
if behavior is intentionally unchanged.

## Tests

Paste the exact commands run and their results.

```text
cargo fmt --check
RUSTFLAGS="-D warnings" cargo check --all-targets
RUSTFLAGS="-D warnings" cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Checklist

- [ ] Patch is focused and avoids unrelated refactors.
- [ ] Generated artifacts from `build/`, `target/`, corpus output, QEMU logs, and local fsck/kernel products are not included.
- [ ] `vendor/linux` and `vendor/erofs-utils` are unchanged, or the PR explains why vendor changes are required.
- [ ] New parsing or mutation logic bounds-checks offsets and lengths and uses explicit little-endian decoding.
- [ ] Checksum repair or preservation behavior is intentional and covered by tests or report output.
- [ ] Kernel replay or malformed-image policy changes were tested with the relevant `make smoke*` target, or the PR explains why not.
- [ ] Commits use kernel-style subjects and include `Signed-off-by:`.
