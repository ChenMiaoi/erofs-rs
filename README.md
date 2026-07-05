# erofs-rs

A Rust-based advanced fuzzing and image injection toolkit for the
[EROFS](https://erofs.docs.kernel.org/) filesystem.

This repository is a complete Rust rewrite of the original Python tooling. It
exposes the same functionality through a single, composable CLI and a reusable
library crate, making it suitable for fuzzing campaigns, regression testing, and
standalone malformed-image construction.

## Features

- **Structured image injection** by named field (`superblock.root_nid`,
  `inode.mode`, `dirent.file_type`, …) or raw offset/width.
- **One-field-at-a-time mutation** for superblock, inode, and directory-entry
  structures, with optional superblock checksum recalculation.
- **fsck.erofs integration** and consistent result classification.
- **Corpus management**: deduplicate artifacts by SHA-256 and classify them into
  behavior-based categories with a summary report.
- **Mutation-based fuzzer** that runs random combinations of bit/byte/word
  mutations and structured field mutations against a seed corpus, with
  per-artifact JSON sidecars for reproduction.
- **Image introspection** (`info`) to print superblock, inode, and dirent
  metadata.

## Mapping from Python scripts

| Original Python script | Rust command |
|---|---|
| `erofs-inject.py` | `erofs-rs inject` |
| `erofs-mutate-superblock.py` | `erofs-rs mutate --target superblock` |
| `erofs-mutate-inode.py` | `erofs-rs mutate --target inode` |
| `erofs-mutate-dirent.py` | `erofs-rs mutate --target dirent` |
| `erofs-corpus-manager.py` | `erofs-rs corpus` |
| `erofs_utils.py` | `src/lib.rs` modules (`image`, `checksum`, `inode`, `dirent`, `fsck`) |
| `erofs-recalc-checksum.py` | `erofs-rs inject --fix-checksum` / `erofs-rs info --fix-checksum` |

## Building

Requires a stable Rust toolchain with Rust 2024 edition support (1.85+
recommended).

```bash
cargo build --release
```

The binary is produced at `target/release/erofs-rs`.

## Vendor submodules

This repository includes two Git submodules, both cloned with `--depth=1`:

- `vendor/erofs-utils` — EROFS userspace utilities (`fsck.erofs`, `dump.erofs`, fuzzer).
- `vendor/linux` — upstream Linux kernel tree (`https://github.com/torvalds/linux.git`).

After cloning this repo, initialize the submodules:

```bash
git submodule update --init --depth=1
```

### Building `fsck.erofs`

```bash
make erofs-utils
# Binary will be at build/erofs-utils/fsck/fsck.erofs
```

For the integration tests, copy or symlink the binary into the fixture directory:

```bash
cp build/erofs-utils/fsck/fsck.erofs tests/fixtures/fsck.erofs
```

## Running tests

```bash
cargo test
```

Integration tests use the seed images under `tests/fixtures/` and the
`fsck.erofs` binary at `tests/fixtures/fsck.erofs`.

## CLI usage

### `info` – inspect an image

```bash
erofs-rs info --input corpus/seeds/single.erofs
```

### `inject` – deterministic mutation

Named field:

```bash
erofs-rs inject \
    --input corpus/seeds/single.erofs \
    --output /tmp/mutated.erofs \
    --field superblock.root_nid \
    --value 0x1234 \
    --fix-checksum \
    --manifest /tmp/mutated.manifest
```

Raw offset:

```bash
erofs-rs inject \
    --input corpus/seeds/single.erofs \
    --output /tmp/mutated.erofs \
    --offset 0x40E --width u16 \
    --value 0xFFFF \
    --fix-checksum
```

### `mutate` – structured mutations

```bash
erofs-rs mutate \
    --input corpus/seeds/single.erofs \
    --output-dir /tmp/mutated/superblock/ \
    --manifest /tmp/mutated/superblock/manifest.txt \
    --fsck build/erofs-utils/fsck/fsck.erofs \
    --target superblock \
    --fix-checksum
```

`--target` accepts `superblock`, `inode`, `dirent`, `xattr`, `chunk`,
`compression`, `fragment`, `device`, `cross`, or `all`.
`mutate` runs `fsck.erofs` for each generated image and accepts the same
execution-limit flags as `fuzz`: `--exec-timeout`, `--max-output-bytes`,
`--rss-limit-mb`, and `--no-kill-process-group`.

### `corpus` – corpus management

```bash
erofs-rs corpus \
    --input-dir /tmp/mutated/ \
    --output-dir /tmp/artifacts/ \
    --report /tmp/artifacts/report.txt
```

`corpus` defaults to `--mode hash`, which reads mutation manifests, deduplicates
by full SHA-256, and writes artifacts into fsck classification directories. Use
`--mode classification` to preserve every manifest-listed artifact while still
grouping by classification. Use `--mode coverage` for inputs that have already
been selected by a coverage-guided engine such as `cargo fuzz cmin`; it writes
unique units under `coverage-interesting/` and reports total files, unique
hashes, coverage-interesting units, crashes, and timeouts. Coverage mode also
writes `coverage-manifest.json` in the output directory with a stable schema,
per-target input/collected/duplicate counts, source paths, copied artifact
paths, sizes, lifecycle buckets, and full SHA-256 digests. For `cargo-fuzz`
layouts such as `<target>/corpus/<unit>`, the manifest records `<target>` so
weekly `cmin` output can be reviewed and imported without losing provenance.
Reports also include lifecycle buckets such as `queue/userspace`,
`rejects/checksum`, `crashes/userspace`, and `timeouts/userspace` so long-running
campaigns can separate expected rejects from actionable triage queues without
changing the classification directory layout.

### `fuzz` – mutation-based fuzzing

```bash
erofs-rs fuzz \
    --input-dir corpus/seeds/ \
    --output-dir /tmp/fuzz-artifacts/ \
    --max-time 60 \
    --exec-timeout 30 \
    --max-output-bytes 1048576 \
    --rss-limit-mb 512 \
    --seed 12345 \
    --fsck build/erofs-utils/fsck/fsck.erofs
```

If `--seed` is omitted, the generated fuzzing report records the seed that was
used so the run can be replayed.

`--strategy mutation` is the only executable CLI strategy today. The reserved
`structured`, `libfuzzer`, and `replay` strategy names fail with an explicit
"not implemented" error instead of silently falling back to mutation.

Each unique `fuzz_*.erofs` artifact is written with a matching JSON sidecar and
captured fsck output files. The sidecar records the tool version, RNG seed,
iteration, strategy, seed and artifact SHA-256 digests, mutation records, fsck
command, dump summary command, kernel replay command, git revisions when
available, classification, exit status, timeout state, and output truncation
flags. It also records a deterministic signature used by the text report to
bucket actionable findings by classification and first meaningful tool output
line. `--exec-timeout` controls the per-artifact fsck timeout, and
`--max-output-bytes` caps the retained bytes for each fsck output stream. On
Unix, timed-out fsck executions run in a dedicated process group and the whole
group is killed by default; use `--no-kill-process-group` only when debugging
process lifetime issues manually. `--rss-limit-mb` applies a per-execution
address-space limit on Unix.

When stdout is an interactive terminal, `fuzz` opens a post-run TUI dashboard
with the RNG seed, campaign totals, actionable finding count, classification
mix, recent representative runs, and report path. Expected malformed-image
rejections such as checksum, invalid, corruption, and read errors are reported
separately from interesting or unsafe findings. Use `--no-tui` for plain
script-friendly output.

### Coverage-guided fuzz targets

The `fuzz/` package contains Rust-native libFuzzer targets for the library
parsers and helpers. These targets run in-process and are separate from the
`erofs-rs fuzz` CLI orchestration command:

```bash
cargo install cargo-fuzz
cargo fuzz build
cargo fuzz run superblock_parse -- -runs=1000
cargo fuzz run inode_locate -- -runs=1000
cargo fuzz run dirent_locate -- -runs=1000
cargo fuzz run checksum_fix_no_panic -- -runs=1000
cargo fuzz run info_no_panic -- -runs=1000
cargo fuzz run inject_named_field -- -runs=1000
cargo fuzz run xattr_parse -- -runs=1000
cargo fuzz run chunk_parse -- -runs=1000
cargo fuzz run compression_parse -- -runs=1000
```

The initial targets cover superblock parsing, inode location, directory-entry
location, inline xattr parsing, chunk metadata parsing, compression map header
parsing, checksum repair, named-field injection, and the strict `info`
traversal path. Generated libFuzzer corpora and artifacts under
`fuzz/corpus/`, `fuzz/artifacts/`, and `fuzz/target/` are local byproducts and
should not be committed unless a minimized regression is intentionally added.

### Seed matrix generation

The basic and complex seed scripts create a small hand-written corpus. For
feature coverage, `generate-seed-matrix.sh` builds a reproducible matrix with
block-size, compression, user-xattr, POSIX ACL, large-directory, special-file,
socket, device-node, chunked-file, and packed-fragment variants when the host
tools can create them:

```bash
./scripts/generate-seed-matrix.sh
./scripts/generate-seed-matrix.sh \
    --output-dir /tmp/seed-matrix \
    --block-size 1024,4096 \
    --compression none,lz4
```

The script writes `manifest.json` next to the generated images with the source
profile, mkfs command, mkfs version, erofs-utils revision, feature tags, and
full SHA-256 for each seed.

### `oracle` – userspace differential checks

```bash
erofs-rs oracle \
    --input corpus/seeds/single.erofs \
    --fsck build/erofs-utils/fsck/fsck.erofs \
    --dump build/erofs-utils/dump/dump.erofs \
    --report /tmp/oracle-report.txt
```

The oracle report compares the Rust strict parser, `fsck.erofs`, optional
`dump.erofs -s`, and `fsck.erofs` after Rust checksum repair. Disagreements are
reported as interesting findings so parser/tool/checksum mismatches can be
triaged separately from ordinary malformed image rejections.

## Library usage

The crate can also be used as a library:

```rust
use erofs_rs::{read_image, fix_checksum, locate_inodes};

let mut img = read_image("single.erofs")?;
let sb = img.superblock()?;
let inodes = locate_inodes(&img, &sb)?;
let (_, _) = fix_checksum(&mut img)?;
```

## QEMU environment

A `Makefile` is provided to build a minimal QEMU + Linux + EROFS test
environment. It compiles the kernel from `vendor/linux`, builds
`mkfs.erofs` from `vendor/erofs-utils`, creates a tiny initramfs, and
generates a sample EROFS root image.

### Quick start

```bash
# 1. Install dependencies (Ubuntu/Debian)
make apt-deps

# 2. Build kernel, initramfs, and sample EROFS image
make all

# 3. Run QEMU interactively
make run

# 4. Or run a smoke test with timeout
make smoke
```

### Useful Makefile targets

| Target | Description |
|---|---|
| `make kernel` | Build `arch/x86/boot/bzImage` from `vendor/linux` |
| `make erofs-utils` | Build `mkfs.erofs` from `vendor/erofs-utils` |
| `make erofs-utils-sanitized` | Build `mkfs.erofs`, `fsck.erofs`, and `dump.erofs` with ASAN/UBSAN |
| `make erofs-utils-safety` | Run a tool-safety smoke over `mkfs.erofs`, `fsck.erofs`, `dump.erofs`, and available `.erofs` images |
| `make erofs-image` | Generate `build/rootfs.erofs` |
| `make run` | Boot QEMU with the sample EROFS image |
| `make smoke` | Boot QEMU, verify successful mount and traversal |
| `make smoke-malformed MALFORMED_IMG=...` | Boot with a malformed image and verify safe rejection |
| `make smoke-dmesg` | Capture full dmesg to `build/qemu-dmesg.log` |
| `make test` | Run `cargo test` |
| `make clean` | Remove `build/` artifacts |
| `make distclean` | Also clean kernel and erofs-utils build trees |

### Testing malformed images in QEMU

```bash
# Generate a mutated image
./target/release/erofs-rs inject \
    --input tests/fixtures/single.erofs \
    --output build/mutated.erofs \
    --field superblock.root_nid --value 0xFFFF --fix-checksum

# Boot QEMU and verify the kernel rejects it cleanly
make smoke-malformed MALFORMED_IMG=build/mutated.erofs
```

## Continuous Integration

CI is split by cost and feedback speed:

- `.github/workflows/ci.yml` runs on pull requests and pushes. It first checks
  formatting, all-target compilation with warnings as errors, unit tests, and
  Clippy. A second job builds and briefly runs the Rust-native libFuzzer
  targets under `fuzz/` with `cargo-fuzz`. A third job builds
  `vendor/erofs-utils`, installs the local `fsck.erofs` fixture, runs the full
  Rust test suite, generates basic, complex, and matrix seed images,
  runs an `erofs-utils` safety smoke over `mkfs.erofs`, `fsck.erofs`, and
  `dump.erofs`, and performs a deterministic short fuzz smoke with `--no-tui`.
- `.github/workflows/fuzz-erofs.yml` runs weekly and by manual dispatch. It
  builds `vendor/erofs-utils`, runs tests, generates seed corpus and seed
  matrix, runs
  structured mutations, classifies artifacts, builds the upstream libFuzzer
  target, runs a short fuzzing session, runs the Rust-native libFuzzer targets
  and `cargo fuzz cmin` corpus minimization, collects the minimized Rust fuzz
  corpus with `erofs-rs corpus --mode coverage`, builds ASAN/UBSAN-instrumented
  `erofs-utils`, scans seeds and generated artifacts for tool crashes,
  timeouts, and sanitizer diagnostics, and uploads reports, minimized corpora,
  logs, and manifests.

The `erofs-utils` safety checks do not prove the tools are safe. They report a
bounded smoke result such as `tool crashes: 0`, `tool timeouts: 0`, and
`sanitizer findings: 0`; normal rejection of malformed images is counted
separately from unsafe tool behavior.

Kernel replay is intentionally **not** run in CI because building the kernel is
too heavy for the default GitHub Actions runner. Use the local `Makefile` for
QEMU-based kernel testing.

Issue and pull request templates require reproducible commands, fuzz seeds or
artifacts when relevant, observed output, test coverage, and DCO-style
`Signed-off-by:` commit metadata.

## Documentation

设计背景与理念请参阅 [`docs/01-origin-and-design.md`](docs/01-origin-and-design.md)。

## License

GPL-2.0+ — see [LICENSE](LICENSE).
