# Corpus and Artifact Formats

This document defines the repository-facing corpus layout for `erofs-rs`
fuzzing work. It focuses on files that may be reviewed, imported, uploaded as
CI artifacts, or attached to a finding report.

## Directory Roles

| Path | Owner | Commit policy |
|---|---|---|
| `corpus/seeds/manual/` | humans | Small, intentional fixtures may be committed |
| `corpus/seeds/generated/` | scripts | Commit only when the script and fixture purpose are reviewed |
| `corpus/seeds/minimized/<target>/` | coverage engine output | Import only curated, minimized units with provenance |
| `corpus/seeds/matrix/` | `generate-seed-matrix.sh` | Local generated output by default |
| `corpus/mutated/` | `erofs-rs mutate` | Local generated output |
| `corpus/crashes/userspace/` | userspace triage | Keep local or attach as finding bundles |
| `corpus/crashes/kernel-candidates/` | kernel replay triage | Curated queue for QEMU/KASAN replay |
| `fuzz/corpus/`, `fuzz/artifacts/`, `fuzz/target/` | cargo-fuzz | Do not commit bulk generated output |

Generated corpora should stay out of commits unless the change is a deliberate
regression fixture or reviewed seed import. Large fuzzing outputs belong in CI
artifacts, external storage, or finding bundles.

## Seed Matrix Manifest

`scripts/generate-seed-matrix.sh` writes `manifest.json` beside generated seed
images. Each entry describes one generated image:

```json
{
  "seed": "block-4096-plain.erofs",
  "path": "/tmp/seed-matrix/block-4096-plain.erofs",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "source_profile": "basic",
  "requirement": "required",
  "mkfs": "mkfs.erofs -b4096 /tmp/seed-matrix/block-4096-plain.erofs <source:basic>",
  "mkfs_version": "mkfs.erofs 1.8.0",
  "erofs_utils_git": "",
  "features": [
    "block_size:4096",
    "compression:none",
    "layout:plain"
  ]
}
```

`requirement` is `required` for seeds expected on ordinary CI hosts and
`best_effort` for seeds that depend on host capabilities such as xattr, POSIX
ACL, socket, or device-node support. Older manifests without `requirement` are
interpreted as `required` by the Rust validator.

Feature tags use `namespace:value` strings. Prefer stable tags such as
`block_size:4096`, `compression:lz4`, `layout:chunked`, `xattrs:user`,
`xattrs:long_prefix`, and `dir_size:multiblock` over prose descriptions.

## Coverage Corpus Manifest

`erofs-rs corpus --mode coverage` treats its input as already selected by a
coverage-guided engine. It deduplicates by full SHA-256 and writes
`coverage-manifest.json` using the `erofs-rs.coverage-corpus.v1` schema.

The manifest records:

- source paths and copied artifact paths,
- full SHA-256 digests,
- target names inferred from cargo-fuzz corpus layout,
- input, collected, and duplicate counts per target,
- recommended import roots such as `corpus/seeds/minimized/<target>/`,
- lifecycle buckets such as `queue/userspace`, `crashes/userspace`, and
  `timeouts/userspace`.

The coverage mode does not execute minimization. Run the coverage engine first,
then collect its minimized output with `corpus --mode coverage`. Reviewers can
use each unit's `recommended_import_path` when deciding which minimized units to
copy into the long-lived seed corpus.

When collecting a cargo-fuzz tree, coverage mode reads `<target>/corpus/`
entries and skips `<target>/artifacts/` so crash artifacts stay in triage
bundles instead of entering the minimized seed import path.

## Fuzz Campaign Artifacts

`erofs-rs fuzz` writes one artifact set per unique mutated image:

| File | Purpose |
|---|---|
| `fuzz_<seed>_iter<N>.erofs` | Mutated image |
| `fuzz_<seed>_iter<N>.json` | `erofs-rs.fuzz-artifact.v1` sidecar |
| `fuzz_<seed>_iter<N>.stdout.txt` | Captured fsck stdout |
| `fuzz_<seed>_iter<N>.stderr.txt` | Captured fsck stderr |

The sidecar is the source of truth for reproduction. It records the RNG seed,
iteration, strategy, seed and artifact SHA-256 digests, mutation records,
commands, tool versions, git revisions, fsck status, timeout state, truncation
state, classification, reason, and signature.

Campaign-level files:

| File | Schema or format | Purpose |
|---|---|---|
| `fuzz-report.txt` | text | Human-readable campaign summary |
| `fuzz-buckets.json` | `erofs-rs.fuzz-buckets.v1` | Machine-readable signature buckets |

Use `erofs-rs triage` to merge multiple `fuzz-buckets.json` files into an
`erofs-rs.bucket-db.v1` bucket database.

## Kernel Replay Report

Kernel replay reports use the `erofs-rs.kernel-replay.v1` schema. Generate one
from a captured QEMU dmesg or console log with:

```bash
erofs-rs kernel-report \
    --dmesg build/qemu-dmesg.log \
    --qemu-exit-code 0 \
    --artifact build/mutated.erofs \
    --output build/kernel-replay.json
```

The report records the artifact SHA-256 when an artifact is supplied, the
kernel revision when `--kernel-git` is supplied, the QEMU exit code, a kernel
outcome, a normalized signature, and the dangerous pattern that triggered an
unsafe verdict. Passing `--artifact-sha256` verifies that the replayed artifact
matches the expected digest before writing the report.

## Finding Bundle Manifest

A portable finding bundle should include:

- the mutated image,
- the fuzz sidecar,
- captured stdout and stderr,
- optional replay, oracle, and kernel replay reports,
- a `bundle.json` manifest.

The manifest schema is `erofs-rs.finding-bundle.v1`. It stores file paths and
full SHA-256 digests so a reviewer can verify that reports match the artifact
under discussion. Use `erofs-rs bundle --sidecar <fuzz_*.json> --output
bundle.json` to create the manifest from sidecar metadata; pass
`--replay-report`, `--oracle-report`, or `--kernel-report` to include optional
reports. The command verifies the artifact digest against the sidecar before
writing the manifest.

## Import Rules

Before importing a corpus unit into the repository:

1. Confirm the image is small and intentionally scoped.
2. Record provenance: source campaign, target, command, sidecar, or manifest.
3. Prefer minimized coverage units over raw campaign output.
4. Re-run the relevant parser, fsck, oracle, or replay check.
5. Name the test or fixture after the behavior it preserves.

Do not import generated directories wholesale. A useful corpus commit explains
which behavior is being preserved and why that artifact is the minimal reviewed
representative.

## Cleanup Rules

Safe local cleanup targets include:

- `target/`
- `fuzz/target/`
- `fuzz/artifacts/`
- local `corpus/mutated/`
- temporary fuzz output directories under `/tmp`
- QEMU logs and locally built kernel or erofs-utils products

Do not clean user-provided seeds, checked-in fixtures, or finding bundles unless
the cleanup is explicitly requested.
