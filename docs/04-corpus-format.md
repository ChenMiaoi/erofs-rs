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

`corpus/crashes/kernel-candidates/` is the input queue consumed by the scheduled
kernel replay workflow. It is usually local or supplied on a replay branch. Keep
entries small, curated, and accompanied by sidecars or finding bundles when
they graduate from local triage to a reviewed report.

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
`xattrs:long_prefix`, and `dir_size:multiblock` over prose descriptions. The
Rust manifest validator rejects feature tags without both a namespace and a
value. It also rejects duplicate seed names, generated paths, SHA-256 digests,
and duplicate feature tags within one entry.

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

The Rust library parser rejects unknown coverage-manifest schemas, malformed
SHA-256 digests, empty required paths, and inconsistent global or per-target
counts before callers use the report for seed import decisions. It also rejects
duplicate collected unit hashes, copied paths, and recommended import paths so
one minimized unit cannot be represented twice in a review manifest. The
recommended import directories and per-unit import paths must match the
manifest root, target name, and copied unit name. Target names must be single
portable path components, and copied paths must use
`coverage-interesting/<unit>`.

When collecting a cargo-fuzz tree, coverage mode reads `<target>/corpus/`
entries and skips `<target>/artifacts/` so crash artifacts stay in triage
bundles instead of entering the minimized seed import path.

## Cmin Summary

The periodic fuzzing workflow writes `corpus/rust-fuzz/cmin-summary.json` using
the `erofs-rs.cmin-summary.v1` schema before collecting minimized units. It
records the cargo-fuzz version, nightly rustc version, run/cmin/regression
flags, and one entry per target with:

- corpus unit counts before and after `cargo fuzz cmin`,
- crash artifact counts,
- corpus and artifact directories,
- run, cmin, and `-runs=0` regression log paths.

Use this report with `coverage-manifest.json` to review whether a minimized
unit should be imported into `corpus/seeds/minimized/<target>/`. The Rust
library parser rejects unknown schemas, empty required fields or flag lists,
duplicate targets, and summaries where a target has more corpus units after
`cmin` than before.

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
state, classification, reason, and signature. The Rust library parser rejects
unknown sidecar schemas, unknown fields, malformed SHA-256 digests, empty
required fields, empty command vectors, empty command arguments, and empty
optional version or mutation string fields. It also rejects signatures that do
not match the recorded classification prefix.

Campaign-level files:

| File | Schema or format | Purpose |
|---|---|---|
| `fuzz-report.txt` | text | Human-readable campaign summary |
| `fuzz-buckets.json` | `erofs-rs.fuzz-buckets.v1` | Machine-readable signature buckets |

Use `erofs-rs triage` to merge multiple `fuzz-buckets.json` files into an
`erofs-rs.bucket-db.v1` bucket database. The Rust parser rejects unknown
bucket report fields, invalid or mismatched outcome kinds, non-actionable
buckets, mismatched actionable finding counts, unknown database schemas,
duplicate source reports or signatures, unknown example source reports,
inconsistent outcome metadata, and source bucket counts that do not match the
examples.

## Mutation Manifests

`erofs-rs mutate` writes a text manifest beside generated structured mutation
artifacts. Each row records the output image, target structure, mutated field,
interesting value, derived mutation class, checksum policy, fsck result, and
classification reason. `erofs-rs corpus` rejects malformed manifest rows and
rows that reference missing artifact files before copying or classifying
artifacts.

Mutation classes are derived from parser and fsck outcomes:

- `grammar_preserving` for images accepted by both strict parser and fsck,
- `grammar_edge` for accepted images with tolerant parser recovery,
- `grammar_invalid` for malformed images rejected by the parser,
- `semantic_invalid` for parser-decodable images rejected by fsck,
- `checksum_invalid` for checksum rejections,
- `unsafe_userspace` and `timeout` for tool crashes, sanitizer findings, and
  execution timeouts.

Checksum policy is `checksum_repaired` when mutation repaired the superblock
checksum and `checksum_raw` when the checksum was deliberately left stale or
mutated directly.

## Oracle JSON Report

Userspace oracle reports use the `erofs-rs.oracle-report.v1` schema. Generate
one with:

```bash
erofs-rs oracle \
    --input corpus/seeds/single.erofs \
    --fsck build/erofs-utils/fsck/fsck.erofs \
    --kernel-report build/kernel-replay.json \
    --json-report build/oracle-report.json
```

The report stores the input path, input SHA-256, individual check verdicts,
pairwise matrix rows, and the number of disagreeing rows. The Rust library
parser rejects unknown schemas, unknown fields, empty required fields,
malformed input digests, invalid status or verdict values, inconsistent
`disagrees` flags or matrix verdicts, and mismatched
`interesting_findings` counts. It also rejects duplicate checks, duplicate
matrix rows, matrix rows that reference checks missing from the report, rows
that copy status or classification values that differ from the referenced
checks, and reports that omit the canonical row for any check pair.
When `--kernel-report` is supplied, the oracle parses the existing
`erofs-rs.kernel-replay.v1` JSON report and adds it as a matrix check instead
of starting QEMU itself.

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
matches the expected digest before writing the report. The Rust library parser
rejects unknown schemas, malformed artifact digests, empty required fields, and
signatures whose `kernel_*:` prefix does not match the outcome. Unsafe reports
must include the dangerous pattern. Non-unsafe reports must not carry a
dangerous pattern.

Scheduled kernel replay uploads `kernel-replay/summary.json` using the
`erofs-rs.kernel-replay-summary.v1` schema. The summary records the candidate
queue path, candidate count, failure count, and one row per candidate with the
artifact SHA-256, QEMU exit code, replay status, report status, and report
path. The Rust library parser rejects malformed artifact digests, duplicate
candidates or report paths, invalid status values, and mismatched candidate or
failure counts before automation consumes the replay artifact.

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
bundle.json` to create the manifest from validated sidecar metadata; pass
`--replay-report`, `--oracle-report`, or `--kernel-report` to include optional
reports. The command verifies the artifact digest against the sidecar before
writing the manifest. JSON replay, oracle, and kernel reports are parsed with
their stable schemas before they enter the bundle; legacy text reports remain
opaque attachments. JSON replay, oracle, and kernel reports must match the
bundled artifact SHA-256. Manifest parsing rejects non-actionable
classifications, signatures that do not match the classification prefix, and
duplicate paths so each bundle role points at a distinct attachment.

Replay JSON reports use the `erofs-rs.replay-report.v1` schema. Generate one
with `erofs-rs replay --sidecar <fuzz_*.json> --json-report replay-report.json`
so bundles can carry the original sidecar outcome, replayed fsck outcome, and
match booleans without scraping the text report. The parser rejects original
signatures that do not match the recorded classification prefix.

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
