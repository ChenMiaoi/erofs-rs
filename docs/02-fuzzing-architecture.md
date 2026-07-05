# Fuzzing Architecture

This document describes how `erofs-rs` turns seed images into reproducible
fuzzing findings. It is intentionally operational: each layer names its inputs,
outputs, and failure boundary so campaign results can be reviewed without
guessing which tool produced an artifact.

## Scope

`erofs-rs` has two fuzzing paths:

- The `erofs-rs fuzz` command is an orchestration and triage path. It mutates
  complete EROFS images, runs external tools such as `fsck.erofs`, records
  artifacts, and emits campaign reports.
- The `fuzz/` package is the coverage-guided Rust library path. It uses
  libFuzzer targets for in-process parser and helper coverage.

The CLI path is not a coverage engine. It should stay focused on
reproducibility, artifact metadata, userspace oracles, and kernel replay
handoff. Coverage feedback belongs in libFuzzer, AFL++, ClusterFuzzLite, or a
similar engine that can be integrated later.

## Layers

| Layer | Code | Responsibility |
|---|---|---|
| Image core | `src/image.rs`, `src/checksum.rs` | Bounds-checked image IO, endian-aware field access, checksum repair |
| Format discovery | `src/inode.rs`, `src/dirent.rs`, `src/parse.rs` | Locate known EROFS structures and report strict or tolerant parse results |
| Mutation | `src/mutate.rs`, `src/fuzz.rs` | Generate deterministic or random image mutations |
| Tool execution | `src/fsck.rs` | Run external tools with timeout, output limits, process-group kill, and rlimit |
| Corpus lifecycle | `src/corpus.rs`, `src/seed_manifest.rs` | Deduplicate, classify, and describe seed or coverage corpora |
| Oracles | `src/oracle.rs`, `src/kernel_replay.rs` | Compare parser, fsck, dump, checksum repair, sanitizer, and dmesg outcomes |
| Reproduction | `src/replay.rs`, `src/finding_bundle.rs` | Re-run sidecar-described artifacts and validate portable finding bundles |
| Triage | `src/triage.rs`, `src/fuzz.rs` | Bucket campaign findings and merge bucket reports across runs |

Keep these layers separated. Parsing should not invoke tools, mutation should
not silently repair unrelated checksums, and replay should consume recorded
metadata instead of guessing how an artifact was produced.

## Campaign Flow

1. Generate or import seeds.
   Use hand-written fixtures, `scripts/generate-seed-corpus.sh`,
   `scripts/generate-complex-seeds.sh`, or
   `scripts/generate-seed-matrix.sh`. Seed matrix manifests mark entries as
   `required` or `best_effort` so host-dependent coverage gaps are explicit.

2. Mutate images.
   Use `erofs-rs mutate` for deterministic one-field mutations, or
   `erofs-rs fuzz` for random mutation campaigns with a recorded RNG seed.

3. Classify userspace behavior.
   `fsck.erofs` results are mapped into outcome kinds: clean accept, expected
   reject, interesting semantic finding, unsafe crash, unsafe timeout, or
   tooling error. Expected malformed-image rejects are not actionable findings.

4. Record artifacts.
   Each unique fuzz artifact gets an image, a JSON sidecar, captured stdout and
   stderr files, and campaign reports. Sidecars carry the RNG seed, iteration,
   mutation records, commands, tool revisions, full SHA-256 digests, and
   classification signature.

5. Run differential checks.
   Use `erofs-rs oracle` to compare Rust parser verdicts, fsck, optional dump,
   checksum-repaired fsck, optional sanitized fsck, optional kernel replay
   reports, and strict/tolerant parser behavior. The oracle records both
   check-level matrix rows and detail diffs for parser-vs-dump fields and
   fsck-vs-kernel behavior, and maps disagreements into triage buckets. Use
   JSON reports when later tooling needs stable inputs.

6. Replay and bundle.
   Use `erofs-rs replay` to re-run a sidecar-described artifact. Finding
   bundles should keep the artifact, sidecar, stdout/stderr, replay report,
   oracle report, and any kernel dmesg together with a `bundle.json` manifest.

7. Merge triage state.
   `erofs-rs fuzz` writes `fuzz-buckets.json` beside the text report.
   `erofs-rs triage` merges those reports into a cross-campaign bucket database
   keyed by signature.

## Artifact Contracts

| Artifact | Producer | Schema or format | Purpose |
|---|---|---|---|
| `fuzz_*.erofs` | `erofs-rs fuzz` | raw EROFS image | Mutated test case |
| `fuzz_*.json` | `erofs-rs fuzz` | `erofs-rs.fuzz-artifact.v1` | Per-artifact replay metadata |
| replay JSON report | `erofs-rs replay` | `erofs-rs.replay-report.v1` | Sidecar replay outcome and match state |
| `fuzz_*.stdout.txt` / `stderr.txt` | `erofs-rs fuzz` | text | Captured tool output with truncation metadata in sidecar |
| `fuzz-report.txt` | `erofs-rs fuzz` | text | Human-readable campaign summary |
| `fuzz-buckets.json` | `erofs-rs fuzz` | `erofs-rs.fuzz-buckets.v1` | Machine-readable signature buckets for one campaign |
| mutation manifest | `erofs-rs mutate` | text table | Per-artifact mutation family, class, checksum policy, parser outcome, and fsck classification |
| bucket database | `erofs-rs triage` | `erofs-rs.bucket-db.v1` | Cross-campaign signature counts and examples |
| oracle JSON report | `erofs-rs oracle` | `erofs-rs.oracle-report.v1` | Machine-readable differential oracle rows |
| coverage manifest | `erofs-rs corpus --mode coverage` | `erofs-rs.coverage-corpus.v1` | Coverage corpus provenance and lifecycle buckets |
| cmin summary | periodic fuzz workflow | `erofs-rs.cmin-summary.v1` | Per-target minimization counts, engine flags, and toolchain metadata |
| seed matrix manifest | `generate-seed-matrix.sh` | JSON array | Reproducible seed provenance and feature tags |
| finding bundle manifest | library validator | `erofs-rs.finding-bundle.v1` | Portable triage bundle index |
| kernel replay report | library schema | `erofs-rs.kernel-replay.v1` | Dmesg classification and unsafe signal metadata |
| kernel replay summary | scheduled replay workflow | `erofs-rs.kernel-replay-summary.v1` | Per-candidate replay status, queue profile, kernel profile, and regression status |
| kernel bucket database | `erofs-rs kernel-buckets` | `erofs-rs.kernel-bucket-db.v1` | Cross-run kernel signature counts and examples |

Schema names are part of the review surface. Add a new schema version when a
consumer cannot safely handle the old shape.

## Failure Boundaries

- Image reads and writes must validate offset plus width before touching bytes.
- On-disk fields must use explicit little-endian decoding and fixed-width
  integer types.
- External command failures must include the image path, tool path, exit status,
  timeout state, truncation state, and enough output for triage.
- Expected malformed-image rejections should stay separate from unsafe crashes,
  unsafe timeouts, tooling errors, and semantic disagreements.
- Kernel replay output must treat BUG, Oops, panic, KASAN, KMSAN, KFENCE, UBSAN,
  lockdep, RCU stalls, hung tasks, and unexpected exits as unsafe until proven
  otherwise.

## CI Roles

PR CI should stay small and deterministic:

- Build the crate and run tests with warnings denied.
- Build and short-run Rust libFuzzer targets.
- Generate representative seed matrices.
- Run userspace safety smoke tests.

Scheduled or self-hosted jobs can be broader:

- Longer libFuzzer campaigns and corpus minimization.
- Sanitized erofs-utils checks.
- Cross-campaign bucket database generation.
- Kernel replay over curated candidate artifacts. The scheduled kernel replay
  workflow is manual/scheduled only, scans general, KASAN, KCOV, and regression
  queues, can consume a prebuilt kernel artifact, and uploads
  `erofs-rs.kernel-replay.v1` reports plus an
  `erofs-rs.kernel-replay-summary.v1` summary and
  `erofs-rs.kernel-bucket-db.v1` signature database instead of joining the
  default PR gate.

Do not make heavyweight kernel replay a default PR requirement unless the
runner can provide a reproducible kernel artifact and stable runtime budget.

## Extension Rules

- Add new mutation families behind explicit targets or strategy names.
- Add machine-readable reports before building automation that scrapes text.
- Preserve existing sidecar and manifest fields unless a schema version changes.
- Prefer small, reviewable corpus imports with clear provenance over large
  generated dumps.
- Treat vendor trees as external inputs; do not patch them for fuzzing workflow
  changes unless the change is explicitly requested.
