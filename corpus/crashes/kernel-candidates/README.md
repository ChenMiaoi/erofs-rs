# Kernel Replay Candidates

This directory is the curated input queue for the scheduled kernel replay
workflow. Keep bulk fuzzing output, generated corpora, and raw crash dumps out
of git. Candidate `.erofs` images remain ignored by default; use `git add -f`
only for a reviewed kernel replay candidate that should run in scheduled or
manually dispatched QEMU replay.

Before adding a candidate, keep or attach the fuzz sidecar, userspace logs,
oracle report, or finding bundle that explains where the image came from. The
scheduled workflow writes QEMU logs, raw QEMU exit codes, and
`erofs-rs.kernel-replay.v1` JSON reports as CI artifacts.

Queue roles:

- `corpus/crashes/kernel-candidates/`: general curated kernel replay queue.
- `corpus/crashes/kernel-kasan-candidates/`: candidates that need sanitizer
  replay because userspace or unsanitized kernel replay suggests memory-safety
  risk.
- `corpus/crashes/kernel-kcov-candidates/`: candidates selected for coverage
  replay or KCOV-guided follow-up.
- `corpus/regressions/kernel/`: fixed kernel crash artifacts that must keep
  replaying as safe rejections.

Promotion lifecycle:

1. Keep new artifacts local until their sidecar, oracle report, or finding
   bundle explains why kernel replay is needed.
2. Import only the minimized `.erofs` image with `erofs-rs kernel-queue-import`
   and set `--input <image> --queue <general|kasan|kcov|regression>`.
   Attach `--kernel-report` when one exists.
3. Add the imported queue entry intentionally with `git add -f`.
4. Let scheduled/manual replay produce QEMU logs, kernel reports, summary JSON,
   and the kernel signature bucket database.
5. Once a kernel bug is fixed, move the minimized artifact to
   `corpus/regressions/kernel/` so replay continues to guard the fix.
