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
