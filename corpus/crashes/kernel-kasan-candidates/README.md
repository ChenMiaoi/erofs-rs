# KASAN Kernel Replay Candidates

Use this queue for minimized `.erofs` images that should be replayed with a
KASAN-capable kernel profile. Candidate images remain ignored by default; use
`git add -f` only after the artifact has sidecar, oracle, or finding-bundle
provenance.

Scheduled/manual kernel replay records these entries with the `kasan` queue
profile in `erofs-rs.kernel-replay-summary.v1` and folds their signatures into
`erofs-rs.kernel-bucket-db.v1`.
