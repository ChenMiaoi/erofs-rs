# KCOV Kernel Replay Candidates

Use this queue for minimized `.erofs` images selected for KCOV-oriented replay
or coverage follow-up. Candidate images remain ignored by default; use
`git add -f` only for reviewed inputs with reproducible provenance.

Scheduled/manual kernel replay records these entries with the `kcov` queue
profile in `erofs-rs.kernel-replay-summary.v1` and folds their signatures into
`erofs-rs.kernel-bucket-db.v1`.
