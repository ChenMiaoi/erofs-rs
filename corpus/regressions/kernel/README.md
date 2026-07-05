# Kernel Regression Replay Corpus

Use this queue for minimized `.erofs` artifacts that previously triggered
dangerous kernel behavior and are now expected to replay as safe rejections.
Regression images remain ignored by default; use `git add -f` only after the
kernel fix or mitigation is understood and the artifact is intentionally kept.

The scheduled/manual kernel replay workflow records these entries with the
`regression` queue profile and `regression_status`. Any replay that is not a
clean rejection remains a workflow failure and appears in the kernel signature
bucket database.

Import a fixed artifact with `erofs-rs kernel-queue-import --queue regression`
and attach `--kernel-report` when a previous replay report is available. The
command preserves the artifact under a SHA-256-derived filename before the
queue entry is intentionally added with `git add -f`.
