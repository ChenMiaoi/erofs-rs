# AGENTS.md

Guidance for LLM coding agents working in this repository.

This project is Rust tooling for EROFS filesystem fuzzing, image mutation,
fsck integration, and kernel/QEMU replay. Treat it as kernel-adjacent
infrastructure: correctness, reproducibility, explicit failure modes, and
reviewable patches matter more than cleverness or convenience.

## Scope

- This file applies to the whole repository.
- Prefer existing project conventions over introducing new abstractions.
- Do not modify `vendor/linux` or `vendor/erofs-utils` unless the user
  explicitly asks for vendor changes.
- Do not commit generated artifacts from `build/`, `target/`, temporary corpus
  output, QEMU logs, or local fsck/kernel build products.

## Engineering Principles

- Be conservative with filesystem-format logic. EROFS on-disk structures are
  kernel ABI. Do not infer layout rules from a single fixture if a documented
  or upstream definition exists.
- Keep parsing, validation, mutation, checksum repair, and external command
  execution separated. Avoid hidden side effects across these boundaries.
- Prefer deterministic behavior. Fuzzing paths may use randomness, but expose
  seeds or enough metadata to reproduce artifacts where practical.
- Fail closed on malformed images. Bounds checks, integer overflow checks,
  endian-aware reads, and explicit error context are required for untrusted
  input.
- Never silently ignore short reads, invalid offsets, invalid widths, checksum
  failures, fsck failures, or unexpected kernel/QEMU output.
- Keep public CLI behavior stable unless the user explicitly asks for an
  incompatible change.

## Rust Style

- Use `cargo fmt` formatting. Do not hand-format against `rustfmt`.
- Keep code idiomatic and boring: clear data types, small functions, explicit
  names, and straightforward control flow.
- Keep individual `.rs` source files at or below 1600 lines whenever practical.
  If an existing Rust file exceeds that size, split it along clear module and
  ownership boundaries instead of adding to it.
- Prefer `Result<T, E>` over panics for library and CLI implementation paths.
  Panics are acceptable only in tests or for truly impossible internal states
  with a clear invariant.
- Use `anyhow::Context` at CLI/integration boundaries so failures identify the
  path, field, offset, command, or fixture involved.
- Use `thiserror` for reusable library error types when callers need to match
  variants. Do not expose stringly typed errors from core parsing logic.
- Use fixed-width integer types for on-disk data (`u8`, `u16`, `u32`, `u64`).
  Avoid `usize` except for host memory sizes and slice indexes.
- Handle EROFS fields with explicit little-endian conversions. Do not rely on
  host endianness or unsafe layout casts.
- Avoid `unsafe`. If it becomes necessary, explain the invariant in a nearby
  comment and keep the unsafe block as small as possible.
- Avoid lossy casts. Use `try_from`, checked arithmetic, and range validation
  for offsets, block numbers, inode numbers, and lengths.
- Keep dependencies minimal. New crates need a clear reason, compatible
  licensing, and should not duplicate standard-library functionality.
- Do not add broad `allow(...)` attributes to silence warnings. Fix the cause
  or add a narrow, justified exception.

## Filesystem and Kernel-Safety Rules

- Treat all image bytes as attacker-controlled input.
- Validate offset + width before every read or write into an image buffer.
- Preserve checksum semantics intentionally: tests and manifests should make it
  clear when a mutation fixes the checksum and when it deliberately does not.
- When classifying malformed images, distinguish tool errors, fsck rejections,
  checksum rejections, kernel-safe rejections, and dangerous kernel behavior.
- QEMU/kernel replay checks must detect dangerous output such as oops, panic,
  BUG, KASAN, UBSAN, lockdep splats, hung tasks, and unexpected exits.
- Do not weaken kernel smoke tests to make flaky output pass. Tighten matching
  or improve diagnostics instead.

## CLI and UX

- CLI commands should be scriptable: stable flags, deterministic output where
  possible, nonzero exit on failure, and useful stderr context.
- Prefer explicit flags over hidden behavior. Do not make checksum repair,
  corpus copying, or fsck execution implicit unless existing behavior already
  does so.
- Manifest and report formats should remain easy to diff and grep.
- Paths in errors should identify the user-provided input, output, manifest,
  fixture, fsck binary, or QEMU log involved.

## Tests

Run the smallest relevant test first, then broaden before finishing.

Baseline checks for most Rust changes:

```bash
cargo fmt --check
RUSTFLAGS="-D warnings" cargo check --all-targets
RUSTFLAGS="-D warnings" cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

When touching parsing, mutation, checksum, corpus classification, or CLI
argument handling, add or update focused unit/integration tests.

When touching fsck integration or fixture behavior:

```bash
make erofs-utils
RUSTFLAGS="-D warnings" cargo test
```

When touching kernel replay, QEMU scripts, `Makefile` kernel targets, or
malformed-image safety policy:

```bash
make smoke
make smoke-malformed MALFORMED_IMG=<path-to-mutated-image>
```

If a required local dependency is missing, report exactly what could not be run
and why. Do not claim tests passed when they were skipped.

## Fixtures, Corpus, and Generated Data

- Keep checked-in fixtures small, intentional, and documented by test names or
  comments.
- Do not replace fixtures casually. Fixture changes should explain what format
  property or kernel/fsck behavior they cover.
- Corpus artifacts are useful for local analysis, but do not add large generated
  corpora unless the user explicitly asks for them.
- Prefer temporary directories in tests. Do not write test output into the
  repository unless the test is explicitly regenerating fixtures.

## Code Submission Discipline

- Keep patches focused. Avoid drive-by refactors, formatting churn, dependency
  churn, and generated-file noise.
- Before every commit, the code must compile, be formatted, pass tests, and pass
  Clippy with no errors or warnings. Treat warnings as errors for compile and
  lint checks.
- Required pre-commit gate for Rust changes:

  ```bash
  cargo fmt --check
  RUSTFLAGS="-D warnings" cargo check --all-targets
  RUSTFLAGS="-D warnings" cargo test
  cargo clippy --all-targets --all-features -- -D warnings
  ```

- Review `git diff --stat` and `git diff` before finalizing.
- Mention all commands run and any commands that could not be run.
- Preserve user changes in the working tree. Do not reset, checkout, or clean
  unrelated files.

## Kernel-Style Commit Messages

Use Linux kernel commit-message style for commits. Commit messages are part of
the review surface for this kernel-adjacent project, so keep them concise,
wrapped, and free of local test logs.

Format:

```text
area: concise imperative summary

Explain the problem first. Describe the observable failure, missing coverage,
reproducibility gap, unsafe behavior, or maintenance risk.

Explain the approach second. Describe what changed and why it reduces the
risk. Include relevant EROFS, fsck, corpus, or kernel-replay context when it
helps review the patch.

Signed-off-by: Name <email@example.com>
```

Rules:

- Keep the subject line 75 characters or fewer.
- Wrap body text at 75 characters or fewer. Trailer lines may exceed this only
  when the trailer value itself requires it.
- Use real blank lines between the subject, body paragraphs, and trailers. Do
  not encode paragraph breaks as literal `\n` strings.
- Use a lowercase subsystem-style prefix such as `image:`, `inode:`,
  `dirent:`, `checksum:`, `fsck:`, `fuzz:`, `corpus:`, `cli:`, `tests:`,
  `scripts:`, `qemu:`, or `docs:`.
- Use imperative mood: `fix`, `reject`, `validate`, `record`, `add`, not
  `fixed`, `rejects`, or `adding`.
- The body must answer why the change is needed, what changed, and what risk it
  reduces. Prefer two short paragraphs: problem first, approach second.
- Mention user-visible behavior, compatibility impact, corpus format changes,
  or kernel/fsck safety consequences when they matter.
- Do not add `Tests:`, `Tests run:`, `Test plan:`, or similar command-log
  sections to commit messages. Exact commands that were run belong in PR notes,
  cover letters, or the agent's final response, not in the commit body.
- Do not paste long command output, workflow logs, benchmark dumps, or local
  environment notes into commit messages.
- Include `Fixes:` only when there is a real referenced commit.
- Include `Reported-by:`, `Tested-by:`, `Reviewed-by:`, or `Co-developed-by:`
  only when accurate.
- Include `Signed-off-by:` for Developer Certificate of Origin style tracking.
- Keep trailers at the end of the message, one per line, after a blank line.
- Before finalizing a rewritten commit stack, check all commit messages for
  subject/body line length, forbidden test-log sections, and missing
  `Signed-off-by:` trailers.

Example:

```text
image: reject superblock reads past the image end

Malformed inputs can advertise fields that require reading beyond the
available image buffer. Reject those images before decoding the field so the
parser reports a controlled validation error instead of relying on slice
indexing behavior.

This keeps the mutation and info paths consistent for truncated images.

Signed-off-by: Your Name <you@example.com>
```

## Documentation

- Update `README.md` or `docs/` when CLI behavior, test setup, kernel replay
  workflow, fixture requirements, or corpus classification changes.
- Keep documentation precise and operational. Prefer commands and observed
  behavior over broad claims.
- Do not document speculative kernel behavior as fact. Label assumptions and
  cite upstream docs or source paths when possible.

## Security and Robustness Checklist

Before finalizing changes that touch image bytes, mutation, fsck, fuzzing, or
kernel replay, check:

- Are all image offsets and lengths bounds-checked?
- Are integer additions and multiplications checked for overflow?
- Is little-endian decoding explicit?
- Is malformed input rejected with useful context?
- Are checksum changes intentional and tested?
- Does the test cover both accepted and rejected behavior where relevant?
- Could generated artifacts accidentally enter the commit?
