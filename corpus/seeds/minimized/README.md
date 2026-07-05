# Reviewed Minimized Corpus

This directory is the long-lived import root for reviewed `cargo-fuzz` corpus
units. Do not copy raw weekly artifacts here directly.

Import reviewed units from a collected coverage manifest with:

```bash
erofs-rs minimized-import \
  --coverage-manifest corpus/minimized/rust-fuzz/coverage-manifest.json
```

The import command copies units into `corpus/seeds/minimized/<target>/`, updates
`manifest.json`, preserves coverage provenance, and refuses to overwrite an
existing path with different bytes. Validate the committed corpus with:

```bash
erofs-rs minimized-check --manifest corpus/seeds/minimized/manifest.json
```

Each target directory is replayed by CI with `cargo fuzz run <target>
corpus/seeds/minimized/<target> -- -runs=0`.
