# Development

```sh
cargo fmt --all
cargo fix --workspace --allow-dirty
cargo clippy --workspace --all-targets --fix --allow-dirty
cargo check --package otunnel --all-targets --no-default-features
cargo dist
```

`cargo dist` writes the native release to `dist/`. `cargo xtask matrix` supplies the release targets from the same workspace tooling.

A `vX.Y.Z` tag starts platform checks and prepares a GitHub release draft. Manual workflow runs offer `dryrun` for artifacts or `draft` for a tagged commit. Publishing the draft publishes the crate through Trusted Publishing, configured for `publish.yml` and the `release` environment. Manual dispatch with the tag resumes a publication.
