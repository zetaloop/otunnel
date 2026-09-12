# Development

The workspace contains the `otunnel` library and executable, plus an unpublished `xtask` for release tooling.

```sh
cargo fmt --all
cargo fix --workspace --allow-dirty
cargo clippy --workspace --all-targets --fix --allow-dirty
cargo check --package otunnel --all-targets --no-default-features
```

`cargo build --release` builds for the current machine. `cargo dist` packages that executable, documentation, and shell completions in `dist/`. `cargo xtask matrix` supplies the native Windows, macOS, and Linux release matrix from the target table used by the project.

## Release

Update the version in `Cargo.toml` and its lockfile, then push the matching `vX.Y.Z` tag. The release workflow runs formatting, Clippy, library compilation, and the existing Cargo tests on each platform before packaging. A successful run creates a GitHub release draft containing all platform archives.

The workflow can also be started manually. `dryrun` produces downloadable artifacts; `draft` creates a release draft when a version tag points at the selected commit.

Publishing the draft triggers the crates.io workflow. It publishes `otunnel` through Trusted Publishing and skips a version already present in the registry. Configure the crate's trusted publisher for this repository, `publish.yml`, and the `release` environment. Manual dispatch with the release tag can resume an interrupted publication.
