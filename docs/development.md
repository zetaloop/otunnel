# Development

```sh
cargo fmt --all
cargo fix --workspace --allow-dirty
cargo clippy --workspace --all-targets --fix --allow-dirty
cargo check --package otunnel --all-targets --no-default-features
cargo dist
```

Packages go to `dist/`. `cargo xtask matrix` lists release targets.

A `vX.Y.Z` tag runs platform checks and creates a release draft. Manual runs provide `dryrun` artifacts or a `draft` for a tag. Publishing the draft publishes the crate through Trusted Publishing, using `publish.yml` and the `release` environment.
