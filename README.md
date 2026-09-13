# otunnel

A Rust CLI and library for the [tunnel-client](https://github.com/openai/tunnel-client) MCP runtime, with concurrent stdio forwarding.

## Install

```sh
cargo binstall otunnel
```

From source: `cargo install --path .`.

## Use

```sh
otunnel doctor --config tunnel.yaml
otunnel run --config tunnel.yaml
```

Uses tunnel-client’s [configuration](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md) and profiles. Cloudflare tunnels require `cloudflared` on `PATH`.

## Library

```toml
[dependencies]
otunnel = { version = "0.1", default-features = false }
```

Runs on the application’s Tokio runtime. See the [embedding example](examples/embedded.rs).

## Development

`cargo dist` builds a native package in `dist/`. [Checks and releases](docs/development.md).

MIT licensed.
