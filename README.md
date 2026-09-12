# otunnel

A Rust implementation of [tunnel-client](https://github.com/openai/tunnel-client), with concurrent stdio forwarding and a shared implementation for runtime connections and diagnostics.

## Installation

```sh
cargo binstall otunnel
```

From a checkout: `cargo install --path .`.

## Usage

```sh
otunnel run --config tunnel.yaml
otunnel doctor --profile serena
```

See the [tunnel-client configuration reference](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md).

## Library

```toml
[dependencies]
otunnel = { version = "0.1", default-features = false }
```

The library uses the application's Tokio runtime. `Tunnel::run()` accepts a shutdown token, `Tunnel::status()` provides live state, and `Tunnel::bind()` attaches an application-owned transport. See the [embedding example](examples/embedded.rs).

## Development

`cargo dist` packages a native release. See [development](docs/development.md) for checks and publication.

MIT licensed.
