# otunnel

A Rust implementation of the [tunnel-client](https://github.com/openai/tunnel-client) runtime, providing a CLI and an embeddable library for MCP tunnels. Connections, OAuth, Harpoon, process management, and diagnostics share one implementation, with concurrent stdio forwarding.

## Installation

```sh
cargo binstall otunnel
```

From a checkout: `cargo install --path .`.

## Usage

```sh
otunnel run --config tunnel.yaml
otunnel doctor --config tunnel.yaml
```

The compatibility target is tunnel-client’s runtime commands and configuration: `run`, `doctor`, `health`, `init`, `profiles`, `admin`, `admin-profiles`, `runtimes`, `completion`, and `cloudflared config`. See the [configuration reference](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md).

Profiles use the upstream YAML syntax, environment variables, and profile directories. Configuration for features outside the runtime scope retains its upstream defaults. Cloudflare connections require a user-installed `cloudflared` on `PATH`; `cloudflared.path` can select an explicit executable.

Diagnostic headers identify the implementation as `otunnel` with its own release version. Wire-protocol versions and channel declarations follow the [tunnel protocol](https://github.com/openai/tunnel-client/blob/master/docs/protocol.md).

## Library

```toml
[dependencies]
otunnel = { version = "0.1", default-features = false }
```

The library uses the application's Tokio runtime. `Tunnel::run()` accepts a shutdown token, `Tunnel::status()` provides live state, and `Tunnel::bind()` attaches an application-owned transport. See the [embedding example](examples/embedded.rs).

## Development

`cargo dist` packages a native release. See [development](docs/development.md) for checks and publication.

MIT licensed.
