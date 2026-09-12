# otunnel

A Rust client for [OpenAI MCP tunnels](https://github.com/openai/tunnel-client), available as a library and CLI in one Cargo package.

`otunnel` forwards MCP requests through stdio, Streamable HTTP, or HTTP over Unix sockets. A shared stdio connection can carry concurrent calls, and configured service processes follow the tunnel's lifetime. OAuth discovery, Harpoon targets, and a local activity page are included.

## Installation

```sh
cargo binstall otunnel
```

Or from a checkout:

```sh
cargo install --path .
```

## Usage

Create `tunnel.yaml` with an existing Tunnel ID and a file containing the runtime API key:

```yaml
control_plane:
  tunnel_id: tunnel_...
  api_key: file:tunnel.key
mcp:
  commands:
    - command: [serena, start-mcp-server]
health:
  url_file: otunnel.url
```

```sh
otunnel doctor --config tunnel.yaml
otunnel run --config tunnel.yaml
otunnel health --config tunnel.yaml
```

`doctor` starts the configured services and checks their actual MCP connections. `run` serves tunnel requests until stopped. The activity page is at `/ui` on the address written to `otunnel.url`.

[Configuration](docs/configuration.md) covers HTTP bindings, profiles, credentials, OAuth, and logging. Relative paths use the working directory.

## Library

```toml
[dependencies]
otunnel = { version = "0.1", default-features = false }
```

The library shares the application's Tokio runtime:

```rust,no_run
async fn connect(config: otunnel::config::Config, stop: otunnel::CancellationToken) -> otunnel::Result<()> {
    otunnel::Tunnel::new(config)?.run(stop).await
}
```

`Tunnel::status()` exposes live state, and `Tunnel::bind()` accepts an application-owned transport. See the [embedding example](examples/embedded.rs).

## Development

`cargo dist` builds and packages a native release. Tagged releases and manual workflow runs prepare release drafts; publishing a draft publishes the crate. See [development](docs/development.md).

MIT licensed.
