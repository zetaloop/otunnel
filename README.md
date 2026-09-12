# otunnel

A Rust client for OpenAI MCP tunnels, available as a command-line program and an embedding library in one Cargo package.

The client receives tunnel commands, forwards them to local MCP services, and returns their notifications and results. It supports concurrent stdio, Streamable HTTP, HTTP over Unix sockets, OAuth discovery, Harpoon targets, and configuration-owned service processes.

## Run

Build from the repository:

```sh
cargo build --release
```

The executable is `target/release/otunnel` on macOS and Linux, or `target\release\otunnel.exe` on Windows. Published binaries use the same package name:

```sh
cargo binstall otunnel
```

Create `tunnel.yaml` with an existing Tunnel ID and runtime API key. For example, a configured Serena installation can be started through stdio:

```yaml
control_plane:
  tunnel_id: tunnel_...
  api_key: file:tunnel.key

mcp:
  commands:
    - channel: main
      command: [serena, start-mcp-server]

health:
  url_file: otunnel.url
```

`tunnel.key` contains the runtime API key. Relative paths are resolved from the client's working directory. The command array preserves argument boundaries on every platform; a shell-style command string is also accepted.

```sh
otunnel doctor --config tunnel.yaml
otunnel run --config tunnel.yaml
```

`doctor` starts the configured services, performs MCP discovery and tool listing through their actual transports, checks OAuth when required, reads tunnel metadata, and shuts its processes down. Run it separately from another client managing the same service socket.

`run` manages the service processes for its lifetime. Stopping the client closes its transports and stops its children. A service process or stdio connection that exits unexpectedly terminates the run with an error.

## HTTP and Unix sockets

An HTTP binding describes an existing server:

```yaml
mcp:
  server_urls:
    - channel: main
      url: http://127.0.0.1:9000/mcp
```

For HTTP over a Unix socket:

```yaml
mcp:
  server_urls:
    - channel: main
      url: http://localhost/mcp
      unix_socket: /tmp/mcp.sock
```

The URL supplies the HTTP scheme, host, and path; `unix_socket` supplies the actual connection. Windows uses native AF_UNIX with a Windows path such as `C:/Tmp/mcp.sock`.

An HTTP binding can also contain `command`, `cwd`, and `env`. The client starts that command before probing the endpoint and owns its lifetime. Existing configurations that use a separate process-only channel and `control_plane.poll_channels` work through the same process manager.

## Concurrent requests

A stdio transport has one reader and one writer. Each active request receives a private wire ID, so requests from separate conversations can reuse JSON-RPC IDs. Responses, progress tokens, subscriptions, and cancellation are routed back to the corresponding request. A long-running tool can coexist with other requests on the same process.

The tunnel's `response_timeout` includes queueing, local execution, and result delivery. Retrying delivery resends the serialized result. MCP invocation is performed once. Intermediate notification delivery is best-effort; the terminal result has its own delivery handling.

Discovery negotiates MCP 2026-07-28 for stateless servers and initialization for servers using MCP 2025-11-25. Tool calls retain their original payloads, including unknown fields, `_meta`, image data, resource content, and JSON Schema. The ChatGPT host determines how received images and resources appear in the conversation and execution environment.

## Health and logs

The default health listener is `127.0.0.1:0`. Its actual URL is written to the configured `health.url_file` and reported in the startup log.

```sh
otunnel health --config tunnel.yaml
otunnel health --url http://127.0.0.1:49152 --json
```

The status service provides `/ui`, `/api/status`, `/api/events`, `/healthz`, `/readyz`, and `/metrics`. The UI receives status changes over server-sent events. Set `health.listen_addr: ""` to run without a TCP status listener, or set `health.unix_socket` to use a local socket.

Logs go to stderr by default. `log.file` selects an append-only log file, `stdout`, or `stderr`. `log.format` accepts `text`, `struct-text`, or `json`, and `log.level` accepts tracing filters such as `info,otunnel=debug`.

## Embed

```toml
[dependencies]
otunnel = { version = "0.1", default-features = false }
```

The library uses the application's Tokio runtime:

```rust,no_run
use otunnel::{CancellationToken, Tunnel, config::Config};

async fn connect(config: Config, shutdown: CancellationToken) -> otunnel::Result<()> {
    Tunnel::new(config)?.run(shutdown).await
}
```

`Tunnel::status()` returns a Tokio watch receiver carrying channel discovery, connection state, request counters, and the latest runtime error. `Tunnel::diagnose()` runs the same configured startup and discovery process and returns a structured report.

`Tunnel::bind(channel, Arc<dyn Transport>)` attaches a host-owned transport. `Pipe::new(reader, writer)` accepts Tokio asynchronous streams, and `HttpTransport::new(server, config)` creates an HTTP or socket binding. Applications with an in-process MCP implementation can implement `Transport` and pass notifications and terminal responses to its `Sink`.

The `cli` feature enables the executable and optional health service. The library's `run` method leaves logging, operating-system signal handling, and health listeners to the host. See [the embedding example](examples/embedded.rs) and [the configuration reference](docs/configuration.md).

## Build and release

The repository uses Cargo formatting and Clippy:

```sh
cargo fmt
cargo fix --allow-dirty
cargo clippy --fix --allow-dirty
cargo build --release
```

The release workflow builds x86-64 and ARM64 binaries on native Windows, macOS, and Linux runners. Each archive contains the binary, license, configuration reference, and shell completions. A `v<VERSION>` tag identifies the Cargo package version for release assets; publishing the corresponding crate enables registry-based `cargo binstall` discovery.

`python scripts/package.py` performs the release build and writes the native archive to `target/dist`. The workflow calls the same script with its runner's target. After the release assets are available, `cargo publish` publishes the library and CLI package to the registry.

The implementation follows the public [Secure MCP Tunnel protocol](https://github.com/openai/tunnel-client/blob/master/docs/protocol.md) and [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28). It is distributed under the [MIT license](LICENSE).
