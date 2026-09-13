# otunnel

A Rust implementation of OpenAI's MCP tunnel client, available as a CLI and library.

## Scope

Follow tunnel-client's runtime protocol and command behavior. Reuse its configuration syntax, defaults, precedence, profiles and local state formats.

Ship one executable, `otunnel`, and use its name and version in client metadata.

Include MCP forwarding, OAuth, Harpoon, health, metrics, diagnostics, profiles and tunnel/runtime management. Status and system APIs support runtime management.

Use an externally installed `cloudflared` from `PATH` or `cloudflared.path`.

Upstream Codex integration, plugin installers, the web dashboard, payload history and dev commands are outside scope. Their settings accept upstream defaults; unsupported activation reports an error.

## Implementation

The CLI and library share one implementation on the caller's Tokio runtime. Diagnostics use the same transports, configuration and process management as normal operation.

Stdio routes concurrent requests, progress and cancellation by session and request ID. Preserve unknown JSON fields and numeric precision. Delivery retries resend completed results without rerunning tools.

Human-readable logs and language-runtime metrics may differ from upstream.

## Development

See `docs/development.md` for checks and native packaging. Validate behavioral changes with targeted protocol experiments and upstream comparisons.
