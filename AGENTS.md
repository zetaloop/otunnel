# otunnel

A Rust implementation of OpenAI's MCP tunnel client, available as a CLI and library.

## Scope

Follow the latest tunnel-client runtime protocol and command behavior. Reuse its configuration syntax, defaults, precedence, profiles and local state formats. Treat differences outside the explicit choices below as implementation errors.

Ship one executable, `otunnel`. Product identity uses its own name and version; protocol identifiers and cryptographic domain strings follow upstream.

Include MCP forwarding, OAuth, Harpoon, health, metrics, diagnostics, profiles and tunnel/runtime management. Status and system APIs support runtime management.

Use an externally installed `cloudflared` from `PATH` or `cloudflared.path`.

Upstream Codex integration, plugin installers, the web dashboard, payload history and dev commands are outside scope. Their settings accept upstream defaults; unsupported activation reports an error.

## Implementation

The CLI and library share one implementation on the caller's Tokio runtime. Diagnostics use the same transports, configuration and process management as normal operation.

Stdio routes concurrent requests, progress and cancellation by session and request ID. The incoming `X-Request-Id` is available in `params._meta["otunnel/requestId"]`. Preserve unknown JSON fields and numeric precision. Delivery retries resend completed results without rerunning tools.

Tunnel-client metrics, labels and accounting follow upstream. Human-readable logs and Rust runtime telemetry may differ.

## Development

See `docs/development.md` for checks and native packaging. Validate behavioral changes with targeted protocol experiments and upstream comparisons.
