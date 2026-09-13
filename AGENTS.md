# otunnel

## Design

One Cargo package provides the `otunnel` CLI and an embedding library on the caller's Tokio runtime. Normal operation and diagnostics share transports, configuration and process management.

Match tunnel-client's runtime protocol, supported command effects, configuration syntax, defaults, precedence, profiles and local state. Use `otunnel` for executable and client identity. Compatibility concerns wire data, JSON results, health semantics and exit codes; log wording and language-runtime metrics are implementation-specific.

Stdio multiplexes concurrent requests by session and request ID, including progress and cancellation. Preserve opaque JSON fields and numeric precision. Result delivery retries reuse the completed result without executing the tool again.

## Product scope

Provide MCP forwarding, OAuth discovery, Harpoon, health, metrics, diagnostics, profiles and tunnel/runtime administration. Keep the status and system APIs used by runtime management.

Cloudflare support supervises an externally installed `cloudflared`, located through `PATH` or `cloudflared.path`. Distribute only the `otunnel` executable.

Codex and plugin integration, the web dashboard, payload history and development/demo commands are outside the product scope. UI and payload-capture settings accept their upstream defaults and report unsupported activation.

## Development

Follow the checks and native packaging commands in `docs/development.md`. Use targeted protocol experiments and upstream comparisons to validate behavioral changes.
