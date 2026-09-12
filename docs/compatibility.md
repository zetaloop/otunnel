# Compatibility

This comparison uses the public [tunnel-client source at 661a06f](https://github.com/openai/tunnel-client/tree/661a06f9989d50612d822093fdf8ac72f6443bdc). The wire contract is described in its [protocol reference](https://github.com/openai/tunnel-client/blob/661a06f9989d50612d822093fdf8ac72f6443bdc/docs/protocol.md). `otunnel` is an independent implementation of the tunnel runtime, with its own library and operator interfaces.

## Runtime design

| Area | tunnel-client | otunnel | Rationale |
| --- | --- | --- | --- |
| Shared stdio | Serializes the complete request lifetime | Routes concurrent requests through one reader and writer | A long-running tool can coexist with another conversation's request |
| Embedding | Go SDK and application wiring | Rust library on the caller's Tokio runtime | The same runtime serves the CLI and embedded applications |
| Diagnostics | Separate diagnostic client and startup flow | Uses the configured MCP transport and service lifecycle | Socket, TLS, and startup behavior can be checked through the actual connection |
| HTTP-owned processes | Uses a separate process channel with explicit poll selection | Also accepts `command`, `cwd`, and `env` on the HTTP binding | Process ownership can be described in one service entry |
| Command arguments | Shell-style command string | Also accepts an argument array | Argument boundaries survive spaces and platform-specific paths |
| Startup | May continue polling after a failed MCP startup probe | Requires configured service discovery to complete | The process reports a startup error when its selected services cannot be used |
| Local activity | Full administrative UI and exports | Status page, events, and counters | The operator interface is independent of the MCP payload format |

The stdio multiplexing design owns the downstream initialization. Legacy initialization results are cached, upstream sessions receive separate session IDs, and requests use private downstream IDs. This has different initialization and client-capability behavior from a verbatim byte relay. The concurrency improvement does not imply identical session state in every MCP server.

## Configuration locations

Both programs select a YAML file with `--config`, a named profile with `--profile`, or a profile path with `--profile-file`. Explicit command-line source selection takes precedence over environment selection. A configuration path is selected explicitly; the working directory supplies the base for relative paths inside the file.

| Profile location | tunnel-client | otunnel |
| --- | --- | --- |
| `XDG_CONFIG_HOME` is set | `$XDG_CONFIG_HOME/tunnel-client` | `$XDG_CONFIG_HOME/otunnel` |
| Otherwise, `HOME` is set | `$HOME/.config/tunnel-client` | `$HOME/.config/otunnel` |
| Windows without either variable | `%APPDATA%/tunnel-client` | `%APPDATA%/otunnel` |
| macOS without either variable | `~/Library/Application Support/tunnel-client` | `~/Library/Application Support/otunnel` |

Each named profile is `NAME.yaml`. `--profile-dir` can select the existing tunnel-client directory. The namespace change gives the Rust client's settings their own location while explicit paths reuse existing files.

`otunnel` accepts the original runtime environment names for the implemented settings, plus `OTUNNEL_CONFIG` and `OTUNNEL_HTTP_PROXY`. Collections follow replacement precedence: a command-line or environment header collection replaces the YAML collection. Bindings accept newline-separated environment entries; headers also accept JSON objects.

Literal runtime keys and command arrays extend the accepted configuration syntax. Certificate references select PEM files. The YAML reader reports unsupported fields; a profile containing a full-client-only setting must be reviewed against the [configuration reference](configuration.md).

## Defaults

| Setting | tunnel-client | otunnel | Assessment |
| --- | --- | --- | --- |
| Health listener | `127.0.0.1:8080` | `127.0.0.1:0` | An ephemeral port supports multiple local instances without choosing fixed ports |
| Log destination | stdout | stderr | stdout remains available for command results and reports |
| MCP startup allowance | Opt-in | `30s` | Configuration-owned processes receive time to create their listener |
| MCP connection lifetime | `10m` | Unset | The service's response deadline applies; a separate local lifetime remains configurable |
| Concurrent MCP requests | `10` | `32` per channel | A tuning difference; there is no comparative benchmark establishing 32 as a better default |
| Harpoon redirect limit | `5` | `10` | A policy difference rather than a demonstrated optimization |
| Harpoon response limit | `102400` bytes | Unset | Larger responses are accepted by default; a configured limit still applies |

The control-plane inflight default, poll duration, initial poll duration, and poll allowance are the same: 20 requests, 30 seconds, 30 seconds, and 5 seconds. The initial requested wait is capped by the ordinary poll duration. The service-supplied response deadline includes queueing, execution, and response delivery.

## Protocol-sensitive differences

The following differences affect authentication or request semantics and require agreement with the original behavior when those features are used. They are separate from configurable defaults.

| Area | Observable difference | Consequence |
| --- | --- | --- |
| Static MCP headers | Incoming headers override configured runtime headers in otunnel; the original applies operator headers last, then discovery-specific headers | A request can select a different credential than the configured one |
| HTTP redirects | otunnel carries configured headers across same-origin paths and clears all headers on a cross-origin redirect; the original scopes static runtime headers to the configured MCP path | Redirected requests can have different credentials and protocol headers |
| OAuth metadata status | otunnel accepts successful HTTP statuses and continues to another candidate after other failures; the original has status-specific fallback and preserves selected metadata statuses | An authorization failure can be replaced by a different discovery result |
| Authorization server identity | otunnel selects the first successful metadata document with an issuer; the original prefers a document matching the advertised issuer before using its mismatch fallback | A pathful issuer can resolve to the wrong authorization server metadata |
| Private OAuth registration | The original propagates the trusted MCP origin into private-host registration and issuer-path socket routing; otunnel's checks use a different origin and host-classifier combination | Different private endpoints can become callable through Harpoon |
| Harpoon request policy | Header filtering, request-body limits, redirect exhaustion, and conflicting URL transports are handled differently | The same call can transmit different headers, be accepted under different limits, or return a different error |
| Harpoon templates | The original uses full-string patterns, restricted identifiers, credential-header rules, and detailed bounds; otunnel accepts a broader schema and value set | A template is not an interchangeable authorization policy between clients |
| Health and metrics | Liveness and readiness status codes have the same purpose, but response bodies, component routes, and metric names differ | Existing dashboards and health clients need the corresponding interface |

A `404` response to notification delivery retires the command, just as a terminal response `404` does. The tool is not re-executed. Individual malformed poll items are skipped without discarding other items from the same response. Unknown command properties remain accepted, and unsupported command types are logged independently.

The original exposes optional structured tunnel-failure provenance. otunnel preserves actual MCP errors but has its own synthesized transport-error text. Applications inspecting diagnostic details should use the appropriate client interface.

## Additional operator features

The original full client provides profile creation and management, admin commands, native runtime management, Codex integration, log and payload export, and an expanded administrative UI. The otunnel CLI provides `run`, `doctor`, `health`, and shell completion.

The original distribution bundles cloudflared. otunnel supervises an installed executable selected by `cloudflared.path`. Both static and managed tokens are supported, and an explicit static token takes precedence. Distribution size and the external executable dependency are separate tradeoffs.

The original also learns a shorter long-poll wait after certain proxy idle disconnects. otunnel retries with the configured wait. Its status page shows connection recovery, but that does not supply the adaptive proxy behavior.

## Release checks

The release workflow checks formatting, Clippy, the native executable, the pure library, and existing Cargo tests before producing a release draft. This is build validation, not a claim of upstream behavioral conformance.

The original [end-to-end harness](https://github.com/openai/tunnel-client/tree/661a06f9989d50612d822093fdf8ac72f6443bdc/e2e) mixes Go-library scenarios with shipped-binary scenarios. The binary scenarios also assert original log messages, health bodies, and administrative behavior. Reusing those scenarios requires a subject adapter and an explicit selection of the interface being compared; compiling the Rust crate alone does not run them.
