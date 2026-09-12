# Configuration

`otunnel` reads YAML with the same runtime sections used by the official tunnel client. The CLI applies explicit arguments, then their environment variables, then YAML values, then defaults. `otunnel run --help` lists flag names and environment variables. Library callers construct `Config` directly or use `Config::read`; environment lookup occurs for explicit `env:` references.

`--config` selects a YAML file. `OTUNNEL_CONFIG` and `TUNNEL_CLIENT_CONFIG` can supply its path. Named profiles use `--profile NAME` and `--profile-dir DIRECTORY`; the default directory is `$XDG_CONFIG_HOME/otunnel` or `~/.config/otunnel`. A named profile is `NAME.yaml`. `--profile-file` selects a profile by path. The corresponding `TUNNEL_CLIENT_PROFILE`, `TUNNEL_CLIENT_PROFILE_DIR`, and `TUNNEL_CLIENT_PROFILE_FILE` variables are accepted.

Paths are relative to the working directory, including paths in a configuration file. Durations use strings such as `250ms`, `30s`, and `10m`.

## Credentials and headers

API keys, configured header values, child environment values, socket paths, and proxy settings accept literal values, `env:NAME`, and `file:PATH`. File and environment references are evaluated by the client. Certificate settings accept a PEM file path or PEM content.

```yaml
control_plane:
  tunnel_id: tunnel_...
  api_key: file:tunnel.key
  organization_id: org_...

mcp:
  extra_headers:
    Authorization: file:mcp-authorization.txt
  discovery_extra_headers:
    X-Service-Discovery: env:SERVICE_DISCOVERY_KEY
```

The example MCP authorization file contains the entire header value, such as `Bearer ...`. Discovery headers are used for MCP discovery, initialization, tool listing, session cleanup, and OAuth discovery. Ordinary forwarded requests use `extra_headers` and their incoming request headers.

`CONTROL_PLANE_API_KEY` and `--control-plane.api-key` override the YAML runtime key. `OPENAI_API_KEY` supplies a key when none was configured through those sources.

## Control plane

| YAML field | Default | Meaning |
| --- | --- | --- |
| `control_plane.tunnel_id` | Required | Existing OpenAI Tunnel ID |
| `control_plane.api_key` | Required | Runtime key or credential reference |
| `control_plane.base_url` | `https://api.openai.com` | Control-plane origin |
| `control_plane.url_path` | Empty | Prefix before `/v1/tunnels/...` |
| `control_plane.organization_id` | Unset | `OpenAI-Organization` header |
| `control_plane.poll_channels` | All configured channels | Subscribed channel names |
| `control_plane.max_inflight_requests` | `20` | Outstanding commands, including queued work |
| `control_plane.poll_timeout` | `30s` | Requested long-poll duration |
| `control_plane.initial_poll_timeout` | `30s` | First requested poll duration, capped at `poll_timeout` |
| `control_plane.poll_deadline_guardrail` | `5s` | Additional network allowance for polling |
| `control_plane.extra_headers` | Empty | Additional HTTP headers |
| `control_plane.http_proxy` | Unset | Control-plane proxy override |
| `control_plane.client_cert` | Unset | PEM client certificate |
| `control_plane.client_key` | Unset | Matching PEM private key |

The instance ID is generated once per client instance. Polls and responses share its client identity and channel declaration. The declaration reflects each transport's stateless behavior and process affinity.

The control-plane service supplies `response_timeout` on individual commands. Its clock starts when the poll response arrives, before local queueing. An expired request releases its resources and cancels its local request. A shared stdio process remains available to other calls.

Poll failures use backoff with jitter and `Retry-After`. Terminal response delivery retries the existing bytes for eligible failures; it never re-executes the tool. Notification delivery has a bounded best-effort window so an unavailable notification endpoint cannot indefinitely block the terminal result.

## MCP services

### Stdio commands

```yaml
mcp:
  commands:
    - channel: main
      command: [serena, start-mcp-server]
      cwd: /work/project
      env:
        SERVICE_TOKEN: file:service-token.txt
```

Each command is a process with an owned stdin/stdout transport. Arguments can be supplied as an array or a shell-style string. Strings are parsed into arguments; shell operators require an explicit shell in the command. Stderr remains available to the parent terminal or its redirection.

`channel` defaults to `main`. A channel has one binding. Each enabled command is discovered before polling starts. Commands outside `control_plane.poll_channels` still run as configuration-owned processes; their stdout is inherited rather than consumed as MCP.

### HTTP bindings

```yaml
mcp:
  server_urls:
    - channel: main
      url: http://localhost/mcp
      unix_socket: /tmp/mcp.sock
      command: [chappie-lab, serve, --socket, /tmp/mcp.sock, --data, /work/lab-data]
```

`command`, `cwd`, and `env` are optional. When present, the process belongs to the HTTP binding and starts before endpoint discovery. With `unix_socket`, the URL remains the HTTP address while the connector uses the socket. Windows accepts paths such as `C:/Tmp/mcp.sock`.

Bindings may have their own `http_proxy`, `client_cert`, and `client_key`; otherwise they inherit the MCP section's values. Client certificates and socket routing are scoped to the configured origin. Requests to other origins use the ordinary HTTPS client.

| MCP field | Default | Meaning |
| --- | --- | --- |
| `server_urls` | Empty | HTTP bindings |
| `commands` | Empty | Stdio or process-only bindings |
| `extra_headers` | Empty | Base headers for MCP requests |
| `discovery_extra_headers` | Empty | Additional headers for client-owned discovery |
| `startup_wait_timeout` | `30s` | Startup allowance per service |
| `max_concurrent_requests` | `32` | Active requests per channel |
| `connection_max_ttl` | Unset | Optional lifetime for a forwarded MCP request; `0s` disables this additional limit |
| `http_proxy` | Unset | MCP proxy override |
| `client_cert` / `client_key` | Unset | Default MCP client identity |

Connection-refused and missing-socket errors during startup are retried until the startup deadline. The implementation uses the operating system's error classification on Windows and Unix.

`doctor` and `run` use the same discovery implementation. Tool listing follows all pages. For a server requiring authorization, successful OAuth discovery supplies the information needed for authentication; an unauthenticated tool list is not required.

## OAuth and Harpoon

OAuth discovery reads the protected-resource metadata advertised by a `WWW-Authenticate` challenge or the corresponding well-known document. Authorization server metadata identifies token, registration, introspection, revocation, and JWKS endpoints.

Private endpoints can be registered on the `harpoon` channel. The protected-resource document and HTTP results then use `harpoon://LABEL` references where the tunnel host must access a private endpoint. Resource identity and the token endpoint's JWT audience retain their original values. OAuth authorization pages remain browser-accessible URLs.

Harpoon provides `list_targets`, `call_target`, and `get_oauth_target_audience`. `call_target_template` appears when a parameterized target is configured. Tool results include the HTTP status, multi-value response headers, and base64-encoded response bytes. Configured response limits return an error when exceeded.

```yaml
harpoon:
  targets:
    - label: local-status
      url: http://localhost/status
      unix_socket: /tmp/service.sock
      description: Local service status
  hosts_include_loopback: true
  hosts_include_private: true
  hosts_include_suffix: [internal.example]
  hosts_include_regex: ['^auth[0-9]+\.example$']
```

Target URL calls accept GET, POST, and PUT. Redirects resolve only to registered URL targets. The default redirect limit is ten; `max_redirects` changes it. `max_response_bytes` optionally limits response bodies, and `http_proxy` selects Harpoon's outbound proxy. Per-call limits can narrow these settings.

OAuth host matching uses loopback addresses, private addresses, configured host suffixes, and regular expressions. `hosts_include_loopback` and `hosts_include_private` default to `true`; suffix and expression lists default to empty. `harpoon` is advertised when it contains targets and is included by the channel selection.

### Parameterized targets

A template binds a GET operation to an HTTPS origin, path structure, query keys, and parameter schema:

```yaml
harpoon:
  targets:
    - label: release
      description: Read a repository release
      template:
        version: 1
        origin: https://api.github.com
        method: GET
        path_template: /repos/{owner}/{repository}/releases/latest
        parameters:
          owner:
            type: string
            required: true
            min_length: 1
            max_length: 64
            pattern: '^[A-Za-z0-9-]+$'
            examples: [openai]
          repository:
            type: string
            required: true
            min_length: 1
            max_length: 100
            pattern: '^[A-Za-z0-9_.-]+$'
            examples: [tunnel-client]
        headers:
          Accept: application/vnd.github+json
        allowed_headers: [if-none-match]
```

A parameter occupies an entire path segment or query value. The URL builder encodes it in that position. Each parameter is required and has a maximum length; `pattern`, `enum`, `min_length`, `reserved_values`, and `examples` describe additional constraints. Templates declare every parameter they use. Fixed headers can use credential references, while caller-supplied headers are selected by `allowed_headers`. Template calls use their fixed destination without redirecting.

`list_targets` includes each template's parameter schema, specialized invocation schema, and usable examples when provided by the configuration.

## Health, logging, and process files

```yaml
health:
  listen_addr: 127.0.0.1:0
  url_file: otunnel.url
  show_details: true
log:
  level: info
  format: json
  file: otunnel.log
process:
  pid_file: otunnel.pid
```

`health.unix_socket` selects an AF_UNIX listener in place of TCP. An empty `health.listen_addr` disables the TCP listener. Binding an existing socket path fails; the client removes socket paths it created when that listener closes.

`/healthz` reports process liveness. `/readyz` and `/health` report readiness with HTTP 200 or 503. `/api/status` and `/health/mcp` expose the snapshot, `/api/events` streams changes, `/ui` displays activity, and `/metrics` exposes Prometheus text metrics.

The snapshot includes control-plane connection state, optional Cloudflare readiness, discovered MCP services, in-flight requests, and completed, expired, or failed command counts. Completed counts refer to delivered tunnel commands, including MCP error results.

`log.file` appends to an existing file and defaults to stderr. `log.format` accepts `text`, `struct-text`, or `json`. `log.level` accepts a tracing filter. Runtime URL and PID files are removed during normal shutdown when they still contain this process's recorded value.

`doctor --json` emits a machine-readable report. `doctor` and `health` exit with status 0 when their checks pass and 2 when they fail. `run` returns 1 for startup or runtime failure.

## Cloudflare companion

A static token starts an installed `cloudflared` alongside the tunnel:

```yaml
cloudflared:
  token: file:cloudflare.key
```

A managed token is obtained through the OpenAI tunnel control plane:

```yaml
cloudflared:
  managed: true
```

Select one token source. `cloudflared.path` defaults to `cloudflared`, and `cloudflared.ready_timeout` defaults to `30s`. The token is supplied through the child environment. The companion binds its metrics listener to an ephemeral loopback port, and readiness comes from its native `/ready` endpoint. Its state contributes to the main readiness result. The process shares the client's shutdown lifecycle.

## TLS and proxies

`ca_bundle` adds PEM roots to the platform trust store. `client_cert` and `client_key` are configured together. Setting the control-plane client identity with the default OpenAI API host selects `mtls.api.openai.com`.

`http_proxy` provides the common proxy, with overrides under `control_plane`, `mcp`, individual HTTP bindings, and `harpoon`. Ordinary `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` behavior is supplied by the HTTP client when an explicit proxy is absent. The CLI's explicit global proxy variable is `OTUNNEL_HTTP_PROXY`.

## Command-line bindings

Bindings may also be specified on the command line:

```sh
otunnel run --control-plane.tunnel-id tunnel_... --control-plane.api-key file:tunnel.key --mcp.command 'channel=main,command=serena start-mcp-server'
otunnel run --config tunnel.yaml --mcp.server-url 'channel=main,url=http://localhost/mcp,unix-socket=/tmp/mcp.sock'
```

Binding values accept CSV-style `name=value` fields or JSON objects. Repeated binding options replace the corresponding YAML list; repeated header options merge by header name. List-valued environment variables can be JSON arrays of strings. `otunnel completion` generates Bash, Elvish, Fish, PowerShell, or Zsh completion scripts.
