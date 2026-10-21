<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">WebSocket inspector agent</h3>

<p align="center">Inspects WebSocket frames after the upgrade for XSS, SQL injection and command injection patterns, schema violations, size and rate limits.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-websocket-inspector/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-websocket-inspector/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/websocket-inspector/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For applications that carry user input over WebSocket, where request-phase
inspection never sees the messages. The agent receives each frame in both
directions, checks size and per-connection rate limits, matches text frames
(and optionally binary frames) against built-in and custom regex patterns, and
validates them against a JSON Schema or as MessagePack. A pattern or schema hit
drops the frame; a size or rate-limit violation closes the connection.
Inspection is per frame: fragmented messages are not reassembled, so a payload
split across frames can evade the patterns.

## Quick start

```bash
zentinel bundle install websocket-inspector
zentinel-websocket-inspector-agent --socket /var/run/zentinel/websocket-inspector.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "websocket-inspector" type="custom" {
        unix-socket "/var/run/zentinel/websocket-inspector.sock"
        events "websocket_frame"
        timeout-ms 50
        failure-mode "closed"
    }
}

routes {
    route "ws" {
        matches {
            path-prefix "/ws"
        }
        websocket #true
        websocket-inspection #true
        upstream "backend"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

Frames reach the agent because the route sets both `websocket #true` and
`websocket-inspection #true`, and the agent subscribes to `websocket_frame`; no
filter is involved. For frames, the agent block's `failure-mode` decides what
happens when the agent is unavailable (`"open"` forwards frames uninspected).
The proxy skips frame inspection when the connection negotiates
`permessage-deflate`.

## Install

**Bundle (recommended).** Downloads the release binary for your platform:

```bash
zentinel bundle install websocket-inspector
```

See [the bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

**Cargo, from the repository.** The crate is not on crates.io; this builds the
`zentinel-websocket-inspector-agent` binary from `main`:

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-websocket-inspector
```

**Release binaries.** Each [release](https://github.com/zentinelproxy/zentinel-agent-websocket-inspector/releases)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` archives:

```bash
VERSION=0.4.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-websocket-inspector-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-websocket-inspector/releases/download/v${VERSION}/zentinel-websocket-inspector-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-websocket-inspector-agent.tar.gz
sudo install -m 0755 zentinel-websocket-inspector-agent /usr/local/bin/
```

**From source.**

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-websocket-inspector
cd zentinel-agent-websocket-inspector
cargo build --release
```

## Configuration

The agent is configured with flags or environment variables; an agent block's
`config { }` in the proxy's KDL is not forwarded to the agent by the current
proxy.

Boolean flags take no value: `--fail-open` turns an option on. Options that
default to on can only be turned off through their environment variable, for
example `WS_BLOCK_MODE=false` for detect-only mode or `WS_CMD=false`
(`--block-mode false` is rejected).

```bash
# Rate and size limits
zentinel-websocket-inspector-agent \
  --socket /var/run/zentinel/websocket-inspector.sock \
  --max-messages-per-sec 100 --max-bytes-per-sec 1048576 --rate-limit-burst 20 \
  --max-text-frame-size 65536

# Detect-only, with JSON Schema validation
WS_BLOCK_MODE=false zentinel-websocket-inspector-agent \
  --socket /var/run/zentinel/websocket-inspector.sock \
  --json-schema /etc/zentinel/ws-schema.json
```

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--socket <PATH>` | `AGENT_SOCKET` | `/tmp/zentinel-ws.sock` | Unix socket to listen on |
| `--grpc-address <ADDR>` | `WS_GRPC_ADDRESS` | none | Serve gRPC on this address instead of the socket |
| `--xss-detection` | `WS_XSS` | on | XSS patterns |
| `--sqli-detection` | `WS_SQLI` | on | SQL injection patterns |
| `--command-injection` | `WS_CMD` | on | Command injection patterns |
| `--custom-patterns <LIST>` | `WS_PATTERNS` | none | Comma-separated regexes to block |
| `--json-schema <PATH>` | `WS_JSON_SCHEMA` | none | Validate text frames against this JSON Schema |
| `--msgpack-validation` | `WS_MSGPACK` | off | Require binary frames to decode as MessagePack |
| `--inspect-binary` | `WS_INSPECT_BINARY` | off | Also run patterns on binary frames |
| `--max-messages-per-sec <N>` | `WS_RATE_MESSAGES` | `0` (off) | Frames per second per connection |
| `--max-bytes-per-sec <N>` | `WS_RATE_BYTES` | `0` (off) | Bytes per second per connection |
| `--rate-limit-burst <N>` | `WS_RATE_BURST` | `10` | Added to the per-second limits |
| `--max-text-frame-size <N>` | `WS_MAX_TEXT` | `0` (off) | Largest text or continuation frame, bytes |
| `--max-binary-frame-size <N>` | `WS_MAX_BINARY` | `0` (off) | Largest binary frame, bytes |
| `--max-message-size <N>` | `WS_MAX_MESSAGE` | `0` | Accepted but not enforced (messages are not reassembled) |
| `--block-mode` | `WS_BLOCK_MODE` | on | Off: log detections and forward the frame |
| `--fail-open` | `WS_FAIL_OPEN` | off | Forward frames the agent cannot decode instead of dropping them |
| `--log-frames` | `WS_LOG_FRAMES` | off | Log every frame |
| `-v, --verbose` | `VERBOSE` | off | Debug logging |

Proxy-side options (`events`, `timeout-ms`, `failure-mode`):
<https://docs.zentinelproxy.io/configuration/agents/>. Agent reference:
<https://registry.zentinelproxy.io/websocket-inspector/>.

## How it works

For each frame, in order:

1. Size limit by opcode. Exceeded: close with `1009` (Message Too Big), tag `ws-size-limit`.
2. Rate limit per connection, over a one-second window, counting frames in both
   directions. Exceeded: close with `1008` (Policy Violation), tag `ws-rate-limit`.
3. Control frames (close, ping, pong) are allowed.
4. Text and continuation frames are matched against the enabled patterns and
   the JSON Schema; binary frames against the patterns (with
   `--inspect-binary`) and MessagePack. A hit drops the frame, tagged
   `ws-xss`, `ws-sqli`, `ws-cmd-injection`, `ws-custom-pattern` or
   `ws-schema-invalid`.

In detect-only mode the same tags are logged with `detect-only` and the frame
is forwarded.

Built-in patterns:

- **XSS:** `<script`, `</script`, `on…=` event handlers, `javascript:`,
  `vbscript:`, `data:text/html`, CSS `expression(`, `<svg … onload=`,
  `<iframe`, `<object` / `<embed`.
- **SQL injection:** `UNION [ALL] SELECT`, `OR 1=1`, `' OR '`, `AND 1=1`,
  trailing `--` or `#`, `/* … */`, `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`,
  `; DROP|DELETE|UPDATE|…`, `INFORMATION_SCHEMA`, `0x…` hex literals.
- **Command injection:** `;`, `|`, `&&` or `||` followed by a word, backticks,
  `$(…)`, reads of `/etc/`, `rm -r`/`-f`, `wget`/`curl http`, `nc -…`,
  `/bin/sh -i|-c`, `/dev/tcp/` redirects.

The command-injection and hex patterns are broad: any free text containing
`; word` or `| word` is dropped while they are on, so test against your real
traffic, or start in detect-only mode.

The agent reports frame, block, drop, rate-limit and byte counters as v2
metrics.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --test integration   # integration tests only
```

## Related

- [Registry page](https://registry.zentinelproxy.io/websocket-inspector/)
- [Agents configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)
- [MQTT gateway agent](https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway), for MQTT over WebSocket

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
