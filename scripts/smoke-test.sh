#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared #
# release workflow sets. Run by that workflow on every platform before any #
# asset is published, and by CI on every push and pull request. # # Over the
# Unix socket and over gRPC, with the default configuration: #   * the v2
# handshake works and plain HTTP requests (GET, POST) are allowed #
# through to the upstream: the agent subscribes to WebSocket frames and #
# must not get in the way of anything else; #   * with the agent stopped the
# clean request is refused (agent on the path). # # The WebSocket inspector's
# decisions (content filtering, schema validation, rate and size limits) are
# made on WebSocket frames. The harness speaks plain HTTP only, so frame cases
# are not covered here; they are covered by the unit and integration tests
# (cargo test).

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

cases=(
    --clean '{"name": "plain GET", "path": "/smoke"}'
    --case '{"name": "plain POST", "method": "POST", "path": "/smoke", "headers": {"Content-Type": "application/json"}, "body": "{\"msg\": \"<script>alert(1)</script>\"}", "expect": 200}'
)

for transport in uds grpc; do
    echo "=== websocket-inspector agent over $transport"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" \
        --name websocket-inspector --transport "$transport" \
        --events request_headers,websocket_frame \
        "${cases[@]}"
done
