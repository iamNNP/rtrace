#!/usr/bin/env bash
set -euo pipefail

AGENT_BIN="/samples/rtrace-agent"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage:
  /samples/rtrace-agent --help
  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 500 --verbose

Examples:
  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 500 --stop-on-hit
  /samples/rtrace-agent --rules-dir /rules --pid 1234 --artifacts-dir /artifacts --stop-on-hit
  /samples/rtrace-agent --rules-dir /rules --artifacts-dir /artifacts --scan-interval-ms 500 --stop-on-hit
  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --save-maps --dump-regions
  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --once
EOF
  exit 0
fi

if [[ ! -x "$AGENT_BIN" ]]; then
  echo "Agent binary is not executable: $AGENT_BIN" >&2
  exit 1
fi

args=("$@")

if [[ "$#" -eq 0 ]]; then
  args=(--help)
fi

if [[ "$(id -u)" -eq 0 ]]; then
  exec "$AGENT_BIN" "${args[@]}"
else
  exec sudo "$AGENT_BIN" "${args[@]}"
fi
