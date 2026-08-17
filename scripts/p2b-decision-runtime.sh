#!/usr/bin/env bash
# P2-B Governance decision runtime — exact-owned lifecycle. Loopback only.
#
#   GOVERNANCE_EXPECTED_SHA=<sha> scripts/p2b-decision-runtime.sh up [port]
#   scripts/p2b-decision-runtime.sh status
#   scripts/p2b-decision-runtime.sh down
#
# SAFETY / FAIL-CLOSED GATES (any failure refuses to start):
#  1. GOVERNANCE_EXPECTED_SHA is required and must equal `git rev-parse HEAD`
#     of this checkout (wrong Governance SHA -> refused).
#  2. The canonical trust config config/p2b-canary-trust.json must exist,
#     carry the RESOLVED_AT_LAUNCH placeholder, and validate after the git
#     HEAD is stamped in (malformed config -> refused).
#  3. Binding is hardcoded loopback (127.0.0.1); the server additionally
#     refuses the decision runtime on any non-loopback HOST.
#  4. down() kills only the PID this script recorded. No broad kills.
#  5. GOVERNANCE_RUNTIME_DIR may point the runtime state (pidfile, stamped
#     config, receipt chains) at an isolated directory so test launches can
#     never touch a live runtime's append-only chains. Default is the
#     canonical .p2b-runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN="${GOVERNANCE_RUNTIME_DIR:-$ROOT/.p2b-runtime}"
CANON="$ROOT/config/p2b-canary-trust.json"
RUNTIME_CONFIG="$RUN/trust.runtime.json"
PIDFILE="$RUN/server.pid"
PORT="${2:-${GOVERNANCE_PORT:-8848}}"
HOST="127.0.0.1"

up() {
  mkdir -p "$RUN"

  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "refuse: runtime already up (pid $(cat "$PIDFILE"))" >&2; exit 1
  fi

  if [[ -z "${GOVERNANCE_EXPECTED_SHA:-}" ]]; then
    echo "refuse: GOVERNANCE_EXPECTED_SHA is required" >&2; exit 1
  fi

  local head_sha
  head_sha="$(git -C "$ROOT" rev-parse HEAD)"

  if [[ "$head_sha" != "$GOVERNANCE_EXPECTED_SHA" ]]; then
    echo "refuse: governance SHA mismatch (HEAD $head_sha != expected $GOVERNANCE_EXPECTED_SHA)" >&2; exit 1
  fi

  if [[ ! -f "$CANON" ]]; then
    echo "refuse: canonical trust config missing: $CANON" >&2; exit 1
  fi

  # Stamp implementation_sha with the verified HEAD, then validate strictly.
  umask 177
  IMPL_SHA="$head_sha" CANON="$CANON" OUT="$RUNTIME_CONFIG" node --input-type=module -e '
    import fs from "node:fs";
    import { validateTrustConfig } from "./src/trust.mjs";
    const raw = JSON.parse(fs.readFileSync(process.env.CANON, "utf8"));
    if (raw.implementation_sha !== "RESOLVED_AT_LAUNCH") {
      console.error("refuse: canonical config implementation_sha must be the RESOLVED_AT_LAUNCH placeholder");
      process.exit(1);
    }
    raw.implementation_sha = process.env.IMPL_SHA;
    validateTrustConfig(raw);
    fs.writeFileSync(process.env.OUT, JSON.stringify(raw, null, 2) + "\n");
  '
  umask 022

  HOST="$HOST" PORT="$PORT" \
  GOVERNANCE_DECISION_ENABLED=1 \
  GOVERNANCE_TRUST_CONFIG="$RUNTIME_CONFIG" \
  GOVERNANCE_RECEIPTS_LOG="$RUN/receipts.jsonl" \
  GOVERNANCE_CONSUMPTION_LOG="$RUN/consumption.jsonl" \
  GOVERNANCE_AUTHORIZE_RECEIPTS_LOG="$RUN/authorize-receipts.jsonl" \
  GOVERNANCE_AUTHORIZE_CONSUMPTION_LOG="$RUN/authorize-consumption.jsonl" \
  GOVERNANCE_AUDIT_LOG="$RUN/audit.jsonl" \
  node src/server.mjs > "$RUN/server.log" 2>&1 &
  echo $! > "$PIDFILE"

  for _ in $(seq 1 40); do
    if curl -sf "http://$HOST:$PORT/health" > /dev/null 2>&1; then
      echo "up: pid $(cat "$PIDFILE") on http://$HOST:$PORT (decision runtime enabled, SHA $head_sha)"
      return 0
    fi
    sleep 0.25
  done

  echo "refuse: server did not become healthy; stopping" >&2
  down
  exit 1
}

status() {
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "up: pid $(cat "$PIDFILE")"
    curl -s "http://$HOST:$PORT/health" || true
    echo
  else
    echo "down"
  fi
}

down() {
  if [[ -f "$PIDFILE" ]]; then
    local pid
    pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
    echo "down (exact-owned pid only)"
  else
    echo "down (no pidfile)"
  fi
}

case "${1:-}" in
  up) up ;;
  status) status ;;
  down) down ;;
  *) echo "usage: [GOVERNANCE_EXPECTED_SHA=<sha>] $0 {up [port]|status|down}" >&2; exit 1 ;;
esac
