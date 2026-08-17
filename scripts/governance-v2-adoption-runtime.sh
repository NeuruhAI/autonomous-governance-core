#!/usr/bin/env bash
# Governance V2 adoption runtime — ISOLATED alternate-port lifecycle.
#
#   GOVERNANCE_EXPECTED_SHA=<sha> \
#   GOVERNANCE_RUNTIME_DIR=<isolated-dir> \
#   GOVERNANCE_FOUNDER_SECRET=<secret> \
#     scripts/governance-v2-adoption-runtime.sh {up|verify|up-verified|status|down} <port>
#
# SAFETY / FAIL-CLOSED GATES (any failure refuses):
#  1. GOVERNANCE_EXPECTED_SHA is required and must equal `git rev-parse HEAD`.
#  2. GOVERNANCE_RUNTIME_DIR is required and must NOT be the canonical
#     .p2b-runtime: an adoption launch never shares pidfile or append-only
#     chains with a live runtime.
#  3. The port is required and must NOT be 8848 (the live port): this script
#     can never bind over live Governance.
#  4. GOVERNANCE_FOUNDER_SECRET is required (>=16 chars, not the placeholder)
#     and is stamped into the runtime copy of the adoption trust config; the
#     committed config carries only the RESOLVED_AT_LAUNCH placeholder.
#  5. Binding is hardcoded loopback; the server additionally refuses the
#     decision runtime on any non-loopback HOST.
#  6. down() kills only the PID this script recorded. No broad kills.
#  7. up-verified: after a healthy start the FULL acceptance matrix
#     (scripts/governance-v2-acceptance-probe.mjs) runs against the instance;
#     ANY semantic failure triggers AUTOMATIC ROLLBACK (exact-owned down) and
#     a non-zero exit. An instance that cannot prove its semantics does not
#     stay up.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CANON="$ROOT/config/governance-v2-adoption-trust.json"
LIVE_PORT="8848"
HOST="127.0.0.1"
MODE="${1:-}"
PORT="${2:-}"

require_isolation() {
  if [[ -z "${GOVERNANCE_RUNTIME_DIR:-}" ]]; then
    echo "refuse: GOVERNANCE_RUNTIME_DIR is required (isolated adoption runtime dir)" >&2; exit 1
  fi
  case "$(cd "$(dirname "$GOVERNANCE_RUNTIME_DIR")" 2>/dev/null && pwd)/$(basename "$GOVERNANCE_RUNTIME_DIR")" in
    "$ROOT/.p2b-runtime")
      echo "refuse: GOVERNANCE_RUNTIME_DIR must not be the canonical .p2b-runtime" >&2; exit 1 ;;
  esac
  RUN="$GOVERNANCE_RUNTIME_DIR"
  RUNTIME_CONFIG="$RUN/trust.runtime.json"
  PIDFILE="$RUN/server.pid"
}

require_port() {
  if [[ -z "$PORT" ]]; then
    echo "refuse: port argument is required" >&2; exit 1
  fi
  if [[ "$PORT" == "$LIVE_PORT" ]]; then
    echo "refuse: port $LIVE_PORT is the live Governance port; adoption runtime never binds it" >&2; exit 1
  fi
}

up() {
  require_isolation
  require_port
  mkdir -p "$RUN"

  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "refuse: adoption runtime already up (pid $(cat "$PIDFILE"))" >&2; exit 1
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
    echo "refuse: adoption trust config missing: $CANON" >&2; exit 1
  fi

  if [[ -z "${GOVERNANCE_FOUNDER_SECRET:-}" || "${#GOVERNANCE_FOUNDER_SECRET}" -lt 16 || "${GOVERNANCE_FOUNDER_SECRET}" == "RESOLVED_AT_LAUNCH" ]]; then
    echo "refuse: GOVERNANCE_FOUNDER_SECRET is required (>=16 chars, not the placeholder)" >&2; exit 1
  fi

  # Stamp implementation_sha and the founder secret, then validate strictly.
  umask 177
  IMPL_SHA="$head_sha" CANON="$CANON" OUT="$RUNTIME_CONFIG" node --input-type=module -e '
    import fs from "node:fs";
    import { validateTrustConfig } from "./src/trust.mjs";
    const raw = JSON.parse(fs.readFileSync(process.env.CANON, "utf8"));
    if (raw.implementation_sha !== "RESOLVED_AT_LAUNCH") {
      console.error("refuse: adoption config implementation_sha must be the RESOLVED_AT_LAUNCH placeholder");
      process.exit(1);
    }
    if (!raw.approvers || !raw.approvers.founder || raw.approvers.founder.secret !== "RESOLVED_AT_LAUNCH") {
      console.error("refuse: adoption config founder secret must be the RESOLVED_AT_LAUNCH placeholder");
      process.exit(1);
    }
    raw.implementation_sha = process.env.IMPL_SHA;
    raw.approvers.founder.secret = process.env.GOVERNANCE_FOUNDER_SECRET;
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
      echo "up: pid $(cat "$PIDFILE") on http://$HOST:$PORT (isolated adoption runtime, SHA $head_sha)"
      return 0
    fi
    sleep 0.25
  done

  echo "refuse: server did not become healthy; stopping" >&2
  down
  exit 1
}

verify() {
  require_isolation
  require_port
  PROBE_FOUNDER_SECRET="${PROBE_FOUNDER_SECRET:-${GOVERNANCE_FOUNDER_SECRET:-}}" \
  node "$ROOT/scripts/governance-v2-acceptance-probe.mjs" "http://$HOST:$PORT"
}

up_verified() {
  up
  if verify; then
    echo "up-verified: acceptance matrix PASS on http://$HOST:$PORT"
  else
    echo "SEMANTIC FAILURE: acceptance matrix failed — automatic rollback (exact-owned down)" >&2
    down
    exit 1
  fi
}

status() {
  require_isolation
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "up: pid $(cat "$PIDFILE")"
    if [[ -n "$PORT" ]]; then curl -s "http://$HOST:$PORT/health" || true; echo; fi
  else
    echo "down"
  fi
}

down() {
  require_isolation
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

case "$MODE" in
  up) up ;;
  verify) verify ;;
  up-verified) up_verified ;;
  status) status ;;
  down) down ;;
  *) echo "usage: GOVERNANCE_EXPECTED_SHA=<sha> GOVERNANCE_RUNTIME_DIR=<dir> GOVERNANCE_FOUNDER_SECRET=<secret> $0 {up|verify|up-verified|status|down} <port>" >&2; exit 1 ;;
esac
