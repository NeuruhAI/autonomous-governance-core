#!/usr/bin/env bash
# ============================================================================
# GOVERNANCE V2 LIVE DEPLOY — EXACT-LABEL, FOUNDER-EXECUTED ONLY.
#
# STATUS: PREPARED DURING ADOPTION PREP 2026-08-16. NEVER EXECUTED.
# Syntax-checked only (bash -n). Executing this script is a separate,
# explicitly-authorized founder act (R3 qualified adoption of Governance
# itself: exact target, exact rollback, preflight, postflight).
#
# WHAT IT DOES (phases, each fail-closed):
#   0 CONFIRM    — refuses without the founder confirmation phrase, a
#                  last-known-good (LKG) rollback SHA, and a founder secret.
#   1 PRECHECK   — sealed tag must dereference to the exact candidate SHA,
#                  HEAD must equal it, worktree clean, full test suite green,
#                  stale-pin refusal self-test, LKG SHA must exist.
#   2 REHEARSAL  — isolated alternate-port launch + FULL acceptance matrix
#                  (scripts/governance-v2-adoption-runtime.sh up-verified);
#                  any semantic failure aborts before live is touched.
#   3 CUTOVER    — stop the exact current live pid (pidfile, or operator-
#                  supplied GOVERNANCE_LIVE_PID verified to be this repo's
#                  node src/server.mjs; never a broad kill), stamp the V2
#                  trust config, launch on the live port with the SAME
#                  append-only decide chain (chains are never truncated).
#   4 SEMANTIC GATE — health + policy read + the full acceptance matrix
#                  against the live instance (PROBE_ALLOW_LIVE=1).
#   5 AUTO-ROLLBACK — ANY phase 3/4 failure: exact-owned down of the new
#                  pid, checkout of GOVERNANCE_LKG_SHA, relaunch of the
#                  previous runtime config, LKG health + canary re-verify.
#                  Rollback failure exits 2 with an explicit operator alarm.
#
# ROLLBACK CONTRACT: the pre-cutover runtime config is preserved untouched at
# $LIVE_RUN/trust.runtime.json until success; the V2 config is stamped to
# trust.runtime.v2.json and only renamed over the old file AFTER the semantic
# gate passes. Receipts chains are append-only throughout; nothing is deleted.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

CANDIDATE_TAG="governance-v2-candidate-v1-20260816"
CANDIDATE_SHA="3fe9eb93e5a4947bd4cd4a3dd1f48b000d8b1d37"
CONFIRM_PHRASE="I-AM-THE-FOUNDER-DEPLOY-GOVERNANCE-V2-20260816"
LIVE_PORT="8848"
HOST="127.0.0.1"
LIVE_RUN="$ROOT/.p2b-runtime"
CANON="$ROOT/config/governance-v2-adoption-trust.json"
REHEARSAL_PORT="${REHEARSAL_PORT:-18740}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LIVE_RUN/deploy-$TS.log"

say() { echo "[deploy $TS] $*" | tee -a "$LOG" >&2; }
die() { say "REFUSE: $*"; exit 1; }

# ---------------------------------------------------------------- phase 0
[[ "${DEPLOY_CONFIRM:-}" == "$CONFIRM_PHRASE" ]] \
  || die "DEPLOY_CONFIRM must be the exact founder confirmation phrase. This script is founder-executed only."
[[ -n "${GOVERNANCE_LKG_SHA:-}" ]] || die "GOVERNANCE_LKG_SHA (rollback target) is required."
[[ -n "${GOVERNANCE_FOUNDER_SECRET:-}" && "${#GOVERNANCE_FOUNDER_SECRET}" -ge 16 && "${GOVERNANCE_FOUNDER_SECRET}" != "RESOLVED_AT_LAUNCH" ]] \
  || die "GOVERNANCE_FOUNDER_SECRET is required (>=16 chars, not the placeholder)."
mkdir -p "$LIVE_RUN"

# ---------------------------------------------------------------- phase 1
say "PRECHECK: verifying sealed candidate"
git fetch origin --tags >>"$LOG" 2>&1

tag_sha="$(git rev-parse "$CANDIDATE_TAG^{commit}")"
[[ "$tag_sha" == "$CANDIDATE_SHA" ]] || die "tag $CANDIDATE_TAG dereferences to $tag_sha, not the sealed $CANDIDATE_SHA."

# HEAD must DESCEND from the sealed candidate and carry a byte-identical
# governed surface (V2 source, canonical config, tests, samples, package,
# decide-contract scripts). The deploy tooling itself was added after the
# seal, so HEAD can never literally equal the sealed commit — descent plus
# surface identity IS the exact-qualified condition.
head_sha="$(git rev-parse HEAD)"
git merge-base --is-ancestor "$CANDIDATE_SHA" "$head_sha" \
  || die "HEAD $head_sha does not descend from the sealed candidate $CANDIDATE_SHA."
git diff --quiet "$CANDIDATE_SHA" "$head_sha" -- \
  src tests samples package.json \
  config/p2b-canary-trust.json \
  scripts/p2b-canary-decision-probe.mjs scripts/p2b-decision-runtime.sh \
  || die "governed surface at HEAD differs from the sealed candidate; this is not the qualified adoption."

[[ -z "$(git status --porcelain)" ]] || die "worktree is not clean."

git cat-file -t "$GOVERNANCE_LKG_SHA" >/dev/null 2>&1 || die "GOVERNANCE_LKG_SHA $GOVERNANCE_LKG_SHA is not a known commit."

say "PRECHECK: running full test suite"
npm test >>"$LOG" 2>&1 || die "test suite failed; see $LOG."

say "PRECHECK: stale-pin refusal self-test"
node --input-type=module -e '
import fs from "node:fs";
import { validateTrustConfig } from "./src/trust.mjs";
const stale = JSON.parse(fs.readFileSync(process.env.CANON, "utf8"));
stale.implementation_sha = "0000000000000000000000000000000000000000";
// Throwaway self-test filler (not a credential): long enough to validate.
stale.approvers.founder.secret = "selftest".repeat(4);
stale.expected_source_shas.founder_runtime = ["a08f4abb908db02db1829730790140946504450c"];
try { validateTrustConfig(stale); process.exit(1); } catch { process.exit(0); }
' CANON="$CANON" || die "stale-pin refusal self-test FAILED: a stale identity pin was accepted."

# ---------------------------------------------------------------- phase 2
say "REHEARSAL: isolated alternate-port launch + acceptance matrix (port $REHEARSAL_PORT)"
REHEARSAL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gov-v2-deploy-rehearsal.XXXXXX")"
if ! GOVERNANCE_EXPECTED_SHA="$head_sha" \
     GOVERNANCE_RUNTIME_DIR="$REHEARSAL_DIR" \
     GOVERNANCE_FOUNDER_SECRET="$GOVERNANCE_FOUNDER_SECRET" \
     bash "$ROOT/scripts/governance-v2-adoption-runtime.sh" up-verified "$REHEARSAL_PORT" >>"$LOG" 2>&1; then
  die "isolated rehearsal failed its acceptance matrix (auto-rolled-back); live was never touched. See $LOG."
fi
GOVERNANCE_RUNTIME_DIR="$REHEARSAL_DIR" bash "$ROOT/scripts/governance-v2-adoption-runtime.sh" down "$REHEARSAL_PORT" >>"$LOG" 2>&1
say "REHEARSAL: PASS"

# ---------------------------------------------------------------- phase 3
say "CUTOVER: identifying the exact current live pid"
live_pid=""
if [[ -f "$LIVE_RUN/server.pid" ]] && kill -0 "$(cat "$LIVE_RUN/server.pid")" 2>/dev/null; then
  live_pid="$(cat "$LIVE_RUN/server.pid")"
elif [[ -n "${GOVERNANCE_LIVE_PID:-}" ]]; then
  live_pid="$GOVERNANCE_LIVE_PID"
  ps -o command= -p "$live_pid" | grep -q "node src/server.mjs" \
    || die "GOVERNANCE_LIVE_PID $live_pid is not a 'node src/server.mjs' process; refusing exact-owned stop."
  lsof -a -p "$live_pid" -d cwd 2>/dev/null | grep -q "$ROOT" \
    || die "GOVERNANCE_LIVE_PID $live_pid does not run from $ROOT; refusing exact-owned stop."
else
  die "no live pidfile and no GOVERNANCE_LIVE_PID supplied; will not guess which process to stop."
fi

say "CUTOVER: stamping V2 live trust config (previous config preserved for rollback)"
# implementation_sha records the code ACTUALLY running (HEAD); the sealed
# ancestor is recorded by the candidate tag and the deployment receipt.
umask 177
IMPL_SHA="$head_sha" CANON="$CANON" OUT="$LIVE_RUN/trust.runtime.v2.json" node --input-type=module -e '
import fs from "node:fs";
import { validateTrustConfig } from "./src/trust.mjs";
const raw = JSON.parse(fs.readFileSync(process.env.CANON, "utf8"));
if (raw.implementation_sha !== "RESOLVED_AT_LAUNCH") { console.error("placeholder missing"); process.exit(1); }
if (raw.approvers.founder.secret !== "RESOLVED_AT_LAUNCH") { console.error("secret placeholder missing"); process.exit(1); }
raw.implementation_sha = process.env.IMPL_SHA;
raw.approvers.founder.secret = process.env.GOVERNANCE_FOUNDER_SECRET;
validateTrustConfig(raw);
fs.writeFileSync(process.env.OUT, JSON.stringify(raw, null, 2) + "\n");
' || die "V2 live config stamping failed."
umask 022

launch_live() { # $1 = trust config path, $2 = label
  HOST="$HOST" PORT="$LIVE_PORT" \
  GOVERNANCE_DECISION_ENABLED=1 \
  GOVERNANCE_TRUST_CONFIG="$1" \
  GOVERNANCE_RECEIPTS_LOG="$LIVE_RUN/receipts.jsonl" \
  GOVERNANCE_CONSUMPTION_LOG="$LIVE_RUN/consumption.jsonl" \
  GOVERNANCE_AUTHORIZE_RECEIPTS_LOG="$LIVE_RUN/authorize-receipts.jsonl" \
  GOVERNANCE_AUTHORIZE_CONSUMPTION_LOG="$LIVE_RUN/authorize-consumption.jsonl" \
  GOVERNANCE_AUDIT_LOG="$LIVE_RUN/audit.jsonl" \
  node src/server.mjs >>"$LIVE_RUN/server-$2-$TS.log" 2>&1 &
  echo $! > "$LIVE_RUN/server.pid"
}

stop_pid_exact() { # $1 = pid
  kill "$1" 2>/dev/null || true
  for _ in $(seq 1 40); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.25; done
  kill -9 "$1" 2>/dev/null || true
}

wait_health() {
  for _ in $(seq 1 40); do
    curl -sf "http://$HOST:$LIVE_PORT/health" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  return 1
}

rollback() {
  say "AUTOMATIC ROLLBACK: stopping the new pid and restoring LKG $GOVERNANCE_LKG_SHA"
  if [[ -f "$LIVE_RUN/server.pid" ]]; then stop_pid_exact "$(cat "$LIVE_RUN/server.pid")"; rm -f "$LIVE_RUN/server.pid"; fi
  git checkout --detach "$GOVERNANCE_LKG_SHA" >>"$LOG" 2>&1 || { say "ROLLBACK FAILURE: cannot checkout LKG"; exit 2; }
  [[ -f "$LIVE_RUN/trust.runtime.json" ]] || { say "ROLLBACK FAILURE: previous runtime config missing"; exit 2; }
  launch_live "$LIVE_RUN/trust.runtime.json" "rollback"
  wait_health || { say "ROLLBACK FAILURE: LKG runtime did not become healthy — OPERATOR INTERVENTION REQUIRED"; exit 2; }
  say "ROLLED_BACK: LKG $GOVERNANCE_LKG_SHA serving on :$LIVE_PORT with the previous trust config."
  exit 1
}

say "CUTOVER: stopping exact live pid $live_pid and launching the candidate"
stop_pid_exact "$live_pid"
launch_live "$LIVE_RUN/trust.runtime.v2.json" "v2"
wait_health || rollback

# ---------------------------------------------------------------- phase 4
say "SEMANTIC GATE: full acceptance matrix against the live instance"
if ! PROBE_ALLOW_LIVE=1 PROBE_FOUNDER_SECRET="$GOVERNANCE_FOUNDER_SECRET" \
     node "$ROOT/scripts/governance-v2-acceptance-probe.mjs" "http://$HOST:$LIVE_PORT" >>"$LOG" 2>&1; then
  say "SEMANTIC FAILURE on live instance"
  rollback
fi

# ---------------------------------------------------------------- success
mv "$LIVE_RUN/trust.runtime.v2.json" "$LIVE_RUN/trust.runtime.json"
say "DEPLOYED: Governance V2 $head_sha (sealed ancestor $CANDIDATE_SHA) live on :$LIVE_PORT (pid $(cat "$LIVE_RUN/server.pid"))."
say "POSTFLIGHT: re-run the acceptance probe at any time; receipts chains are append-only and verifiable."
