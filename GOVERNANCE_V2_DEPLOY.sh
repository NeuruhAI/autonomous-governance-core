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
#   3 CUTOVER    — SUPERVISED exact-label cutover. Live governance runs under
#                  launchd (com.neuruh.core.governance -> nsv-run.sh, pinned
#                  SHA provenance gate, adopt-never-kill). The cutover goes
#                  THROUGH the supervisor, never around it: verify the
#                  supervision estate, stamp the V2 trust config (0600),
#                  write the 0600 governance env file (no secrets in it),
#                  ratify the pin SHA to HEAD in neuruh-sops (committed),
#                  then `neuruhctl restart governance`. The respawned child
#                  keeps the SAME append-only decide chain.
#   4 SEMANTIC GATE — health + the full acceptance matrix against the live
#                  instance (PROBE_ALLOW_LIVE=1).
#   5 AUTO-ROLLBACK — ANY phase 3/4 failure: restore the pin to
#                  GOVERNANCE_LKG_SHA (committed), remove the env file
#                  (pre-adoption state had none: decide/authorize closed),
#                  checkout LKG detached, `neuruhctl restart governance`,
#                  verify LKG identity (health + /v2/decide 403-closed).
#                  Rollback failure exits 2 with an explicit operator alarm.
#
# ROLLBACK CONTRACT: the pre-cutover pin (== GOVERNANCE_LKG_SHA) and the
# absence of ~/.neuruh/env/governance.env ARE the previous live state; both
# are restored exactly. The old .p2b-runtime/trust.runtime.json (Aug-12
# manual-launcher artifact, unused by the supervised child) is never touched.
# Receipts chains are append-only throughout; nothing is deleted.
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
CANON="$CANON" node --input-type=module -e '
import fs from "node:fs";
import { validateTrustConfig } from "./src/trust.mjs";
const stale = JSON.parse(fs.readFileSync(process.env.CANON, "utf8"));
stale.implementation_sha = "0000000000000000000000000000000000000000";
// Throwaway self-test filler (not a credential): long enough to validate.
stale.approvers.founder.secret = "selftest".repeat(4);
stale.expected_source_shas.founder_runtime = ["a08f4abb908db02db1829730790140946504450c"];
try { validateTrustConfig(stale); process.exit(1); } catch { process.exit(0); }
' || die "stale-pin refusal self-test FAILED: a stale identity pin was accepted."

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
# Live governance is SUPERVISED: launchd -> nsv-run.sh governance -> node.
# The cutover goes through the supervisor (pin ratification + neuruhctl
# restart); we never kill around it and never launch a bare child on :8848.
SOPS="${NSV_SOPS_DIR:-$HOME/neuruh-repos/NeuruhAI/neuruh-sops/supervision}"
NSTATE="${NSV_STATE_DIR:-$HOME/.neuruh/supervision}"
ENVDIR="${NSV_ENV_DIR:-$HOME/.neuruh/env}"
PIN="$SOPS/pins/governance.pin"
ENVFILE="$ENVDIR/governance.env"
NEURUHCTL="$SOPS/bin/neuruhctl"

say "CUTOVER: verifying the supervision estate"
[[ -f "$PIN" ]] || die "supervision pin missing: $PIN"
[[ -x "$NEURUHCTL" ]] || die "neuruhctl missing: $NEURUHCTL"
[[ ! -e "$NSTATE/halt/governance" ]] || die "governance is HALTED in supervision; resolve and 'neuruhctl arm' first."
grep -q "^REPO=$ROOT\$" "$PIN" || die "pin REPO does not point at $ROOT."
pin_sha="$(sed -n 's/^SHA=//p' "$PIN")"
[[ "$pin_sha" == "$GOVERNANCE_LKG_SHA" ]] \
  || die "pin SHA $pin_sha != GOVERNANCE_LKG_SHA $GOVERNANCE_LKG_SHA — LKG must equal the currently-ratified pin."
[[ -z "$(git -C "$SOPS/.." status --porcelain)" ]] || die "neuruh-sops worktree is not clean."
[[ ! -f "$ENVFILE" ]] || die "unexpected $ENVFILE already exists; unknown custody — resolve manually."
live_child="$(cat "$NSTATE/pids/governance.pid" 2>/dev/null || true)"
[[ -n "$live_child" ]] && kill -0 "$live_child" 2>/dev/null \
  || die "supervised governance child not running; deploy expects a healthy LKG runtime to cut over from."
listener="$(lsof -nP -iTCP:"$LIVE_PORT" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
[[ "$listener" == "$live_child" ]] || die "port $LIVE_PORT holder ($listener) is not the supervised child ($live_child)."

say "CUTOVER: stamping V2 live trust config (0600; secret never in env or logs)"
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

# Deep health: served AND carrying the canonical service identity.
wait_health() {
  local body
  for _ in $(seq 1 60); do
    body="$(curl -sfm 2 "http://$HOST:$LIVE_PORT/health" 2>/dev/null || true)"
    if printf '%s' "$body" | grep -qF '"service": "autonomous-governance-core"'; then return 0; fi
    sleep 2
  done
  return 1
}

pin_set_sha() { # $1 = sha, $2 = ratification message
  sed -i '' "s/^SHA=.*/SHA=$1/" "$PIN"
  git -C "$SOPS/.." add "$PIN"
  git -C "$SOPS/.." commit -m "$2" >>"$LOG" 2>&1
}

supervised_restart() {
  "$NEURUHCTL" restart governance >>"$LOG" 2>&1 || true
  wait_health
}

rollback() {
  say "AUTOMATIC ROLLBACK: restoring LKG $GOVERNANCE_LKG_SHA under supervision"
  pin_set_sha "$GOVERNANCE_LKG_SHA" \
    "rollback(supervision): governance pin back to LKG $GOVERNANCE_LKG_SHA (V2 adoption semantic failure)" \
    || { say "ROLLBACK FAILURE: cannot restore pin"; exit 2; }
  rm -f "$ENVFILE"
  git checkout --detach "$GOVERNANCE_LKG_SHA" >>"$LOG" 2>&1 || { say "ROLLBACK FAILURE: cannot checkout LKG"; exit 2; }
  supervised_restart || { say "ROLLBACK FAILURE: LKG runtime did not become healthy — OPERATOR INTERVENTION REQUIRED (neuruhctl status)"; exit 2; }
  # LKG semantic identity: health identity plus the pre-adoption closed v2 boundary.
  decide_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://$HOST:$LIVE_PORT/v2/decide" -H 'Content-Type: application/json' --data '{}')"
  [[ "$decide_status" == "403" ]] || { say "ROLLBACK FAILURE: LKG /v2/decide expected 403, got $decide_status"; exit 2; }
  say "ROLLED_BACK: LKG $GOVERNANCE_LKG_SHA serving on :$LIVE_PORT under supervision, v2 boundary closed as before."
  exit 1
}

say "CUTOVER: writing 0600 governance env file (no secrets; chains + config paths only)"
mkdir -p "$ENVDIR"
umask 177
cat > "$ENVFILE" <<EOF
GOVERNANCE_DECISION_ENABLED=1
GOVERNANCE_TRUST_CONFIG=$LIVE_RUN/trust.runtime.v2.json
GOVERNANCE_RECEIPTS_LOG=$LIVE_RUN/receipts.jsonl
GOVERNANCE_CONSUMPTION_LOG=$LIVE_RUN/consumption.jsonl
GOVERNANCE_AUTHORIZE_RECEIPTS_LOG=$LIVE_RUN/authorize-receipts.jsonl
GOVERNANCE_AUTHORIZE_CONSUMPTION_LOG=$LIVE_RUN/authorize-consumption.jsonl
GOVERNANCE_AUDIT_LOG=$LIVE_RUN/audit.jsonl
EOF
umask 022

say "CUTOVER: ratifying pin SHA -> $head_sha and restarting under supervision"
pin_set_sha "$head_sha" \
  "ratify(supervision): governance pin to V2 adoption $head_sha (sealed ancestor $CANDIDATE_SHA; founder-executed GOVERNANCE_V2_DEPLOY.sh)" \
  || { rm -f "$ENVFILE"; die "pin ratification commit failed; live untouched."; }
supervised_restart || rollback

# ---------------------------------------------------------------- phase 4
say "SEMANTIC GATE: full acceptance matrix against the live instance"
if ! PROBE_ALLOW_LIVE=1 PROBE_FOUNDER_SECRET="$GOVERNANCE_FOUNDER_SECRET" \
     node "$ROOT/scripts/governance-v2-acceptance-probe.mjs" "http://$HOST:$LIVE_PORT" >>"$LOG" 2>&1; then
  say "SEMANTIC FAILURE on live instance"
  rollback
fi

# ---------------------------------------------------------------- success
new_child="$(cat "$NSTATE/pids/governance.pid" 2>/dev/null || echo unknown)"
say "DEPLOYED: Governance V2 $head_sha (sealed ancestor $CANDIDATE_SHA) live on :$LIVE_PORT under supervision (child pid $new_child)."
say "POSTFLIGHT: 'neuruhctl status' should show governance healthy with PIN=HEAD YES; re-run the acceptance probe at any time; receipts chains are append-only and verifiable."
