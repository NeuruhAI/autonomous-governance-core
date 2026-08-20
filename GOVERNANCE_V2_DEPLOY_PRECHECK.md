# Governance V2 — Deploy Precheck (adoption prep, 2026-08-16)

Sealed source: tag `governance-v2-candidate-v1-20260816` →
`3fe9eb93e5a4947bd4cd4a3dd1f48b000d8b1d37`.
Prep branch: `release/governance-v2-adoption-20260816` (descendant of the
sealed commit; V2 source untouched — prep adds only config, scripts, tests
of the adoption path, and these documents).

Status: **PREPARED AND REHEARSED IN ISOLATION. LIVE NOT DEPLOYED.**
`GOVERNANCE_V2_DEPLOY.sh` has never been executed (parse-checked only).

## 1. What deploy will run

| Piece | Path | Role |
|-------|------|------|
| Adoption trust config | `config/governance-v2-adoption-trust.json` | Canary `/v2/decide` surface unchanged (one A0 read-only op, mutation sealed) + ONE authorize-side founder approver. Secrets and implementation SHA are launch-stamped placeholders — nothing sensitive is committed. |
| Isolated runtime lifecycle | `scripts/governance-v2-adoption-runtime.sh` | Alternate-port, isolated-dir launch (`up`/`verify`/`up-verified`/`status`/`down`). Refuses port 8848 and the canonical `.p2b-runtime` by design; `up-verified` auto-rolls-back (exact-owned down) on ANY semantic failure. |
| Acceptance probe | `scripts/governance-v2-acceptance-probe.mjs` | The FULL adoption matrix over the wire (20 rows: V1 compat, decide identity semantics, authorize risk semantics). Exit 0 only when every row matches decision AND reason. Probing :8848 requires `PROBE_ALLOW_LIVE=1`. |
| Deploy procedure | `GOVERNANCE_V2_DEPLOY.sh` | Founder-executed exact-label cutover with automatic rollback (§4). |

## 2. Rehearsal evidence (this prep session, isolated — live untouched)

- **Isolated alternate-port launch**: `up-verified` on `127.0.0.1:18730`,
  runtime dir in session scratch, SHA-gated to the sealed commit.
  **ACCEPTANCE: 20/20 rows PASS**, including:
  - V1 compat: `/health`, `/v1/policy`, `/v1/evaluate` enum (`escalate` on the
    ratified sample).
  - `/v2/decide` compatibility: canary allow → replay `NONCE_REPLAYED`;
    stale identity `a08f4abb…` → `SOURCE_SHA_SUPERSEDED` naming `e64c545…`;
    current qualified identity → allow.
  - `/v2/authorize`: R0 read allow; R1 scoped write allow under grant; repeat
    write allow with NO founder prompt; R2 feature-branch allow; R3 exact
    qualified adoption allow; expired grant → `GRANT_EXPIRED`
    founder_required; wrong repo → deny; path escape → deny; symlink escape
    → deny; secret path → deny; external contact / spend → founder_required;
    destructive / force push → founder_required.
  - All three receipt chains verified after shutdown (decide len 3,
    authorize len 14, consumption 0), exact-owned `down`.
- **Automatic rollback on semantic failure**: `up-verified` on `:18731` with
  deliberately mismatched probe authority → 10 rows FAIL → script performed
  the automatic exact-owned down, exit 1, no pidfile left, port closed.
  Live :8848 (pid 3794) remained up and untouched throughout.
- **Stale-pin refusal self-test**: adoption config re-pinned to `a08f4abb…`
  is refused at validation (`STALE_SOURCE_PIN`).

## 3. Trust identity migration

The candidate already carries the migrated identity: pin
`e64c545adccf47394b1e45e860751816753617b4` (qualified 2026-08-16), lineage
records `a08f4abb908db02db1829730790140946504450c` as superseded. Contracts
enforced at every layer:

- config-load: a stale pin refuses to load (`STALE_SOURCE_PIN`) — the
  boundary closes rather than serving a stale identity;
- decision-time: a superseded requester SHA denies `SOURCE_SHA_SUPERSEDED`
  with the superseding SHA named; unknown SHAs stay `SOURCE_SHA_MISMATCH`;
- future migrations: append the newly qualified SHA to `source_lineage`,
  mark the old entry superseded (`superseded_by`), and move
  `expected_source_shas` — validation forces the pin and lineage to agree.

Operator note (superseded by T31B, 2026-08-20): the qualified Founder Runtime
identity is now `20a184f36088be934ded5f8a93039d7aeabad86f`. `e64c545…` is itself
recorded as superseded and a client still presenting it fails closed with the
precise reason. Everything above is the acceptance evidence for the Governance
V2 adoption deploy as it stood on 2026-08-16 and is left intact; the current
matrix is in `GOVERNANCE_V2_POLICY_MATRIX.md`.

## 4. Exact-label deployment procedure (NOT yet executed)

`GOVERNANCE_V2_DEPLOY.sh` — founder-executed only. Requires:

- `DEPLOY_CONFIRM` = exact founder phrase (in the script header),
- `GOVERNANCE_LKG_SHA` = last-known-good rollback commit
  (current live lineage: `714ace36922d815253464df815eb291e4118808d`),
- `GOVERNANCE_FOUNDER_SECRET` (≥16 chars; stamped at launch, never committed),
- `GOVERNANCE_LIVE_PID` if no pidfile exists (the CURRENT live server
  predates pidfile custody — the script verifies the pid is
  `node src/server.mjs` running from this repo before the exact-owned stop;
  it never guesses and never broad-kills).

Phases: precheck (tag→SHA seal, HEAD equality, clean tree, full `npm test`,
stale-pin self-test, LKG exists) → isolated rehearsal (`up-verified`, aborts
before live is touched) → exact cutover (stop exact pid, stamp
`trust.runtime.v2.json`, relaunch :8848 with the SAME append-only decide
chain) → semantic gate (full acceptance matrix on live) → success renames
the V2 config over the old one.

## 5. Exact rollback

Automatic on any cutover/semantic-gate failure, and manually re-runnable:

1. exact-owned stop of the new pid (pidfile only);
2. `git checkout --detach $GOVERNANCE_LKG_SHA`;
3. relaunch :8848 with the PRESERVED previous runtime config
   (`.p2b-runtime/trust.runtime.json` is not overwritten until success);
4. health + canary verification of the restored runtime;
5. rollback failure exits 2 with an explicit operator alarm — nothing is
   left half-up, chains are never truncated.

## 5b. Supervision-aware cutover (revision, 2026-08-16, pre-execution)

Discovery during adoption authorization: live governance runs under launchd
supervision (`com.neuruh.core.governance` → `nsv-run.sh governance`), with a
committed SHA-pinned provenance gate (`neuruh-sops/supervision/pins/
governance.pin`), adopt-never-kill, halt semantics — and NO governance env
vars (the supervised live surface is V1-only; `/v2/decide` is 403-closed
today; `.p2b-runtime/trust.runtime.json` is an unused Aug-12 manual-launcher
artifact). The originally-prepared bare-child cutover would have caused a
supervisor `sha_mismatch` HALT and left the new server unsupervised.

`GOVERNANCE_V2_DEPLOY.sh` was therefore revised BEFORE execution to cut over
THROUGH the supervisor: verify the estate (pin==LKG, no halt, sops clean,
supervised child owns :8848, no pre-existing env file), stamp
`trust.runtime.v2.json` (0600, founder secret only there), write a 0600
`~/.neuruh/env/governance.env` (paths only, no secrets), ratify the pin SHA
to HEAD (committed in neuruh-sops), then `neuruhctl restart governance` and
gate semantically. Automatic rollback restores the exact pre-adoption state:
pin back to LKG (committed), env file removed (v2 boundary closed again),
LKG checkout, supervised restart, health + 403-closed verification.
`GOVERNANCE_LIVE_PID` is no longer used — the supervisor owns pid custody.
The gate that required `HEAD == sealed candidate` (unsatisfiable, since the
deploy tooling postdates the seal) was replaced by sealed-ancestor descent
plus a byte-identical governed surface (src, tests, samples, package,
canonical canary config, decide-contract scripts).

## 6. Operator checklist before executing deploy

- [ ] T5's independent evaluation of the frozen T4 candidate is complete.
- [ ] Founder has reviewed GOVERNANCE_V2_ADOPTION.md and the policy matrix.
- [ ] The candidate tag still dereferences to `3fe9eb93…` (`git fetch --tags`).
- [ ] `GOVERNANCE_LKG_SHA` chosen and reachable.
- [ ] Founder secret generated out-of-band; never committed, never logged.
- [ ] A maintenance window for :8848 (decide callers tolerate the restart).
- [ ] After deploy: issue initial FounderGrants (lane scopes, proof roots,
      any pre-qualified restart/deploy operations) with bounded expiries.
