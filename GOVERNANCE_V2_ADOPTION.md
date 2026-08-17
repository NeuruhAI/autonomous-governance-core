# Governance V2 — Adoption Plan (risk-scoped founder authority)

Branch: `policy/risk-scoped-founder-grants-20260816` (base `714ace3`).
Status: **BUILT, TESTED, PUSHED — NOT MERGED, NOT DEPLOYED.** The live
Governance runtime on 127.0.0.1:8848 was not restarted, reconfigured or
mutated by this work; its `.p2b-runtime` state is byte-identical.

## What this candidate fixes

### Defect A — governance too coarse for normal operation

The real T4 court showed a broad action tag (`file_modify`) escalating
bounded, reversible, $0, no-externality, rollback-known operations to the
founder. Technically valid under tag policy; unusable in practice.

V2 adds a consequence-based boundary (`/v2/authorize`,
`src/risk.mjs` + `src/grants.mjs` + `src/authorize.mjs` + `src/pathscope.mjs`)
where risk derives from target, scope, externality, reversibility, blast
radius, spend, production effect and identity — see
GOVERNANCE_V2_POLICY_MATRIX.md. Bounded work (court artifacts, proof writes,
alias repair, feature-branch development, pre-qualified adoption) auto-allows
inside scoped, expiring, receipted, non-transferable FounderGrants; external,
destructive and privileged consequence stays founder-interactive. The legacy
`/v1/evaluate` path and its ratified behavior are UNCHANGED — no old hostile
court was weakened; lanes migrate to `/v2/authorize` to get the smarter
semantics.

### Defect B — stale trust identity pin

`config/p2b-canary-trust.json` pinned `founder_runtime` to superseded
`a08f4abb…` while the qualified Founder Runtime lineage is `e64c545…`.
T4 correctly refused to falsify the identity.

**What the pin represents:** the git source SHA of the requesting component —
the one identity the requester can honestly attest and the launcher can
verify. It deliberately stays a source-SHA pin: a "semantic contract SHA"
would let behavior drift inside an unchanged contract, and a process-level
runtime pin is not stable across restarts.

**Why it went stale:** the pin was a bare string frozen at qualification time
with no lineage model — when the Founder Runtime advanced there was no
contract slot to say "qualified then, superseded now," leaving only two bad
options: falsify or stay stale.

**The repair:** `source_lineage` in `gov.trust.v1` (additive, optional)
records the qualification history. Validation now enforces that
`expected_source_shas` equals exactly the qualified lineage set — a config
still pinning a superseded SHA is refused at load (`STALE_SOURCE_PIN`), so
the boundary closes rather than serving a stale identity. At decision time a
superseded SHA gets the precise reason `SOURCE_SHA_SUPERSEDED` naming the
superseding SHA. The canary config now pins `e64c545…` as qualified and
records `a08f4abb…` as superseded; the probe sends the qualified identity.

## What was NOT changed

- Live runtime :8848 — not restarted, not reconfigured; `.p2b-runtime`
  untouched (test launches now use `GOVERNANCE_RUNTIME_DIR` isolation so a
  test can never share pidfile or append-only chains with a live runtime).
- T4 candidate, T5 evaluator, AXON runtime, Qdrant, Founder Runtime.
- AXON worktree containment (`E_OUT_OF_WORKTREE` stands). V2 adds explicitly
  granted writable roots via FounderGrant `allowed_paths` — bounded, never
  broad, never Desktop-wide, realpath/symlink-safe.
- Legacy `/v1/evaluate` semantics, enum, default policy, and every prior
  hostile court (all pre-existing tests pass unmodified in substance; the
  launcher test was pointed at an isolated runtime dir, an equal-strength
  proof without live mutation).
- `/v2/decide` contracts (`gov.decision.v1`, `gov.approval.v1`,
  `gov.trust.v1` compatible-extended), closed-by-default gating, loopback
  binding, unratified mutation seal.

## Adoption steps (each a separate, explicitly-authorized act)

1. **Review** this branch; run `npm test` (149 tests; see
   GOVERNANCE_V2_TEST_RECEIPT.json for the receipted run).
2. **T5 evaluation** of the frozen T4 candidate proceeds independently; this
   branch does not touch it.
3. **Promotion to main** — explicit founder act; not performed here.
4. **Deploy** — restart the runtime from the promoted SHA via
   `GOVERNANCE_EXPECTED_SHA=<sha> scripts/p2b-decision-runtime.sh up`; the
   launcher stamps and validates the trust config (a stale pin refuses to
   start). Founder Runtime clients then present `e64c545…` and, for the
   authorize boundary, their lane grants.
5. **Issue initial grants** — founder signs lane grants (court-artifact
   roots, owned-repo development, any pre-qualified restart/deploy
   operations) with bounded expiries.

Rollback: the branch is additive; reverting to `main` (`714ace3`) restores
the exact prior behavior. Runtime state files are forward-compatible (new
chains live in separate files).

## Honest limits

- Session-scope approvals live in runtime memory: a restart forgets them
  (fails closed — the founder is asked again; never open).
- `production_permission` admits R3 production-labeled operations under a
  qualified grant; R4 customer-data effects still always reach the founder.
- Path realpath enforcement sees the filesystem of the governance host;
  remote-host paths are enforced lexically plus by grant scope.
- The `file_modify` tag still escalates on the legacy `/v1/evaluate` path by
  design (non-regression); coarse-tag relief comes from migrating callers to
  `/v2/authorize`.
