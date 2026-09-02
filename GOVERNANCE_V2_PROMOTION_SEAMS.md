# Governance V2 — the two seams that consume it (approval resolver, promotion executor)

Mission `NEURUH-APPROVAL-AND-PROMOTION-SEAMS-20260902`. This document changes
NOTHING in `config/` or `src/`: it records what the real surface answered for
each seam's exact facts (`tests/approval-promotion-seams.test.mjs`, 17/17) and
names the founder-owned changes each seam is waiting on. Governance remains
the authority; neither seam widens it.

## What the seams present

| Seam | Component | Lane | Facts | Baseline tier |
|---|---|---|---|---|
| Approval resolver (recipe-engine `founder_runtime.runtime.approval_resolver`) | `founder_runtime` | `founder-runtime-approval-resolver` | A0/A1 → `status`/`read`; A2 → `artifact_write`; A3 → `test_run`; A4 → `git_commit` on `mission/<id>`; A5 → `publish` (externality `publication`); A6 → `broad_delete` (broad, irreversible) | R0 / R0 / R1 / R2 / R2 / R4 / R5 |
| Promotion executor (neuruh-workers `git_custodian.promotion`) | `git_custodian` | `honey-pot-promotion` | `merge`, target `pull_request:<repo>#<n>`, branch = protected base, `precondition_hash` over repo/branch/head/base/base-head/PR, fresh nonce | R3 (merge + protected branch) |

## What the LIVE surface answers today (`.p2b-runtime/trust.runtime.v2.json`, impl fc50bd0)

| Ask | Answer | Why |
|---|---|---|
| founder_runtime A0/A1 from pinned `520ae43` | **allow** `AUTO_ALLOW_OBSERVE` | R0 auto-allow, receipted |
| founder_runtime A0/A1 from `38c359f` (the SHA actually running on :19090) | **deny** `SOURCE_SHA_MISMATCH` | identity pin is `520ae43` only; live receipts seq 137/138 |
| founder_runtime A2–A6 (any grant) | **deny** `ACTION_CLASS_NOT_ADMITTED` / `RISK_TIER_EXCEEDED` | component capped at R0, read-only classes |
| git_custodian merge | **deny** `IDENTITY_UNKNOWN` | component not registered |
| any non-R0 class, any component, in `mode: live` | **deny** `MUTATION_NOT_RATIFIED` | `validateTrustConfig` refuses `mutation_ratified: true` outright (`src/trust.mjs`) |

So, live, the resolver can only ever auto-resolve **R0** (safe read-only
missions), and only once the running Founder Runtime SHA is qualified. Nothing
above R0 — including every promotion — can be allowed on the live surface
until the mutation path is ratified as its own reviewed change. Both seams
already handle these answers honestly: the resolver parks the mission with the
reason surfaced (`UNRESOLVED`, never `BLOCKED_POLICY` for identity/ratification
denials); the executor refuses with the reason and merges nothing.

## Founder gates — CLOSED by the T03 ratification change (see GOVERNANCE_V2_POLICY_MATRIX.md)

All four were implemented in `feat/mutation-ratification-20260902`. Kept below as the record of what each one was.

### Original gate list

1. **Re-qualify the Founder Runtime lineage** to the SHA that ships the
   resolver (`source_lineage.founder_runtime`: mark `520ae43` superseded_by the
   new SHA; pin `expected_source_shas.founder_runtime` to it; identical in
   `config/p2b-canary-trust.json` and `config/governance-v2-adoption-trust.json`;
   deploy via `GOVERNANCE_V2_DEPLOY.sh` — same idiom as T31B/T39).
   Unlocks: R0 auto-resolution of safe missions on the live surface.
2. **Ratify the mutation path** (`runtime.mutation_ratified: true` — currently
   refused by `validateTrustConfig`; requires its own reviewed change to
   `src/trust.mjs` plus the canary evidence that change demands).
   Unlocks: anything R1+ on the live surface. Without it, gates 3–4 change
   nothing live.
3. **Widen `founder_runtime`** to `max_risk_tier: R2`, `max_authority_class: A4`,
   `allowed_action_classes` + `artifact_write, test_run, git_commit`, and issue a
   `gov.grant.v1` FounderGrant to lane `founder-runtime-approval-resolver`
   (repos `NeuruhAI/recipe-engine`; classes `artifact_write, test_run,
   git_commit`; ≤ 30 days; the API reads it from `FR_FOUNDER_GRANT_FILE`).
   Unlocks: A2–A4 missions auto-resolve inside the grant; A5/A6 keep asking.
4. **Register `git_custodian`** (`expected_source_shas.git_custodian` = the
   workers SHA that ships the executor; `max_risk_tier: R3`;
   `allowed_action_classes: [git_inspect, read, merge]`), and per promotion
   either a FounderGrant with `qualified_operations` naming the exact
   `pull_request:<repo>#<n>` (allow, no re-prompt) or one `scope_once` founder
   approval to the prompt (allow once).
   Unlocks: mechanical promotion of courted candidates.

The court file proves each unlock against the real `authorizeAction` in
fixture mode and proves the live seal against it in live mode.
