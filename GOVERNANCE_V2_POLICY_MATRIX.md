# Governance V2 — Risk-Scoped Policy Matrix

Principle: **GOVERN CONSEQUENCE, NOT SYNTAX.** A broad action tag
(`file_modify`) is not meaningful risk. Risk is a deterministic function of
TARGET, SCOPE, EXTERNALITY, REVERSIBILITY, BLAST RADIUS, SPEND, PRODUCTION
EFFECT and IDENTITY, computed by `src/risk.mjs` and enforced by
`src/authorize.mjs`. Escalating factors only ever RAISE the tier; nothing
de-escalates; an unrecognized consequence fails closed at validation.

## Risk tiers

| Tier | Meaning | Action classes (baseline) | Outcome |
|------|---------|---------------------------|---------|
| R0 | OBSERVE | `read`, `query`, `health`, `status`, `retrieval`, `git_inspect` | AUTO ALLOW, receipted |
| R1 | BOUNDED LOCAL REVERSIBLE | `artifact_write`, `report_write`, `screenshot_write`, `receipt_write`, `temp_write`, `alias_repair`, `preview_write` | AUTO ALLOW inside valid FounderGrant, receipted |
| R2 | OWNED FEATURE-BRANCH DEVELOPMENT | `repo_edit`, `test_run`, `build`, `git_commit`, `git_push` | AUTO ALLOW inside valid FounderGrant + feature-branch discipline (correct lane, correct repo, feature branch, no force, no secret access, no external contact, no production mutation) |
| R3 | QUALIFIED CONTROLLED ADOPTION | `merge`, `deploy`, `service_restart`, `migration_additive` | ALLOW without re-prompt when the grant names the exact operation (target, rollback, preflight, postflight); otherwise ask the founder ONCE |
| R4 | EXTERNAL CONSEQUENCE | `external_message`, `esign_send`, `provider_enrollment`, `spend`, `publish`, `customer_create`, `customer_data_mutation`, `legal_acceptance` | FOUNDER REQUIRED, approve-once only (never session, never grant) |
| R5 | DESTRUCTIVE / PRIVILEGED | `force_push`, `history_rewrite`, `db_drop`, `db_wipe`, `broad_delete`, `broad_kill`, `secret_exposure`, `privilege_escalation`, `canonical_destroy`, `reboot` | FOUNDER REQUIRED interactively, EVERY TIME (never session, never grant) |

## Escalators (worst factor wins)

| Consequence | Escalates to |
|-------------|--------------|
| Secret-denied path or declared `secret_access` | R5 → **DENY** (`SECRET_ROOT_DENIED`; no grant or approval can admit it) |
| Mutation of canonical Governance state (`config/`, `src/`, `.p2b-runtime/` of this repo) | R5 |
| `force: true` | R5 |
| Irreversible + broad blast radius | R5 |
| Any externality (`email`, `sms`, `call`, `esign`, `provider_enrollment`, `publication`, `customer_create`) | ≥ R4 |
| `spend_usd > 0` | ≥ R4 |
| Production customer-data effect | ≥ R4 |
| Irreversible | ≥ R4 |
| Broad blast radius on a mutating action | ≥ R4 |
| Production `service_restart` | ≥ R3 |
| Mutation of protected branch (`main`, `master`, `production`) | ≥ R3 |

## Path / scope classes

These are categorically different and classified as such (`src/pathscope.mjs`):

| Target | Class |
|--------|-------|
| `~/Desktop/NEURUH_LIVE_PROOF_20260816/RESULT.md` | grantable scoped root → R1 under grant |
| repository feature file on approved branch | R2 under grant |
| `~/.ssh/id_ed25519` (any spelling, incl. via symlink) | secret-denied → DENY |
| production database destructive SQL | R5 → founder interactive |
| canonical Governance policy (`autonomous-governance-core/config`, `/src`, `/.p2b-runtime`) | R5 → founder interactive |

Enforcement layers, all fail-closed: lexical canonical form (one spelling per
path; `..`, `//`, `\`, trailing `/`, wildcards, non-NFC, NUL all refused) →
real-path resolution (deepest existing ancestor realpath'd; symlink escape of
a granted root **denies**) → sensitivity classes checked on the lexical AND
resolved spelling. AXON worktree containment is untouched; approved writable
roots are granted explicitly and Desktop is never globally writable (grant
roots under a home directory must be ≥ 4 segments deep; system roots are
never grantable).

## FounderGrant (`gov.grant.v1`, `src/grants.mjs`)

Fields: `grant_id`, `issuer`, `issued_at`, `expires_at`, `subject.lane`,
`allowed_repos`, `allowed_paths`, `allowed_action_classes`,
`denied_action_classes` (deny wins), `allowed_services`,
`production_permission`, `external_contact_permission`, `spend_ceiling_usd`,
`destructive_permission`, `rollback_required`, `receipt_required`,
`qualified_operations` (R3: exact target + rollback + preflight + postflight),
HMAC `signature` by a founder-grade (enhanced) approver from trusted config.

A grant is **scoped, expiring, receipted, non-transferable, path-safe** — and
never arbitrary authority. Hard floors validated fail-closed:
`external_contact_permission` and `destructive_permission` MUST be false,
`receipt_required` MUST be true, `allowed_action_classes` may never name an
R4/R5 class, roots may never be broad, secret or governance-canonical.
Wrong lane (`GRANT_LANE_MISMATCH`) and wrong repo (`GRANT_REPO_MISMATCH`) are
hostile misuse → DENY. An expired grant is not hostile → FOUNDER REQUIRED.

## Approval UX (`src/authorize.mjs`)

When founder approval is required the decision returns ONE concise
`founder_prompt`: ACTION, TARGET, RISK, WHY HUMAN REQUIRED, ROLLBACK, SPEND,
CONTACT, PRODUCTION EFFECT, GRANT EXPIRY — plus `approve_once: true` and
`approve_scope_session` (true only at ≤ R3). Identical pending scope returns
the SAME `prompt_id` with `already_prompted: true` — no repeated identical
prompts. `gov.founder.approval.v1` approvals are HMAC-signed by an enhanced
approver, TTL-bounded, one-time-consumed on a hash-chained ledger:

- mode `once` — binds the exact canonical facts hash; valid at any tier.
- mode `session_scope` — binds the exact scope key; valid ONLY ≤ R3
  (`SESSION_SCOPE_FORBIDDEN` at R4/R5); registers the scope until the
  approval's own expiry; subsequent identical-scope actions allow with
  `SESSION_SCOPE_ACTIVE` and no prompt.

A `founder_required` outcome is a pending ask, not a terminal decision: it
does not burn the facts nonce, so the approved re-presentation of the same
facts is not a replay. Terminal outcomes (allow/deny) consume the nonce.

## Identity (trust lineage, `src/trust.mjs`)

`expected_source_shas` pins the git source SHA a component honestly attests.
`source_lineage` records the qualification history: each SHA is `qualified`
(with `qualified_at`) or `superseded` (with `superseded_by`). Contracts:

- A config pinning a superseded SHA is refused at validation
  (`STALE_SOURCE_PIN`) — a stale trust config can never load; the boundary
  stays closed instead of stale.
- A request presenting a superseded SHA is denied `SOURCE_SHA_SUPERSEDED`
  with the superseding SHA named — precise, fail-closed, never falsified.
- An unknown SHA remains `SOURCE_SHA_MISMATCH`.

Current Founder Runtime lineage (identical in
`config/p2b-canary-trust.json` and `config/governance-v2-adoption-trust.json`
— the runtime's identity is ONE fact, and a SHA that is current on one surface
must not read as stale on the other):

| SHA | Status | Qualified | Superseded |
|---|---|---|---|
| `520ae4381def8be52486935e1b9c53da31e52202` | **qualified** | 2026-08-20 (T39) | — |
| `20a184f36088be934ded5f8a93039d7aeabad86f` | superseded | 2026-08-20 (T31B) | 2026-08-20 |
| `949a8b8c99f2b111edf8c734f2cfcad89c47bdf2` | superseded | 2026-08-20 (T31A) | 2026-08-20 |
| `e64c545adccf47394b1e45e860751816753617b4` | superseded | 2026-08-16 | 2026-08-20 |
| `a08f4abb908db02db1829730790140946504450c` | superseded | 2026-07-22 | 2026-08-16 |

T31B qualified `949a8b8` and then superseded it within the same lane, because
the lane's own recipe-engine merge advanced the Founder Runtime again. That is
not churn to be tidied away: qualifying a runtime is what advancing it costs,
and a pin that stayed at `949a8b8` would be exactly the stale identity this
contract exists to refuse.

T39 did it again, for the same reason: routing the mission authority gate over
HTTP advanced the Founder Runtime a fourth time. Four entries in five days is
what an honest identity contract looks like while the thing it identifies is
still being finished — the alternative is not a shorter table, it is a pin that
quietly names a runtime nobody is running.

`superseded_by` on every superseded entry names the CURRENTLY QUALIFIED head,
not the immediate successor: validation requires it to be a qualified lineage
SHA, so the whole history forwards to one identity. `superseded_at` records the
real order in which each SHA was retired.

## T31B — the authority chain on /v2/authorize

Three gates run before any tier can allow. Each existed on `/v2/decide` or in
the trust config already; none of them ran here, and each absence was a way to
be authorized without being checked.

**Identity (`IDENTITY_UNKNOWN` / `SOURCE_SHA_MISMATCH` / `SOURCE_SHA_SUPERSEDED`).**
`facts.source_sha` is REQUIRED. The component must be registered and the SHA it
attests must be the pinned, currently-qualified one. Without this the surface
could not tell a current runtime from a superseded one, so the denial the whole
lineage contract exists to produce was unreachable here.

**Unratified-mutation seal (`MUTATION_NOT_RATIFIED`).** While
`runtime.mode = "live"` and `runtime.mutation_ratified` is false, any action
class whose baseline tier is above R0 is refused outright. No grant and no
approval is consulted first: the seal is not a permission question.

**Presented credentials are never ignored.** A founder approval is verified
against these exact facts, and a grant's signature/issuer/shape is verified,
BEFORE any tier can short-circuit to an allow — R0 included. Previously a
forged credential riding inside an otherwise-allowable request was discarded
unexamined and the receipt said "allow" without recording that forged evidence
had been offered. Grant EXPIRY remains non-hostile: it still degrades to the
founder prompt.

### Component narrowing (optional, purely restrictive)

`components[id].max_risk_tier` caps the consequence tier a component can ever
reach, whatever it presents (`RISK_TIER_EXCEEDED`).
`components[id].allowed_action_classes` admits only the named classes for that
component (`ACTION_CLASS_NOT_ADMITTED`). Both are absent-by-default and there is
deliberately no field that widens a component beyond the surface's own tier
rules. The live adoption config caps `founder_runtime` at `R0` and admits only
the six observation classes.

### `mode: "scope_once"` — an asynchronous human decision, still one-shot

`once` binds `facts_hash`, which covers the freshness nonce and `issued_at` the
requester only mints at request time — so no external process can sign it in
advance, and a human decision is by nature asynchronous. `session_scope` is
signable in advance but leaves a standing permission for its TTL, which is not
one-shot.

`scope_once` binds `scope_key`, `source_sha`, `risk_tier`, `nonce`, `issued_at`
and `expires_at`: the stable action coordinates, the attested runtime version,
and the classified tier. It is consumed exactly once through the nonce ledger
and never opens a session scope, so the next request must carry its own
externally decided approval. Version binding is what makes a founder decision
non-transferable across a source advance rather than merely time-limited
(`APPROVAL_SOURCE_MISMATCH`).

## Wire surface

`POST /v2/authorize` — body `{ facts, grant?, founder_approval? }`. Closed by
default: requires `GOVERNANCE_DECISION_ENABLED=1`, a valid
`GOVERNANCE_TRUST_CONFIG`, loopback binding, and its OWN chain files
(`GOVERNANCE_AUTHORIZE_RECEIPTS_LOG`, `GOVERNANCE_AUTHORIZE_CONSUMPTION_LOG`)
— one chain file never has two appenders. Decisions are
`allow | deny | founder_required`, every outcome receipted, and no receipt
ever claims execution (`NOT_CLAIMED_BY_GOVERNANCE`). The legacy
`/v1/evaluate` enum (`allow | escalate | block`) and `/v2/decide` contracts
are unchanged.
