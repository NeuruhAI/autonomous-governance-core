import assert from "node:assert/strict";
import { test } from "node:test";
import { authorizeAction, signFounderApproval, scopeKeyFor, FOUNDER_APPROVAL_SCHEMA_VERSION } from "../src/authorize.mjs";
import { FOUNDER_SECRET, T0, freshAuthorizeRuntime, freshNonce, iso, makeGrant } from "./v2-helpers.mjs";

// The two seams this court pins on the REAL authority surface:
//
//   APPROVAL RESOLVER (recipe-engine founder_runtime.runtime.approval_resolver)
//     presents a parked mission's consequence as gov.action.facts.v1 from
//     component founder_runtime, lane founder-runtime-approval-resolver.
//   PROMOTION EXECUTOR (neuruh-workers git_custodian.promotion)
//     presents one exact merge as action_class "merge" from component
//     git_custodian, target the pull request, branch the protected base.
//
// Neither side may invent its own answer; this file is what each side's
// stand-in Governance is held to.

const FR_SHA = "38c359fc6c5eb6efb6398b7426d8a85cda046d42";
const WORKERS_SHA = "95fadbe0118e56fbedc778f5209a47ba1f9655ac";
const RESOLVER_LANE = "founder-runtime-approval-resolver";
const PROMOTION_LANE = "honey-pot-promotion";

// The live adoption trust config as it stands today (founder_runtime capped at
// R0 read-only, live, mutation unratified), then the two widenings the founder
// would have to make for each seam to authorize more than observation.
function liveShape(config) {
  config.expected_source_shas.founder_runtime = [FR_SHA];
  config.components.founder_runtime = {
    capabilities: ["observe"], max_authority_class: "A0", max_risk_tier: "R0",
    allowed_action_classes: ["read", "query", "health", "status", "retrieval", "git_inspect"]
  };
  config.runtime = { mode: "live", mutation_ratified: false };
}

// validateTrustConfig REFUSES mutation_ratified:true outright ("mutation path
// is not ratified"), and authorize.mjs seals every non-R0 class while
// runtime.mode is "live". So the widened shapes below are exercised in
// fixture mode: they prove the AUTHORIZATION LOGIC each seam relies on, and a
// separate test proves that the live seal still denies them today. Ratifying
// live mutation is a reviewed Governance change, not something either seam
// may do.
function resolverWidened(config) {
  liveShape(config);
  config.components.founder_runtime = {
    capabilities: ["observe", "write"], max_authority_class: "A4", max_risk_tier: "R2",
    allowed_action_classes: ["read", "query", "health", "status", "retrieval", "git_inspect",
      "artifact_write", "test_run", "git_commit"]
  };
  config.runtime = { mode: "fixture", mutation_ratified: false };
}

function liveSealed(config) {
  resolverWidened(config);
  config.expected_source_shas.git_custodian = [WORKERS_SHA];
  config.components.git_custodian = {
    capabilities: ["write"], max_authority_class: "A5", max_risk_tier: "R3",
    allowed_action_classes: ["git_inspect", "read", "merge"]
  };
  config.runtime = { mode: "live", mutation_ratified: false };
}

function promotionRegistered(config) {
  resolverWidened(config);
  config.expected_source_shas.git_custodian = [WORKERS_SHA];
  config.components.git_custodian = {
    capabilities: ["write"], max_authority_class: "A5", max_risk_tier: "R3",
    allowed_action_classes: ["git_inspect", "read", "merge"]
  };
}

// --- the resolver's facts, exactly as approval_resolver.resolver_facts builds them
function resolverFacts(cls, overrides = {}) {
  const mission = "msn_court";
  const byClass = {
    A0: { action_class: "status", target: { type: "observation", id: "organism_status" }, reversibility: "reversible", blast_radius: "single_target", production_effect: "read", repository: "NeuruhAI/recipe-engine" },
    A1: { action_class: "read", target: { type: "observation", id: "local_read_analysis" }, reversibility: "reversible", blast_radius: "single_target", production_effect: "read", repository: "NeuruhAI/recipe-engine" },
    A2: { action_class: "artifact_write", target: { type: "mission", id: mission }, reversibility: "reversible", blast_radius: "bounded", production_effect: "none" },
    A3: { action_class: "test_run", target: { type: "mission", id: mission }, reversibility: "reversible", blast_radius: "bounded", production_effect: "none" },
    A4: { action_class: "git_commit", target: { type: "mission", id: mission }, reversibility: "rollback_known", blast_radius: "bounded", production_effect: "none", repository: "NeuruhAI/recipe-engine", branch: `mission/${mission}`, rollback_plan: "reset the mission branch to its recorded prior head; a protected branch is never written" },
    A5: { action_class: "publish", target: { type: "mission", id: mission }, reversibility: "irreversible", blast_radius: "bounded", production_effect: "none", externality: "publication" },
    A6: { action_class: "broad_delete", target: { type: "mission", id: mission }, reversibility: "irreversible", blast_radius: "broad", production_effect: "none" }
  };
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "govauthz_" + cls,
    lane: RESOLVER_LANE,
    component: "founder_runtime",
    source_sha: FR_SHA,
    summary: `transition:AWAITING_APPROVAL->QUEUED [mission_transition:AWAITING_APPROVAL:QUEUED] ${cls}`,
    externality: "none",
    spend_usd: 0,
    nonce: freshNonce("resolver-nonce"),
    issued_at: iso(T0 - 1000),
    ...byClass[cls],
    ...overrides
  };
}

function resolverGrant(runtime, overrides = {}) {
  return makeGrant({
    subject: { lane: RESOLVER_LANE },
    allowed_repos: ["NeuruhAI/recipe-engine"],
    allowed_action_classes: ["artifact_write", "test_run", "git_commit"],
    ...overrides
  });
}

// --- the executor's facts, exactly as promotion.promotion_facts builds them
function promotionFacts(overrides = {}) {
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "promote-court-0001",
    lane: PROMOTION_LANE,
    component: "git_custodian",
    source_sha: WORKERS_SHA,
    action_class: "merge",
    summary: "promote NeuruhAI/fixture#7 feat/x@abcdef123456 into main",
    target: { type: "pull_request", id: "NeuruhAI/fixture#7" },
    repository: "NeuruhAI/fixture",
    branch: "main",
    externality: "none",
    reversibility: "rollback_known",
    rollback_plan: "git revert -m 1 <merge_sha> on main; reopen PR #7",
    blast_radius: "bounded",
    production_effect: "none",
    spend_usd: 0,
    precondition_hash: "a".repeat(64),
    nonce: freshNonce("promotion-nonce"),
    issued_at: iso(T0 - 1000),
    ...overrides
  };
}

function scopeOnce(facts, riskTier, { sourceSha = facts.source_sha, secret = FOUNDER_SECRET, approver = "founder" } = {}) {
  const unsigned = {
    schema_version: FOUNDER_APPROVAL_SCHEMA_VERSION,
    approval_id: "fappr_" + freshNonce("f").slice(-8),
    approver_id: approver,
    mode: "scope_once",
    bound: {
      scope_key: scopeKeyFor(facts),
      source_sha: sourceSha,
      risk_tier: riskTier,
      nonce: freshNonce("fnonce"),
      issued_at: iso(T0 - 1000),
      expires_at: iso(T0 + 600 * 1000)
    }
  };
  return signFounderApproval(unsigned, secret);
}

// ============================================================ RESOLVER SEAM ==
test("resolver: today's live pin auto-allows a safe read-only mission (A0/A1) — nobody is required", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  for (const cls of ["A0", "A1"]) {
    const decision = authorizeAction(runtime, resolverFacts(cls));
    assert.equal(decision.decision, "allow", cls);
    assert.equal(decision.reason_code, "AUTO_ALLOW_OBSERVE");
    assert.equal(decision.risk_tier, "R0");
    assert.equal(decision.execution, "NOT_CLAIMED_BY_GOVERNANCE");
    assert.ok(decision.decision_receipt_hash, "an allow is receipted");
    assert.deepEqual(decision.approver_ids, [], "no human decided this");
  }
});

test("resolver: today's live pin refuses every mutating class from founder_runtime (RISK_TIER_EXCEEDED / not admitted) — the widening is the founder's, not the resolver's", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  for (const cls of ["A2", "A3", "A4", "A5", "A6"]) {
    const decision = authorizeAction(runtime, resolverFacts(cls), { grant: resolverGrant(runtime) });
    assert.equal(decision.decision, "deny", cls);
    assert.ok(["ACTION_CLASS_NOT_ADMITTED", "RISK_TIER_EXCEEDED"].includes(decision.reason_code), decision.reason_code);
  }
});

test("resolver: a superseded/unknown runtime SHA is refused before any tier (identity is never falsified)", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  const decision = authorizeAction(runtime, resolverFacts("A0", { source_sha: "0".repeat(40) }));
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "SOURCE_SHA_MISMATCH");
});

test("LIVE SEAL: with runtime.mode live (mutation unratified, as validation requires), a widened component still cannot reach R1, and a registered custodian cannot merge — R0 alone is allowed", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveSealed });
  const r1 = authorizeAction(runtime, resolverFacts("A2"), { grant: resolverGrant(runtime) });
  assert.equal(r1.decision, "deny");
  assert.equal(r1.reason_code, "MUTATION_NOT_RATIFIED");
  const merge = authorizeAction(runtime, promotionFacts());
  assert.equal(merge.decision, "deny");
  assert.equal(merge.reason_code, "MUTATION_NOT_RATIFIED");
  const observe = authorizeAction(runtime, resolverFacts("A0"));
  assert.equal(observe.decision, "allow");
  assert.equal(observe.reason_code, "AUTO_ALLOW_OBSERVE");
});

test("resolver (widened + ratified): A2 without a grant asks the founder ONCE with one concise prompt; with a grant it allows", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: resolverWidened });
  const ask = authorizeAction(runtime, resolverFacts("A2"));
  assert.equal(ask.decision, "founder_required");
  assert.equal(ask.reason_code, "FOUNDER_REQUIRED_NO_GRANT");
  assert.equal(ask.risk_tier, "R1");
  assert.ok(ask.founder_prompt && ask.founder_prompt.why_human_required);
  assert.equal(ask.founder_prompt.approve_once, true);
  assert.equal(ask.founder_prompt.scope_key, ask.scope_key);

  const allowed = authorizeAction(runtime, resolverFacts("A2"), { grant: resolverGrant(runtime) });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "GRANT_BOUNDED_LOCAL");
  assert.deepEqual(allowed.approver_ids, ["founder"]);
});

test("resolver (widened + ratified): A3/A4 allow under the grant with feature-branch discipline; A4 on a protected branch does not", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: resolverWidened });
  const grant = resolverGrant(runtime);
  for (const cls of ["A3", "A4"]) {
    const decision = authorizeAction(runtime, resolverFacts(cls), { grant });
    assert.equal(decision.decision, "allow", cls);
    assert.equal(decision.reason_code, "GRANT_BOUNDED_DEVELOPMENT");
    assert.equal(decision.risk_tier, "R2");
  }
  const protectedBranch = authorizeAction(runtime, resolverFacts("A4", { branch: "main" }), { grant });
  assert.notEqual(protectedBranch.decision, "allow");
  assert.equal(protectedBranch.risk_tier, "R3");
});

test("resolver (widened + ratified): A5/A6 stay founder-required even with a grant presented", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: resolverWidened });
  const grant = resolverGrant(runtime);
  const a5 = authorizeAction(runtime, resolverFacts("A5"), { grant });
  // founder_runtime is capped at R2 here, so the cap refuses before the tier
  // could even ask; the point is that no credential reaches an allow.
  assert.notEqual(a5.decision, "allow");
  const a6 = authorizeAction(runtime, resolverFacts("A6"), { grant });
  assert.notEqual(a6.decision, "allow");
});

test("resolver (uncapped): A5 is R4 FOUNDER_REQUIRED_EXTERNAL and A6 is R5 FOUNDER_REQUIRED_DESTRUCTIVE, grant or not", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: (c) => { resolverWidened(c); delete c.components.founder_runtime.max_risk_tier; delete c.components.founder_runtime.allowed_action_classes; c.components.founder_runtime.max_authority_class = "A6"; } });
  const grant = resolverGrant(runtime);
  const a5 = authorizeAction(runtime, resolverFacts("A5"), { grant });
  assert.equal(a5.decision, "founder_required");
  assert.equal(a5.reason_code, "FOUNDER_REQUIRED_EXTERNAL");
  assert.equal(a5.risk_tier, "R4");
  assert.equal(a5.founder_prompt.approve_scope_session, false);
  const a6 = authorizeAction(runtime, resolverFacts("A6"), { grant });
  assert.equal(a6.decision, "founder_required");
  assert.equal(a6.reason_code, "FOUNDER_REQUIRED_DESTRUCTIVE");
  assert.equal(a6.risk_tier, "R5");
});

test("resolver: the founder's scope_once answer to the published prompt allows exactly once, bound to scope + source SHA + tier", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: resolverWidened });
  const first = resolverFacts("A2");
  const ask = authorizeAction(runtime, first);
  assert.equal(ask.decision, "founder_required");
  // What the resolver publishes: scope_key + source_sha + risk_tier. The
  // founder signs exactly that; the next presentation carries a fresh nonce.
  const approval = scopeOnce(first, ask.risk_tier);
  const second = resolverFacts("A2");
  assert.equal(scopeKeyFor(second), ask.scope_key, "same scope across nonces");
  const allowed = authorizeAction(runtime, second, { founder_approval: approval });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");
  assert.deepEqual(allowed.approver_ids, ["founder"]);
  // Spent: the same artifact cannot open the gate again.
  const replay = authorizeAction(runtime, resolverFacts("A2"), { founder_approval: approval });
  assert.equal(replay.decision, "deny");
  // Bound to the runtime version: a decision about one SHA is void for another.
  const advanced = resolverFacts("A2", { source_sha: "1".repeat(40) });
  const wrongVersion = authorizeAction(runtime, advanced, { founder_approval: scopeOnce(advanced, "R1", { sourceSha: FR_SHA }) });
  assert.equal(wrongVersion.decision, "deny");
});

test("resolver: a forged founder approval (wrong secret) is denied, never ignored", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  const facts = resolverFacts("A0");
  const forged = scopeOnce(facts, "R0", { secret: "not-the-founder-secret-0000000000" });
  const decision = authorizeAction(runtime, facts, { founder_approval: forged });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_SIGNATURE_INVALID");
});

test("resolver: a facts nonce is one-time; the exact same facts presented twice replay-deny", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  const facts = resolverFacts("A0");
  assert.equal(authorizeAction(runtime, facts).decision, "allow");
  const replay = authorizeAction(runtime, facts);
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

// ========================================================== PROMOTION SEAM ==
test("promotion: today's live pin knows no git_custodian component (IDENTITY_UNKNOWN) — registration is the founder's", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  const decision = authorizeAction(runtime, promotionFacts());
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "IDENTITY_UNKNOWN");
});

test("promotion: founder_runtime may never present a merge (it is capped at R0 read-only)", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveShape });
  const decision = authorizeAction(runtime, promotionFacts({ component: "founder_runtime", source_sha: FR_SHA }));
  assert.equal(decision.decision, "deny");
  assert.ok(["ACTION_CLASS_NOT_ADMITTED", "RISK_TIER_EXCEEDED"].includes(decision.reason_code));
});

test("promotion (registered): a merge into main classifies R3 and asks the founder ONCE when no grant qualifies it", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: promotionRegistered });
  const decision = authorizeAction(runtime, promotionFacts());
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_NO_GRANT");
  assert.equal(decision.risk_tier, "R3");
  assert.ok(decision.risk_factors.some((f) => /protected branch main/.test(f)));
  assert.equal(decision.founder_prompt.target, "pull_request:NeuruhAI/fixture#7");
  assert.equal(decision.founder_prompt.approve_scope_session, true);
  // Asking twice for the identical scope returns the same prompt, not a second one.
  const again = authorizeAction(runtime, promotionFacts());
  assert.equal(again.founder_prompt.prompt_id, decision.founder_prompt.prompt_id);
  assert.equal(again.founder_prompt.already_prompted, true);
});

test("promotion (registered): a FounderGrant that qualifies the EXACT operation allows without re-prompt; a different PR does not", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: promotionRegistered });
  const grant = makeGrant({
    subject: { lane: PROMOTION_LANE },
    allowed_repos: ["NeuruhAI/fixture"],
    allowed_action_classes: ["merge", "git_inspect"],
    qualified_operations: [{
      action_class: "merge",
      target: { type: "pull_request", id: "NeuruhAI/fixture#7" },
      rollback: "git revert -m 1 <merge_sha> on main; reopen PR #7",
      preflight: "Sentinel PASS sealed for head; Honey Pot custody valid; CI PASS; head and base unchanged",
      postflight: "main contains head; PR merged; deploy child event emitted if required"
    }]
  });
  const allowed = authorizeAction(runtime, promotionFacts(), { grant });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "GRANT_QUALIFIED_ADOPTION");
  assert.equal(allowed.risk_tier, "R3");
  assert.equal(allowed.founder_prompt, null);
  const other = authorizeAction(runtime, promotionFacts({ target: { type: "pull_request", id: "NeuruhAI/fixture#8" }, summary: "promote #8" }), { grant });
  assert.equal(other.decision, "founder_required");
});

test("promotion (registered): the founder's scope_once approval for this PR allows once; a head-drifted precondition is a different fact set the executor must re-ask for", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: promotionRegistered });
  const facts = promotionFacts();
  const ask = authorizeAction(runtime, facts);
  assert.equal(ask.decision, "founder_required");
  const approval = scopeOnce(facts, "R3");
  const allowed = authorizeAction(runtime, promotionFacts(), { founder_approval: approval });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");
  const replay = authorizeAction(runtime, promotionFacts(), { founder_approval: approval });
  assert.equal(replay.decision, "deny", "a spent approval never merges twice");
});

test("promotion (registered): a grant can never carry a forced or destructive promotion, and a stale workers SHA is refused", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: promotionRegistered });
  const grant = makeGrant({ subject: { lane: PROMOTION_LANE }, allowed_repos: ["NeuruhAI/fixture"], allowed_action_classes: ["merge"] });
  const forced = authorizeAction(runtime, promotionFacts({ force: true }), { grant });
  assert.equal(forced.decision, "deny");
  assert.equal(forced.reason_code, "RISK_TIER_EXCEEDED");
  const stale = authorizeAction(runtime, promotionFacts({ source_sha: "0".repeat(40) }), { grant });
  assert.equal(stale.decision, "deny");
  assert.equal(stale.reason_code, "SOURCE_SHA_MISMATCH");
});
