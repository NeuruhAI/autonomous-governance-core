import assert from "node:assert/strict";
import fs from "node:fs";
import { test } from "node:test";
import { authorizeAction, signFounderApproval, scopeKeyFor, FOUNDER_APPROVAL_SCHEMA_VERSION } from "../src/authorize.mjs";
import { validateTrustConfig } from "../src/trust.mjs";
import { MAX_RATIFIABLE_TIER, RATIFICATION_SCHEMA_VERSION, signRatification } from "../src/ratification.mjs";
import { FOUNDER_SECRET, T0, freshAuthorizeRuntime, freshNonce, iso, makeGrant, makeV2TrustConfig } from "./v2-helpers.mjs";

// MUTATION COURT. Ratification is a signed, scoped, expiring artifact — never a
// switch. These cases pin the RED side (what stays sealed) as hard as the GREEN
// side (what a founder can deliberately open), because the whole value of the
// change is that opening one thing does not open the rest.

const FR_SHA = "fae23008e910b0a93eea31cd3eef36d6adb6b7a6";      // canonical recipe-engine main
const STALE_FR_SHA = "520ae4381def8be52486935e1b9c53da31e52202"; // the pin this supersedes
const CUSTODIAN_SHA = "e36d1bf05d22020324aea5cf48a35bb1f83c1495"; // canonical neuruh-workers main
const RESOLVER_LANE = "founder-runtime-approval-resolver";
const PROMOTION_LANE = "honey-pot-promotion";

const RATIFIED_CLASSES = ["artifact_write", "report_write", "test_run", "git_commit", "merge"];

function ratification(overrides = {}, { secret = FOUNDER_SECRET, approver = "founder" } = {}) {
  const unsigned = {
    schema_version: RATIFICATION_SCHEMA_VERSION,
    ratified_by: approver,
    ratified_at: iso(T0 - 3600 * 1000),
    expires_at: iso(T0 + 30 * 24 * 3600 * 1000),
    max_ratified_tier: "R3",
    ratified_action_classes: [...RATIFIED_CLASSES],
    ...overrides
  };
  return signRatification(unsigned, secret);
}

// The live shape this change is written for: both seams registered, mutation
// ratified for exactly the classes they need, everything else untouched.
function liveRatified(config, ratificationOverrides) {
  config.expected_source_shas.founder_runtime = [FR_SHA];
  config.expected_source_shas.git_custodian = [CUSTODIAN_SHA];
  config.components.founder_runtime = {
    capabilities: ["observe", "write"],
    max_authority_class: "A4",
    max_risk_tier: "R2",
    allowed_action_classes: ["read", "query", "health", "status", "retrieval", "git_inspect",
      "artifact_write", "report_write", "test_run", "git_commit"]
  };
  config.components.git_custodian = {
    capabilities: ["write"],
    max_authority_class: "A5",
    max_risk_tier: "R3",
    allowed_action_classes: ["git_inspect", "read", "merge"]
  };
  config.runtime = {
    mode: "live",
    mutation_ratified: false,
    mutation_ratification: ratification(ratificationOverrides)
  };
}

function liveUnratified(config) {
  liveRatified(config);
  delete config.runtime.mutation_ratification;
}

function resolverFacts(actionClass, overrides = {}) {
  const mission = "msn_ratification_court";
  const shape = {
    status: { target: { type: "observation", id: "organism_status" }, reversibility: "reversible", blast_radius: "single_target", production_effect: "read", repository: "NeuruhAI/recipe-engine" },
    read: { target: { type: "observation", id: "local_read_analysis" }, reversibility: "reversible", blast_radius: "single_target", production_effect: "read", repository: "NeuruhAI/recipe-engine" },
    artifact_write: { target: { type: "mission", id: mission }, reversibility: "reversible", blast_radius: "bounded", production_effect: "none" },
    test_run: { target: { type: "mission", id: mission }, reversibility: "reversible", blast_radius: "bounded", production_effect: "none" },
    git_commit: { target: { type: "mission", id: mission }, reversibility: "rollback_known", blast_radius: "bounded", production_effect: "none", repository: "NeuruhAI/recipe-engine", branch: "mission/" + mission, rollback_plan: "reset the mission branch to its recorded prior head" },
    publish: { target: { type: "mission", id: mission }, reversibility: "irreversible", blast_radius: "bounded", production_effect: "none", externality: "publication" },
    broad_delete: { target: { type: "mission", id: mission }, reversibility: "irreversible", blast_radius: "broad", production_effect: "none" }
  }[actionClass];
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "govauthz_" + actionClass,
    lane: RESOLVER_LANE,
    component: "founder_runtime",
    source_sha: FR_SHA,
    action_class: actionClass,
    summary: "transition:AWAITING_APPROVAL->QUEUED " + actionClass,
    externality: "none",
    spend_usd: 0,
    nonce: freshNonce("resolver-nonce"),
    issued_at: iso(T0 - 1000),
    ...shape,
    ...overrides
  };
}

function promotionFacts(overrides = {}) {
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "promote-court",
    lane: PROMOTION_LANE,
    component: "git_custodian",
    source_sha: CUSTODIAN_SHA,
    action_class: "merge",
    summary: "promote NeuruhAI/fixture#7 into main",
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

function resolverGrant(overrides = {}) {
  return makeGrant({
    subject: { lane: RESOLVER_LANE },
    allowed_repos: ["NeuruhAI/recipe-engine"],
    allowed_action_classes: ["artifact_write", "report_write", "test_run", "git_commit"],
    ...overrides
  });
}

function promotionGrant(prId = "NeuruhAI/fixture#7", overrides = {}) {
  return makeGrant({
    subject: { lane: PROMOTION_LANE },
    allowed_repos: ["NeuruhAI/fixture"],
    allowed_action_classes: ["merge", "git_inspect"],
    qualified_operations: [{
      action_class: "merge",
      target: { type: "pull_request", id: prId },
      rollback: "git revert -m 1 <merge_sha> on main; reopen the PR",
      preflight: "Sentinel PASS sealed for head; Honey Pot custody valid; CI PASS; head and base unchanged",
      postflight: "main contains head; PR merged; deploy child emitted if required"
    }],
    ...overrides
  });
}

function scopeOnce(facts, riskTier, { sourceSha = facts.source_sha, secret = FOUNDER_SECRET } = {}) {
  return signFounderApproval({
    schema_version: FOUNDER_APPROVAL_SCHEMA_VERSION,
    approval_id: "fappr_" + freshNonce("f").slice(-8),
    approver_id: "founder",
    mode: "scope_once",
    bound: {
      scope_key: scopeKeyFor(facts),
      source_sha: sourceSha,
      risk_tier: riskTier,
      nonce: freshNonce("fnonce"),
      issued_at: iso(T0 - 1000),
      expires_at: iso(T0 + 600 * 1000)
    }
  }, secret);
}

// =========================================================== CONFIG VALIDATION
test("the mutation_ratified boolean is still refused outright — ratification never became a switch", () => {
  const config = makeV2TrustConfig();
  config.runtime = { mode: "live", mutation_ratified: true };
  assert.throws(() => validateTrustConfig(config), /mutation_ratified must be false/);
});

test("an unsigned, forged, malformed or unknown-approver ratification fails config validation", () => {
  const cases = [
    ["unsigned", (r) => { delete r.signature; }, /signature is required/],
    ["forged", (r) => { r.signature = "0".repeat(64); }, /signature does not verify/],
    ["tampered after signing", (r) => { r.ratified_action_classes.push("force_push"); }, /signature does not verify/],
    ["unknown field", (r) => { r.scope = "everything"; }, /Unknown mutation_ratification field/],
    ["bad schema", (r) => { r.schema_version = "gov.ratification.v0"; }, /schema_version/],
  ];
  for (const [name, mutate, pattern] of cases) {
    const config = makeV2TrustConfig();
    liveRatified(config);
    mutate(config.runtime.mutation_ratification);
    assert.throws(() => validateTrustConfig(config), pattern, name);
  }
});

test("a ratification signed by a non-enhanced approver, or an unknown one, is refused", () => {
  for (const approver of ["reviewer-c", "nobody"]) {
    const config = makeV2TrustConfig();
    liveRatified(config);
    config.runtime.mutation_ratification = ratification({}, { approver, secret: FOUNDER_SECRET });
    assert.throws(() => validateTrustConfig(config), /approver|enhanced/, approver);
  }
});

test("R4 and R5 can NEVER be ratified — external consequence and destruction stay founder-interactive", () => {
  for (const tier of ["R4", "R5"]) {
    const config = makeV2TrustConfig();
    liveRatified(config, { max_ratified_tier: tier });
    assert.throws(() => validateTrustConfig(config),
      new RegExp("may never exceed " + MAX_RATIFIABLE_TIER), tier);
  }
});

test("a ratification may not name an action class above its own ceiling", () => {
  const config = makeV2TrustConfig();
  liveRatified(config, { max_ratified_tier: "R1", ratified_action_classes: ["artifact_write", "merge"] });
  assert.throws(() => validateTrustConfig(config), /above its own ceiling/);

  const destructive = makeV2TrustConfig();
  liveRatified(destructive, { ratified_action_classes: ["force_push"] });
  assert.throws(() => validateTrustConfig(destructive), /above its own ceiling/);
});

test("an inverted or over-long validity window is refused", () => {
  const inverted = makeV2TrustConfig();
  liveRatified(inverted, { ratified_at: iso(T0), expires_at: iso(T0 - 1000) });
  assert.throws(() => validateTrustConfig(inverted), /expires_at must be after/);

  const tooLong = makeV2TrustConfig();
  liveRatified(tooLong, { ratified_at: iso(T0), expires_at: iso(T0 + 400 * 24 * 3600 * 1000) });
  assert.throws(() => validateTrustConfig(tooLong), /exceeds the configured maximum/);
});

test("a well-formed ratification validates, and its absence is still a valid config", () => {
  const ratified = makeV2TrustConfig();
  liveRatified(ratified);
  assert.doesNotThrow(() => validateTrustConfig(ratified));

  const unratified = makeV2TrustConfig();
  liveUnratified(unratified);
  assert.doesNotThrow(() => validateTrustConfig(unratified));
});

// ==================================================================== RED SIDE
test("unratified live: every R1+ class is denied, and R0 observation still allows", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveUnratified });
  for (const cls of ["artifact_write", "test_run", "git_commit"]) {
    const d = authorizeAction(runtime, resolverFacts(cls), { grant: resolverGrant() });
    assert.equal(d.decision, "deny", cls);
    assert.equal(d.reason_code, "MUTATION_NOT_RATIFIED");
  }
  const merge = authorizeAction(runtime, promotionFacts(), { grant: promotionGrant() });
  assert.equal(merge.decision, "deny");
  assert.equal(merge.reason_code, "MUTATION_NOT_RATIFIED");

  const observe = authorizeAction(runtime, resolverFacts("status"));
  assert.equal(observe.decision, "allow");
  assert.equal(observe.reason_code, "AUTO_ALLOW_OBSERVE");
});

test("an expired ratification authorizes nothing", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (c) => liveRatified(c, { ratified_at: iso(T0 - 7200 * 1000), expires_at: iso(T0 - 1000) })
  });
  const d = authorizeAction(runtime, resolverFacts("artifact_write"), { grant: resolverGrant() });
  assert.equal(d.decision, "deny");
  assert.equal(d.reason_code, "MUTATION_NOT_RATIFIED");
  assert.match(d.reasons[0], /expired/);
});

test("a stale Founder Runtime source SHA is denied before any tier or ratification", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const d = authorizeAction(runtime, resolverFacts("status", { source_sha: STALE_FR_SHA }));
  assert.equal(d.decision, "deny");
  assert.equal(d.reason_code, "SOURCE_SHA_MISMATCH");
});

test("an unknown component is denied whatever it presents", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const d = authorizeAction(runtime, promotionFacts({ component: "some-other-worker" }), { grant: promotionGrant() });
  assert.equal(d.decision, "deny");
  assert.equal(d.reason_code, "IDENTITY_UNKNOWN");
});

test("RATIFICATION IS NOT A SWITCH: an escalator re-seals a class that IS ratified", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  // git_commit is ratified. These are all git_commit, and each must still seal.
  const escalators = [
    ["force", { action_class: "git_commit", force: true }],
    ["secret access", { action_class: "git_commit", secret_access: true }],
    ["externality", { action_class: "git_commit", externality: "email" }],
    ["spend", { action_class: "git_commit", spend_usd: 5 }],
    ["irreversible + broad", { action_class: "git_commit", reversibility: "irreversible", blast_radius: "broad" }],
  ];
  for (const [name, overrides] of escalators) {
    const d = authorizeAction(runtime, resolverFacts("git_commit", overrides), { grant: resolverGrant() });
    assert.notEqual(d.decision, "allow", name);
  }
});

test("A5 publish and A6 broad delete stay founder-required or denied under a full ratification", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (c) => {
      liveRatified(c);
      // Even with the component ceiling lifted as far as validation allows.
      c.components.founder_runtime.max_risk_tier = "R3";
      c.components.founder_runtime.allowed_action_classes.push("publish", "broad_delete");
    }
  });
  for (const cls of ["publish", "broad_delete"]) {
    const d = authorizeAction(runtime, resolverFacts(cls), { grant: resolverGrant() });
    assert.notEqual(d.decision, "allow", cls);
    // Two independent refusals stand in front of these, and which one speaks
    // first does not matter: the component consequence ceiling (R3) refuses an
    // action that classifies R4/R5, and behind it the seal would refuse anyway
    // because R4/R5 can never appear in a ratification at all.
    assert.ok(["RISK_TIER_EXCEEDED", "MUTATION_NOT_RATIFIED"].includes(d.reason_code),
      cls + " refused with " + d.reason_code);
  }

  // And with no component ceiling at all, the founder is still required.
  const { runtime: uncapped } = freshAuthorizeRuntime({
    mutateConfig: (c) => {
      liveRatified(c);
      delete c.components.founder_runtime.max_risk_tier;
      delete c.components.founder_runtime.allowed_action_classes;
      c.components.founder_runtime.max_authority_class = "A6";
    }
  });
  const publish = authorizeAction(uncapped, resolverFacts("publish"), { grant: resolverGrant() });
  assert.equal(publish.decision, "deny");
  assert.equal(publish.reason_code, "MUTATION_NOT_RATIFIED");
  const destroy = authorizeAction(uncapped, resolverFacts("broad_delete"), { grant: resolverGrant() });
  assert.equal(destroy.decision, "deny");
  assert.equal(destroy.reason_code, "MUTATION_NOT_RATIFIED");
});

// ================================================================== GREEN SIDE
test("the canonical Founder Runtime observes freely: A0/A1 auto-allow with no credential", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  for (const cls of ["status", "read"]) {
    const d = authorizeAction(runtime, resolverFacts(cls));
    assert.equal(d.decision, "allow", cls);
    assert.equal(d.reason_code, "AUTO_ALLOW_OBSERVE");
    assert.equal(d.risk_tier, "R0");
    assert.deepEqual(d.approver_ids, []);
  }
});

test("bounded internal A2-A4 allow ONLY inside a valid grant on the exact lane", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const grant = resolverGrant();

  const write = authorizeAction(runtime, resolverFacts("artifact_write"), { grant });
  assert.equal(write.decision, "allow");
  assert.equal(write.reason_code, "GRANT_BOUNDED_LOCAL");
  assert.equal(write.risk_tier, "R1");

  for (const cls of ["test_run", "git_commit"]) {
    const d = authorizeAction(runtime, resolverFacts(cls), { grant });
    assert.equal(d.decision, "allow", cls);
    assert.equal(d.reason_code, "GRANT_BOUNDED_DEVELOPMENT");
    assert.equal(d.risk_tier, "R2");
  }

  // Without the grant the founder is asked once; the ratification alone allows nothing.
  const ungranted = authorizeAction(runtime, resolverFacts("artifact_write"));
  assert.equal(ungranted.decision, "founder_required");
});

test("the same action from a different lane is refused — a grant is non-transferable", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const d = authorizeAction(runtime, resolverFacts("git_commit", { lane: "some-other-lane" }),
                            { grant: resolverGrant() });
  assert.equal(d.decision, "deny");
  assert.equal(d.reason_code, "GRANT_LANE_MISMATCH");
});

test("git_custodian merges ONE exact pull request under a qualified grant", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const allowed = authorizeAction(runtime, promotionFacts(), { grant: promotionGrant() });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "GRANT_QUALIFIED_ADOPTION");
  assert.equal(allowed.risk_tier, "R3");
  assert.equal(allowed.founder_prompt, null);
});

test("a different repo, PR, base or action is refused by the same grant", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const grant = promotionGrant();
  const cases = [
    ["different PR", { target: { type: "pull_request", id: "NeuruhAI/fixture#8" } }],
    ["different repo", { repository: "NeuruhAI/other", target: { type: "pull_request", id: "NeuruhAI/other#7" } }],
    ["forced", { force: true }],
  ];
  for (const [name, overrides] of cases) {
    const d = authorizeAction(runtime, promotionFacts(overrides), { grant });
    assert.notEqual(d.decision, "allow", name);
  }
  const staleSha = authorizeAction(runtime, promotionFacts({ source_sha: "0".repeat(40) }), { grant });
  assert.equal(staleSha.decision, "deny");
  assert.equal(staleSha.reason_code, "SOURCE_SHA_MISMATCH");
});

test("a scope_once founder approval merges exactly once; the replay is denied", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const facts = promotionFacts();
  const ask = authorizeAction(runtime, facts);
  assert.equal(ask.decision, "founder_required");
  assert.equal(ask.risk_tier, "R3");

  const approval = scopeOnce(facts, "R3");
  const allowed = authorizeAction(runtime, promotionFacts(), { founder_approval: approval });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");

  const replay = authorizeAction(runtime, promotionFacts(), { founder_approval: approval });
  assert.equal(replay.decision, "deny");
});

test("a forged or expired grant is denied, and no secret appears in any receipt", () => {
  const { runtime, receiptsPath } = freshAuthorizeRuntime({ mutateConfig: liveRatified });
  const forged = { ...promotionGrant(), signature: "0".repeat(64) };
  const denied = authorizeAction(runtime, promotionFacts(), { grant: forged });
  assert.equal(denied.decision, "deny");
  assert.equal(denied.reason_code, "GRANT_SIGNATURE_INVALID");

  // A short, well-formed window that has simply passed. Expiry is not hostile:
  // it degrades to the founder prompt, where a forged signature denies outright.
  const expired = promotionGrant("NeuruhAI/fixture#7", {
    issued_at: iso(T0 - 7200 * 1000),
    expires_at: iso(T0 - 1000)
  });
  const afterExpiry = authorizeAction(runtime, promotionFacts(), { grant: expired });
  assert.equal(afterExpiry.decision, "founder_required");
  assert.equal(afterExpiry.reason_code, "GRANT_EXPIRED");

  const fs = require_fs();
  const chain = fs.existsSync(receiptsPath) ? fs.readFileSync(receiptsPath, "utf8") : "";
  assert.ok(!chain.includes(FOUNDER_SECRET), "no approver secret is ever receipted");
});

function require_fs() {
  return globalThis.__court_fs || (globalThis.__court_fs = fsModule());
}
function fsModule() {
  // node:fs is imported lazily so the rest of the court stays pure.
  return { existsSync: (p) => { try { return statSync(p); } catch { return false; } },
           readFileSync: (p, e) => readFile(p, e) };
}
import { existsSync as statSync, readFileSync as readFile } from "node:fs";
