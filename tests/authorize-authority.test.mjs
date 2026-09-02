import assert from "node:assert/strict";
import test from "node:test";
import { authorizeAction, createAuthorizeRuntime, scopeKeyFor } from "../src/authorize.mjs";
import { verifyChain } from "../src/receipts.mjs";
import { validateTrustConfig } from "../src/trust.mjs";
import {
  AXON_SHA,
  FOUNDER_SECRET,
  freshAuthorizeRuntime,
  iso,
  makeFacts,
  makeFounderApproval,
  makeGrant,
  T0
} from "./v2-helpers.mjs";
import { AXON_SHA_ALT } from "./helpers.mjs";

// T31B — the authority chain on /v2/authorize.
//
// Three things were true of this surface before this court existed, and each of
// them was a way to be authorized without being checked:
//
//   * it had NO identity attestation at all, so it could not tell a current
//     runtime from a superseded one and SOURCE_SHA_SUPERSEDED — the denial the
//     trust config's whole lineage contract exists to produce — was unreachable
//     here even though /v2/decide had enforced it since P2-B;
//   * it did not enforce the unratified-mutation seal, so a FounderGrant could
//     authorize live mutation that runtime.mutation_ratified: false declares
//     unratified;
//   * a founder approval or grant presented on a path that did not need it was
//     ignored rather than checked, so a forged credential rode inside an
//     otherwise-allowable request and the receipt recorded an allow without ever
//     recording that forged evidence had been offered.
//
// Each test below fails if any of those returns.

const SUPERSEDED_SHA = "aaaabbbbccccddddeeeeffff0000111122223333";
const UNKNOWN_SHA = "9999888877776666555544443333222211110000";

// A trust config whose axon-gateway component carries a real lineage: one
// qualified SHA and one superseded SHA that names it.
function withLineage(config) {
  config.expected_source_shas["axon-gateway"] = [AXON_SHA];
  config.source_lineage = {
    "axon-gateway": [
      { sha: SUPERSEDED_SHA, status: "superseded", qualified_at: "2026-01-01T00:00:00Z", superseded_by: AXON_SHA },
      { sha: AXON_SHA, status: "qualified", qualified_at: "2026-02-01T00:00:00Z" }
    ]
  };
}

// The founder secret with exactly one character changed. Derived rather than
// written out so no secret-shaped literal lives in the tree, and so the test
// says precisely what it means: a near-miss key is still the wrong key.
const WRONG_SECRET = FOUNDER_SECRET.slice(0, -1) + (FOUNDER_SECRET.endsWith("0") ? "1" : "0");

function scopeOnce(facts, options = {}) {
  return makeFounderApproval(facts, null, { mode: "scope_once", riskTier: "R0", ...options });
}

// ---------------------------------------------------------------- identity ---

test("identity attestation is mandatory, not optional", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();
  delete facts.source_sha;

  const result = authorizeAction(runtime, facts);

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "MALFORMED_FACTS");
  assert.ok(result.reasons.some((reason) => /source_sha is required/.test(reason)));
});

test("an unregistered component cannot be authorized at any tier", () => {
  const { runtime } = freshAuthorizeRuntime();

  const result = authorizeAction(runtime, makeFacts({ component: "impostor-service" }));

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "IDENTITY_UNKNOWN");
});

test("a source SHA that is not pinned is refused", () => {
  const { runtime } = freshAuthorizeRuntime();

  const result = authorizeAction(runtime, makeFacts({ source_sha: UNKNOWN_SHA }));

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "SOURCE_SHA_MISMATCH");
});

test("a superseded source SHA is refused precisely, naming the qualified identity", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: withLineage });

  const result = authorizeAction(runtime, makeFacts({ source_sha: SUPERSEDED_SHA }));

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "SOURCE_SHA_SUPERSEDED");
  assert.match(result.reasons[0], new RegExp("superseded by " + AXON_SHA));
  assert.match(result.reasons[0], /never falsified/);
});

test("the currently qualified source SHA is accepted", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: withLineage });

  const result = authorizeAction(runtime, makeFacts({ source_sha: AXON_SHA }));

  assert.equal(result.decision, "allow");
  assert.equal(result.reason_code, "AUTO_ALLOW_OBSERVE");
});

test("a superseded identity is refused even with a valid signed founder approval", () => {
  const { runtime } = freshAuthorizeRuntime({ mutateConfig: withLineage });
  const facts = makeFacts({ source_sha: SUPERSEDED_SHA });

  const result = authorizeAction(runtime, facts, { founder_approval: scopeOnce(facts) });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "SOURCE_SHA_SUPERSEDED");
});

// ------------------------------------------------- component narrowing -------

test("a component allowlist admits only the action classes it names", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.components["axon-gateway"].allowed_action_classes = ["read", "query", "status"];
    }
  });

  assert.equal(authorizeAction(runtime, makeFacts({ action_class: "query" })).decision, "allow");

  const refused = authorizeAction(runtime, makeFacts({
    action_class: "artifact_write",
    summary: "Write an artifact.",
    target: { type: "path", id: "/tmp/report.md" }
  }));

  assert.equal(refused.decision, "deny");
  assert.equal(refused.reason_code, "ACTION_CLASS_NOT_ADMITTED");
});

test("the component consequence ceiling beats a valid grant and a valid approval", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.components["axon-gateway"].max_risk_tier = "R0";
    }
  });

  const facts = makeFacts({
    action_class: "repo_edit",
    summary: "Edit an owned repository.",
    target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" },
    repository: "NeuruhAI/autonomous-governance-core",
    branch: "feature/t31b"
  });

  const result = authorizeAction(runtime, facts, {
    grant: makeGrant(),
    founder_approval: makeFounderApproval(facts, null, { mode: "scope_once", riskTier: "R2" })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "RISK_TIER_EXCEEDED");
  assert.equal(result.approver_ids.length, 0, "no approver may be credited for a refused action");
});

// ---------------------------------------------------- unratified mutation ----

test("a live trust config refuses mutating action classes while mutation is unratified", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.runtime.mode = "live";
    }
  });

  const facts = makeFacts({
    action_class: "repo_edit",
    summary: "Edit an owned repository.",
    target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" },
    repository: "NeuruhAI/autonomous-governance-core",
    branch: "feature/t31b"
  });

  const result = authorizeAction(runtime, facts, { grant: makeGrant() });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "MUTATION_NOT_RATIFIED");
});

test("the mutation seal cannot be bought off with a founder approval", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.runtime.mode = "live";
    }
  });

  const facts = makeFacts({
    action_class: "git_push",
    summary: "Push a feature branch.",
    target: { type: "branch", id: "feature/t31b" },
    repository: "NeuruhAI/autonomous-governance-core",
    branch: "feature/t31b"
  });

  const result = authorizeAction(runtime, facts, {
    founder_approval: makeFounderApproval(facts, null, { mode: "scope_once", riskTier: "R2" })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "MUTATION_NOT_RATIFIED");
});

test("read-only observation is untouched by the seal in live mode", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.runtime.mode = "live";
    }
  });

  assert.equal(authorizeAction(runtime, makeFacts()).decision, "allow");
});

// -------------------------------------------- presented, never ignored -------

test("a forged founder approval presented at R0 denies instead of being ignored", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();

  const result = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { secret: WRONG_SECRET })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_SIGNATURE_INVALID");
});

test("a forged grant presented at R0 denies instead of being ignored", () => {
  const { runtime } = freshAuthorizeRuntime();
  const grant = makeGrant();
  grant.signature = "0".repeat(grant.signature.length);

  const result = authorizeAction(runtime, makeFacts(), { grant });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "GRANT_SIGNATURE_INVALID");
});

test("an expired grant is not hostile: an R0 observation still allows", () => {
  const { runtime } = freshAuthorizeRuntime();
  const expired = makeGrant({ issued_at: iso(T0 - 7200 * 1000), expires_at: iso(T0 - 3600 * 1000) });

  const result = authorizeAction(runtime, makeFacts(), { grant: expired });

  assert.equal(result.decision, "allow");
  assert.equal(result.reason_code, "AUTO_ALLOW_OBSERVE");
});

// ------------------------------------------------------------- scope_once ----

test("scope_once: a signed external decision authorizes exactly once and opens no session", () => {
  const { runtime, consumptionPath } = freshAuthorizeRuntime();
  const facts = makeFacts();
  const approval = scopeOnce(facts);

  const first = authorizeAction(runtime, facts, { founder_approval: approval });

  assert.equal(first.decision, "allow");
  assert.equal(first.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");
  assert.deepEqual(first.approver_ids, ["founder"]);
  assert.equal(first.session_scope_used, false, "scope_once must never open a session scope");
  assert.equal(runtime.sessionScopes.size, 0, "scope_once must leave no standing permission behind");
  assert.ok(first.evidence_refs.some((ref) => ref.kind === "founder_approval_consumption"));
  assert.equal(verifyChain(consumptionPath).ok, true);

  // Same signed artifact, fresh facts: the approval nonce is spent.
  const replay = authorizeAction(runtime, makeFacts(), { founder_approval: approval });

  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("scope_once consumption is durable: a restarted runtime still refuses the spent approval", () => {
  const { runtime, config, receiptsPath, consumptionPath } = freshAuthorizeRuntime();
  const facts = makeFacts();
  const approval = scopeOnce(facts);

  assert.equal(authorizeAction(runtime, facts, { founder_approval: approval }).decision, "allow");

  // A restarted server reopens the same append-only chains. The spent approval
  // must be refused from the ledger, not from process memory.
  const restarted = createAuthorizeRuntime({ config, receiptsPath, consumptionPath, now: () => T0 });

  const replay = authorizeAction(restarted, makeFacts(), { founder_approval: approval });

  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("scope_once is version bound: an approval for another source SHA is void", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts({ source_sha: AXON_SHA });

  const result = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { sourceSha: AXON_SHA_ALT })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_SOURCE_MISMATCH");
  assert.match(result.reasons[0], new RegExp(AXON_SHA));
});

test("scope_once is scope bound: an approval for another target is void", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();
  const other = makeFacts({ target: { type: "service", id: "some-other-service" } });

  const result = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { mutateBound: (bound) => { bound.scope_key = scopeKeyFor(other); } })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_CONTENT_MISMATCH");
});

test("scope_once binds the classified tier: an approval issued for another tier is void", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();

  const result = authorizeAction(runtime, facts, { founder_approval: scopeOnce(facts, { riskTier: "R3" }) });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_RISK_MISMATCH");
});

test("scope_once expiry and maximum TTL are enforced", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();

  const expired = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { issuedMs: T0 - 600_000, ttlSeconds: 60 })
  });

  assert.equal(expired.decision, "deny");
  assert.equal(expired.reason_code, "APPROVAL_EXPIRED");

  const tooLong = authorizeAction(runtime, makeFacts(), {
    founder_approval: scopeOnce(makeFacts(), { ttlSeconds: 4000 })
  });

  assert.equal(tooLong.decision, "deny");
  assert.ok(["APPROVAL_TTL_EXCEEDED", "APPROVAL_CONTENT_MISMATCH"].includes(tooLong.reason_code));
});

test("scope_once bound fields are closed: extra or missing fields are malformed", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();

  const extended = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { mutateBound: (bound) => { bound.extra = "smuggled"; } })
  });

  assert.equal(extended.decision, "deny");
  assert.equal(extended.reason_code, "APPROVAL_MALFORMED");

  const missing = authorizeAction(runtime, makeFacts(), {
    founder_approval: scopeOnce(makeFacts(), { mutateBound: (bound) => { delete bound.source_sha; } })
  });

  assert.equal(missing.decision, "deny");
  assert.equal(missing.reason_code, "APPROVAL_MALFORMED");
});

test("a lane cannot founder-approve its own action under scope_once either", () => {
  const { runtime } = freshAuthorizeRuntime({
    mutateConfig: (config) => {
      config.approvers["lane-t3-governance"] = { secret: FOUNDER_SECRET, enhanced: true };
    }
  });

  const facts = makeFacts();

  const result = authorizeAction(runtime, facts, {
    founder_approval: scopeOnce(facts, { approver: "lane-t3-governance" })
  });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "SELF_APPROVAL");
});

test("an unknown approver cannot mint authority, however well formed the artifact", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts();

  const result = authorizeAction(runtime, facts, { founder_approval: scopeOnce(facts, { approver: "mission" }) });

  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVER_UNKNOWN");
});

test("every authorization outcome is receipted on the chain, allow and deny alike", () => {
  const { runtime, receiptsPath } = freshAuthorizeRuntime();
  const facts = makeFacts();

  authorizeAction(runtime, makeFacts({ component: "impostor-service" }));
  authorizeAction(runtime, facts, { founder_approval: scopeOnce(facts) });

  const chain = verifyChain(receiptsPath);

  assert.equal(chain.ok, true);
  assert.equal(chain.length, 2);
});

test("the adoption trust config on disk is the qualified one and stays narrow", async () => {
  const fs = await import("node:fs");
  const raw = JSON.parse(fs.readFileSync(new URL("../config/governance-v2-adoption-trust.json", import.meta.url), "utf8"));

  raw.implementation_sha = "0".repeat(40);
  raw.approvers.founder.secret = "x".repeat(32);
  validateTrustConfig(raw);

  const pinned = raw.expected_source_shas.founder_runtime;
  const lineage = raw.source_lineage.founder_runtime;
  const qualified = lineage.filter((entry) => entry.status === "qualified").map((entry) => entry.sha);

  assert.deepEqual(pinned, qualified, "the pin must be exactly the qualified lineage");
  assert.equal(qualified.length, 1, "exactly one qualified Founder Runtime identity");
  assert.ok(!pinned.includes("*"), "no wildcard identity");

  const { ACTION_CLASS_TIERS, riskRank } = await import("../src/risk.mjs");
  const { MAX_RATIFIABLE_TIER } = await import("../src/ratification.mjs");

  // T03 widened this component from observe-only to bounded internal work, so
  // the guard widens with it — and stays a guard. The Founder Runtime may now
  // reach R2 (bounded, reversible, feature-branch development) and no further;
  // every class it may present must sit at or below that ceiling, so nothing
  // external, spending or destructive can be admitted here quietly.
  const component = raw.components.founder_runtime;

  assert.equal(component.max_authority_class, "A4");
  assert.equal(component.max_risk_tier, "R2");
  assert.deepEqual(component.capabilities, ["observe", "write"]);

  for (const actionClass of component.allowed_action_classes) {
    assert.ok(actionClass in ACTION_CLASS_TIERS, actionClass + " is not a known action class");
    assert.ok(riskRank(ACTION_CLASS_TIERS[actionClass]) <= riskRank("R2"),
      actionClass + " (" + ACTION_CLASS_TIERS[actionClass] + ") is above the Founder Runtime ceiling");
  }

  // The promotion executor is registered for exactly one mutating operation.
  const custodian = raw.components.git_custodian;

  assert.ok(custodian, "git_custodian is registered");
  assert.equal(custodian.max_risk_tier, "R3");
  assert.deepEqual(custodian.allowed_action_classes.filter(
    (cls) => ACTION_CLASS_TIERS[cls] !== "R0"), ["merge"],
    "the only mutating class the custodian may present is merge");
  assert.ok(raw.expected_source_shas.git_custodian, "the custodian identity is pinned");

  // Neither component may ever reach external consequence or destruction, and
  // the ratification that unseals live mutation cannot name those tiers either.
  for (const id of ["founder_runtime", "git_custodian"]) {
    assert.ok(riskRank(raw.components[id].max_risk_tier) <= riskRank(MAX_RATIFIABLE_TIER),
      id + " is trusted above the ratifiable ceiling");
  }

  assert.equal(raw.runtime.mutation_ratified, false, "the ratified boolean stays false, permanently");

  // The shipped config carries no ratification: it is a signed artifact the
  // founder mints at launch against the real secret, never a committed one.
  assert.equal(raw.runtime.mutation_ratification, undefined,
    "no ratification is committed to the repository");
});
