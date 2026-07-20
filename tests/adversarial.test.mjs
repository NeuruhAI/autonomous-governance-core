// UP-2 acceptance attacks (mission section 7). Each test is one named attack
// against the decision boundary; every one must end in deny / refusal.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createDecisionRuntime, decideRequest } from "../src/decision.mjs";
import { entryHash, readChain, verifyChain } from "../src/receipts.mjs";
import { loadTrustConfig, validateTrustConfig, TrustConfigError } from "../src/trust.mjs";
import { hashCanonical } from "../src/canonical.mjs";
import {
  AXON_SHA,
  AXON_SHA_ALT,
  RECIPE_SHA,
  SECRETS,
  T0,
  freshNonce,
  freshRuntime,
  iso,
  makeA5Request,
  makeA6Request,
  makeApproval,
  makeRequest,
  makeTrustConfig,
  tempDir
} from "./helpers.mjs";

function approvedThenMutated(mutate) {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  const mutated = structuredClone(request);
  mutate(mutated);
  return decideRequest(runtime, mutated, [approval]);
}

test("attack: swapping target after approval", () => {
  const decision = approvedThenMutated((request) => { request.target = { type: "branch", id: "main" }; });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_CONTENT_MISMATCH");
});

test("attack: changing one argument", () => {
  const decision = approvedThenMutated((request) => { request.args = { remote: "attacker-remote" }; });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_CONTENT_MISMATCH");
});

test("attack: adding a hidden argument", () => {
  const decision = approvedThenMutated((request) => { request.args = { remote: "origin", force: true }; });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_CONTENT_MISMATCH");
});

test("attack: path normalization differences", () => {
  const { runtime } = freshRuntime();

  for (const alias of ["/repo/docs/../docs/file.md", "/repo/./docs/file.md", "/repo//docs/file.md", "/repo/docs/file.md/"]) {
    const request = makeRequest({ target: { type: "path", id: alias }, nonce: freshNonce("req") });
    const decision = decideRequest(runtime, request);
    assert.equal(decision.decision, "deny", "alias should be refused: " + alias);
    assert.equal(decision.reason_code, "TARGET_AMBIGUOUS");
  }
});

test("attack: Unicode normalization differences", () => {
  const { runtime } = freshRuntime();
  const nfdPath = "/repo/docs/r\u0065\u0301sume.md"; // e + combining accent (NFD)
  const decision = decideRequest(runtime, makeRequest({ target: { type: "path", id: nfdPath }, nonce: freshNonce("req") }));
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "CANONICALIZATION_FAILED");
});

test("attack: changing tool", () => {
  const decision = approvedThenMutated((request) => {
    request.tool = "fs";
    request.operation = "write_file";
  });
  assert.equal(decision.decision, "deny");
});

test("attack: changing mission, plan or step", () => {
  for (const field of ["mission_id", "plan_id", "step_id"]) {
    const decision = approvedThenMutated((request) => { request[field] = "hijacked"; });
    assert.equal(decision.decision, "deny", field + " swap must deny");
    assert.equal(decision.reason_code, "APPROVAL_CONTENT_MISMATCH");
  }
});

test("attack: changing source SHA", () => {
  // Both SHAs are pinned for the component, so only the approval binding
  // stands between them — and it must hold.
  const decision = approvedThenMutated((request) => { request.requester = { component: "axon-gateway", source_sha: AXON_SHA_ALT }; });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_CONTENT_MISMATCH");

  const { runtime } = freshRuntime();
  const unpinned = decideRequest(runtime, makeRequest({ requester: { component: "axon-gateway", source_sha: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" } }));
  assert.equal(unpinned.decision, "deny");
  assert.equal(unpinned.reason_code, "SOURCE_SHA_MISMATCH");
});

test("attack: changing policy version", () => {
  const { runtime } = freshRuntime();
  const wrongVersion = decideRequest(runtime, makeRequest({ policy_version: "attacker-chosen-policy" }));
  assert.equal(wrongVersion.decision, "deny");
  assert.equal(wrongVersion.reason_code, "POLICY_VERSION_MISMATCH");

  const request = makeA5Request({ nonce: freshNonce("req") });
  const staleApproval = makeApproval(request, runtime, { policyVersionOverride: "stale-policy-version-hash" });
  const decision = decideRequest(runtime, request, [staleApproval]);
  assert.equal(decision.decision, "deny");
});

test("attack: authority escalation", () => {
  const { runtime } = freshRuntime();
  const decision = decideRequest(runtime, makeRequest({
    requester: { component: "observer", source_sha: "c3d4e5f60718293a4b5c6d7e8f9012345678a1b2" },
    authority_class: "A5",
    operation: "push_branch",
    tool: "git",
    mutation_class: "persistent_write",
    requested_capability: "write",
    nonce: freshNonce("req")
  }));
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "AUTHORITY_EXCEEDED");
});

test("attack: read-to-write upgrade", () => {
  const { runtime } = freshRuntime();
  const mislabeled = decideRequest(runtime, makeRequest({
    operation: "write_file",
    mutation_class: "read_only",
    nonce: freshNonce("req")
  }));
  assert.equal(mislabeled.decision, "deny");
  assert.equal(mislabeled.reason_code, "MUTATION_CLASS_MISMATCH");

  // An approval bound to the read operation must not authorize the write.
  const readRequest = makeRequest({ nonce: freshNonce("req") });
  const readApproval = makeApproval(readRequest, runtime);
  const writeRequest = makeRequest({
    authority_class: "A4",
    operation: "write_file",
    mutation_class: "persistent_write",
    requested_capability: "write",
    nonce: freshNonce("req")
  });
  const upgraded = decideRequest(runtime, writeRequest, [readApproval]);
  assert.equal(upgraded.decision, "deny");
});

test("attack: fixture-to-live upgrade", () => {
  const { runtime } = freshRuntime({ mutateConfig: (config) => { config.runtime.mode = "live"; } });

  const fixtureInLive = decideRequest(runtime, makeRequest({ evidence_class: "fixture" }));
  assert.equal(fixtureInLive.decision, "deny");
  assert.equal(fixtureInLive.reason_code, "EVIDENCE_CLASS_MISMATCH");

  // A fixture-bound approval presented for a live request dies on binding
  // (and live mutation would die on the unratified seal regardless).
  const liveRequest = makeA5Request({ evidence_class: "live", nonce: freshNonce("req") });
  const fixtureApproval = makeApproval(liveRequest, runtime, { mutateBound: (bound) => { bound.evidence_class = "fixture"; } });
  const decision = decideRequest(runtime, liveRequest, [fixtureApproval]);
  assert.equal(decision.decision, "deny");
});

test("attack: wildcard approval", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const wildTarget = makeApproval(request, runtime, { mutateBound: (bound) => { bound.target = { type: "path", id: "*" }; } });
  assert.equal(decideRequest(runtime, request, [wildTarget]).decision, "deny");

  const request2 = makeA5Request({ nonce: freshNonce("req") });
  const wildOperation = makeApproval(request2, runtime, { mutateBound: (bound) => { bound.operation = "*"; } });
  const decision = decideRequest(runtime, request2, [wildOperation]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_WILDCARD");

  const wildRequest = makeRequest({ target: { type: "path", id: "*" }, nonce: freshNonce("req") });
  const wildDecision = decideRequest(runtime, wildRequest);
  assert.equal(wildDecision.decision, "deny");
  assert.equal(wildDecision.reason_code, "TARGET_AMBIGUOUS");
});

test("attack: expired approval", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const expired = makeApproval(request, runtime, { issuedMs: T0 - 700_000, ttlSeconds: 600 });
  const decision = decideRequest(runtime, request, [expired]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_EXPIRED");
});

test("attack: replayed approval", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  assert.equal(decideRequest(runtime, request, [approval]).decision, "allow");

  const replay = decideRequest(runtime, request, [approval]);
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("attack: concurrent double consume", async () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);

  const outcomes = await Promise.all([
    Promise.resolve().then(() => decideRequest(runtime, request, [approval])),
    Promise.resolve().then(() => decideRequest(runtime, request, [approval]))
  ]);

  const allows = outcomes.filter((decision) => decision.decision === "allow");
  const denies = outcomes.filter((decision) => decision.decision === "deny");
  assert.equal(allows.length, 1);
  assert.equal(denies.length, 1);
});

test("attack: forged approver identity", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const forged = makeApproval(request, runtime, { approver: "owner-a", secret: "not-the-owner-secret-0123456789a" });
  const decision = decideRequest(runtime, request, [forged]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_SIGNATURE_INVALID");
});

test("attack: model self-approval", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request({ requester: { component: "model-x", source_sha: "d4e5f60718293a4b5c6d7e8f9012345678a1b2c3" } });
  const selfApproval = makeApproval(request, runtime, { approver: "model-x", secret: SECRETS["model-x"] });
  const decision = decideRequest(runtime, request, [selfApproval]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "SELF_APPROVAL");
});

test("attack: receipt tampering", () => {
  const { runtime, config, receiptsPath, consumptionPath } = freshRuntime();
  decideRequest(runtime, makeRequest());

  const entries = readChain(receiptsPath);
  entries[0].decision = "allow-everything";
  fs.writeFileSync(receiptsPath, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(receiptsPath).ok, false);

  const reopened = createDecisionRuntime({ config, receiptsPath, consumptionPath, now: () => T0 });
  const decision = decideRequest(reopened, makeRequest({ nonce: freshNonce("req") }));
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "RECEIPT_CHAIN_POISONED");
});

test("attack: receipt deletion and reordering", () => {
  const { runtime, receiptsPath } = freshRuntime();
  decideRequest(runtime, makeRequest());
  decideRequest(runtime, makeRequest({ nonce: freshNonce("req") }));
  decideRequest(runtime, makeRequest({ nonce: freshNonce("req") }));

  const entries = readChain(receiptsPath);

  const deleted = [entries[0], entries[2]];
  fs.writeFileSync(receiptsPath, deleted.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(receiptsPath).ok, false);

  const reordered = [entries[1], entries[0], entries[2]];
  fs.writeFileSync(receiptsPath, reordered.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(receiptsPath).ok, false);
});

test("attack: persistence failure", () => {
  const badDir = path.join(tempDir(), "no-such-dir");
  const { config } = freshRuntime();
  const runtime = createDecisionRuntime({
    config,
    receiptsPath: path.join(badDir, "receipts.jsonl"),
    consumptionPath: path.join(badDir, "consumption.jsonl"),
    now: () => T0
  });

  const decision = decideRequest(runtime, makeRequest());
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "RECEIPT_PERSISTENCE_FAILED");
  assert.equal(decision.decision_receipt_hash, null);
});

test("attack: missing configuration", () => {
  delete process.env.GOVERNANCE_TRUST_CONFIG;
  assert.throws(() => loadTrustConfig(process.env), TrustConfigError);

  assert.throws(() => createDecisionRuntime({ config: null, receiptsPath: "x", consumptionPath: "y" }));

  const noApprovers = makeTrustConfig();
  noApprovers.approvers = {};
  validateTrustConfig(noApprovers);
  const { runtime } = freshRuntime({ mutateConfig: (config) => { config.approvers = {}; } });
  const request = makeA5Request();
  const orphanApproval = makeApproval(request, runtime, { approver: "owner-a", secret: SECRETS["owner-a"] });
  const decision = decideRequest(runtime, request, [orphanApproval]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVER_UNKNOWN");

  const ratifiedClaim = makeTrustConfig();
  ratifiedClaim.runtime.mutation_ratified = true;
  assert.throws(() => validateTrustConfig(ratifiedClaim), /not ratified/);
});

test("attack: malformed canonical payload", () => {
  const { runtime } = freshRuntime();

  const nan = decideRequest(runtime, makeRequest({ spend_usd: NaN }));
  assert.equal(nan.decision, "deny");
  assert.equal(nan.reason_code, "CANONICALIZATION_FAILED");

  const proto = decideRequest(runtime, makeRequest({ args: JSON.parse('{"__proto__": {"polluted": true}}'), nonce: freshNonce("req") }));
  assert.equal(proto.decision, "deny");
  assert.equal(proto.reason_code, "CANONICALIZATION_FAILED");

  const unknownField = decideRequest(runtime, makeRequest({ nonce: freshNonce("req"), surprise: "field" }));
  assert.equal(unknownField.decision, "deny");
  assert.equal(unknownField.reason_code, "MALFORMED_REQUEST");
});

test("attack: dependency failure at consumption time", () => {
  // The consumption ledger's backing store vanishes between runtime start and
  // the decision — the boundary must deny, not allow-and-hope.
  const dir = tempDir();
  const consumptionDir = path.join(dir, "consumption-store");
  fs.mkdirSync(consumptionDir);
  const { config } = freshRuntime();
  const runtime = createDecisionRuntime({
    config,
    receiptsPath: path.join(dir, "receipts.jsonl"),
    consumptionPath: path.join(consumptionDir, "consumption.jsonl"),
    now: () => T0
  });

  fs.rmSync(consumptionDir, { recursive: true, force: true });

  const request = makeA5Request();
  const decision = decideRequest(runtime, request, [makeApproval(request, runtime)]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "CONSUMPTION_PERSISTENCE_FAILED");
});

test("attack: decision/receipt hash mismatch is detectable", () => {
  const { runtime, receiptsPath } = freshRuntime();
  const decision = decideRequest(runtime, makeRequest());

  const { decision_hash, decision_receipt_hash, receipt_seq, ...core } = decision;
  assert.equal(hashCanonical(core), decision_hash);

  const tampered = { ...core, decision: "deny" };
  assert.notEqual(hashCanonical(tampered), decision_hash);

  const entries = readChain(receiptsPath);
  const receipt = entries[entries.length - 1];
  const { entry_hash, ...receiptBody } = receipt;
  assert.equal(entryHash(receipt.prev_hash, receiptBody), entry_hash);

  const forgedReceipt = { ...receiptBody, decision: "allow-everything" };
  assert.notEqual(entryHash(receipt.prev_hash, forgedReceipt), entry_hash);
});

test("attack: surplus approvals are refused, not silently picked from", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const decision = decideRequest(runtime, request, [
    makeApproval(request, runtime, { approver: "owner-a" }),
    makeApproval(request, runtime, { approver: "owner-b", secret: SECRETS["owner-b"] })
  ]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "APPROVAL_SURPLUS");
});

test("attack: A6 with duplicate or non-enhanced approvers", () => {
  const { runtime } = freshRuntime();

  const request = makeA6Request();
  const duplicate = decideRequest(runtime, request, [
    makeApproval(request, runtime, { approver: "owner-a", enhanced: true, nonce: freshNonce("apr") }),
    makeApproval(request, runtime, { approver: "owner-a", enhanced: true, nonce: freshNonce("apr") })
  ]);
  assert.equal(duplicate.decision, "deny");
  assert.equal(duplicate.reason_code, "APPROVAL_DUPLICATE_APPROVER");

  const request2 = makeA6Request({ nonce: freshNonce("req") });
  const weak = decideRequest(runtime, request2, [
    makeApproval(request2, runtime, { approver: "owner-a", enhanced: true }),
    makeApproval(request2, runtime, { approver: "reviewer-c", secret: SECRETS["reviewer-c"], enhanced: false })
  ]);
  assert.equal(weak.decision, "deny");
  assert.equal(weak.reason_code, "APPROVAL_NOT_ENHANCED");
});
