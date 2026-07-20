import test from "node:test";
import assert from "node:assert/strict";
import { hashCanonical } from "../src/canonical.mjs";
import { decideRequest, decisionIsExpired } from "../src/decision.mjs";
import { verifyChain, readChain } from "../src/receipts.mjs";
import {
  AXON_SHA_ALT,
  T0,
  freshNonce,
  freshRuntime,
  iso,
  makeA5Request,
  makeA6Request,
  makeApproval,
  makeRequest
} from "./helpers.mjs";

test("A0 read with clean policy allows without approvals", () => {
  const { runtime, receiptsPath } = freshRuntime();
  const decision = decideRequest(runtime, makeRequest());
  assert.equal(decision.decision, "allow");
  assert.equal(decision.reason_code, "POLICY_ALLOW");
  assert.equal(decision.execution, "NOT_CLAIMED_BY_GOVERNANCE");
  assert.equal(verifyChain(receiptsPath).ok, true);
});

test("decision envelope carries the full canonical contract", () => {
  const { runtime } = freshRuntime();
  const request = makeRequest();
  const decision = decideRequest(runtime, request);

  for (const field of [
    "schema_version", "decision_id", "request_id", "mission_id", "plan_id", "step_id",
    "correlation_id", "causation_id", "requester_component", "requester_source_sha",
    "policy_id", "policy_version", "authority_class", "operation", "tool",
    "mutation_class", "target", "canonical_args_hash", "canonical_request_hash",
    "precondition_hash", "requested_capability", "decision", "reason_code",
    "approver_ids", "issued_at", "expires_at", "request_nonce", "decision_nonce",
    "one_time_use", "evidence_refs", "decision_hash", "decision_receipt_hash"
  ]) {
    assert.ok(field in decision, "envelope missing field: " + field);
  }

  assert.equal(decision.canonical_request_hash, hashCanonical(request));
  assert.equal(decision.canonical_args_hash, hashCanonical(request.args));
});

test("decision hash recomputes from the envelope (receipt binding)", () => {
  const { runtime, receiptsPath } = freshRuntime();
  const decision = decideRequest(runtime, makeRequest());
  const { decision_hash, decision_receipt_hash, receipt_seq, ...core } = decision;
  assert.equal(hashCanonical(core), decision_hash);

  const receipts = readChain(receiptsPath);
  assert.equal(receipts[receipts.length - 1].entry_hash, decision_receipt_hash);
  assert.equal(receipts[receipts.length - 1].decision_hash, decision_hash);
});

test("A2+ without approvals returns approval_required, never allow", () => {
  const { runtime } = freshRuntime();
  const decision = decideRequest(runtime, makeA5Request());
  assert.equal(decision.decision, "approval_required");
  assert.equal(decision.reason_code, "APPROVAL_REQUIRED");
});

test("A5 with one valid content-bound approval allows (deterministically reachable)", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime, { approver: "owner-a" });
  const decision = decideRequest(runtime, request, [approval]);
  assert.equal(decision.decision, "allow");
  assert.equal(decision.reason_code, "APPROVED_CONTENT_BOUND");
  assert.deepEqual(decision.approver_ids, ["owner-a"]);
  assert.equal(decision.one_time_use.approvals_consumed.length, 1);
});

test("A6 requires two distinct enhanced approvers and is reachable with them", () => {
  const { runtime } = freshRuntime();
  const request = makeA6Request();

  const alone = decideRequest(runtime, request, [makeApproval(request, runtime, { approver: "owner-a", enhanced: true })]);
  assert.equal(alone.decision, "approval_required");
  assert.equal(alone.reason_code, "APPROVAL_QUORUM_INCOMPLETE");

  const request2 = makeA6Request({ nonce: freshNonce("req") });
  const decision = decideRequest(runtime, request2, [
    makeApproval(request2, runtime, { approver: "owner-a", enhanced: true }),
    makeApproval(request2, runtime, { approver: "owner-b", enhanced: true })
  ]);
  assert.equal(decision.decision, "allow");
  assert.deepEqual([...decision.approver_ids].sort(), ["owner-a", "owner-b"]);
});

test("policy-blocked domain denies even with valid approvals", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request({ domain: "credential_exposure" });
  const approval = makeApproval(request, runtime);
  const decision = decideRequest(runtime, request, [approval]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "POLICY_BLOCKED");
});

test("escalation cannot silently become allow, even with approvals attached", () => {
  const { runtime } = freshRuntime();
  const request = makeRequest({ tags: ["external_message"] });
  const bare = decideRequest(runtime, request);
  assert.equal(bare.decision, "escalate");
  assert.equal(bare.reason_code, "ESCALATION_REQUIRED");

  const request2 = makeRequest({ tags: ["external_message"], nonce: freshNonce("req") });
  const withApproval = decideRequest(runtime, request2, [makeApproval(request2, runtime)]);
  assert.equal(withApproval.decision, "escalate");
});

test("live read-only allows; live mutation denies under the unratified seal", () => {
  const { runtime } = freshRuntime({ mutateConfig: (config) => { config.runtime.mode = "live"; } });

  const read = decideRequest(runtime, makeRequest({ evidence_class: "live" }));
  assert.equal(read.decision, "allow");

  const write = makeA5Request({ evidence_class: "live", nonce: freshNonce("req") });
  const approval = makeApproval(write, runtime);
  const decision = decideRequest(runtime, write, [approval]);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "MUTATION_PATH_NOT_RATIFIED");
});

test("decision expiry is bounded and detectable", () => {
  const { runtime, config } = freshRuntime();
  const decision = decideRequest(runtime, makeRequest());
  assert.equal(decisionIsExpired(decision, T0), false);
  assert.equal(decisionIsExpired(decision, T0 + config.decision_ttl_seconds * 1000 + 1), true);
  assert.equal(decisionIsExpired({}, T0), true);
});

test("every decision, including denials, appends a verifiable receipt", () => {
  const { runtime, receiptsPath } = freshRuntime();
  decideRequest(runtime, makeRequest());
  decideRequest(runtime, makeRequest({ requester: { component: "ghost", source_sha: AXON_SHA_ALT }, nonce: freshNonce("req") }));
  decideRequest(runtime, makeA5Request({ nonce: freshNonce("req") }));

  const verification = verifyChain(receiptsPath);
  assert.equal(verification.ok, true);
  assert.equal(verification.length, 3);

  const receipts = readChain(receiptsPath);
  for (const receipt of receipts) {
    assert.equal(receipt.kind, "governance_decision");
    assert.equal(receipt.execution, "NOT_CLAIMED_BY_GOVERNANCE");
    assert.ok(!JSON.stringify(receipt).includes("secret"));
  }
});

test("issued and expiration times come from the governance clock", () => {
  const clock = { ms: T0 };
  const { runtime, config } = freshRuntime({ clock });
  const decision = decideRequest(runtime, makeRequest());
  assert.equal(decision.issued_at, iso(T0));
  assert.equal(decision.expires_at, iso(T0 + config.decision_ttl_seconds * 1000));
});
