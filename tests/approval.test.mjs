import test from "node:test";
import assert from "node:assert/strict";
import { hashCanonical } from "../src/canonical.mjs";
import { expectedApprovalBound, requiredApprovalCount, verifyApproval, APPROVAL_CONTENT_FIELDS } from "../src/approval.mjs";
import { T0, freshRuntime, makeA5Request, makeApproval, SECRETS } from "./helpers.mjs";

function expected(request, runtime) {
  return expectedApprovalBound(request, hashCanonical(request), runtime.policy_version);
}

test("a well-formed approval verifies against its exact request", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  const result = verifyApproval(approval, expected(request, runtime), config, T0);
  assert.equal(result.ok, true);
  assert.equal(result.approver_id, "owner-a");
});

test("every bound content field individually invalidates on change", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();

  for (const field of APPROVAL_CONTENT_FIELDS) {
    const approval = makeApproval(request, runtime, {
      mutateBound: (bound) => {
        bound[field] = field === "target" ? { type: "path", id: "/other/target" } : "poisoned-value";
      }
    });

    const result = verifyApproval(approval, expected(request, runtime), config, T0);
    assert.equal(result.ok, false, "field should invalidate: " + field);
  }
});

test("tampering with the bound block after signing breaks the signature", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  approval.bound.operation = "purge_history";
  const result = verifyApproval(approval, expected(request, runtime), config, T0);
  assert.equal(result.ok, false);
  assert.equal(result.reason_code, "APPROVAL_SIGNATURE_INVALID");
});

test("approvals cannot drop or extend the bound field set", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();

  const dropped = makeApproval(request, runtime, { mutateBound: (bound) => { delete bound.repository; } });
  assert.equal(verifyApproval(dropped, expected(request, runtime), config, T0).ok, false);

  const extended = makeApproval(request, runtime, { mutateBound: (bound) => { bound.extra_grant = "everything"; } });
  assert.equal(verifyApproval(extended, expected(request, runtime), config, T0).ok, false);
});

test("expired, premature and over-long approvals are refused", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();

  const expired = makeApproval(request, runtime, { issuedMs: T0 - 700_000, ttlSeconds: 600 });
  assert.equal(verifyApproval(expired, expected(request, runtime), config, T0).reason_code, "APPROVAL_EXPIRED");

  const premature = makeApproval(request, runtime, { issuedMs: T0 + 120_000, ttlSeconds: 600 });
  assert.equal(verifyApproval(premature, expected(request, runtime), config, T0).reason_code, "APPROVAL_NOT_YET_VALID");

  const tooLong = makeApproval(request, runtime, { ttlSeconds: 86_400 });
  assert.equal(verifyApproval(tooLong, expected(request, runtime), config, T0).reason_code, "APPROVAL_TTL_EXCEEDED");
});

test("unknown approver, forged signature and self-approval are refused", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();

  const unknown = makeApproval(request, runtime, { approver: "stranger", secret: "stranger-secret-0123456789abcdef" });
  assert.equal(verifyApproval(unknown, expected(request, runtime), config, T0).reason_code, "APPROVER_UNKNOWN");

  const forged = makeApproval(request, runtime, { approver: "owner-a", secret: "wrong-secret-0123456789abcdef000" });
  assert.equal(verifyApproval(forged, expected(request, runtime), config, T0).reason_code, "APPROVAL_SIGNATURE_INVALID");

  const selfRequest = makeA5Request({ requester: { component: "model-x", source_sha: "d4e5f60718293a4b5c6d7e8f9012345678a1b2c3" } });
  const selfApproval = makeApproval(selfRequest, runtime, { approver: "model-x", secret: SECRETS["model-x"] });
  assert.equal(verifyApproval(selfApproval, expected(selfRequest, runtime), config, T0).reason_code, "SELF_APPROVAL");
});

test("wildcard bound fields are refused before content comparison", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();
  const wildcard = makeApproval(request, runtime, { mutateBound: (bound) => { bound.operation = "*"; } });
  const result = verifyApproval(wildcard, expected(request, runtime), config, T0);
  assert.equal(result.ok, false);
  assert.equal(result.reason_code, "APPROVAL_WILDCARD");
});

test("enhanced approvals demand an enhanced approver", () => {
  const { runtime, config } = freshRuntime();
  const request = makeA5Request();
  const overstated = makeApproval(request, runtime, { approver: "reviewer-c", secret: SECRETS["reviewer-c"], enhanced: true });
  assert.equal(verifyApproval(overstated, expected(request, runtime), config, T0).reason_code, "APPROVER_NOT_ENHANCED");
});

test("approval doctrine counts: A0/A1 none, A2-A5 one, A6 two", () => {
  assert.equal(requiredApprovalCount("A0"), 0);
  assert.equal(requiredApprovalCount("A1"), 0);
  assert.equal(requiredApprovalCount("A2"), 1);
  assert.equal(requiredApprovalCount("A3"), 1);
  assert.equal(requiredApprovalCount("A4"), 1);
  assert.equal(requiredApprovalCount("A5"), 1);
  assert.equal(requiredApprovalCount("A6"), 2);
});
