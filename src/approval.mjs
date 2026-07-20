import { canonicalize, hashCanonical, hmacHex, isSha256Hex, timingSafeEqualHex } from "./canonical.mjs";
import { authorityRank } from "./trust.mjs";

// Content-bound approvals. One approval authorizes exactly one canonical
// request: every bound field is checked for exact equality against the request
// being decided, the signature is an HMAC keyed by the approver secret held in
// trusted configuration (never in the request payload), and the approval nonce
// is consumed exactly once. Changing any bound field invalidates the approval.

export const APPROVAL_SCHEMA_VERSION = "gov.approval.v1";

// Fields bound to the request content itself (checked for exact equality
// against the canonical request) …
export const APPROVAL_CONTENT_FIELDS = [
  "request_hash",
  "requester_component",
  "requester_source_sha",
  "operation",
  "tool",
  "mutation_class",
  "authority_class",
  "evidence_class",
  "repository",
  "target",
  "args_hash",
  "mission_id",
  "plan_id",
  "step_id",
  "policy_version"
];

// … plus the approval-intrinsic fields (validated on their own terms).
export const APPROVAL_BOUND_FIELDS = [...APPROVAL_CONTENT_FIELDS, "nonce", "issued_at", "expires_at"];

function approvalSigningPayload(approval) {
  return {
    schema_version: approval.schema_version,
    approval_id: approval.approval_id,
    approver_id: approval.approver_id,
    enhanced: approval.enhanced,
    bound: approval.bound
  };
}

export function signApproval(unsigned, approverSecret) {
  return { ...unsigned, signature: hmacHex(approverSecret, canonicalize(approvalSigningPayload(unsigned))) };
}

function boundStringIsExact(value) {
  return typeof value === "string" && value.length > 0 && !value.includes("*");
}

// Returns { ok: true } or { ok: false, reason_code, detail }.
export function verifyApproval(approval, expectedBound, config, nowMs) {
  if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval must be an object." };
  }

  if (approval.schema_version !== APPROVAL_SCHEMA_VERSION) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Unknown approval schema version." };
  }

  if (!boundStringIsExact(approval.approval_id) || typeof approval.enhanced !== "boolean") {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "approval_id or enhanced flag invalid." };
  }

  const bound = approval.bound;

  if (!bound || typeof bound !== "object" || Array.isArray(bound)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval bound block missing." };
  }

  const boundKeys = Object.keys(bound).sort();
  const expectedKeys = [...APPROVAL_BOUND_FIELDS].sort();

  if (canonicalizeSafe(boundKeys) !== canonicalizeSafe(expectedKeys)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval bound fields incomplete or extended." };
  }

  // Approver identity comes from trusted configuration, never the payload.
  const approver = config.approvers[approval.approver_id];

  if (!approver) {
    return { ok: false, reason_code: "APPROVER_UNKNOWN", detail: "Approver is not in trusted configuration." };
  }

  // Model self-approval: the approver may not be the requesting component.
  if (approval.approver_id === bound.requester_component) {
    return { ok: false, reason_code: "SELF_APPROVAL", detail: "Requester cannot approve its own request." };
  }

  if (approval.enhanced && !approver.enhanced) {
    return { ok: false, reason_code: "APPROVER_NOT_ENHANCED", detail: "Approver lacks enhanced authority." };
  }

  // Signature check before content comparison: a forged approver identity or
  // altered bound block dies here because the HMAC key never leaves config.
  let expectedSignature;

  try {
    expectedSignature = hmacHex(approver.secret, canonicalize(approvalSigningPayload(approval)));
  } catch (error) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval is not canonical: " + error.message };
  }

  if (!timingSafeEqualHex(approval.signature, expectedSignature)) {
    return { ok: false, reason_code: "APPROVAL_SIGNATURE_INVALID", detail: "Approval signature does not verify." };
  }

  // Wildcards and vagueness are refused wholesale.
  for (const field of APPROVAL_BOUND_FIELDS) {
    if (field === "target") continue;

    if (!boundStringIsExact(bound[field])) {
      return { ok: false, reason_code: "APPROVAL_WILDCARD", detail: "Bound field is not exact: " + field };
    }
  }

  if (!isSha256Hex(bound.request_hash) || !isSha256Hex(bound.args_hash)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Bound hashes must be sha256 hex." };
  }

  // Expiry: absolute, and the granted window itself must respect the
  // configured maximum so nobody issues a decade-long approval.
  const issuedAt = Date.parse(bound.issued_at);
  const expiresAt = Date.parse(bound.expires_at);

  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval validity window is invalid." };
  }

  if ((expiresAt - issuedAt) / 1000 > config.approval_max_ttl_seconds) {
    return { ok: false, reason_code: "APPROVAL_TTL_EXCEEDED", detail: "Approval window exceeds configured maximum." };
  }

  if (nowMs >= expiresAt) {
    return { ok: false, reason_code: "APPROVAL_EXPIRED", detail: "Approval has expired." };
  }

  if (nowMs < issuedAt) {
    return { ok: false, reason_code: "APPROVAL_NOT_YET_VALID", detail: "Approval is not yet valid." };
  }

  // Content binding: every bound field must equal the canonical request fact.
  for (const field of APPROVAL_CONTENT_FIELDS) {
    const boundValue = canonicalizeSafe(bound[field]);
    const expectedValue = canonicalizeSafe(expectedBound[field]);

    if (boundValue === null || expectedValue === null || boundValue !== expectedValue) {
      return {
        ok: false,
        reason_code: "APPROVAL_CONTENT_MISMATCH",
        detail: "Approval bound field does not match request: " + field
      };
    }
  }

  return { ok: true, approver_id: approval.approver_id, enhanced: approval.enhanced, nonce: bound.nonce };
}

function canonicalizeSafe(value) {
  try {
    return canonicalize(value);
  } catch {
    return null;
  }
}

// The exact bound facts a valid approval must carry for a given canonical
// request. Everything derives from the request and authority-side state.
export function expectedApprovalBound(request, canonicalRequestHash, policyVersion) {
  return {
    request_hash: canonicalRequestHash,
    requester_component: request.requester.component,
    requester_source_sha: request.requester.source_sha,
    operation: request.operation,
    tool: request.tool,
    mutation_class: request.mutation_class,
    authority_class: request.authority_class,
    evidence_class: request.evidence_class,
    repository: request.repository,
    target: request.target,
    args_hash: hashCanonical(request.args),
    mission_id: request.mission_id,
    plan_id: request.plan_id,
    step_id: request.step_id,
    policy_version: policyVersion
  };
}

export function requiredApprovalCount(authorityClass) {
  // Doctrine: A0/A1 need no approval; A2-A5 need one; A6 needs two distinct
  // enhanced approvers. A5/A6 stay deterministically reachable through this
  // path — nothing else upgrades a decision.
  const rank = authorityRank(authorityClass);

  if (rank <= 1) return 0;
  if (rank <= 5) return 1;
  return 2;
}
