import { canonicalize, hashCanonical, isSha256Hex, targetPathErrors } from "./canonical.mjs";
import { makeId } from "./id.mjs";
import { appendToChain, openChain } from "./receipts.mjs";
import { consumeNonce, openConsumptionLedger } from "./consumption.mjs";
import { expectedApprovalBound, requiredApprovalCount, verifyApproval } from "./approval.mjs";
import {
  AUTHORITY_CLASSES,
  EVIDENCE_CLASSES,
  MUTATION_CLASSES,
  authorityRank,
  trustConfigFingerprint
} from "./trust.mjs";
import { defaultPolicy, policyVersion } from "./policy.mjs";
import { scoreAction } from "./evaluator.mjs";

// The canonical decision boundary. Every gate that cannot positively verify
// its condition DENIES: identity, source SHA, policy version, capability,
// authority, target exactness, freshness, replay, approval content binding,
// one-time consumption and receipt persistence. Governance decides; AXON
// executes — no receipt written here ever claims execution.

export const DECISION_SCHEMA_VERSION = "gov.decision.v1";
export const REQUEST_SCHEMA_VERSION = "gov.decision.request.v1";
export const DECISIONS = ["allow", "deny", "escalate", "approval_required"];

const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

const REQUEST_STRING_FIELDS = [
  "schema_version",
  "request_id",
  "mission_id",
  "plan_id",
  "step_id",
  "correlation_id",
  "causation_id",
  "authority_class",
  "operation",
  "tool",
  "mutation_class",
  "evidence_class",
  "repository",
  "domain",
  "summary",
  "requested_capability",
  "policy_version",
  "precondition_hash",
  "nonce",
  "issued_at"
];

const REQUEST_ALL_FIELDS = [...REQUEST_STRING_FIELDS, "requester", "target", "args", "tags", "spend_usd"];

export function requestErrors(request) {
  const errors = [];

  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return ["Request must be a JSON object."];
  }

  for (const field of REQUEST_STRING_FIELDS) {
    if (typeof request[field] !== "string" || request[field].length === 0) {
      errors.push(field + " is required and must be a non-empty string.");
    }
  }

  for (const key of Object.keys(request)) {
    if (!REQUEST_ALL_FIELDS.includes(key)) {
      errors.push("Unknown request field: " + key);
    }
  }

  const requester = request.requester;

  if (!requester || typeof requester !== "object" || Array.isArray(requester)) {
    errors.push("requester must be an object.");
  } else {
    if (typeof requester.component !== "string" || requester.component.length === 0) {
      errors.push("requester.component is required.");
    }
    if (typeof requester.source_sha !== "string" || requester.source_sha.length < 7) {
      errors.push("requester.source_sha is required.");
    }
    for (const key of Object.keys(requester)) {
      if (key !== "component" && key !== "source_sha") {
        errors.push("Unknown requester field: " + key);
      }
    }
  }

  const target = request.target;

  if (!target || typeof target !== "object" || Array.isArray(target)) {
    errors.push("target must be an object.");
  } else {
    if (typeof target.type !== "string" || target.type.length === 0) {
      errors.push("target.type is required.");
    }
    if (typeof target.id !== "string" || target.id.length === 0) {
      errors.push("target.id is required.");
    }
    for (const key of Object.keys(target)) {
      if (key !== "type" && key !== "id") {
        errors.push("Unknown target field: " + key);
      }
    }
  }

  if (!request.args || typeof request.args !== "object" || Array.isArray(request.args)) {
    errors.push("args must be an object (use {} for no arguments).");
  }

  if (request.tags !== undefined && (!Array.isArray(request.tags) || !request.tags.every((tag) => typeof tag === "string"))) {
    errors.push("tags must be an array of strings when provided.");
  }

  if (request.spend_usd !== undefined && typeof request.spend_usd !== "number") {
    errors.push("spend_usd must be a number when provided.");
  }

  if (request.schema_version !== undefined && request.schema_version !== REQUEST_SCHEMA_VERSION) {
    errors.push("Unknown request schema_version.");
  }

  if (typeof request.authority_class === "string" && !AUTHORITY_CLASSES.includes(request.authority_class)) {
    errors.push("Unknown authority_class.");
  }

  if (typeof request.mutation_class === "string" && !MUTATION_CLASSES.includes(request.mutation_class)) {
    errors.push("Unknown mutation_class.");
  }

  if (typeof request.evidence_class === "string" && !EVIDENCE_CLASSES.includes(request.evidence_class)) {
    errors.push("Unknown evidence_class.");
  }

  if (typeof request.precondition_hash === "string" && !isSha256Hex(request.precondition_hash)) {
    errors.push("precondition_hash must be sha256 hex.");
  }

  if (typeof request.nonce === "string" && !NONCE_PATTERN.test(request.nonce)) {
    errors.push("nonce must be 16-128 url-safe characters.");
  }

  return errors;
}

export function createDecisionRuntime({ config, receiptsPath, consumptionPath, now }) {
  if (!config) throw new Error("Decision runtime requires a validated trust config.");
  if (!receiptsPath) throw new Error("Decision runtime requires a receipts chain path.");
  if (!consumptionPath) throw new Error("Decision runtime requires a consumption ledger path.");

  const policy = defaultPolicy();
  const receipts = openChain(receiptsPath);
  const requestNonces = new Set();

  for (const entry of receipts.entries) {
    if (entry.kind === "governance_decision" && typeof entry.request_nonce === "string") {
      requestNonces.add(entry.request_nonce);
    }
  }

  return {
    config,
    policy,
    policy_version: policyVersion(policy),
    config_fingerprint: trustConfigFingerprint(config),
    receipts,
    ledger: openConsumptionLedger(consumptionPath),
    requestNonces,
    now: now || (() => Date.now())
  };
}

function finalize(runtime, request, requestHash, decision, reasonCode, extra = {}) {
  const nowMs = runtime.now();
  const raw = (field) => (request && typeof request === "object" && !Array.isArray(request) ? request[field] : undefined) ?? null;

  // Echoed caller fields must never make the envelope itself uncanonical: an
  // uncanonical value is replaced by null (its rejection is already the reason
  // for the decision when it matters).
  const get = (field) => {
    const value = raw(field);

    try {
      canonicalize(value);
      return value;
    } catch {
      return null;
    }
  };

  const safeReasons = (extra.reasons || []).map((reason) => {
    try {
      canonicalize(reason);
      return reason;
    } catch {
      return "UNCANONICAL_REASON_TEXT";
    }
  });

  const requester = get("requester");

  let argsHash = null;

  try {
    argsHash = raw("args") === null ? null : hashCanonical(raw("args"));
  } catch {
    argsHash = null;
  }

  const envelope = {
    schema_version: DECISION_SCHEMA_VERSION,
    decision_id: extra.decision_id || makeId("dec"),
    request_id: get("request_id"),
    mission_id: get("mission_id"),
    plan_id: get("plan_id"),
    step_id: get("step_id"),
    correlation_id: get("correlation_id"),
    causation_id: get("causation_id"),
    requester_component: requester && typeof requester === "object" ? requester.component ?? null : null,
    requester_source_sha: requester && typeof requester === "object" ? requester.source_sha ?? null : null,
    policy_id: runtime.policy.policy_id,
    policy_version: runtime.policy_version,
    authority_class: get("authority_class"),
    operation: get("operation"),
    tool: get("tool"),
    mutation_class: get("mutation_class"),
    evidence_class: get("evidence_class"),
    repository: get("repository"),
    target: get("target"),
    canonical_args_hash: argsHash,
    canonical_request_hash: requestHash,
    precondition_hash: get("precondition_hash"),
    requested_capability: get("requested_capability"),
    decision,
    reason_code: reasonCode,
    reasons: safeReasons,
    approver_ids: extra.approver_ids || [],
    issued_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + runtime.config.decision_ttl_seconds * 1000).toISOString(),
    request_nonce: get("nonce"),
    decision_nonce: makeId("dnonce"),
    one_time_use: {
      request_nonce_recorded: typeof get("nonce") === "string",
      approvals_consumed: extra.approvals_consumed || []
    },
    evidence_refs: [
      { kind: "trust_config_fingerprint", value: runtime.config_fingerprint },
      { kind: "implementation_sha", value: runtime.config.implementation_sha },
      ...(extra.evidence_refs || [])
    ],
    execution: "NOT_CLAIMED_BY_GOVERNANCE"
  };

  envelope.decision_hash = hashCanonical(envelope);

  let receipt = null;

  try {
    receipt = appendToChain(runtime.receipts, { kind: "governance_decision", ...envelope });
  } catch (error) {
    if (typeof envelope.request_nonce === "string") {
      runtime.requestNonces.add(envelope.request_nonce);
    }

    const denied = {
      ...envelope,
      decision: "deny",
      // A deny that was already about the receipt layer keeps its more
      // specific reason (e.g. RECEIPT_CHAIN_POISONED).
      reason_code: reasonCode === "RECEIPT_CHAIN_POISONED" ? reasonCode : "RECEIPT_PERSISTENCE_FAILED",
      reasons: ["Decision receipt could not be persisted; failing closed.", error.message]
    };

    delete denied.decision_hash;
    denied.decision_hash = hashCanonical(denied);

    return { ...denied, decision_receipt_hash: null, receipt_seq: null };
  }

  if (typeof envelope.request_nonce === "string") {
    runtime.requestNonces.add(envelope.request_nonce);
  }

  return { ...envelope, decision_receipt_hash: receipt.entry_hash, receipt_seq: receipt.seq };
}

export function decideRequest(runtime, request, approvals = []) {
  const deny = (reasonCode, requestHash, reasons) =>
    finalize(runtime, request, requestHash, "deny", reasonCode, { reasons });

  if (!runtime || !runtime.config) {
    throw new Error("Decision runtime is not configured.");
  }

  if (runtime.receipts.poisoned) {
    return deny("RECEIPT_CHAIN_POISONED", null, [runtime.receipts.poison_reason]);
  }

  // Canonicalize first: the hash must cover every caller-controlled field or
  // not exist at all.
  let requestHash = null;

  try {
    requestHash = hashCanonical(request);
  } catch (error) {
    return deny("CANONICALIZATION_FAILED", null, [error.message]);
  }

  const errors = requestErrors(request);

  if (errors.length) {
    return deny("MALFORMED_REQUEST", requestHash, errors);
  }

  if (!Array.isArray(approvals)) {
    return deny("APPROVAL_MALFORMED", requestHash, ["approvals must be an array."]);
  }

  const config = runtime.config;
  const nowMs = runtime.now();

  // Identity: the component must be registered and its source SHA pinned.
  const component = config.components[request.requester.component];

  if (!component) {
    return deny("IDENTITY_UNKNOWN", requestHash, ["Requesting component is not registered."]);
  }

  const pinnedShas = config.expected_source_shas[request.requester.component] || [];

  if (!pinnedShas.includes(request.requester.source_sha)) {
    return deny("SOURCE_SHA_MISMATCH", requestHash, ["Requester source SHA is not the pinned SHA."]);
  }

  // Policy is selected by Governance, never by the requester; the requester
  // states which version it believes applies and must be exactly right.
  if (request.policy_version !== runtime.policy_version) {
    return deny("POLICY_VERSION_MISMATCH", requestHash, ["Requested policy version is not the applied policy version."]);
  }

  if (request.evidence_class !== config.runtime.mode) {
    return deny("EVIDENCE_CLASS_MISMATCH", requestHash, ["Request evidence class does not match runtime mode."]);
  }

  const tool = config.tools[request.tool];

  if (!tool) {
    return deny("TOOL_UNKNOWN", requestHash, ["Tool is not in the trusted capability map."]);
  }

  const operation = tool.operations[request.operation];

  if (!operation) {
    return deny("OPERATION_UNKNOWN", requestHash, ["Operation is not declared for this tool."]);
  }

  if (request.mutation_class !== operation.mutation_class) {
    return deny("MUTATION_CLASS_MISMATCH", requestHash, ["Declared mutation class does not match the trusted classification."]);
  }

  if (request.requested_capability !== operation.capability) {
    return deny("CAPABILITY_MISMATCH", requestHash, ["Requested capability does not match the operation capability."]);
  }

  const requestRank = authorityRank(request.authority_class);

  if (requestRank > authorityRank(component.max_authority_class)) {
    return deny("AUTHORITY_EXCEEDED", requestHash, ["Component claimed a stronger authority class than trusted configuration grants."]);
  }

  if (requestRank < authorityRank(operation.min_authority_class)) {
    return deny("AUTHORITY_INSUFFICIENT", requestHash, ["Operation requires a stronger authority class."]);
  }

  if (!component.capabilities.includes(request.requested_capability)) {
    return deny("CAPABILITY_EXCEEDED", requestHash, ["Component is not granted the requested capability."]);
  }

  if (Array.isArray(operation.repositories) && !operation.repositories.includes(request.repository)) {
    return deny("REPOSITORY_MISMATCH", requestHash, ["Repository is not authorized for this operation."]);
  }

  // Purpose pinning: when the trusted operation declares admitted domains or
  // targets, anything outside them is an altered decision purpose — deny.
  if (Array.isArray(operation.domains) && !operation.domains.includes(request.domain)) {
    return deny("DOMAIN_MISMATCH", requestHash, ["Domain is not admitted for this operation."]);
  }

  if (Array.isArray(operation.targets) && !operation.targets.some((admitted) => admitted.type === request.target.type && admitted.id === request.target.id)) {
    return deny("TARGET_NOT_ADMITTED", requestHash, ["Target is not admitted for this operation."]);
  }

  if (request.target.id.includes("*") || request.target.type.includes("*")) {
    return deny("TARGET_AMBIGUOUS", requestHash, ["Wildcard targets are refused."]);
  }

  if (request.target.type === "path") {
    const pathErrors = targetPathErrors(request.target.id);

    if (pathErrors.length) {
      return deny("TARGET_AMBIGUOUS", requestHash, pathErrors);
    }
  }

  const issuedAtMs = Date.parse(request.issued_at);

  if (!Number.isFinite(issuedAtMs) || issuedAtMs > nowMs + 60_000) {
    return deny("REQUEST_TIME_INVALID", requestHash, ["Request issued_at is unparseable or in the future."]);
  }

  if (nowMs - issuedAtMs > config.request_max_age_seconds * 1000) {
    return deny("REQUEST_EXPIRED", requestHash, ["Request is older than the accepted window."]);
  }

  if (runtime.requestNonces.has(request.nonce)) {
    return deny("NONCE_REPLAYED", requestHash, ["Request nonce was already decided."]);
  }

  // Mutation seal: live mutation is not ratified, no approval overrides it.
  if (request.evidence_class === "live" && request.mutation_class !== "read_only" && config.runtime.mutation_ratified !== true) {
    return deny("MUTATION_PATH_NOT_RATIFIED", requestHash, ["Live mutation is not ratified; denying regardless of approvals."]);
  }

  // Policy opinion via the ratified scoring semantics.
  const policyOutcome = scoreAction(
    {
      action_id: request.request_id,
      actor: request.requester.component,
      tool: request.tool,
      domain: request.domain,
      tags: request.tags,
      spend_usd: request.spend_usd,
      summary: request.summary
    },
    runtime.policy
  );

  if (policyOutcome.decision === "block") {
    return deny("POLICY_BLOCKED", requestHash, policyOutcome.reasons);
  }

  const needed = requiredApprovalCount(request.authority_class);

  if (needed === 0) {
    if (policyOutcome.decision === "escalate") {
      return finalize(runtime, request, requestHash, "escalate", "ESCALATION_REQUIRED", {
        reasons: policyOutcome.reasons
      });
    }

    return finalize(runtime, request, requestHash, "allow", "POLICY_ALLOW", {
      reasons: policyOutcome.reasons
    });
  }

  if (approvals.length === 0) {
    return finalize(runtime, request, requestHash, "approval_required", "APPROVAL_REQUIRED", {
      reasons: [
        "Authority class " + request.authority_class + " requires " + needed + " content-bound approval(s).",
        ...policyOutcome.reasons
      ]
    });
  }

  if (approvals.length > needed) {
    return deny("APPROVAL_SURPLUS", requestHash, ["More approvals than required were presented; refusing ambiguous consumption."]);
  }

  const expectedBound = expectedApprovalBound(request, requestHash, runtime.policy_version);
  const verified = [];
  const seenApprovers = new Set();

  for (const approval of approvals) {
    const result = verifyApproval(approval, expectedBound, config, nowMs);

    if (!result.ok) {
      return deny(result.reason_code, requestHash, [result.detail]);
    }

    if (needed >= 2 && !result.enhanced) {
      return deny("APPROVAL_NOT_ENHANCED", requestHash, ["Authority class " + request.authority_class + " requires enhanced approvals."]);
    }

    if (seenApprovers.has(result.approver_id)) {
      return deny("APPROVAL_DUPLICATE_APPROVER", requestHash, ["Each approval must come from a distinct approver."]);
    }

    seenApprovers.add(result.approver_id);
    verified.push(result);
  }

  if (verified.length < needed) {
    return finalize(runtime, request, requestHash, "approval_required", "APPROVAL_QUORUM_INCOMPLETE", {
      reasons: ["Valid approvals: " + verified.length + " of " + needed + " required."],
      approver_ids: verified.map((approvalResult) => approvalResult.approver_id)
    });
  }

  // One-time consumption before the allow is issued; a consumed or uncertain
  // nonce can never be spent again.
  const decisionId = makeId("dec");
  const consumptionRefs = [];

  for (const approvalResult of verified) {
    const consumption = consumeNonce(runtime.ledger, {
      nonce: approvalResult.nonce,
      scope: "approval",
      decision_id: decisionId,
      request_hash: requestHash,
      consumed_at: new Date(nowMs).toISOString()
    });

    if (!consumption.ok) {
      return deny(consumption.reason_code, requestHash, ["Approval nonce could not be atomically consumed."]);
    }

    consumptionRefs.push({
      kind: "approval_consumption",
      approver_id: approvalResult.approver_id,
      nonce: approvalResult.nonce,
      entry_hash: consumption.entry.entry_hash,
      seq: consumption.entry.seq
    });
  }

  return finalize(runtime, request, requestHash, "allow", "APPROVED_CONTENT_BOUND", {
    decision_id: decisionId,
    reasons: policyOutcome.reasons,
    approver_ids: verified.map((approvalResult) => approvalResult.approver_id),
    approvals_consumed: consumptionRefs,
    evidence_refs: consumptionRefs
  });
}

export function decisionIsExpired(envelope, nowMs) {
  const expires = Date.parse(envelope && envelope.expires_at);
  return !Number.isFinite(expires) || nowMs >= expires;
}
