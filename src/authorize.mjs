import { canonicalize, hashCanonical, hmacHex, timingSafeEqualHex, isSha256Hex } from "./canonical.mjs";
import { makeId } from "./id.mjs";
import { appendToChain, openChain } from "./receipts.mjs";
import { consumeNonce, openConsumptionLedger } from "./consumption.mjs";
import { trustConfigFingerprint } from "./trust.mjs";
import {
  ACTION_CLASS_TIERS,
  RISK_TIERS,
  actionFactsErrors,
  classifyRisk,
  featureBranchViolations,
  riskRank
} from "./risk.mjs";
import { grantAdmits, grantQualifiesOperation, verifyGrant } from "./grants.mjs";
import { classifyPathSensitivity, pathLexicalErrors, resolveRealTargetPath } from "./pathscope.mjs";

// The risk-scoped authorization boundary (Governance V2). It governs
// CONSEQUENCE, not syntax:
//
//   R0 observe                  -> allow
//   R1 bounded local reversible -> allow inside a valid FounderGrant, receipted
//   R2 owned feature-branch dev -> allow inside a valid FounderGrant + discipline
//   R3 qualified adoption       -> allow when the grant names the exact
//                                  operation (target, rollback, preflight,
//                                  postflight); otherwise ask the founder ONCE
//   R4 external consequence     -> founder required, approve-once only
//   R5 destructive / privileged -> founder required interactively, every time
//
// Secret-denied roots and path escapes deny outright — no grant, session
// scope or approval evaluated here can admit them. Every outcome is receipted
// on a hash-chained ledger and every facts nonce is one-time-use.

export const AUTHORIZATION_SCHEMA_VERSION = "gov.authorization.v1";
export const FOUNDER_APPROVAL_SCHEMA_VERSION = "gov.founder.approval.v1";
export const AUTHORIZE_DECISIONS = ["allow", "deny", "founder_required"];

// Authority reference for the risk ruleset itself: changes when the
// class->tier mapping changes (the same idiom as policyVersion).
export function riskModelVersion() {
  return hashCanonical({ tiers: RISK_TIERS, action_classes: ACTION_CLASS_TIERS });
}

export function createAuthorizeRuntime({ config, receiptsPath, consumptionPath, now, fsImpl }) {
  if (!config) throw new Error("Authorize runtime requires a validated trust config.");
  if (!receiptsPath) throw new Error("Authorize runtime requires a receipts chain path.");
  if (!consumptionPath) throw new Error("Authorize runtime requires a consumption ledger path.");

  const receipts = openChain(receiptsPath);
  const factsNonces = new Set();

  for (const entry of receipts.entries) {
    // A founder_required outcome is a pending ask, not a terminal decision:
    // its nonce stays spendable so the founder-approved re-presentation of the
    // exact same facts is not mistaken for a replay.
    if (entry.kind === "governance_authorization" && typeof entry.facts_nonce === "string" && entry.decision !== "founder_required") {
      factsNonces.add(entry.facts_nonce);
    }
  }

  return {
    config,
    risk_model_version: riskModelVersion(),
    config_fingerprint: trustConfigFingerprint(config),
    receipts,
    ledger: openConsumptionLedger(consumptionPath),
    factsNonces,
    // Session-scoped founder approvals: scope_key -> { expiresAtMs, approver_id }.
    sessionScopes: new Map(),
    // Idempotent prompts: scope_key -> prompt_id (no repeated identical prompts).
    promptedScopes: new Map(),
    now: now || (() => Date.now()),
    fsImpl
  };
}

// The exact scope a session approval covers: lane + action class + exact
// target coordinates. Anything different is a different scope.
export function scopeKeyFor(facts) {
  return hashCanonical({
    lane: facts.lane,
    action_class: facts.action_class,
    target: facts.target,
    repository: facts.repository ?? null,
    branch: facts.branch ?? null,
    service_label: facts.service_label ?? null
  });
}

function founderApprovalSigningPayload(approval) {
  return {
    schema_version: approval.schema_version,
    approval_id: approval.approval_id,
    approver_id: approval.approver_id,
    mode: approval.mode,
    bound: approval.bound
  };
}

export function signFounderApproval(unsigned, approverSecret) {
  return { ...unsigned, signature: hmacHex(approverSecret, canonicalize(founderApprovalSigningPayload(unsigned))) };
}

const SESSION_SAFE_MAX_RANK = riskRank("R3");

// Verify a founder approval against the expected facts. Returns
// { ok: true, mode, approver_id, nonce } or { ok: false, reason_code, detail }.
export function verifyFounderApproval(approval, expected, config, nowMs) {
  if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Founder approval must be an object." };
  }

  if (approval.schema_version !== FOUNDER_APPROVAL_SCHEMA_VERSION) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Unknown founder approval schema version." };
  }

  if (typeof approval.approval_id !== "string" || approval.approval_id.length === 0) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "approval_id is required." };
  }

  if (approval.mode !== "once" && approval.mode !== "session_scope") {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "mode must be once or session_scope." };
  }

  const bound = approval.bound;

  if (!bound || typeof bound !== "object" || Array.isArray(bound)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval bound block missing." };
  }

  const expectedKeys = [approval.mode === "once" ? "facts_hash" : "scope_key", "risk_tier", "nonce", "issued_at", "expires_at"].sort();

  if (JSON.stringify(Object.keys(bound).sort()) !== JSON.stringify(expectedKeys)) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval bound fields incomplete or extended." };
  }

  const approver = config.approvers[approval.approver_id];

  if (!approver) {
    return { ok: false, reason_code: "APPROVER_UNKNOWN", detail: "Approver is not in trusted configuration." };
  }

  if (!approver.enhanced) {
    return { ok: false, reason_code: "APPROVER_NOT_ENHANCED", detail: "Founder approvals require founder-grade (enhanced) authority." };
  }

  if (approval.approver_id === expected.lane || approval.approver_id === expected.component) {
    return { ok: false, reason_code: "SELF_APPROVAL", detail: "A lane cannot founder-approve its own action." };
  }

  let expectedSignature;

  try {
    expectedSignature = hmacHex(approver.secret, canonicalize(founderApprovalSigningPayload(approval)));
  } catch (error) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval is not canonical: " + error.message };
  }

  if (!timingSafeEqualHex(approval.signature, expectedSignature)) {
    return { ok: false, reason_code: "APPROVAL_SIGNATURE_INVALID", detail: "Approval signature does not verify." };
  }

  if (bound.risk_tier !== expected.risk_tier) {
    return {
      ok: false,
      reason_code: "APPROVAL_RISK_MISMATCH",
      detail: "Approval was issued for risk tier " + String(bound.risk_tier) + " but the classified tier is " + expected.risk_tier + "."
    };
  }

  if (approval.mode === "once") {
    if (!isSha256Hex(bound.facts_hash) || bound.facts_hash !== expected.facts_hash) {
      return { ok: false, reason_code: "APPROVAL_CONTENT_MISMATCH", detail: "Approval is not bound to these exact action facts." };
    }
  } else {
    if (riskRank(expected.risk_tier) > SESSION_SAFE_MAX_RANK) {
      return {
        ok: false,
        reason_code: "SESSION_SCOPE_FORBIDDEN",
        detail: "Session-scoped approval is never valid at " + expected.risk_tier + "; approve once, interactively."
      };
    }

    if (!isSha256Hex(bound.scope_key) || bound.scope_key !== expected.scope_key) {
      return { ok: false, reason_code: "APPROVAL_CONTENT_MISMATCH", detail: "Approval is not bound to this exact scope." };
    }
  }

  if (typeof bound.nonce !== "string" || bound.nonce.length < 16) {
    return { ok: false, reason_code: "APPROVAL_MALFORMED", detail: "Approval nonce is required." };
  }

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

  return { ok: true, mode: approval.mode, approver_id: approval.approver_id, nonce: bound.nonce, expiresAtMs: expiresAt };
}

const WHY_HUMAN = {
  R4: "External consequence (contact, spend, publication, customer or legal effect) always requires the founder.",
  R5: "Destructive or privileged action requires interactive founder approval every time.",
  no_grant: "No valid FounderGrant covers this bounded action; the founder is asked once for this exact scope.",
  grant_expired: "The presented FounderGrant has expired; the founder must re-authorize this scope."
};

function finalize(runtime, facts, factsHash, decision, reasonCode, extra = {}) {
  const nowMs = runtime.now();
  const raw = (field) => (facts && typeof facts === "object" && !Array.isArray(facts) ? facts[field] : undefined) ?? null;

  // Echoed caller fields must never make the envelope uncanonical.
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

  const envelope = {
    schema_version: AUTHORIZATION_SCHEMA_VERSION,
    authorization_id: extra.authorization_id || makeId("auth"),
    action_id: get("action_id"),
    lane: get("lane"),
    component: get("component"),
    action_class: get("action_class"),
    target: get("target"),
    repository: get("repository"),
    branch: get("branch"),
    service_label: get("service_label"),
    summary: get("summary"),
    risk_tier: extra.risk_tier || null,
    risk_factors: extra.risk_factors || [],
    risk_model_version: runtime.risk_model_version,
    decision,
    reason_code: reasonCode,
    reasons: safeReasons,
    grant_id: extra.grant_id || null,
    grant_expires_at: extra.grant_expires_at || null,
    approver_ids: extra.approver_ids || [],
    session_scope_used: extra.session_scope_used === true,
    scope_key: extra.scope_key || null,
    founder_prompt: extra.founder_prompt || null,
    canonical_facts_hash: factsHash,
    facts_nonce: get("nonce"),
    issued_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + runtime.config.decision_ttl_seconds * 1000).toISOString(),
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
    receipt = appendToChain(runtime.receipts, { kind: "governance_authorization", ...envelope });
  } catch (error) {
    if (typeof envelope.facts_nonce === "string") {
      runtime.factsNonces.add(envelope.facts_nonce);
    }

    const denied = {
      ...envelope,
      decision: "deny",
      reason_code: reasonCode === "RECEIPT_CHAIN_POISONED" ? reasonCode : "RECEIPT_PERSISTENCE_FAILED",
      reasons: ["Authorization receipt could not be persisted; failing closed.", error.message],
      founder_prompt: null
    };

    delete denied.decision_hash;
    denied.decision_hash = hashCanonical(denied);

    return { ...denied, decision_receipt_hash: null, receipt_seq: null };
  }

  if (typeof envelope.facts_nonce === "string" && decision !== "founder_required") {
    runtime.factsNonces.add(envelope.facts_nonce);
  }

  return { ...envelope, decision_receipt_hash: receipt.entry_hash, receipt_seq: receipt.seq };
}

export function authorizeAction(runtime, facts, { grant, founder_approval } = {}) {
  if (!runtime || !runtime.config) {
    throw new Error("Authorize runtime is not configured.");
  }

  const deny = (reasonCode, factsHash, reasons, extra = {}) =>
    finalize(runtime, facts, factsHash, "deny", reasonCode, { ...extra, reasons });

  if (runtime.receipts.poisoned) {
    return deny("RECEIPT_CHAIN_POISONED", null, [runtime.receipts.poison_reason]);
  }

  let factsHash = null;

  try {
    factsHash = hashCanonical(facts);
  } catch (error) {
    return deny("CANONICALIZATION_FAILED", null, [error.message]);
  }

  const errors = actionFactsErrors(facts);

  if (errors.length) {
    return deny("MALFORMED_FACTS", factsHash, errors);
  }

  const config = runtime.config;
  const nowMs = runtime.now();

  const issuedAtMs = Date.parse(facts.issued_at);

  if (!Number.isFinite(issuedAtMs) || issuedAtMs > nowMs + 60_000) {
    return deny("FACTS_TIME_INVALID", factsHash, ["Facts issued_at is unparseable or in the future."]);
  }

  if (nowMs - issuedAtMs > config.request_max_age_seconds * 1000) {
    return deny("FACTS_EXPIRED", factsHash, ["Facts are older than the accepted window."]);
  }

  if (runtime.factsNonces.has(facts.nonce)) {
    return deny("NONCE_REPLAYED", factsHash, ["Facts nonce was already decided."]);
  }

  // ---- Path enforcement: lexical canonical form, then resolved sensitivity.
  let pathSensitivity = "normal";

  if (facts.target.type === "path") {
    const lexical = pathLexicalErrors(facts.target.id);

    if (lexical.length) {
      const escape = lexical.some((message) => /\.\.|empty segments/.test(message));
      return deny(escape ? "PATH_ESCAPE" : "TARGET_AMBIGUOUS", factsHash, lexical);
    }

    const lexicalSensitivity = classifyPathSensitivity(facts.target.id);
    pathSensitivity = lexicalSensitivity.sensitivity;

    const resolution = resolveRealTargetPath(facts.target.id, runtime.fsImpl);

    if (!resolution.ok) {
      return deny("PATH_ESCAPE", factsHash, [resolution.error]);
    }

    const resolvedSensitivity = classifyPathSensitivity(resolution.resolved);

    if (resolvedSensitivity.sensitivity === "secret" || pathSensitivity === "secret") {
      // Canonical policy: secret material is a blocked domain. No grant or
      // approval evaluated here can admit it.
      return deny("SECRET_ROOT_DENIED", factsHash, [
        (resolvedSensitivity.detail || lexicalSensitivity.detail) ?? "secret-denied root.",
        "Secret-denied roots are blocked by canonical policy (credential_exposure / secret_handling)."
      ]);
    }

    if (resolvedSensitivity.sensitivity === "governance_canonical") {
      pathSensitivity = "governance_canonical";
    }
  }

  if (facts.target.id.includes("*") || facts.target.type.includes("*")) {
    return deny("TARGET_AMBIGUOUS", factsHash, ["Wildcard targets are refused."]);
  }

  if (facts.secret_access === true) {
    return deny("SECRET_ROOT_DENIED", factsHash, ["Declared secret access is blocked by canonical policy."]);
  }

  // ---- Consequence classification (worst factor wins; never de-escalates).
  const risk = classifyRisk(facts, { pathSensitivity });
  const scopeKey = scopeKeyFor(facts);

  const base = {
    risk_tier: risk.tier,
    risk_factors: risk.factors,
    scope_key: scopeKey
  };

  const allow = (reasonCode, extra = {}) =>
    finalize(runtime, facts, factsHash, "allow", reasonCode, { ...base, ...extra });

  // R0 — OBSERVE: auto-allow, receipted.
  if (risk.tier === "R0") {
    return allow("AUTO_ALLOW_OBSERVE", { reasons: risk.factors });
  }

  // ---- Grant evaluation (R1–R3 only; R4/R5 are never grant-satisfiable).
  let grantContext = { grant_id: null, grant_expires_at: null };
  let grantMissReasons = [];
  let grantExpired = false;
  let verifiedGrant = null;

  if (grant !== undefined && grant !== null) {
    const verification = verifyGrant(grant, config, nowMs);

    if (!verification.ok) {
      if (verification.reason_code === "GRANT_EXPIRED" || verification.reason_code === "GRANT_NOT_YET_VALID") {
        grantExpired = true;
        grantMissReasons.push(verification.detail);
        grantContext = {
          grant_id: typeof grant.grant_id === "string" ? grant.grant_id : null,
          grant_expires_at: typeof grant.expires_at === "string" ? grant.expires_at : null
        };
      } else {
        return deny(verification.reason_code, factsHash, [verification.detail], base);
      }
    } else {
      verifiedGrant = verification.grant;
      grantContext = { grant_id: verifiedGrant.grant_id, grant_expires_at: verifiedGrant.expires_at };
    }
  }

  if (verifiedGrant && riskRank(risk.tier) <= riskRank("R3")) {
    const admission = grantAdmits(verifiedGrant, facts, { fsImpl: runtime.fsImpl });

    if (!admission.ok && admission.hostile) {
      return deny(admission.reason_code, factsHash, [admission.detail], { ...base, ...grantContext });
    }

    if (admission.ok) {
      if (risk.tier === "R1") {
        return allow("GRANT_BOUNDED_LOCAL", { ...grantContext, reasons: risk.factors, approver_ids: [verifiedGrant.issuer] });
      }

      if (risk.tier === "R2") {
        const violations = featureBranchViolations(facts);

        if (violations.length === 0) {
          return allow("GRANT_BOUNDED_DEVELOPMENT", { ...grantContext, reasons: risk.factors, approver_ids: [verifiedGrant.issuer] });
        }

        grantMissReasons.push(...violations);
      }

      if (risk.tier === "R3") {
        const qualification = grantQualifiesOperation(verifiedGrant, facts);

        if (qualification.ok) {
          return allow("GRANT_QUALIFIED_ADOPTION", {
            ...grantContext,
            reasons: [
              ...risk.factors,
              "Grant qualifies this exact operation: rollback=" + qualification.operation.rollback +
                ", preflight=" + qualification.operation.preflight +
                ", postflight=" + qualification.operation.postflight + "."
            ],
            approver_ids: [verifiedGrant.issuer]
          });
        }

        grantMissReasons.push(qualification.detail);
      }
    } else {
      grantMissReasons.push(admission.detail);
    }
  }

  // ---- Founder path: presented approval, then session scope, then prompt.
  const expected = {
    facts_hash: factsHash,
    scope_key: scopeKey,
    risk_tier: risk.tier,
    lane: facts.lane,
    component: facts.component
  };

  if (founder_approval !== undefined && founder_approval !== null) {
    const result = verifyFounderApproval(founder_approval, expected, config, nowMs);

    if (!result.ok) {
      return deny(result.reason_code, factsHash, [result.detail], { ...base, ...grantContext });
    }

    const consumption = consumeNonce(runtime.ledger, {
      nonce: result.nonce,
      scope: "founder_approval",
      decision_id: null,
      request_hash: factsHash,
      consumed_at: new Date(nowMs).toISOString()
    });

    if (!consumption.ok) {
      return deny(consumption.reason_code, factsHash, ["Founder approval nonce could not be atomically consumed."], { ...base, ...grantContext });
    }

    const consumptionRef = {
      kind: "founder_approval_consumption",
      approver_id: result.approver_id,
      nonce: result.nonce,
      entry_hash: consumption.entry.entry_hash,
      seq: consumption.entry.seq
    };

    if (result.mode === "session_scope") {
      runtime.sessionScopes.set(scopeKey, { expiresAtMs: result.expiresAtMs, approver_id: result.approver_id });
      runtime.promptedScopes.delete(scopeKey);

      return allow("SESSION_SCOPE_APPROVED", {
        ...grantContext,
        reasons: [...risk.factors, "Founder approved this exact scope for the session (until " + new Date(result.expiresAtMs).toISOString() + ")."],
        approver_ids: [result.approver_id],
        session_scope_used: true,
        evidence_refs: [consumptionRef]
      });
    }

    runtime.promptedScopes.delete(scopeKey);

    return allow("FOUNDER_APPROVED_ONCE", {
      ...grantContext,
      reasons: risk.factors,
      approver_ids: [result.approver_id],
      evidence_refs: [consumptionRef]
    });
  }

  if (riskRank(risk.tier) <= SESSION_SAFE_MAX_RANK) {
    const session = runtime.sessionScopes.get(scopeKey);

    if (session && nowMs < session.expiresAtMs) {
      return allow("SESSION_SCOPE_ACTIVE", {
        ...grantContext,
        reasons: [...risk.factors, "Scope was founder-approved for this session; not re-prompting."],
        approver_ids: [session.approver_id],
        session_scope_used: true
      });
    }
  }

  // ---- One concise founder prompt. Identical scope never prompts twice.
  const alreadyPrompted = runtime.promptedScopes.has(scopeKey);
  const promptId = alreadyPrompted ? runtime.promptedScopes.get(scopeKey) : makeId("prompt");

  if (!alreadyPrompted) {
    runtime.promptedScopes.set(scopeKey, promptId);
  }

  let reasonCode = "FOUNDER_REQUIRED_NO_GRANT";
  let why = WHY_HUMAN.no_grant;

  if (risk.tier === "R5") {
    reasonCode = "FOUNDER_REQUIRED_DESTRUCTIVE";
    why = WHY_HUMAN.R5;
  } else if (risk.tier === "R4") {
    reasonCode = "FOUNDER_REQUIRED_EXTERNAL";
    why = WHY_HUMAN.R4;
  } else if (grantExpired) {
    reasonCode = "GRANT_EXPIRED";
    why = WHY_HUMAN.grant_expired;
  }

  const founderPrompt = {
    prompt_id: promptId,
    already_prompted: alreadyPrompted,
    action: facts.action_class + ": " + facts.summary,
    target: facts.target.type + ":" + facts.target.id,
    risk: risk.tier,
    why_human_required: why,
    rollback: typeof facts.rollback_plan === "string" ? facts.rollback_plan : facts.reversibility,
    spend_usd: facts.spend_usd,
    contact: facts.externality,
    production_effect: facts.production_effect,
    grant_expiry: grantContext.grant_expires_at,
    approve_once: true,
    approve_scope_session: riskRank(risk.tier) <= SESSION_SAFE_MAX_RANK,
    scope_key: scopeKey
  };

  return finalize(runtime, facts, factsHash, "founder_required", reasonCode, {
    ...base,
    ...grantContext,
    reasons: [why, ...risk.factors, ...grantMissReasons],
    founder_prompt: founderPrompt
  });
}
