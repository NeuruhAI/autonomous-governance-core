import fs from "node:fs";
import path from "node:path";
import { hashCanonical } from "../src/canonical.mjs";
import { validateTrustConfig } from "../src/trust.mjs";
import { createAuthorizeRuntime, signFounderApproval, scopeKeyFor, FOUNDER_APPROVAL_SCHEMA_VERSION } from "../src/authorize.mjs";
import { signGrant, GRANT_SCHEMA_VERSION } from "../src/grants.mjs";
import { AXON_SHA, T0, freshNonce, iso, makeTrustConfig, tempDir } from "./helpers.mjs";

export { AXON_SHA, T0, freshNonce, iso, tempDir };

export const FOUNDER_SECRET = "founder-secret-0123456789abcdef0";
export const LANE = "lane-t3-governance";

// V2 trust config: the fixture config plus a founder-grade approver who can
// issue grants and founder approvals.
export function makeV2TrustConfig() {
  const config = makeTrustConfig();
  config.approvers.founder = { secret: FOUNDER_SECRET, enhanced: true };
  return config;
}

export function freshAuthorizeRuntime({ mutateConfig, clock } = {}) {
  const config = makeV2TrustConfig();

  if (mutateConfig) mutateConfig(config);

  validateTrustConfig(config);

  const dir = tempDir();
  const receiptsPath = path.join(dir, "authorize-receipts.jsonl");
  const consumptionPath = path.join(dir, "authorize-consumption.jsonl");
  const clockState = clock || { ms: T0 };

  const runtime = createAuthorizeRuntime({
    config,
    receiptsPath,
    consumptionPath,
    now: () => clockState.ms
  });

  return { runtime, config, dir, receiptsPath, consumptionPath, clock: clockState };
}

// A real on-disk proof root (so realpath containment runs against a real fs).
export function makeProofRoot(name = "NEURUH_LIVE_PROOF_20260816") {
  const root = path.join(tempDir(), name);
  fs.mkdirSync(root, { recursive: true });
  return fs.realpathSync(root);
}

export function makeFacts(overrides = {}) {
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "act_" + freshNonce("a").slice(-8),
    lane: LANE,
    component: "axon-gateway",
    source_sha: AXON_SHA,
    action_class: "query",
    summary: "Read Qdrant collection status.",
    target: { type: "service", id: "qdrant" },
    externality: "none",
    reversibility: "reversible",
    blast_radius: "single_target",
    production_effect: "read",
    spend_usd: 0,
    nonce: freshNonce("fact"),
    issued_at: iso(T0 - 1000),
    ...overrides
  };
}

export function makeGrant(overrides = {}, { issuer = "founder", secret = FOUNDER_SECRET } = {}) {
  const unsigned = {
    schema_version: GRANT_SCHEMA_VERSION,
    grant_id: "grant_" + freshNonce("g").slice(-8),
    issuer,
    issued_at: iso(T0 - 3600 * 1000),
    expires_at: iso(T0 + 24 * 3600 * 1000),
    subject: { lane: LANE },
    allowed_repos: ["NeuruhAI/autonomous-governance-core"],
    allowed_paths: [],
    allowed_action_classes: ["artifact_write", "report_write", "alias_repair", "repo_edit", "test_run", "build", "git_commit", "git_push"],
    denied_action_classes: [],
    allowed_services: [],
    production_permission: false,
    external_contact_permission: false,
    spend_ceiling_usd: 0,
    destructive_permission: false,
    rollback_required: false,
    receipt_required: true,
    ...overrides
  };

  return signGrant(unsigned, secret);
}

export function makeFounderApproval(facts, runtime, options = {}) {
  const {
    mode = "once",
    approver = "founder",
    secret = FOUNDER_SECRET,
    riskTier,
    nonce = freshNonce("fapproval"),
    issuedMs = T0 - 1000,
    ttlSeconds = 600,
    sourceSha,
    mutateBound
  } = options;

  const bound = {
    risk_tier: riskTier,
    nonce,
    issued_at: iso(issuedMs),
    expires_at: iso(issuedMs + ttlSeconds * 1000)
  };

  if (mode === "once") {
    bound.facts_hash = hashCanonical(facts);
  } else if (mode === "scope_once") {
    bound.scope_key = scopeKeyFor(facts);
    bound.source_sha = sourceSha === undefined ? facts.source_sha : sourceSha;
  } else {
    bound.scope_key = scopeKeyFor(facts);
  }

  if (mutateBound) mutateBound(bound);

  return signFounderApproval(
    {
      schema_version: FOUNDER_APPROVAL_SCHEMA_VERSION,
      approval_id: freshNonce("faid"),
      approver_id: approver,
      mode,
      bound
    },
    secret
  );
}
