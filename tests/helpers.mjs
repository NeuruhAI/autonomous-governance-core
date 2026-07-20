import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { hashCanonical, sha256Hex } from "../src/canonical.mjs";
import { expectedApprovalBound, signApproval, APPROVAL_SCHEMA_VERSION } from "../src/approval.mjs";
import { createDecisionRuntime } from "../src/decision.mjs";
import { validateTrustConfig } from "../src/trust.mjs";
import { defaultPolicy, policyVersion } from "../src/policy.mjs";

export const T0 = Date.parse("2026-07-20T12:00:00.000Z");

export const AXON_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
export const AXON_SHA_ALT = "ffe2c3d4e5f60718293a4b5c6d7e8f9012345678";
export const RECIPE_SHA = "b2c3d4e5f60718293a4b5c6d7e8f9012345678a1";
export const OBSERVER_SHA = "c3d4e5f60718293a4b5c6d7e8f9012345678a1b2";
export const MODEL_SHA = "d4e5f60718293a4b5c6d7e8f9012345678a1b2c3";

export const SECRETS = {
  "owner-a": "owner-a-secret-0123456789abcdef",
  "owner-b": "owner-b-secret-0123456789abcdef",
  "reviewer-c": "reviewer-c-secret-0123456789abcd",
  "model-x": "model-x-secret-0123456789abcdef0"
};

export const POLICY_VERSION = policyVersion(defaultPolicy());

let nonceCounter = 0;

export function freshNonce(prefix = "nonce") {
  nonceCounter += 1;
  return prefix + "-" + String(nonceCounter).padStart(12, "0");
}

export function iso(ms) {
  return new Date(ms).toISOString();
}

export function makeTrustConfig() {
  return {
    config_version: "gov.trust.v1",
    implementation_sha: "0000000000000000000000000000000000000000",
    expected_source_shas: {
      "axon-gateway": [AXON_SHA, AXON_SHA_ALT],
      "recipe-engine-runtime": [RECIPE_SHA],
      observer: [OBSERVER_SHA],
      "model-x": [MODEL_SHA]
    },
    approvers: {
      "owner-a": { secret: SECRETS["owner-a"], enhanced: true },
      "owner-b": { secret: SECRETS["owner-b"], enhanced: true },
      "reviewer-c": { secret: SECRETS["reviewer-c"], enhanced: false },
      "model-x": { secret: SECRETS["model-x"], enhanced: false }
    },
    components: {
      "axon-gateway": { capabilities: ["read", "write"], max_authority_class: "A5" },
      "recipe-engine-runtime": { capabilities: ["read", "write"], max_authority_class: "A6" },
      observer: { capabilities: ["read"], max_authority_class: "A1" },
      "model-x": { capabilities: ["read", "write"], max_authority_class: "A5" }
    },
    tools: {
      fs: {
        operations: {
          read_file: { mutation_class: "read_only", capability: "read", min_authority_class: "A0" },
          write_file: {
            mutation_class: "persistent_write",
            capability: "write",
            min_authority_class: "A4",
            repositories: ["NeuruhAI/autonomous-governance-core"]
          }
        }
      },
      git: {
        operations: {
          push_branch: { mutation_class: "persistent_write", capability: "write", min_authority_class: "A5" },
          purge_history: { mutation_class: "destructive", capability: "write", min_authority_class: "A6" }
        }
      }
    },
    approval_max_ttl_seconds: 900,
    request_max_age_seconds: 300,
    decision_ttl_seconds: 300,
    runtime: { mode: "fixture", mutation_ratified: false }
  };
}

export function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "gov-up2-"));
}

// Runtime with an injectable clock. mutateConfig may adjust the fixture trust
// config before validation.
export function freshRuntime({ mutateConfig, clock } = {}) {
  const config = makeTrustConfig();

  if (mutateConfig) mutateConfig(config);

  validateTrustConfig(config);

  const dir = tempDir();
  const receiptsPath = path.join(dir, "receipts.jsonl");
  const consumptionPath = path.join(dir, "consumption.jsonl");
  const clockState = clock || { ms: T0 };

  const runtime = createDecisionRuntime({
    config,
    receiptsPath,
    consumptionPath,
    now: () => clockState.ms
  });

  return { runtime, config, dir, receiptsPath, consumptionPath, clock: clockState };
}

export function makeRequest(overrides = {}) {
  return {
    schema_version: "gov.decision.request.v1",
    request_id: "req_0001",
    mission_id: "mis_0001",
    plan_id: "plan_0001",
    step_id: "step_0001",
    correlation_id: "corr_0001",
    causation_id: "cause_0001",
    requester: { component: "axon-gateway", source_sha: AXON_SHA },
    authority_class: "A0",
    operation: "read_file",
    tool: "fs",
    mutation_class: "read_only",
    evidence_class: "fixture",
    repository: "NeuruhAI/autonomous-governance-core",
    domain: "engineering_ops",
    summary: "Read a governed file.",
    target: { type: "path", id: "/repo/docs/file.md" },
    args: { encoding: "utf8" },
    requested_capability: "read",
    policy_version: POLICY_VERSION,
    precondition_hash: sha256Hex("precondition-evidence"),
    nonce: freshNonce("req"),
    issued_at: iso(T0 - 1000),
    ...overrides
  };
}

// A valid A5 mutation request (fixture evidence class).
export function makeA5Request(overrides = {}) {
  return makeRequest({
    authority_class: "A5",
    operation: "push_branch",
    tool: "git",
    mutation_class: "persistent_write",
    requested_capability: "write",
    tags: ["git_commit"],
    target: { type: "branch", id: "fix/governance-up2-content-bound-authority" },
    args: { remote: "origin" },
    ...overrides
  });
}

// A valid A6 destructive request from the A6-capable component.
export function makeA6Request(overrides = {}) {
  return makeRequest({
    requester: { component: "recipe-engine-runtime", source_sha: RECIPE_SHA },
    authority_class: "A6",
    operation: "purge_history",
    tool: "git",
    mutation_class: "destructive",
    requested_capability: "write",
    target: { type: "branch", id: "old/dead-branch" },
    args: { confirm: "explicit" },
    ...overrides
  });
}

export function makeApproval(request, runtime, options = {}) {
  const {
    approver = "owner-a",
    secret = SECRETS[options.approver || "owner-a"],
    enhanced = false,
    nonce = freshNonce("apr"),
    issuedMs = T0 - 1000,
    ttlSeconds = 600,
    mutateBound,
    policyVersionOverride
  } = options;

  const bound = {
    ...expectedApprovalBound(request, hashCanonical(request), policyVersionOverride || runtime.policy_version),
    nonce,
    issued_at: iso(issuedMs),
    expires_at: iso(issuedMs + ttlSeconds * 1000)
  };

  if (mutateBound) mutateBound(bound);

  return signApproval(
    {
      schema_version: APPROVAL_SCHEMA_VERSION,
      approval_id: freshNonce("aprid"),
      approver_id: approver,
      enhanced,
      bound
    },
    secret
  );
}
