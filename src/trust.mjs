import fs from "node:fs";
import { hashCanonical, isSha256Hex } from "./canonical.mjs";

// Trusted decision configuration. Everything here is authority-side state:
// approver identities and secrets, component identity pins, the tool/operation
// capability map, TTL bounds and the runtime mutation seal. None of it may be
// supplied or overridden by a requesting party.

export const TRUST_CONFIG_VERSION = "gov.trust.v1";

export const AUTHORITY_CLASSES = ["A0", "A1", "A2", "A3", "A4", "A5", "A6"];

export const MUTATION_CLASSES = ["read_only", "reversible_write", "persistent_write", "destructive"];

export const EVIDENCE_CLASSES = ["fixture", "live"];

export function authorityRank(authorityClass) {
  return AUTHORITY_CLASSES.indexOf(authorityClass);
}

export class TrustConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "TrustConfigError";
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TrustConfigError(label + " must be a non-empty string.");
  }
}

function requirePlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TrustConfigError(label + " must be an object.");
  }
}

export function validateTrustConfig(config) {
  requirePlainObject(config, "trust config");

  if (config.config_version !== TRUST_CONFIG_VERSION) {
    throw new TrustConfigError("Unknown trust config version: " + String(config.config_version));
  }

  requireString(config.implementation_sha, "implementation_sha");
  requirePlainObject(config.expected_source_shas, "expected_source_shas");

  for (const [component, shas] of Object.entries(config.expected_source_shas)) {
    if (!Array.isArray(shas) || shas.length === 0 || !shas.every((sha) => typeof sha === "string" && sha.length >= 7)) {
      throw new TrustConfigError("expected_source_shas for " + component + " must be a non-empty SHA list.");
    }
  }

  requirePlainObject(config.approvers, "approvers");

  for (const [approverId, approver] of Object.entries(config.approvers)) {
    requirePlainObject(approver, "approver " + approverId);
    requireString(approver.secret, "approver " + approverId + " secret");

    if (approver.secret.length < 16) {
      throw new TrustConfigError("approver " + approverId + " secret is too short.");
    }

    if (typeof approver.enhanced !== "boolean") {
      throw new TrustConfigError("approver " + approverId + " enhanced flag must be boolean.");
    }
  }

  requirePlainObject(config.components, "components");

  for (const [componentId, component] of Object.entries(config.components)) {
    requirePlainObject(component, "component " + componentId);

    if (!Array.isArray(component.capabilities) || !component.capabilities.every((cap) => typeof cap === "string")) {
      throw new TrustConfigError("component " + componentId + " capabilities must be a string list.");
    }

    if (!AUTHORITY_CLASSES.includes(component.max_authority_class)) {
      throw new TrustConfigError("component " + componentId + " max_authority_class is unknown.");
    }

    if (!(componentId in config.expected_source_shas)) {
      throw new TrustConfigError("component " + componentId + " has no pinned source SHA.");
    }
  }

  requirePlainObject(config.tools, "tools");

  for (const [toolId, tool] of Object.entries(config.tools)) {
    requirePlainObject(tool, "tool " + toolId);
    requirePlainObject(tool.operations, "tool " + toolId + " operations");

    for (const [operationId, operation] of Object.entries(tool.operations)) {
      requirePlainObject(operation, "operation " + toolId + "." + operationId);

      if (!MUTATION_CLASSES.includes(operation.mutation_class)) {
        throw new TrustConfigError("operation " + toolId + "." + operationId + " mutation_class is unknown.");
      }

      requireString(operation.capability, "operation " + toolId + "." + operationId + " capability");

      if (!AUTHORITY_CLASSES.includes(operation.min_authority_class)) {
        throw new TrustConfigError("operation " + toolId + "." + operationId + " min_authority_class is unknown.");
      }
    }
  }

  if (!Number.isSafeInteger(config.approval_max_ttl_seconds) || config.approval_max_ttl_seconds <= 0) {
    throw new TrustConfigError("approval_max_ttl_seconds must be a positive integer.");
  }

  if (!Number.isSafeInteger(config.request_max_age_seconds) || config.request_max_age_seconds <= 0) {
    throw new TrustConfigError("request_max_age_seconds must be a positive integer.");
  }

  if (!Number.isSafeInteger(config.decision_ttl_seconds) || config.decision_ttl_seconds <= 0) {
    throw new TrustConfigError("decision_ttl_seconds must be a positive integer.");
  }

  requirePlainObject(config.runtime, "runtime");

  if (!EVIDENCE_CLASSES.includes(config.runtime.mode)) {
    throw new TrustConfigError("runtime.mode must be fixture or live.");
  }

  if (config.runtime.mutation_ratified !== false) {
    // The mutation path is not ratified. A config that claims otherwise is
    // rejected until ratification lands as its own reviewed change.
    throw new TrustConfigError("runtime.mutation_ratified must be false: mutation path is not ratified.");
  }

  return config;
}

export function loadTrustConfig(env = process.env) {
  const path = env.GOVERNANCE_TRUST_CONFIG;

  if (!path) {
    throw new TrustConfigError("GOVERNANCE_TRUST_CONFIG is not set; decision boundary stays closed.");
  }

  let raw;

  try {
    raw = fs.readFileSync(path, "utf8");
  } catch (error) {
    throw new TrustConfigError("Trust config unreadable: " + error.message);
  }

  let parsed;

  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new TrustConfigError("Trust config is not valid JSON: " + error.message);
  }

  return validateTrustConfig(parsed);
}

// Fingerprint identifies the trust config in receipts without leaking secrets.
export function trustConfigFingerprint(config) {
  const redactedApprovers = {};

  for (const [approverId, approver] of Object.entries(config.approvers)) {
    redactedApprovers[approverId] = { enhanced: approver.enhanced, secret: "REDACTED" };
  }

  return hashCanonical({ ...config, approvers: redactedApprovers });
}

export function assertNoSecretMaterial(value, label) {
  const canonicalProbe = JSON.stringify(value);

  if (/"secret"/.test(canonicalProbe)) {
    throw new TrustConfigError(label + " must not contain secret material.");
  }
}

export { isSha256Hex };
