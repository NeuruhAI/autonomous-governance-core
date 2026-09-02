import fs from "node:fs";
import { hashCanonical, isSha256Hex } from "./canonical.mjs";
import { ACTION_CLASS_TIERS, RISK_TIERS } from "./risk.mjs";
import { RatificationError, validateRatification } from "./ratification.mjs";

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

  // Optional per-component source lineage: the qualification history behind
  // the pin. Each entry records WHEN a SHA became the qualified identity and,
  // when superseded, WHAT superseded it. The contract that keeps pins honest:
  // expected_source_shas for a lineage-tracked component must equal exactly
  // the set of currently-qualified lineage SHAs — a pin that still names a
  // superseded SHA is a STALE PIN and the whole config is refused, so a stale
  // trust configuration can never load (the boundary stays closed instead).
  if (config.source_lineage !== undefined) {
    requirePlainObject(config.source_lineage, "source_lineage");

    for (const [component, entries] of Object.entries(config.source_lineage)) {
      if (!(component in config.expected_source_shas)) {
        throw new TrustConfigError("source_lineage names unpinned component: " + component);
      }

      if (!Array.isArray(entries) || entries.length === 0) {
        throw new TrustConfigError("source_lineage for " + component + " must be a non-empty list.");
      }

      const shas = new Set();
      const qualified = new Set();

      for (const entry of entries) {
        requirePlainObject(entry, "source_lineage entry for " + component);
        requireString(entry.sha, "source_lineage sha for " + component);

        if (entry.sha.length < 7) {
          throw new TrustConfigError("source_lineage sha for " + component + " is too short.");
        }

        if (shas.has(entry.sha)) {
          throw new TrustConfigError("source_lineage for " + component + " lists sha twice: " + entry.sha);
        }

        shas.add(entry.sha);
        requireString(entry.qualified_at, "source_lineage qualified_at for " + component);

        if (!Number.isFinite(Date.parse(entry.qualified_at))) {
          throw new TrustConfigError("source_lineage qualified_at for " + component + " must be ISO-8601.");
        }

        if (entry.status === "qualified") {
          qualified.add(entry.sha);
        } else if (entry.status === "superseded") {
          requireString(entry.superseded_by, "source_lineage superseded_by for " + component);
        } else {
          throw new TrustConfigError("source_lineage status for " + component + " must be qualified or superseded.");
        }
      }

      for (const entry of entries) {
        if (entry.status === "superseded" && !qualified.has(entry.superseded_by)) {
          throw new TrustConfigError(
            "source_lineage for " + component + ": superseded_by " + entry.superseded_by + " is not a qualified lineage SHA."
          );
        }
      }

      if (qualified.size === 0) {
        throw new TrustConfigError("source_lineage for " + component + " has no qualified SHA; the component cannot be represented honestly.");
      }

      const pinned = config.expected_source_shas[component];

      for (const sha of pinned) {
        if (!qualified.has(sha)) {
          const entry = entries.find((candidate) => candidate.sha === sha);

          if (entry && entry.status === "superseded") {
            throw new TrustConfigError(
              "STALE_SOURCE_PIN: expected_source_shas for " + component + " pins " + sha +
                ", which lineage marks superseded by " + entry.superseded_by +
                ". Update the pin to the qualified lineage; do not falsify the runtime identity."
            );
          }

          throw new TrustConfigError(
            "expected_source_shas for " + component + " pins " + sha + ", which is not a qualified lineage SHA."
          );
        }
      }

      for (const sha of qualified) {
        if (!pinned.includes(sha)) {
          throw new TrustConfigError(
            "expected_source_shas for " + component + " omits qualified lineage SHA " + sha + "."
          );
        }
      }
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

    // Optional consequence ceiling for the authorize surface. Purely narrowing:
    // absent means the surface's own tier rules decide alone, present means the
    // component can never be authorized above the named tier no matter what
    // grant or approval it presents. There is deliberately no field that widens
    // a component beyond those rules.
    if (component.max_risk_tier !== undefined && !RISK_TIERS.includes(component.max_risk_tier)) {
      throw new TrustConfigError("component " + componentId + " max_risk_tier is unknown.");
    }

    // Optional action-class allowlist, also purely narrowing.
    if (component.allowed_action_classes !== undefined) {
      if (!Array.isArray(component.allowed_action_classes) || component.allowed_action_classes.length === 0) {
        throw new TrustConfigError("component " + componentId + " allowed_action_classes must be a non-empty list when provided.");
      }

      for (const actionClass of component.allowed_action_classes) {
        if (typeof actionClass !== "string" || !(actionClass in ACTION_CLASS_TIERS)) {
          throw new TrustConfigError("component " + componentId + " allowed_action_classes names unknown action class: " + String(actionClass));
        }
      }
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

      // Optional per-operation allowlists. When present they PIN the decision
      // purpose: requests outside them are denied. Purely additive strictness.
      if (operation.repositories !== undefined && (!Array.isArray(operation.repositories) || operation.repositories.length === 0 || !operation.repositories.every((repo) => typeof repo === "string" && repo.length > 0))) {
        throw new TrustConfigError("operation " + toolId + "." + operationId + " repositories must be a non-empty string list when provided.");
      }

      if (operation.domains !== undefined && (!Array.isArray(operation.domains) || operation.domains.length === 0 || !operation.domains.every((domain) => typeof domain === "string" && domain.length > 0))) {
        throw new TrustConfigError("operation " + toolId + "." + operationId + " domains must be a non-empty string list when provided.");
      }

      if (operation.targets !== undefined && (!Array.isArray(operation.targets) || operation.targets.length === 0 || !operation.targets.every((target) => target && typeof target === "object" && !Array.isArray(target) && typeof target.type === "string" && target.type.length > 0 && typeof target.id === "string" && target.id.length > 0))) {
        throw new TrustConfigError("operation " + toolId + "." + operationId + " targets must be a non-empty {type,id} list when provided.");
      }
    }
  }

  if (!Number.isSafeInteger(config.approval_max_ttl_seconds) || config.approval_max_ttl_seconds <= 0) {
    throw new TrustConfigError("approval_max_ttl_seconds must be a positive integer.");
  }

  if (config.grant_max_ttl_seconds !== undefined && (!Number.isSafeInteger(config.grant_max_ttl_seconds) || config.grant_max_ttl_seconds <= 0)) {
    throw new TrustConfigError("grant_max_ttl_seconds must be a positive integer when provided.");
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
    // The boolean stays refused, permanently. It was a switch that would have
    // unsealed every mutating class at once, and nothing needs it: ratification
    // is the signed, scoped, expiring artifact below. A config claiming the
    // boolean is still rejected, so no edit to an existing config can unseal
    // anything, and the adversarial court that pins this keeps passing.
    throw new TrustConfigError("runtime.mutation_ratified must be false: mutation path is not ratified.");
  }

  // Optional, and narrowing. Absent means the surface behaves exactly as it did
  // before ratification existed: in live mode every non-R0 class stays sealed.
  if (config.runtime.mutation_ratification !== undefined) {
    try {
      validateRatification(config.runtime.mutation_ratification, config);
    } catch (error) {
      if (error instanceof RatificationError) {
        throw new TrustConfigError(error.message);
      }

      throw error;
    }
  }

  if (config.ratification_max_ttl_seconds !== undefined
      && (!Number.isSafeInteger(config.ratification_max_ttl_seconds) || config.ratification_max_ttl_seconds <= 0)) {
    throw new TrustConfigError("ratification_max_ttl_seconds must be a positive integer when provided.");
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

// Lineage lookup for decision-time identity messages. Returns the lineage
// entry for a component+sha, or null when no lineage tracks it.
export function lineageEntry(config, component, sha) {
  const entries = (config.source_lineage && config.source_lineage[component]) || [];
  return entries.find((entry) => entry.sha === sha) || null;
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
