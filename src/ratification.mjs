import { canonicalize, hmacHex, timingSafeEqualHex } from "./canonical.mjs";
import { ACTION_CLASS_TIERS, RISK_TIERS, riskRank } from "./risk.mjs";

// MUTATION RATIFICATION (gov.ratification.v1)
//
// Before this module, `runtime.mutation_ratified` was a boolean that
// validateTrustConfig refused to let anyone set: ratification was literally
// unrepresentable, so the live surface could allow R0 and nothing else. That
// was the right default and the wrong permanent state — it meant every bounded
// internal action and every courted promotion was blocked by configuration
// rather than by consequence.
//
// The boolean stays refused. Ratification is not a switch that opens the
// surface; it is a SIGNED, NARROWING artifact, verified the same way a
// FounderGrant is:
//
//   scoped     it names the exact action classes it ratifies, nothing else
//   ceilinged  it names a maximum tier, and R4/R5 can never be named
//   signed     an enhanced approver's HMAC over the canonical block, so
//              editing a config file cannot ratify anything
//   expiring   an absolute window, TTL-bounded like a grant
//
// The load-bearing property is in `ratificationAdmits`: it tests the CLASSIFIED
// tier, after classifyRisk's escalators, not the action class's baseline. So a
// ratification of `git_commit` never ratifies a forced push, a secret-touching
// write, a broad blast radius, an irreversible action or anything carrying
// externality or spend — every one of those escalates past the ceiling and the
// seal closes again on an action whose class was ratified. Ratifying a class is
// not ratifying every consequence that class could have.

export const RATIFICATION_SCHEMA_VERSION = "gov.ratification.v1";

// The hard ceiling on what ratification can ever reach. R4 is external
// consequence (contact, spend, publication, customer and legal effect) and R5
// is destructive or privileged. Neither is delegable to a configuration
// artifact: they stay founder-interactive, by validation rather than by policy
// prose.
export const MAX_RATIFIABLE_TIER = "R3";

export const DEFAULT_RATIFICATION_MAX_TTL_SECONDS = 90 * 24 * 3600;

const RATIFICATION_STRING_FIELDS = [
  "schema_version",
  "ratified_by",
  "ratified_at",
  "expires_at",
  "max_ratified_tier"
];

const RATIFICATION_ALL_FIELDS = [
  ...RATIFICATION_STRING_FIELDS,
  "ratified_action_classes",
  "signature"
];

export class RatificationError extends Error {}

function unsignedRatification(ratification) {
  const { signature, ...unsigned } = ratification;
  return unsigned;
}

export function signRatification(unsigned, approverSecret) {
  const { signature, ...rest } = unsigned;
  return { ...rest, signature: hmacHex(approverSecret, canonicalize(rest)) };
}

// Structural + cryptographic validation. Throws RatificationError; the trust
// loader converts it, so a malformed ratification fails config validation and
// the boundary never comes up at all rather than coming up half-ratified.
export function validateRatification(ratification, config) {
  if (!ratification || typeof ratification !== "object" || Array.isArray(ratification)) {
    throw new RatificationError("runtime.mutation_ratification must be an object when provided.");
  }

  for (const field of RATIFICATION_STRING_FIELDS) {
    if (typeof ratification[field] !== "string" || ratification[field].length === 0) {
      throw new RatificationError("mutation_ratification." + field + " is required and must be a non-empty string.");
    }
  }

  for (const key of Object.keys(ratification)) {
    if (!RATIFICATION_ALL_FIELDS.includes(key)) {
      throw new RatificationError("Unknown mutation_ratification field: " + key);
    }
  }

  if (ratification.schema_version !== RATIFICATION_SCHEMA_VERSION) {
    throw new RatificationError("Unknown mutation_ratification schema_version.");
  }

  if (typeof ratification.signature !== "string" || ratification.signature.length === 0) {
    throw new RatificationError("mutation_ratification.signature is required: a config edit cannot ratify.");
  }

  const approver = config.approvers ? config.approvers[ratification.ratified_by] : undefined;

  if (!approver) {
    throw new RatificationError("mutation_ratification.ratified_by is not a trusted approver.");
  }

  if (!approver.enhanced) {
    throw new RatificationError("mutation_ratification requires a founder-grade (enhanced) approver.");
  }

  let expected;

  try {
    expected = hmacHex(approver.secret, canonicalize(unsignedRatification(ratification)));
  } catch (error) {
    throw new RatificationError("mutation_ratification is not canonical: " + error.message);
  }

  if (!timingSafeEqualHex(ratification.signature, expected)) {
    throw new RatificationError("mutation_ratification signature does not verify.");
  }

  if (!RISK_TIERS.includes(ratification.max_ratified_tier)) {
    throw new RatificationError("mutation_ratification.max_ratified_tier is unknown.");
  }

  if (riskRank(ratification.max_ratified_tier) > riskRank(MAX_RATIFIABLE_TIER)) {
    throw new RatificationError(
      "mutation_ratification.max_ratified_tier may never exceed " + MAX_RATIFIABLE_TIER +
        ": external consequence and destructive action stay founder-interactive."
    );
  }

  if (!Array.isArray(ratification.ratified_action_classes) || ratification.ratified_action_classes.length === 0) {
    throw new RatificationError("mutation_ratification.ratified_action_classes must be a non-empty array.");
  }

  for (const actionClass of ratification.ratified_action_classes) {
    if (typeof actionClass !== "string" || !(actionClass in ACTION_CLASS_TIERS)) {
      throw new RatificationError("mutation_ratification names unknown action class: " + String(actionClass));
    }

    if (riskRank(ACTION_CLASS_TIERS[actionClass]) > riskRank(ratification.max_ratified_tier)) {
      throw new RatificationError(
        "mutation_ratification names action class " + actionClass + " (" + ACTION_CLASS_TIERS[actionClass] +
          ") above its own ceiling " + ratification.max_ratified_tier + "."
      );
    }
  }

  const ratifiedAt = Date.parse(ratification.ratified_at);
  const expiresAt = Date.parse(ratification.expires_at);

  if (!Number.isFinite(ratifiedAt) || !Number.isFinite(expiresAt)) {
    throw new RatificationError("mutation_ratification timestamps must be ISO-8601.");
  }

  if (expiresAt <= ratifiedAt) {
    throw new RatificationError("mutation_ratification.expires_at must be after ratified_at.");
  }

  const maxTtl = Number.isSafeInteger(config.ratification_max_ttl_seconds)
    ? config.ratification_max_ttl_seconds
    : DEFAULT_RATIFICATION_MAX_TTL_SECONDS;

  if ((expiresAt - ratifiedAt) / 1000 > maxTtl) {
    throw new RatificationError("mutation_ratification validity window exceeds the configured maximum.");
  }

  return ratification;
}

// Runtime admission. Returns { ok: true } or { ok: false, detail }.
//
// `classifiedTier` is the tier AFTER classifyRisk, which is the whole point:
// escalators must be able to push a ratified class back above the ceiling.
export function ratificationAdmits(config, facts, classifiedTier, nowMs) {
  const ratification = config.runtime ? config.runtime.mutation_ratification : undefined;

  if (!ratification) {
    return {
      ok: false,
      detail: "Live mutation is not ratified in this trust configuration; action class " +
        facts.action_class + " is mutating."
    };
  }

  if (nowMs >= Date.parse(ratification.expires_at)) {
    return {
      ok: false,
      detail: "The mutation ratification expired at " + ratification.expires_at + "."
    };
  }

  if (nowMs < Date.parse(ratification.ratified_at)) {
    return { ok: false, detail: "The mutation ratification is not yet valid." };
  }

  if (!ratification.ratified_action_classes.includes(facts.action_class)) {
    return {
      ok: false,
      detail: "Action class " + facts.action_class + " is not ratified for live mutation."
    };
  }

  if (riskRank(classifiedTier) > riskRank(ratification.max_ratified_tier)) {
    return {
      ok: false,
      detail: "This action classifies " + classifiedTier + ", above the ratified ceiling " +
        ratification.max_ratified_tier + "; ratifying an action class does not ratify every " +
        "consequence it can carry."
    };
  }

  return { ok: true };
}
