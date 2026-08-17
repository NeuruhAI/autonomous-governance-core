import { canonicalize, hmacHex, timingSafeEqualHex } from "./canonical.mjs";
import {
  broadRootError,
  classifyPathSensitivity,
  isWithinRoot,
  pathLexicalErrors,
  realContainmentErrors,
  resolveRealTargetPath
} from "./pathscope.mjs";
import { ACTION_CLASS_TIERS } from "./risk.mjs";

// FounderGrant: bounded reusable founder authority. A grant pre-authorizes a
// SCOPE of bounded consequence — never arbitrary authority. It is:
//   scoped        — lane, repos, path roots, action classes, services, spend
//   expiring      — absolute issued_at/expires_at window, TTL-bounded
//   receipted     — every use is receipted on the authorization chain
//   non-transferable — bound to exactly one lane subject
//   path-safe     — roots are canonical, never broad, realpath-contained
//
// Hard floors no grant may cross in gov.grant.v1 (validated fail-closed, the
// same idiom as the unratified mutation seal): external contact and
// destructive permission must be false — R4/R5 consequence stays with the
// founder interactively.

export const GRANT_SCHEMA_VERSION = "gov.grant.v1";

export const DEFAULT_GRANT_MAX_TTL_SECONDS = 30 * 24 * 3600;

const GRANT_STRING_FIELDS = ["schema_version", "grant_id", "issuer", "issued_at", "expires_at"];

const GRANT_ALL_FIELDS = [
  ...GRANT_STRING_FIELDS,
  "subject",
  "allowed_repos",
  "allowed_paths",
  "allowed_action_classes",
  "denied_action_classes",
  "allowed_services",
  "production_permission",
  "external_contact_permission",
  "spend_ceiling_usd",
  "destructive_permission",
  "rollback_required",
  "receipt_required",
  "qualified_operations",
  "signature"
];

function isStringList(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0);
}

export function grantErrors(grant) {
  const errors = [];

  if (!grant || typeof grant !== "object" || Array.isArray(grant)) {
    return ["Grant must be a JSON object."];
  }

  for (const field of GRANT_STRING_FIELDS) {
    if (typeof grant[field] !== "string" || grant[field].length === 0) {
      errors.push(field + " is required and must be a non-empty string.");
    }
  }

  for (const key of Object.keys(grant)) {
    if (!GRANT_ALL_FIELDS.includes(key)) {
      errors.push("Unknown grant field: " + key);
    }
  }

  if (grant.schema_version !== undefined && grant.schema_version !== GRANT_SCHEMA_VERSION) {
    errors.push("Unknown grant schema_version.");
  }

  const subject = grant.subject;

  if (!subject || typeof subject !== "object" || Array.isArray(subject)) {
    errors.push("subject must be an object.");
  } else {
    if (typeof subject.lane !== "string" || subject.lane.length === 0 || subject.lane.includes("*")) {
      errors.push("subject.lane is required and must be exact (no wildcards).");
    }
    for (const key of Object.keys(subject)) {
      if (key !== "lane") errors.push("Unknown subject field: " + key);
    }
  }

  for (const field of ["allowed_repos", "allowed_services", "denied_action_classes"]) {
    if (!isStringList(grant[field])) {
      errors.push(field + " must be an array of non-empty strings (use [] for none).");
    } else if (grant[field].some((item) => item.includes("*"))) {
      errors.push(field + " must not contain wildcards.");
    }
  }

  if (!isStringList(grant.allowed_action_classes) || grant.allowed_action_classes.length === 0) {
    errors.push("allowed_action_classes must be a non-empty array of action classes.");
  } else {
    for (const actionClass of grant.allowed_action_classes) {
      if (!(actionClass in ACTION_CLASS_TIERS)) {
        errors.push("allowed_action_classes names unknown action class: " + actionClass);
      } else if (ACTION_CLASS_TIERS[actionClass] === "R4" || ACTION_CLASS_TIERS[actionClass] === "R5") {
        errors.push("allowed_action_classes may not include R4/R5 class: " + actionClass + " (founder-interactive only).");
      }
    }
  }

  if (!Array.isArray(grant.allowed_paths)) {
    errors.push("allowed_paths must be an array (use [] for none).");
  } else {
    for (const root of grant.allowed_paths) {
      const lexical = pathLexicalErrors(root);

      if (lexical.length) {
        errors.push("allowed_paths root not canonical (" + String(root) + "): " + lexical.join(" "));
        continue;
      }

      const broad = broadRootError(root);

      if (broad) {
        errors.push("allowed_paths root refused (" + root + "): " + broad);
      }

      const sensitivity = classifyPathSensitivity(root);

      if (sensitivity.sensitivity !== "normal") {
        errors.push("allowed_paths root refused (" + root + "): " + sensitivity.detail);
      }
    }
  }

  for (const field of ["production_permission", "rollback_required"]) {
    if (typeof grant[field] !== "boolean") {
      errors.push(field + " must be boolean.");
    }
  }

  // Hard floors: gov.grant.v1 can never carry external-contact or destructive
  // authority, and a grant that opts out of receipts is refused outright.
  if (grant.external_contact_permission !== false) {
    errors.push("external_contact_permission must be false: external consequence is founder-interactive (R4).");
  }

  if (grant.destructive_permission !== false) {
    errors.push("destructive_permission must be false: destructive/privileged actions are founder-interactive (R5).");
  }

  if (grant.receipt_required !== true) {
    errors.push("receipt_required must be true: every grant use is receipted.");
  }

  if (typeof grant.spend_ceiling_usd !== "number" || !Number.isFinite(grant.spend_ceiling_usd) || grant.spend_ceiling_usd < 0) {
    errors.push("spend_ceiling_usd must be a non-negative finite number.");
  }

  if (grant.qualified_operations !== undefined) {
    if (!Array.isArray(grant.qualified_operations)) {
      errors.push("qualified_operations must be an array when provided.");
    } else {
      grant.qualified_operations.forEach((operation, index) => {
        const label = "qualified_operations[" + index + "]";

        if (!operation || typeof operation !== "object" || Array.isArray(operation)) {
          errors.push(label + " must be an object.");
          return;
        }

        for (const field of ["action_class", "rollback", "preflight", "postflight"]) {
          if (typeof operation[field] !== "string" || operation[field].length === 0) {
            errors.push(label + "." + field + " is required and must be a non-empty string.");
          }
        }

        const target = operation.target;

        if (!target || typeof target !== "object" || Array.isArray(target) || typeof target.type !== "string" || typeof target.id !== "string" || target.type.length === 0 || target.id.length === 0) {
          errors.push(label + ".target must be an exact {type,id} object.");
        } else if (target.type.includes("*") || target.id.includes("*")) {
          errors.push(label + ".target must be exact (no wildcards).");
        }

        for (const key of Object.keys(operation)) {
          if (!["action_class", "target", "rollback", "preflight", "postflight"].includes(key)) {
            errors.push("Unknown " + label + " field: " + key);
          }
        }
      });
    }
  }

  const issuedAt = Date.parse(grant.issued_at);
  const expiresAt = Date.parse(grant.expires_at);

  if (typeof grant.issued_at === "string" && !Number.isFinite(issuedAt)) {
    errors.push("issued_at must be an ISO-8601 timestamp.");
  }

  if (typeof grant.expires_at === "string" && !Number.isFinite(expiresAt)) {
    errors.push("expires_at must be an ISO-8601 timestamp.");
  }

  if (Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && expiresAt <= issuedAt) {
    errors.push("expires_at must be after issued_at.");
  }

  return errors;
}

function grantSigningPayload(grant) {
  const { signature, ...unsigned } = grant;
  return unsigned;
}

export function signGrant(unsignedGrant, issuerSecret) {
  const { signature, ...unsigned } = unsignedGrant;
  return { ...unsigned, signature: hmacHex(issuerSecret, canonicalize(unsigned)) };
}

// Verify a grant against trusted configuration. Returns
// { ok: true, grant } or { ok: false, reason_code, detail }.
// Expiry is deliberately its own reason: an expired grant is not hostile, it
// falls back to founder approval, whereas a forged one is denied outright.
export function verifyGrant(grant, config, nowMs) {
  const errors = grantErrors(grant);

  if (errors.length) {
    return { ok: false, reason_code: "GRANT_MALFORMED", detail: errors.join(" ") };
  }

  const issuer = config.approvers[grant.issuer];

  if (!issuer) {
    return { ok: false, reason_code: "GRANT_ISSUER_UNKNOWN", detail: "Grant issuer is not in trusted configuration." };
  }

  if (!issuer.enhanced) {
    return { ok: false, reason_code: "GRANT_ISSUER_NOT_ENHANCED", detail: "Grant issuer lacks founder-grade (enhanced) authority." };
  }

  let expectedSignature;

  try {
    expectedSignature = hmacHex(issuer.secret, canonicalize(grantSigningPayload(grant)));
  } catch (error) {
    return { ok: false, reason_code: "GRANT_MALFORMED", detail: "Grant is not canonical: " + error.message };
  }

  if (!timingSafeEqualHex(grant.signature, expectedSignature)) {
    return { ok: false, reason_code: "GRANT_SIGNATURE_INVALID", detail: "Grant signature does not verify." };
  }

  const issuedAt = Date.parse(grant.issued_at);
  const expiresAt = Date.parse(grant.expires_at);
  const maxTtl = Number.isSafeInteger(config.grant_max_ttl_seconds) ? config.grant_max_ttl_seconds : DEFAULT_GRANT_MAX_TTL_SECONDS;

  if ((expiresAt - issuedAt) / 1000 > maxTtl) {
    return { ok: false, reason_code: "GRANT_TTL_EXCEEDED", detail: "Grant validity window exceeds the configured maximum." };
  }

  if (nowMs < issuedAt) {
    return { ok: false, reason_code: "GRANT_NOT_YET_VALID", detail: "Grant is not yet valid." };
  }

  if (nowMs >= expiresAt) {
    return { ok: false, reason_code: "GRANT_EXPIRED", detail: "Grant expired at " + grant.expires_at + "." };
  }

  return { ok: true, grant };
}

// Scope admission: does this verified grant admit these action facts?
// Returns { ok: true } or { ok: false, reason_code, detail }. Lane and repo
// mismatches are hostile (misuse of someone else's grant) and deny; a scope
// the grant simply does not cover falls back to founder approval.
export function grantAdmits(grant, facts, { fsImpl } = {}) {
  if (grant.subject.lane !== facts.lane) {
    return {
      ok: false,
      hostile: true,
      reason_code: "GRANT_LANE_MISMATCH",
      detail: "Grant is non-transferable: issued to lane " + grant.subject.lane + ", presented by lane " + facts.lane + "."
    };
  }

  if (typeof facts.repository === "string" && facts.repository.length > 0 && !grant.allowed_repos.includes(facts.repository)) {
    return {
      ok: false,
      hostile: true,
      reason_code: "GRANT_REPO_MISMATCH",
      detail: "Repository " + facts.repository + " is not named by this grant."
    };
  }

  if (grant.denied_action_classes.includes(facts.action_class)) {
    return {
      ok: false,
      hostile: true,
      reason_code: "GRANT_ACTION_CLASS_DENIED",
      detail: "Action class " + facts.action_class + " is explicitly denied by this grant."
    };
  }

  if (!grant.allowed_action_classes.includes(facts.action_class)) {
    return {
      ok: false,
      reason_code: "GRANT_ACTION_CLASS_NOT_GRANTED",
      detail: "Action class " + facts.action_class + " is not named by this grant."
    };
  }

  if (facts.target.type === "path") {
    const containingRoot = grant.allowed_paths.find((root) => isWithinRoot(facts.target.id, root));

    if (!containingRoot) {
      return {
        ok: false,
        reason_code: "GRANT_PATH_NOT_GRANTED",
        detail: "Path is outside every granted root."
      };
    }

    const realErrors = realContainmentErrors(facts.target.id, containingRoot, fsImpl);

    if (realErrors.length) {
      return { ok: false, hostile: true, reason_code: "PATH_ESCAPE", detail: realErrors.join(" ") };
    }

    const resolution = resolveRealTargetPath(facts.target.id, fsImpl);

    if (resolution.ok) {
      const resolvedSensitivity = classifyPathSensitivity(resolution.resolved);

      if (resolvedSensitivity.sensitivity !== "normal") {
        return { ok: false, hostile: true, reason_code: "SECRET_ROOT_DENIED", detail: resolvedSensitivity.detail };
      }
    }
  }

  if (facts.target.type === "service" || typeof facts.service_label === "string") {
    const label = facts.service_label ?? facts.target.id;

    if (!grant.allowed_services.includes(label)) {
      return {
        ok: false,
        reason_code: "GRANT_SERVICE_NOT_GRANTED",
        detail: "Service " + label + " is not named by this grant."
      };
    }
  }

  if (facts.production_effect !== "none" && facts.production_effect !== "read" && grant.production_permission !== true) {
    return {
      ok: false,
      reason_code: "GRANT_PRODUCTION_NOT_GRANTED",
      detail: "Grant does not carry production permission."
    };
  }

  if (facts.spend_usd > grant.spend_ceiling_usd) {
    return {
      ok: false,
      reason_code: "GRANT_SPEND_CEILING_EXCEEDED",
      detail: "Spend " + facts.spend_usd + " exceeds the grant ceiling " + grant.spend_ceiling_usd + "."
    };
  }

  if (grant.rollback_required && facts.reversibility !== "reversible" && !(typeof facts.rollback_plan === "string" && facts.rollback_plan.length > 0)) {
    return {
      ok: false,
      reason_code: "GRANT_ROLLBACK_REQUIRED",
      detail: "Grant requires a stated rollback plan for non-trivially-reversible actions."
    };
  }

  return { ok: true };
}

// R3 qualified adoption: the grant must name this exact operation — target,
// action class, rollback, preflight and postflight — for a no-reprompt allow.
export function grantQualifiesOperation(grant, facts) {
  const operations = Array.isArray(grant.qualified_operations) ? grant.qualified_operations : [];

  const match = operations.find(
    (operation) =>
      operation.action_class === facts.action_class &&
      operation.target.type === facts.target.type &&
      operation.target.id === facts.target.id
  );

  if (!match) {
    return {
      ok: false,
      reason_code: "GRANT_OPERATION_NOT_QUALIFIED",
      detail: "Grant does not qualify this exact operation (target, rollback, preflight, postflight)."
    };
  }

  return { ok: true, operation: match };
}
