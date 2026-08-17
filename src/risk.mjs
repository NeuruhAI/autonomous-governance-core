import { isSha256Hex } from "./canonical.mjs";

// Consequence-based risk classification. GOVERN CONSEQUENCE, NOT SYNTAX:
// a broad tag like "file_modify" is not meaningful risk. Risk is a function
// of TARGET, SCOPE, EXTERNALITY, REVERSIBILITY, BLAST RADIUS, SPEND,
// PRODUCTION EFFECT and IDENTITY. Classification is deterministic and
// monotone: escalating factors only ever RAISE the tier (worst factor wins);
// nothing de-escalates, and an unrecognized shape fails closed at validation.

export const RISK_TIERS = ["R0", "R1", "R2", "R3", "R4", "R5"];

export function riskRank(tier) {
  return RISK_TIERS.indexOf(tier);
}

// Base tier of each admitted action class. Unknown classes are refused at
// validation — never guessed at.
export const ACTION_CLASS_TIERS = {
  // R0 — OBSERVE
  read: "R0",
  query: "R0",
  health: "R0",
  status: "R0",
  retrieval: "R0",
  git_inspect: "R0",

  // R1 — BOUNDED LOCAL REVERSIBLE
  artifact_write: "R1",
  report_write: "R1",
  screenshot_write: "R1",
  receipt_write: "R1",
  temp_write: "R1",
  alias_repair: "R1",
  preview_write: "R1",

  // R2 — OWNED FEATURE-BRANCH DEVELOPMENT
  repo_edit: "R2",
  test_run: "R2",
  build: "R2",
  git_commit: "R2",
  git_push: "R2",

  // R3 — QUALIFIED CONTROLLED ADOPTION
  merge: "R3",
  deploy: "R3",
  service_restart: "R3",
  migration_additive: "R3",

  // R4 — EXTERNAL CONSEQUENCE
  external_message: "R4",
  esign_send: "R4",
  provider_enrollment: "R4",
  spend: "R4",
  publish: "R4",
  customer_create: "R4",
  customer_data_mutation: "R4",
  legal_acceptance: "R4",

  // R5 — DESTRUCTIVE / PRIVILEGED
  force_push: "R5",
  history_rewrite: "R5",
  db_drop: "R5",
  db_wipe: "R5",
  broad_delete: "R5",
  broad_kill: "R5",
  secret_exposure: "R5",
  privilege_escalation: "R5",
  canonical_destroy: "R5",
  reboot: "R5"
};

export const FACTS_SCHEMA_VERSION = "gov.action.facts.v1";

export const EXTERNALITIES = [
  "none",
  "email",
  "sms",
  "call",
  "esign",
  "provider_enrollment",
  "publication",
  "customer_create"
];

export const REVERSIBILITIES = ["reversible", "rollback_known", "irreversible"];

export const BLAST_RADII = ["single_target", "bounded", "broad"];

export const PRODUCTION_EFFECTS = ["none", "read", "config", "service_restart", "customer_data"];

const PROTECTED_BRANCHES = new Set(["main", "master", "production"]);

const FACTS_STRING_FIELDS = [
  "schema_version",
  "action_id",
  "lane",
  "component",
  "action_class",
  "summary",
  "externality",
  "reversibility",
  "blast_radius",
  "production_effect",
  "nonce",
  "issued_at"
];

const FACTS_ALL_FIELDS = [
  ...FACTS_STRING_FIELDS,
  "target",
  "repository",
  "branch",
  "service_label",
  "force",
  "rollback_plan",
  "spend_usd",
  "secret_access",
  "precondition_hash"
];

const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export function actionFactsErrors(facts) {
  const errors = [];

  if (!facts || typeof facts !== "object" || Array.isArray(facts)) {
    return ["Action facts must be a JSON object."];
  }

  for (const field of FACTS_STRING_FIELDS) {
    if (typeof facts[field] !== "string" || facts[field].length === 0) {
      errors.push(field + " is required and must be a non-empty string.");
    }
  }

  for (const key of Object.keys(facts)) {
    if (!FACTS_ALL_FIELDS.includes(key)) {
      errors.push("Unknown facts field: " + key);
    }
  }

  if (facts.schema_version !== undefined && facts.schema_version !== FACTS_SCHEMA_VERSION) {
    errors.push("Unknown facts schema_version.");
  }

  if (typeof facts.action_class === "string" && !(facts.action_class in ACTION_CLASS_TIERS)) {
    errors.push("Unknown action_class: " + facts.action_class + " (unrecognized consequence fails closed).");
  }

  const target = facts.target;

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

  if (typeof facts.externality === "string" && !EXTERNALITIES.includes(facts.externality)) {
    errors.push("Unknown externality.");
  }

  if (typeof facts.reversibility === "string" && !REVERSIBILITIES.includes(facts.reversibility)) {
    errors.push("Unknown reversibility.");
  }

  if (typeof facts.blast_radius === "string" && !BLAST_RADII.includes(facts.blast_radius)) {
    errors.push("Unknown blast_radius.");
  }

  if (typeof facts.production_effect === "string" && !PRODUCTION_EFFECTS.includes(facts.production_effect)) {
    errors.push("Unknown production_effect.");
  }

  for (const field of ["repository", "branch", "service_label", "rollback_plan"]) {
    if (facts[field] !== undefined && (typeof facts[field] !== "string" || facts[field].length === 0)) {
      errors.push(field + " must be a non-empty string when provided.");
    }
  }

  for (const field of ["force", "secret_access"]) {
    if (facts[field] !== undefined && typeof facts[field] !== "boolean") {
      errors.push(field + " must be boolean when provided.");
    }
  }

  if (typeof facts.spend_usd !== "number" || !Number.isFinite(facts.spend_usd) || facts.spend_usd < 0) {
    errors.push("spend_usd is required and must be a non-negative finite number (use 0 for no spend).");
  }

  if (facts.precondition_hash !== undefined && !isSha256Hex(facts.precondition_hash)) {
    errors.push("precondition_hash must be sha256 hex when provided.");
  }

  if (typeof facts.nonce === "string" && !NONCE_PATTERN.test(facts.nonce)) {
    errors.push("nonce must be 16-128 url-safe characters.");
  }

  return errors;
}

// Classify validated facts. pathSensitivity is the sensitivity of the target
// path (lexical AND resolved spelling), supplied by the caller that ran path
// enforcement. Returns { tier, factors } where factors name every consequence
// that contributed.
export function classifyRisk(facts, { pathSensitivity = "normal" } = {}) {
  const factors = [];
  const base = ACTION_CLASS_TIERS[facts.action_class];
  let rank = riskRank(base);

  factors.push("action class " + facts.action_class + " is baseline " + base + ".");

  const escalate = (tier, reason) => {
    if (riskRank(tier) > rank) rank = riskRank(tier);
    factors.push(reason + " (>= " + tier + ")");
  };

  if (facts.secret_access === true || pathSensitivity === "secret") {
    escalate("R5", "target touches secret-denied material");
  }

  if (pathSensitivity === "governance_canonical" && rank >= riskRank("R1")) {
    escalate("R5", "mutation targets canonical Governance state");
  }

  if (facts.force === true) {
    escalate("R5", "forced ref update is history-destructive");
  }

  if (facts.externality !== "none") {
    escalate("R4", "external consequence: " + facts.externality);
  }

  if (facts.spend_usd > 0) {
    escalate("R4", "spend of $" + facts.spend_usd);
  }

  if (facts.production_effect === "customer_data") {
    escalate("R4", "production customer data effect");
  }

  if (facts.reversibility === "irreversible") {
    escalate(facts.blast_radius === "broad" ? "R5" : "R4", "irreversible action" + (facts.blast_radius === "broad" ? " with broad blast radius" : ""));
  }

  if (facts.blast_radius === "broad" && rank >= riskRank("R1")) {
    escalate("R4", "broad blast radius on a mutating action");
  }

  if (facts.production_effect === "service_restart") {
    escalate("R3", "production service restart");
  }

  if (typeof facts.branch === "string" && PROTECTED_BRANCHES.has(facts.branch) && rank >= riskRank("R1")) {
    escalate("R3", "mutation of protected branch " + facts.branch);
  }

  return { tier: RISK_TIERS[rank], factors };
}

// R2 auto-allow discipline: owned feature-branch development only — no force,
// no secret access, no external contact, no production mutation, and never a
// protected branch. Returns a list of violations (empty = disciplined).
export function featureBranchViolations(facts) {
  const violations = [];

  if (facts.action_class === "git_push" || facts.action_class === "git_commit" || facts.action_class === "repo_edit") {
    if (typeof facts.branch !== "string" || facts.branch.length === 0) {
      violations.push("branch must be stated for repository mutations.");
    } else if (PROTECTED_BRANCHES.has(facts.branch)) {
      violations.push("branch " + facts.branch + " is protected; adoption is R3+.");
    }
  }

  if (facts.force === true) violations.push("force is never feature-branch development.");
  if (facts.secret_access === true) violations.push("secret access is never feature-branch development.");
  if (facts.externality !== "none") violations.push("external contact is never feature-branch development.");
  if (facts.production_effect !== "none" && facts.production_effect !== "read") {
    violations.push("production mutation is never feature-branch development.");
  }

  return violations;
}
