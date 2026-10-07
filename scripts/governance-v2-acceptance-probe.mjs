#!/usr/bin/env node
// Governance V2 acceptance probe — the FULL adoption matrix over the wire.
//
//   PROBE_FOUNDER_SECRET=<secret> node scripts/governance-v2-acceptance-probe.mjs [base-url]
//
// Runs every adoption matrix row against a running instance (V1 compat,
// /v2/decide identity semantics, /v2/authorize identity + founder-authority
// semantics) and exits 0 only when EVERY row matches its expected decision AND
// reason. This is the semantic gate used by the adoption runtime (up-verified)
// and the deploy procedure: any mismatch is a semantic failure that triggers
// rollback.
//
// The /v2/authorize rows probe THIS configuration, not a hypothetical one. The
// live adoption trust config registers exactly one component (founder_runtime,
// capped at R0 and admitted only for read-only action classes), so the rows
// that used to walk R1-R5 under probe-issued grants could only run by pretending
// the live config grants capabilities it does not. Those tier semantics are
// covered against the fixture config in tests/authorize.test.mjs and
// tests/grants.test.mjs, where the capabilities they need actually exist. What
// is proved here is what this instance will actually do to the real caller.
//
// The probe only requests decisions; Governance never executes. Probing the
// live port 8848 requires PROBE_ALLOW_LIVE=1 (set by the deploy procedure).
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FOUNDER_APPROVAL_SCHEMA_VERSION, scopeKeyFor, signFounderApproval } from "../src/authorize.mjs";
import { canonicalCanaryRequest } from "./p2b-canary-decision-probe.mjs";

const base = process.argv[2] || "http://127.0.0.1:18730";
const FOUNDER_SECRET = process.env.PROBE_FOUNDER_SECRET || "";
const LANE = "adoption-probe-lane";
// The configured secret with one character changed: a near-miss key, derived
// so no secret-shaped literal is ever written into this tree.
const WRONG_SECRET = FOUNDER_SECRET.slice(0, -1) + (FOUNDER_SECRET.endsWith("0") ? "1" : "0");
const REPO = "NeuruhAI/autonomous-governance-core";

if (new URL(base).port === "8848" && process.env.PROBE_ALLOW_LIVE !== "1") {
  console.error("refuse: probing the live port 8848 requires PROBE_ALLOW_LIVE=1 (deploy procedure only)");
  process.exit(1);
}

if (FOUNDER_SECRET.length < 16) {
  console.error("refuse: PROBE_FOUNDER_SECRET is required (>=16 chars) to sign probe founder approvals");
  process.exit(1);
}

function trustPin() {
  const config = JSON.parse(fs.readFileSync(new URL("../config/governance-v2-adoption-trust.json", import.meta.url), "utf8"));
  const pinned = config.expected_source_shas.founder_runtime;

  if (!Array.isArray(pinned) || pinned.length !== 1) {
    console.error("refuse: adoption config must pin exactly one qualified founder_runtime SHA");
    process.exit(1);
  }

  return pinned[0];
}

const nowIso = () => new Date().toISOString();
const isoIn = (ms) => new Date(Date.now() + ms).toISOString();
const nonce = (prefix) => prefix + crypto.randomBytes(12).toString("hex");

function makeFacts(overrides = {}) {
  return {
    schema_version: "gov.action.facts.v1",
    action_id: "act_" + crypto.randomBytes(4).toString("hex"),
    lane: LANE,
    component: "adoption-probe",
    action_class: "query",
    summary: "Adoption probe action.",
    target: { type: "service", id: "qdrant" },
    externality: "none",
    reversibility: "reversible",
    blast_radius: "single_target",
    production_effect: "read",
    spend_usd: 0,
    nonce: nonce("probe"),
    issued_at: nowIso(),
    ...overrides
  };
}

async function post(pathname, body) {
  const response = await fetch(base + pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return { status: response.status, body: await response.json() };
}

async function get(pathname) {
  const response = await fetch(base + pathname);
  return { status: response.status, body: await response.json() };
}

const rows = [];

function record(name, ok, detail) {
  rows.push({ row: name, ok, detail });
  console.log((ok ? "PASS" : "FAIL") + "  " + name + (ok ? "" : "  -> " + detail));
}

async function check(name, fn) {
  try {
    const problem = await fn();
    record(name, !problem, problem || "");
  } catch (error) {
    record(name, false, "exception: " + error.message);
  }
}

// Probe-local root used only to spell a traversal target that must be refused.
const proofRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "gov-adoption-probe-")));

const expectAuthorize = (decision, reason) => (result) => {
  if (result.status !== 200) return "http " + result.status;
  if (result.body.decision !== decision) return "decision " + result.body.decision + " (wanted " + decision + "): " + result.body.reason_code;
  if (reason && result.body.reason_code !== reason) return "reason " + result.body.reason_code + " (wanted " + reason + ")";
  return null;
};

// ---- V1 compatibility ----
await check("v1_compat_health", async () => {
  const result = await get("/health");
  if (result.status !== 200 || result.body.ok !== true) return "health not ok";
  if (!/^[0-9a-f]{64}$/.test(result.body.policy_version)) return "policy_version malformed";
  return null;
});

await check("v1_compat_policy_read", async () => {
  const result = await get("/v1/policy");
  if (result.status !== 200 || result.body.policy_id !== "default") return "policy read failed";
  return null;
});

await check("v1_compat_evaluate_enum", async () => {
  const action = JSON.parse(fs.readFileSync(new URL("../samples/action.json", import.meta.url), "utf8"));
  const result = await post("/v1/evaluate", { action });
  if (result.status !== 200) return "http " + result.status;
  if (result.body.decision !== "escalate") return "sample decision " + result.body.decision;
  if (!["allow", "escalate", "block"].includes(result.body.decision)) return "enum broken";
  return null;
});

// ---- /v2/decide compatibility + identity ----
const canaryRequest = canonicalCanaryRequest({});

await check("v2_decide_current_qualified_identity_allow", async () => {
  const result = await post("/v2/decide", { request: canaryRequest });
  if (result.status !== 200) return "http " + result.status;
  if (result.body.decision !== "allow") return "decision " + result.body.decision + ": " + result.body.reason_code;
  if (result.body.execution !== "NOT_CLAIMED_BY_GOVERNANCE") return "execution claim wrong";
  return null;
});

await check("v2_decide_replay_denied", async () => {
  const result = await post("/v2/decide", { request: canaryRequest });
  if (result.body.decision !== "deny" || result.body.reason_code !== "NONCE_REPLAYED") {
    return result.body.decision + "/" + result.body.reason_code;
  }
  return null;
});

await check("v2_decide_stale_identity_precise_denial", async () => {
  const stale = canonicalCanaryRequest({});
  stale.requester = { component: "founder_runtime", source_sha: "a08f4abb908db02db1829730790140946504450c" };
  const result = await post("/v2/decide", { request: stale });
  if (result.body.decision !== "deny" || result.body.reason_code !== "SOURCE_SHA_SUPERSEDED") {
    return result.body.decision + "/" + result.body.reason_code;
  }
  if (!/superseded by fae23008e910b0a93eea31cd3eef36d6adb6b7a6/.test(result.body.reasons[0])) {
    return "reason lacks superseding SHA";
  }
  return null;
});

// ---- /v2/authorize: identity, ceiling and founder authority ----
//
// The one registered component on this configuration, and the source SHA it
// must honestly attest. Anything else is denied before consequence is even
// classified.
const RUNTIME_COMPONENT = "founder_runtime";
const CURRENT_SHA = trustPin();
const SUPERSEDED_SHA = "e64c545adccf47394b1e45e860751816753617b4";
const PRIOR_SUPERSEDED_SHA = "a08f4abb908db02db1829730790140946504450c";
const UNKNOWN_SHA = "0123456789abcdef0123456789abcdef01234567";

function runtimeFacts(overrides = {}) {
  return makeFacts({
    lane: "founder-runtime-lane",
    component: RUNTIME_COMPONENT,
    source_sha: CURRENT_SHA,
    action_class: "status",
    summary: "Read-only organism status observation.",
    target: { type: "observation", id: "organism_status" },
    repository: "NeuruhAI/recipe-engine",
    ...overrides
  });
}

// The exact artifact the EXTERNAL approval channel produces. The probe holds
// the founder secret only because it stands in for that channel here; nothing
// on the requesting side of this boundary ever signs.
function signScopeOnce(facts, overrides = {}, { secret = FOUNDER_SECRET, approver = "founder" } = {}) {
  const issued = overrides.issuedMs === undefined ? Date.now() - 1000 : overrides.issuedMs;
  const ttl = overrides.ttlSeconds === undefined ? 600 : overrides.ttlSeconds;
  const bound = {
    scope_key: overrides.scopeKey === undefined ? scopeKeyFor(facts) : overrides.scopeKey,
    source_sha: overrides.sourceSha === undefined ? facts.source_sha : overrides.sourceSha,
    risk_tier: overrides.riskTier === undefined ? "R0" : overrides.riskTier,
    nonce: overrides.nonce === undefined ? nonce("fapprv") : overrides.nonce,
    issued_at: new Date(issued).toISOString(),
    expires_at: new Date(issued + ttl * 1000).toISOString()
  };

  return signFounderApproval(
    {
      schema_version: FOUNDER_APPROVAL_SCHEMA_VERSION,
      approval_id: "faid_" + crypto.randomBytes(6).toString("hex"),
      approver_id: approver,
      mode: "scope_once",
      bound
    },
    secret
  );
}

await check("authorize_unregistered_component_deny", async () =>
  expectAuthorize("deny", "IDENTITY_UNKNOWN")(
    await post("/v2/authorize", { facts: makeFacts({ component: "adoption-probe", source_sha: CURRENT_SHA }) })
  ));

await check("authorize_unknown_sha_deny", async () =>
  expectAuthorize("deny", "SOURCE_SHA_MISMATCH")(
    await post("/v2/authorize", { facts: runtimeFacts({ source_sha: UNKNOWN_SHA }) })
  ));

await check("authorize_superseded_sha_precise_denial", async () => {
  const result = await post("/v2/authorize", { facts: runtimeFacts({ source_sha: SUPERSEDED_SHA }) });
  const problem = expectAuthorize("deny", "SOURCE_SHA_SUPERSEDED")(result);
  if (problem) return problem;
  if (!new RegExp("superseded by " + CURRENT_SHA).test(result.body.reasons[0])) return "reason lacks superseding SHA";
  return null;
});

await check("authorize_prior_superseded_sha_denied", async () =>
  expectAuthorize("deny", "SOURCE_SHA_SUPERSEDED")(
    await post("/v2/authorize", { facts: runtimeFacts({ source_sha: PRIOR_SUPERSEDED_SHA }) })
  ));

await check("authorize_current_identity_r0_allow", async () => {
  const result = await post("/v2/authorize", { facts: runtimeFacts() });
  const problem = expectAuthorize("allow", "AUTO_ALLOW_OBSERVE")(result);
  if (problem) return problem;
  if (result.body.risk_tier !== "R0") return "risk tier " + result.body.risk_tier;
  if (result.body.execution !== "NOT_CLAIMED_BY_GOVERNANCE") return "execution claim wrong";
  return null;
});

await check("authorize_facts_replay_denied", async () => {
  const facts = runtimeFacts();
  await post("/v2/authorize", { facts });
  return expectAuthorize("deny", "NONCE_REPLAYED")(await post("/v2/authorize", { facts }));
});

// The component is trusted to observe. A mutating action class is not admitted
// for it at all, so no credential it could present reaches consequence.
await check("authorize_mutating_action_class_not_admitted", async () =>
  expectAuthorize("deny", "ACTION_CLASS_NOT_ADMITTED")(
    await post("/v2/authorize", {
      facts: runtimeFacts({ action_class: "git_push", summary: "Push a branch.", target: { type: "branch", id: "feature/x" }, branch: "feature/x" })
    })
  ));

await check("authorize_secret_path_deny", async () =>
  expectAuthorize("deny", "SECRET_ROOT_DENIED")(
    await post("/v2/authorize", {
      facts: runtimeFacts({ action_class: "read", summary: "Read a private key.", target: { type: "path", id: "/Users/nobody/.ssh/id_ed25519" } })
    })
  ));

await check("authorize_path_escape_deny", async () =>
  expectAuthorize("deny", "PATH_ESCAPE")(
    await post("/v2/authorize", {
      facts: runtimeFacts({ action_class: "read", summary: "Traversal read.", target: { type: "path", id: proofRoot + "/../escape.md" } })
    })
  ));

// ---- the external founder decision, over the wire ----
await check("authorize_signed_scope_once_allow", async () => {
  const facts = runtimeFacts();
  const result = await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts) });
  const problem = expectAuthorize("allow", "FOUNDER_APPROVED_SCOPE_ONCE")(result);
  if (problem) return problem;
  if (!result.body.approver_ids.includes("founder")) return "approver not recorded";
  if (result.body.session_scope_used !== false) return "scope_once must never open a session scope";
  if (!result.body.evidence_refs.some((ref) => ref.kind === "founder_approval_consumption")) {
    return "approval consumption not receipted";
  }
  return null;
});

await check("authorize_scope_once_replay_denied", async () => {
  const first = runtimeFacts();
  const approval = signScopeOnce(first);
  await post("/v2/authorize", { facts: first, founder_approval: approval });
  // Fresh facts, same signed approval: the approval nonce is spent.
  return expectAuthorize("deny", "NONCE_REPLAYED")(
    await post("/v2/authorize", { facts: runtimeFacts(), founder_approval: approval })
  );
});

await check("authorize_unsigned_approval_deny", async () => {
  const facts = runtimeFacts();
  const approval = signScopeOnce(facts);
  delete approval.signature;
  return expectAuthorize("deny", "APPROVAL_SIGNATURE_INVALID")(
    await post("/v2/authorize", { facts, founder_approval: approval })
  );
});

await check("authorize_bad_signature_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVAL_SIGNATURE_INVALID")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, {}, { secret: WRONG_SECRET }) })
  );
});

await check("authorize_self_approval_deny", async () => {
  // A lane named "founder" would otherwise be approved by the approver whose id
  // it shares. The boundary refuses a lane founder-approving its own action.
  const facts = runtimeFacts({ lane: "founder" });
  return expectAuthorize("deny", "SELF_APPROVAL")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts) })
  );
});

await check("authorize_unknown_approver_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVER_UNKNOWN")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, {}, { approver: "mission" }) })
  );
});

await check("authorize_scope_mismatch_deny", async () => {
  const facts = runtimeFacts();
  const other = runtimeFacts({ target: { type: "observation", id: "some_other_observation" } });
  return expectAuthorize("deny", "APPROVAL_CONTENT_MISMATCH")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, { scopeKey: scopeKeyFor(other) }) })
  );
});

await check("authorize_version_mismatch_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVAL_SOURCE_MISMATCH")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, { sourceSha: SUPERSEDED_SHA }) })
  );
});

await check("authorize_risk_tier_mismatch_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVAL_RISK_MISMATCH")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, { riskTier: "R3" }) })
  );
});

await check("authorize_expired_approval_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVAL_EXPIRED")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, { issuedMs: Date.now() - 600_000, ttlSeconds: 60 }) })
  );
});

await check("authorize_ttl_beyond_maximum_deny", async () => {
  const facts = runtimeFacts();
  return expectAuthorize("deny", "APPROVAL_TTL_EXCEEDED")(
    await post("/v2/authorize", { facts, founder_approval: signScopeOnce(facts, { ttlSeconds: 4000 }) })
  );
});

const failed = rows.filter((row) => !row.ok);
console.log("\nACCEPTANCE: " + (rows.length - failed.length) + "/" + rows.length + " rows pass" + (failed.length ? " — SEMANTIC FAILURE" : ""));
process.exit(failed.length ? 1 : 0);
