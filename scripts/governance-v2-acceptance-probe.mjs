#!/usr/bin/env node
// Governance V2 acceptance probe — the FULL adoption matrix over the wire.
//
//   PROBE_FOUNDER_SECRET=<secret> node scripts/governance-v2-acceptance-probe.mjs [base-url]
//
// Runs every adoption matrix row against a running instance (V1 compat,
// /v2/decide identity semantics, /v2/authorize risk semantics) and exits 0
// only when EVERY row matches its expected decision AND reason. This is the
// semantic gate used by the adoption runtime (up-verified) and the deploy
// procedure: any mismatch is a semantic failure that triggers rollback.
//
// The probe only requests decisions; Governance never executes. Probing the
// live port 8848 requires PROBE_ALLOW_LIVE=1 (set by the deploy procedure).
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { signGrant } from "../src/grants.mjs";
import { canonicalCanaryRequest } from "./p2b-canary-decision-probe.mjs";

const base = process.argv[2] || "http://127.0.0.1:18730";
const FOUNDER_SECRET = process.env.PROBE_FOUNDER_SECRET || "";
const LANE = "adoption-probe-lane";
const REPO = "NeuruhAI/autonomous-governance-core";

if (new URL(base).port === "8848" && process.env.PROBE_ALLOW_LIVE !== "1") {
  console.error("refuse: probing the live port 8848 requires PROBE_ALLOW_LIVE=1 (deploy procedure only)");
  process.exit(1);
}

if (FOUNDER_SECRET.length < 16) {
  console.error("refuse: PROBE_FOUNDER_SECRET is required (>=16 chars) to sign probe grants");
  process.exit(1);
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

function makeGrant(overrides = {}) {
  return signGrant(
    {
      schema_version: "gov.grant.v1",
      grant_id: "grant_probe_" + crypto.randomBytes(4).toString("hex"),
      issuer: "founder",
      issued_at: isoIn(-3600 * 1000),
      expires_at: isoIn(24 * 3600 * 1000),
      subject: { lane: LANE },
      allowed_repos: [REPO],
      allowed_paths: [],
      allowed_action_classes: ["artifact_write", "repo_edit", "test_run", "build", "git_commit", "git_push"],
      denied_action_classes: [],
      allowed_services: [],
      production_permission: false,
      external_contact_permission: false,
      spend_ceiling_usd: 0,
      destructive_permission: false,
      rollback_required: false,
      receipt_required: true,
      ...overrides
    },
    FOUNDER_SECRET
  );
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

// Probe-local proof root with a hostile symlink beside honest files.
const proofRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "gov-adoption-probe-")));
const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "gov-adoption-outside-")));
fs.symlinkSync(outside, path.join(proofRoot, "sneaky"));

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
  if (!/superseded by e64c545adccf47394b1e45e860751816753617b4/.test(result.body.reasons[0])) {
    return "reason lacks superseding SHA";
  }
  return null;
});

// ---- /v2/authorize matrix ----
await check("r0_read_allow", async () =>
  expectAuthorize("allow", "AUTO_ALLOW_OBSERVE")(await post("/v2/authorize", { facts: makeFacts() })));

const pathGrant = makeGrant({ allowed_paths: [proofRoot] });

await check("r1_scoped_write_allow_under_grant", async () =>
  expectAuthorize("allow", "GRANT_BOUNDED_LOCAL")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "artifact_write", summary: "Write proof artifact.", target: { type: "path", id: path.join(proofRoot, "RESULT.md") } }),
      grant: pathGrant
    })
  ));

await check("repeat_write_no_reprompt", async () => {
  const result = await post("/v2/authorize", {
    facts: makeFacts({ action_class: "artifact_write", summary: "Write second proof artifact.", target: { type: "path", id: path.join(proofRoot, "SCREENSHOT_INDEX.md") } }),
    grant: pathGrant
  });
  const problem = expectAuthorize("allow", "GRANT_BOUNDED_LOCAL")(result);
  if (problem) return problem;
  if (result.body.founder_prompt !== null) return "unexpected founder prompt on repeat scoped write";
  return null;
});

await check("r2_feature_branch_allow", async () =>
  expectAuthorize("allow", "GRANT_BOUNDED_DEVELOPMENT")(
    await post("/v2/authorize", {
      facts: makeFacts({
        action_class: "repo_edit",
        summary: "Edit owned repo on feature branch.",
        target: { type: "repo", id: REPO },
        repository: REPO,
        branch: "release/governance-v2-adoption-20260816"
      }),
      grant: makeGrant()
    })
  ));

await check("r3_exact_qualified_adoption_allow", async () =>
  expectAuthorize("allow", "GRANT_QUALIFIED_ADOPTION")(
    await post("/v2/authorize", {
      facts: makeFacts({
        action_class: "service_restart",
        summary: "Exact-label restart of axon-worker.",
        target: { type: "service", id: "axon-worker" },
        service_label: "axon-worker",
        production_effect: "service_restart",
        reversibility: "rollback_known",
        rollback_plan: "restart previous label axon-worker@lkg"
      }),
      grant: makeGrant({
        allowed_action_classes: ["service_restart"],
        allowed_services: ["axon-worker"],
        production_permission: true,
        qualified_operations: [
          {
            action_class: "service_restart",
            target: { type: "service", id: "axon-worker" },
            rollback: "restart previous label axon-worker@lkg",
            preflight: "health endpoint 200 before restart",
            postflight: "health endpoint 200 within 60s after restart"
          }
        ]
      })
    })
  ));

await check("expired_grant_founder_required", async () =>
  expectAuthorize("founder_required", "GRANT_EXPIRED")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "artifact_write", summary: "Write under expired grant.", target: { type: "path", id: path.join(proofRoot, "LATE.md") } }),
      grant: makeGrant({ allowed_paths: [proofRoot], issued_at: isoIn(-7200 * 1000), expires_at: isoIn(-3600 * 1000) })
    })
  ));

await check("wrong_repo_deny", async () =>
  expectAuthorize("deny", "GRANT_REPO_MISMATCH")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "repo_edit", summary: "Edit unauthorized repo.", target: { type: "repo", id: "NeuruhAI/recipe-engine" }, repository: "NeuruhAI/recipe-engine", branch: "feature/x" }),
      grant: makeGrant()
    })
  ));

await check("path_escape_deny", async () =>
  expectAuthorize("deny", "PATH_ESCAPE")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "artifact_write", summary: "Traversal write.", target: { type: "path", id: proofRoot + "/../escape.md" } }),
      grant: pathGrant
    })
  ));

await check("symlink_escape_deny", async () =>
  expectAuthorize("deny", "PATH_ESCAPE")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "artifact_write", summary: "Symlink write.", target: { type: "path", id: path.join(proofRoot, "sneaky", "escape.md") } }),
      grant: pathGrant
    })
  ));

await check("secret_path_deny", async () =>
  expectAuthorize("deny", "SECRET_ROOT_DENIED")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "read", summary: "Read a private key.", target: { type: "path", id: "/Users/nobody/.ssh/id_ed25519" } })
    })
  ));

await check("external_contact_founder_required", async () =>
  expectAuthorize("founder_required", "FOUNDER_REQUIRED_EXTERNAL")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "external_message", summary: "Send seller SMS.", target: { type: "channel", id: "sms:+15551230000" }, externality: "sms" })
    })
  ));

await check("spend_founder_required", async () =>
  expectAuthorize("founder_required", "FOUNDER_REQUIRED_EXTERNAL")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "spend", summary: "Provider spend.", spend_usd: 100, target: { type: "service", id: "provider-billing" } })
    })
  ));

await check("destructive_founder_required", async () =>
  expectAuthorize("founder_required", "FOUNDER_REQUIRED_DESTRUCTIVE")(
    await post("/v2/authorize", {
      facts: makeFacts({
        action_class: "db_drop",
        summary: "Drop production database.",
        target: { type: "database", id: "prod-primary" },
        reversibility: "irreversible",
        blast_radius: "broad",
        production_effect: "customer_data"
      })
    })
  ));

await check("force_push_founder_required", async () =>
  expectAuthorize("founder_required", "FOUNDER_REQUIRED_DESTRUCTIVE")(
    await post("/v2/authorize", {
      facts: makeFacts({ action_class: "git_push", summary: "Force push.", force: true, target: { type: "branch", id: "feature/x" }, repository: REPO, branch: "feature/x" }),
      grant: makeGrant()
    })
  ));

const failed = rows.filter((row) => !row.ok);
console.log("\nACCEPTANCE: " + (rows.length - failed.length) + "/" + rows.length + " rows pass" + (failed.length ? " — SEMANTIC FAILURE" : ""));
process.exit(failed.length ? 1 : 0);
