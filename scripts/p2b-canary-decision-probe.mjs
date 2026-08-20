#!/usr/bin/env node
// Canonical P2-B read-only canary decision probe.
//
// Builds THE admitted decision request (the only one the canonical trust
// config config/p2b-canary-trust.json accepts) and POSTs it to a running
// decision runtime. Prints the decision envelope; exits 0 only on "allow".
//
//   node scripts/p2b-canary-decision-probe.mjs [base-url] [--mission <id>]
//
// The request shape below IS the contract the Recipe Engine v2 governance
// client must send (see docs in config/p2b-canary-trust.json).
import crypto from "node:crypto";
import { defaultPolicy, policyVersion } from "../src/policy.mjs";

const base = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "http://127.0.0.1:8848";
const missionFlag = process.argv.indexOf("--mission");
const missionId = missionFlag > -1 ? process.argv[missionFlag + 1] : "mis_p2b_canary_probe";

export function canonicalCanaryRequest({ missionId: mission, nonce, issuedAt } = {}) {
  const m = mission || missionId;
  return {
    schema_version: "gov.decision.request.v1",
    request_id: "req_" + crypto.randomBytes(6).toString("hex"),
    mission_id: m,
    plan_id: "plan_p2b_readonly_canary",
    step_id: "step_governance_decision",
    correlation_id: "corr_" + m,
    causation_id: "cause_p2b_canary",
    requester: {
      component: "founder_runtime",
      // Current qualified Founder Runtime lineage (see source_lineage in
      // config/p2b-canary-trust.json; superseded SHAs are denied precisely).
      source_sha: "520ae4381def8be52486935e1b9c53da31e52202"
    },
    authority_class: "A0",
    operation: "organism_status",
    tool: "observe",
    mutation_class: "read_only",
    evidence_class: "live",
    repository: "NeuruhAI/recipe-engine",
    domain: "organism_status",
    summary: "read-only observation",
    target: { type: "observation", id: "organism_status" },
    args: {},
    requested_capability: "observe",
    policy_version: policyVersion(defaultPolicy()),
    precondition_hash: crypto.createHash("sha256").update("p2b-readonly-canary", "utf8").digest("hex"),
    nonce: nonce || "p2bnonce" + crypto.randomBytes(12).toString("hex"),
    issued_at: issuedAt || new Date().toISOString()
  };
}

if (import.meta.url === "file://" + process.argv[1]) {
  const request = canonicalCanaryRequest({});
  const response = await fetch(base + "/v2/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request })
  });
  const body = await response.json();
  console.log(JSON.stringify(body, null, 1));
  const ok = response.status === 200 && body.decision === "allow" && body.execution === "NOT_CLAIMED_BY_GOVERNANCE";
  console.log("\nPROBE:", ok ? "ALLOW (read-only, receipted)" : "NOT-ALLOW", "| http:", response.status, "| decision:", body.decision, "| reason:", body.reason_code);
  process.exit(ok ? 0 : 1);
}
