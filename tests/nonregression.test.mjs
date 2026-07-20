// Non-regression: the ratified read-only runtime behavior survives UP-2.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { clearAuditLog, listAuditLog } from "../src/audit.mjs";
import { evaluateAction } from "../src/evaluator.mjs";
import { defaultPolicy, policyVersion } from "../src/policy.mjs";
import { verifyChain } from "../src/receipts.mjs";
import { tempDir } from "./helpers.mjs";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

function readSample(name) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, "samples", name), "utf8"));
}

test("ratified default policy content is unchanged", () => {
  const policy = defaultPolicy();
  assert.equal(policy.policy_id, "default");
  assert.deepEqual(policy.blocked_domains, [
    "credential_exposure",
    "unauthorized_scraping",
    "regulated_decisioning",
    "secret_handling"
  ]);
  assert.ok(policy.requires_approval_tags.includes("code_write"));
  assert.equal(policy.max_spend_usd, 0);
  assert.deepEqual(policy.allowed_tools, []);
});

test("sample action still escalates; blocked sample still blocks; enum unchanged", () => {
  clearAuditLog();
  const sample = evaluateAction(readSample("action.json"));
  assert.equal(sample.decision, "escalate");

  const blocked = evaluateAction(readSample("blocked-action.json"));
  assert.equal(blocked.decision, "block");

  for (const decision of [sample, blocked]) {
    assert.ok(["allow", "escalate", "block"].includes(decision.decision));
    assert.equal(typeof decision.risk_score, "number");
    assert.ok(decision.reasons.length > 0);
    assert.ok(decision.required_next_steps.length > 0);
    // UP-2 additive authority reference on every decision.
    assert.equal(decision.policy_id, "default");
    assert.equal(decision.policy_version, policyVersion(defaultPolicy()));
  }

  assert.equal(listAuditLog().length, 2);
});

test("correlation, tenant and principal are additive and echoed", () => {
  clearAuditLog();
  const action = { ...readSample("action.json"), correlation_id: "corr-42", tenant: "neuruh", principal: "founder" };
  const decision = evaluateAction(action);
  assert.equal(decision.correlation_id, "corr-42");
  assert.equal(decision.tenant, "neuruh");
  assert.equal(decision.principal, "founder");
});

test("durable audit chain appends when configured and verifies", () => {
  const auditPath = path.join(tempDir(), "audit.jsonl");
  process.env.GOVERNANCE_AUDIT_LOG = auditPath;

  try {
    clearAuditLog();
    evaluateAction(readSample("action.json"));
    evaluateAction(readSample("blocked-action.json"));
  } finally {
    delete process.env.GOVERNANCE_AUDIT_LOG;
  }

  const verification = verifyChain(auditPath);
  assert.equal(verification.ok, true);
  assert.equal(verification.length, 2);
});

test("server source keeps loopback default and gates caller policy and v2", () => {
  const source = fs.readFileSync(path.join(repoRoot, "src", "server.mjs"), "utf8");
  assert.match(source, /process\.env\.HOST \|\| "127\.0\.0\.1"/);
  assert.match(source, /GOVERNANCE_ALLOW_CALLER_POLICY === "1"/);
  assert.match(source, /GOVERNANCE_DECISION_ENABLED === "1"/);
  assert.doesNotMatch(source, /0\.0\.0\.0/);
});

test("package has no runtime dependencies (Node built-ins only)", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
});

test("live loopback server: health, policy read, caller-policy ignored, v2 closed", async (t) => {
  const port = 18100 + (process.pid % 800);
  const child = spawn(process.execPath, [path.join(repoRoot, "src", "server.mjs")], {
    env: { ...process.env, PORT: String(port), GOVERNANCE_DECISION_ENABLED: "0", GOVERNANCE_ALLOW_CALLER_POLICY: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });

  t.after(() => child.kill("SIGTERM"));

  const base = "http://127.0.0.1:" + port;
  let health = null;

  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(base + "/health");
      health = await response.json();
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  assert.ok(health, "server did not come up on loopback");
  assert.equal(health.ok, true);
  assert.equal(health.service, "autonomous-governance-core");
  assert.equal(health.policy_version, policyVersion(defaultPolicy()));
  // Health carries no identity claim: it can never substitute for identity.
  assert.deepEqual(Object.keys(health).sort(), ["ok", "policy_version", "service"]);

  const policyResponse = await fetch(base + "/v1/policy/default");
  const policyBody = await policyResponse.json();
  assert.equal(policyBody.policy_id, "default");

  // A weakened caller policy must not soften the decision.
  const weakened = await fetch(base + "/v1/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: readSample("blocked-action.json"),
      policy: { policy_id: "weak", name: "weak", blocked_domains: [], requires_approval_tags: [], max_spend_usd: 1000000 }
    })
  });
  const weakenedBody = await weakened.json();
  assert.equal(weakenedBody.decision, "block");
  assert.equal(weakenedBody.policy_id, "default");

  // The v2 decision boundary is closed by default.
  const decide = await fetch(base + "/v2/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request: {} })
  });
  assert.equal(decide.status, 403);
  const decideBody = await decide.json();
  assert.equal(decideBody.ok, false);
});
