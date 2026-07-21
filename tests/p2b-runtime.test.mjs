// P2-B decision runtime: canonical trust config admits exactly one read-only
// canary decision; everything else fails closed. Includes live launcher and
// server fail-closed proofs.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { createDecisionRuntime, decideRequest } from "../src/decision.mjs";
import { validateTrustConfig, TrustConfigError } from "../src/trust.mjs";
import { verifyChain } from "../src/receipts.mjs";
import { canonicalCanaryRequest } from "../scripts/p2b-canary-decision-probe.mjs";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const RE_SHA = "a08f4abb908db02db1829730790140946504450c";
const GOV_SHA = () => execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"]).toString().trim();

function canonicalConfig() {
  const raw = JSON.parse(fs.readFileSync(path.join(repoRoot, "config", "p2b-canary-trust.json"), "utf8"));
  assert.equal(raw.implementation_sha, "RESOLVED_AT_LAUNCH");
  raw.implementation_sha = GOV_SHA();
  return validateTrustConfig(raw);
}

function freshRuntime() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gov-p2b-"));
  const receiptsPath = path.join(dir, "receipts.jsonl");
  return {
    runtime: createDecisionRuntime({
      config: canonicalConfig(),
      receiptsPath,
      consumptionPath: path.join(dir, "consumption.jsonl")
    }),
    receiptsPath
  };
}

test("canonical config is A0-read-only by construction (no approvers, one op)", () => {
  const config = canonicalConfig();
  assert.deepEqual(Object.keys(config.approvers), []);
  assert.equal(config.components.founder_runtime.max_authority_class, "A0");
  assert.deepEqual(Object.keys(config.tools), ["observe"]);
  assert.deepEqual(Object.keys(config.tools.observe.operations), ["organism_status"]);
  assert.equal(config.tools.observe.operations.organism_status.mutation_class, "read_only");
  assert.equal(config.runtime.mutation_ratified, false);
});

test("exact canonical read-only request succeeds, receipted, no execution claim", () => {
  const { runtime, receiptsPath } = freshRuntime();
  const decision = decideRequest(runtime, canonicalCanaryRequest({}));
  assert.equal(decision.decision, "allow");
  assert.equal(decision.reason_code, "POLICY_ALLOW");
  assert.equal(decision.execution, "NOT_CLAIMED_BY_GOVERNANCE");
  assert.equal(decision.mutation_class, "read_only");
  assert.ok(decision.decision_receipt_hash);
  const chain = verifyChain(receiptsPath);
  assert.equal(chain.ok, true);
  assert.equal(chain.length, 1);
});

test("wrong Recipe Engine SHA rejected", () => {
  const { runtime } = freshRuntime();
  const request = canonicalCanaryRequest({});
  request.requester = { component: "founder_runtime", source_sha: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" };
  const decision = decideRequest(runtime, request);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "SOURCE_SHA_MISMATCH");
});

test("unknown service rejected", () => {
  const { runtime } = freshRuntime();
  const request = canonicalCanaryRequest({});
  request.requester = { component: "impostor_service", source_sha: RE_SHA };
  const decision = decideRequest(runtime, request);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "IDENTITY_UNKNOWN");
});

test("mutation-like requests rejected", () => {
  const { runtime } = freshRuntime();

  const upgraded = canonicalCanaryRequest({});
  upgraded.mutation_class = "persistent_write";
  const upgradedDecision = decideRequest(runtime, upgraded);
  assert.equal(upgradedDecision.decision, "deny");
  assert.equal(upgradedDecision.reason_code, "MUTATION_CLASS_MISMATCH");

  const writeTool = canonicalCanaryRequest({});
  writeTool.tool = "git";
  writeTool.operation = "push_branch";
  const writeDecision = decideRequest(runtime, writeTool);
  assert.equal(writeDecision.decision, "deny");
  assert.equal(writeDecision.reason_code, "TOOL_UNKNOWN");
});

test("altered decision purpose rejected (domain and target pins)", () => {
  const { runtime } = freshRuntime();

  const alteredDomain = canonicalCanaryRequest({});
  alteredDomain.domain = "engineering_ops";
  const domainDecision = decideRequest(runtime, alteredDomain);
  assert.equal(domainDecision.decision, "deny");
  assert.equal(domainDecision.reason_code, "DOMAIN_MISMATCH");

  const alteredTarget = canonicalCanaryRequest({});
  alteredTarget.target = { type: "observation", id: "production_database" };
  const targetDecision = decideRequest(runtime, alteredTarget);
  assert.equal(targetDecision.decision, "deny");
  assert.equal(targetDecision.reason_code, "TARGET_NOT_ADMITTED");
});

test("fixture evidence class rejected in the live runtime", () => {
  const { runtime } = freshRuntime();
  const request = canonicalCanaryRequest({});
  request.evidence_class = "fixture";
  const decision = decideRequest(runtime, request);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "EVIDENCE_CLASS_MISMATCH");
});

test("stronger authority claim rejected; no approver can ever exist", () => {
  const { runtime } = freshRuntime();
  const request = canonicalCanaryRequest({});
  request.authority_class = "A2";
  const decision = decideRequest(runtime, request);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "AUTHORITY_EXCEEDED");
});

test("missing evidence rejected (precondition hash required)", () => {
  const { runtime } = freshRuntime();
  const request = canonicalCanaryRequest({});
  delete request.precondition_hash;
  const decision = decideRequest(runtime, request);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "MALFORMED_REQUEST");
});

test("replay is deterministic, denied and receipted", () => {
  const { runtime, receiptsPath } = freshRuntime();
  const request = canonicalCanaryRequest({});
  assert.equal(decideRequest(runtime, request).decision, "allow");

  const replay1 = decideRequest(runtime, request);
  const replay2 = decideRequest(runtime, request);
  assert.equal(replay1.decision, "deny");
  assert.equal(replay1.reason_code, "NONCE_REPLAYED");
  assert.equal(replay2.decision, "deny");
  assert.equal(replay2.reason_code, "NONCE_REPLAYED");

  const chain = verifyChain(receiptsPath);
  assert.equal(chain.ok, true);
  assert.equal(chain.length, 3);
});

test("malformed purpose-pin configs are refused at validation", () => {
  for (const mutate of [
    (config) => { config.tools.observe.operations.organism_status.domains = []; },
    (config) => { config.tools.observe.operations.organism_status.domains = [42]; },
    (config) => { config.tools.observe.operations.organism_status.targets = [{ type: "observation" }]; },
    (config) => { config.tools.observe.operations.organism_status.repositories = "NeuruhAI/recipe-engine"; }
  ]) {
    const raw = JSON.parse(fs.readFileSync(path.join(repoRoot, "config", "p2b-canary-trust.json"), "utf8"));
    raw.implementation_sha = GOV_SHA();
    mutate(raw);
    assert.throws(() => validateTrustConfig(raw), TrustConfigError);
  }
});

// ---- live server / launcher proofs ----

function spawnServer(envOverrides, port) {
  const child = spawn(process.execPath, [path.join(repoRoot, "src", "server.mjs")], {
    env: { ...process.env, PORT: String(port), ...envOverrides },
    stdio: ["ignore", "pipe", "pipe"]
  });
  return child;
}

async function waitHealth(base) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(base + "/health");
      if (response.ok) return true;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }
  return false;
}

test("disabled / unconfigured / malformed-config runtimes fail closed (403)", async (t) => {
  const cases = [
    { name: "disabled", env: { GOVERNANCE_DECISION_ENABLED: "0" } },
    { name: "enabled-no-config", env: { GOVERNANCE_DECISION_ENABLED: "1", GOVERNANCE_TRUST_CONFIG: "" } },
    {
      name: "enabled-malformed-config",
      env: (() => {
        const bad = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "gov-bad-")), "trust.json");
        fs.writeFileSync(bad, JSON.stringify({ config_version: "gov.trust.v1", approvers: "not-an-object" }));
        return { GOVERNANCE_DECISION_ENABLED: "1", GOVERNANCE_TRUST_CONFIG: bad };
      })()
    }
  ];

  let port = 18500 + (process.pid % 400);

  for (const scenario of cases) {
    port += 1;
    const child = spawnServer({ HOST: "127.0.0.1", ...scenario.env }, port);
    t.after(() => child.kill("SIGTERM"));
    const base = "http://127.0.0.1:" + port;
    assert.ok(await waitHealth(base), scenario.name + ": server up");
    const decide = await fetch(base + "/v2/decide", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request: canonicalCanaryRequest({}) })
    });
    assert.equal(decide.status, 403, scenario.name + " must be closed");
    child.kill("SIGTERM");
  }
});

test("non-loopback binding keeps the decision runtime closed", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gov-loop-"));
  const raw = JSON.parse(fs.readFileSync(path.join(repoRoot, "config", "p2b-canary-trust.json"), "utf8"));
  raw.implementation_sha = GOV_SHA();
  const configPath = path.join(dir, "trust.json");
  fs.writeFileSync(configPath, JSON.stringify(raw));

  const port = 18950 + (process.pid % 40);
  const child = spawnServer({
    HOST: "0.0.0.0",
    GOVERNANCE_DECISION_ENABLED: "1",
    GOVERNANCE_TRUST_CONFIG: configPath,
    GOVERNANCE_RECEIPTS_LOG: path.join(dir, "receipts.jsonl"),
    GOVERNANCE_CONSUMPTION_LOG: path.join(dir, "consumption.jsonl")
  }, port);
  t.after(() => child.kill("SIGTERM"));

  const base = "http://127.0.0.1:" + port;
  assert.ok(await waitHealth(base));
  const decide = await fetch(base + "/v2/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request: canonicalCanaryRequest({}) })
  });
  assert.equal(decide.status, 403);
  const body = await decide.json();
  assert.match(body.error, /loopback/);
  child.kill("SIGTERM");
});

test("launcher refuses a wrong Governance SHA; accepts the exact SHA end-to-end", async (t) => {
  const script = path.join(repoRoot, "scripts", "p2b-decision-runtime.sh");

  assert.throws(() =>
    execFileSync("bash", [script, "up", "18990"], {
      env: { ...process.env, GOVERNANCE_EXPECTED_SHA: "0000000000000000000000000000000000000000" },
      stdio: "pipe"
    })
  );
  assert.throws(() =>
    execFileSync("bash", [script, "up", "18990"], { env: { ...process.env, GOVERNANCE_EXPECTED_SHA: "" }, stdio: "pipe" })
  );

  // The runtime receipts chain is append-only across restarts: assert growth,
  // not absolute length.
  const chainPath = path.join(repoRoot, ".p2b-runtime", "receipts.jsonl");
  const before = verifyChain(chainPath);
  assert.equal(before.ok, true, "pre-existing runtime chain must verify");

  const port = 18990;
  execFileSync("bash", [script, "up", String(port)], {
    env: { ...process.env, GOVERNANCE_EXPECTED_SHA: GOV_SHA() },
    stdio: "pipe"
  });
  t.after(() => { try { execFileSync("bash", [script, "down"], { stdio: "pipe" }); } catch {} });

  const base = "http://127.0.0.1:" + port;
  assert.ok(await waitHealth(base));

  // P2-B read contract: the adapter's default_policy() reads /v1/policy.
  const policyRead = await fetch(base + "/v1/policy");
  const policyBody = await policyRead.json();
  assert.equal(policyRead.status, 200);
  assert.match(policyBody.policy_version, /^[0-9a-f]{64}$/);
  assert.equal(policyBody.policy_id, "default");

  const request = canonicalCanaryRequest({});
  const first = await fetch(base + "/v2/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request })
  });
  const firstBody = await first.json();
  assert.equal(first.status, 200);
  assert.equal(firstBody.decision, "allow");
  assert.equal(firstBody.execution, "NOT_CLAIMED_BY_GOVERNANCE");
  assert.ok(firstBody.decision_receipt_hash);

  // replay over the live wire: denied, deterministic, receipted
  const replay = await fetch(base + "/v2/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request })
  });
  const replayBody = await replay.json();
  assert.equal(replayBody.decision, "deny");
  assert.equal(replayBody.reason_code, "NONCE_REPLAYED");

  execFileSync("bash", [script, "down"], { stdio: "pipe" });
  const chain = verifyChain(chainPath);
  assert.equal(chain.ok, true);
  assert.equal(chain.length, before.length + 2);
});
