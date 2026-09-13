// scripts/mint-promotion-approval.mjs — the founder's one-shot answer to a
// promotion prompt. Courted against the real authorizeAction: the minted
// approval lifts exactly the prompted scope, once, on the attested source, and
// nothing else; the script refuses to mint without the secret, without a
// prompt, or at a tier that is never delegable.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { authorizeAction } from "../src/authorize.mjs";
import { FOUNDER_SECRET, freshAuthorizeRuntime, freshNonce, iso, makeFacts, tempDir } from "./v2-helpers.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "mint-promotion-approval.mjs");
const WORKERS_SHA = "e36d1bf05d22020324aea5cf48a35bb1f83c1495";
const OTHER_SHA = "9ab6886b703913310912c4132c53b0cc32e8acbe";

function promotionRegistered(config) {
  config.expected_source_shas.git_custodian = [WORKERS_SHA];
  config.components.git_custodian = {
    capabilities: ["write"], max_authority_class: "A5", max_risk_tier: "R3",
    allowed_action_classes: ["git_inspect", "read", "merge"]
  };
}

function promotionFacts(nowMs, pr = 13) {
  return makeFacts({
    lane: "honey-pot-promotion",
    component: "git_custodian",
    source_sha: WORKERS_SHA,
    action_class: "merge",
    summary: "promote NeuruhAI/neuruh-workers#" + pr + " into main",
    target: { type: "pull_request", id: "NeuruhAI/neuruh-workers#" + pr },
    repository: "NeuruhAI/neuruh-workers",
    branch: "main",
    reversibility: "rollback_known",
    rollback_plan: "git revert -m 1 <merge_sha> on main",
    blast_radius: "bounded",
    production_effect: "none",
    nonce: freshNonce("fact"),
    issued_at: iso(nowMs - 1000)
  });
}

function mint(args, env = { GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET }) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined, ...env }, encoding: "utf8" });
}

function promptedRuntime() {
  const nowMs = Date.now();
  const built = freshAuthorizeRuntime({ mutateConfig: promotionRegistered, clock: { ms: nowMs } });
  const prompted = authorizeAction(built.runtime, promotionFacts(nowMs));
  assert.equal(prompted.decision, "founder_required");
  assert.equal(prompted.reason_code, "FOUNDER_REQUIRED_NO_GRANT");
  assert.equal(prompted.risk_tier, "R3");
  const dir = tempDir();
  const receiptPath = path.join(dir, "prompt-receipt.json");
  fs.writeFileSync(receiptPath, JSON.stringify(prompted));
  const configPath = path.join(dir, "trust.json");
  fs.writeFileSync(configPath, JSON.stringify(built.config));
  return { ...built, nowMs, prompted, receiptPath, configPath };
}

test("minted scope_once approval lifts the prompted promotion exactly once, on the attested source only", () => {
  const { runtime, nowMs, clock, receiptPath, configPath } = promptedRuntime();

  const minted = mint(["--receipt", receiptPath, "--source-sha", WORKERS_SHA, "--config", configPath]);
  assert.equal(minted.status, 0, minted.stderr);
  const approval = JSON.parse(minted.stdout);
  // The founder signs in real time; the courted surface's clock moves past that moment.
  clock.ms = Date.parse(approval.bound.issued_at) + 1000;
  assert.equal(approval.schema_version, "gov.founder.approval.v1");
  assert.equal(approval.mode, "scope_once");
  assert.equal(approval.bound.source_sha, WORKERS_SHA);
  assert.equal(approval.bound.risk_tier, "R3");
  assert.ok(!minted.stdout.includes(FOUNDER_SECRET) && !minted.stderr.includes(FOUNDER_SECRET), "secret never printed");

  // wrong pull request: the approval is bound to the prompted scope, not to the lane
  const other = authorizeAction(runtime, promotionFacts(nowMs, 14), { founder_approval: approval });
  assert.equal(other.decision, "deny");
  assert.equal(other.reason_code, "APPROVAL_CONTENT_MISMATCH");

  // the prompted scope: allowed, receipted, consumed
  const allowed = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");
  assert.equal(allowed.execution, "NOT_CLAIMED_BY_GOVERNANCE");

  // one-shot: the same artifact never authorizes a second merge
  const replay = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("an approval minted for another executor version is void for the one that presents", () => {
  const { runtime, nowMs, clock, receiptPath } = promptedRuntime();
  const minted = mint(["--receipt", receiptPath, "--source-sha", OTHER_SHA]);
  assert.equal(minted.status, 0, minted.stderr);
  const approval = JSON.parse(minted.stdout);
  clock.ms = Date.parse(approval.bound.issued_at) + 1000;
  const result = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_SOURCE_MISMATCH");
});

test("refuses to mint without the founder secret, without a prompt, or at a non-delegable tier", () => {
  const { receiptPath, configPath } = promptedRuntime();

  const noSecret = mint(["--receipt", receiptPath, "--source-sha", WORKERS_SHA], {});
  assert.equal(noSecret.status, 1);
  assert.match(noSecret.stderr, /GOVERNANCE_FOUNDER_SECRET is required/);

  const noPrompt = mint(["--source-sha", WORKERS_SHA]);
  assert.equal(noPrompt.status, 1);
  assert.match(noPrompt.stderr, /scope-key/);

  const badSha = mint(["--receipt", receiptPath, "--source-sha", "not-a-sha"]);
  assert.equal(badSha.status, 1);
  assert.match(badSha.stderr, /source-sha/);

  const r4 = mint(["--receipt", receiptPath, "--source-sha", WORKERS_SHA, "--risk-tier", "R4"]);
  assert.equal(r4.status, 1);
  assert.match(r4.stderr, /R4\/R5/);

  // a receipt that never prompted (an allow) carries no scope to approve
  const dir = tempDir();
  const allowReceipt = path.join(dir, "allow.json");
  fs.writeFileSync(allowReceipt, JSON.stringify({ decision: "allow", founder_prompt: null }));
  const notPrompted = mint(["--receipt", allowReceipt, "--source-sha", WORKERS_SHA]);
  assert.equal(notPrompted.status, 1);
  assert.match(notPrompted.stderr, /founder_prompt/);

  // --config validation catches a TTL the surface would refuse
  const tooLong = mint(["--receipt", receiptPath, "--source-sha", WORKERS_SHA, "--ttl-seconds", "999999", "--config", configPath]);
  assert.equal(tooLong.status, 1);
  assert.match(tooLong.stderr, /APPROVAL_TTL_EXCEEDED/);
});

test("the script is executable as a founder CLI and prints only the artifact on stdout", () => {
  const { receiptPath } = promptedRuntime();
  const out = execFileSync(process.execPath, [SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA], {
    env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"]
  });
  const parsed = JSON.parse(out);
  assert.equal(typeof parsed.signature, "string");
  assert.deepEqual(Object.keys(parsed.bound).sort(), ["expires_at", "issued_at", "nonce", "risk_tier", "scope_key", "source_sha"]);
});
