// scripts/mint-promotion-approval.mjs — founder one-shot approval CLI court.
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

function secureSecretFile(dir) {
  const file = path.join(dir, "founder.secret");
  fs.writeFileSync(file, FOUNDER_SECRET, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

function mint(args, { envSecret = false } = {}) {
  const dir = tempDir();
  const secretFile = secureSecretFile(dir);
  const extraEnv = envSecret ? { GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET } : { GOVERNANCE_FOUNDER_SECRET: undefined };
  const result = spawnSync(process.execPath, [
    SCRIPT,
    ...args,
    "--secret-file", secretFile,
  ], {
    env: { ...process.env, ...extraEnv },
    encoding: "utf8"
  });
  return { ...result, secretFile };
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
  const secretFile = secureSecretFile(dir);
  return { ...built, nowMs, prompted, receiptPath, configPath, secretFile };
}

function mintPrompted(prompted, args = []) {
  return spawnSync(process.execPath, [
    SCRIPT,
    "--receipt", prompted.receiptPath,
    "--source-sha", args.sourceSha || WORKERS_SHA,
    "--config", prompted.configPath,
    "--secret-file", prompted.secretFile,
    ...(args.extra || [])
  ], {
    env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined },
    encoding: "utf8"
  });
}

test("minted scope_once approval lifts the prompted promotion exactly once, on the attested source only", () => {
  const { runtime, nowMs, clock, receiptPath, configPath, secretFile } = promptedRuntime();

  const minted = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA,
    "--config", configPath, "--secret-file", secretFile
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined }, encoding: "utf8" });

  assert.equal(minted.status, 0, minted.stderr);
  const approval = JSON.parse(minted.stdout);
  clock.ms = Date.parse(approval.bound.issued_at) + 1000;
  assert.equal(approval.schema_version, "gov.founder.approval.v1");
  assert.equal(approval.mode, "scope_once");
  assert.equal(approval.bound.source_sha, WORKERS_SHA);
  assert.equal(approval.bound.risk_tier, "R3");
  assert.ok(!minted.stdout.includes(FOUNDER_SECRET) && !minted.stderr.includes(FOUNDER_SECRET), "secret never printed");

  const other = authorizeAction(runtime, promotionFacts(nowMs, 14), { founder_approval: approval });
  assert.equal(other.decision, "deny");
  assert.equal(other.reason_code, "APPROVAL_CONTENT_MISMATCH");

  const allowed = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "FOUNDER_APPROVED_SCOPE_ONCE");
  assert.equal(allowed.execution, "NOT_CLAIMED_BY_GOVERNANCE");

  const replay = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("an approval minted for another executor version is void for the one that presents", () => {
  const { runtime, nowMs, clock, receiptPath, configPath, secretFile } = promptedRuntime();
  const minted = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", OTHER_SHA,
    "--config", configPath, "--secret-file", secretFile
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined }, encoding: "utf8" });
  assert.equal(minted.status, 0, minted.stderr);
  const approval = JSON.parse(minted.stdout);
  clock.ms = Date.parse(approval.bound.issued_at) + 1000;
  const result = authorizeAction(runtime, promotionFacts(nowMs), { founder_approval: approval });
  assert.equal(result.decision, "deny");
  assert.equal(result.reason_code, "APPROVAL_SOURCE_MISMATCH");
});

test("refuses environment signing, missing inputs, insecure secret files, and non-delegable tiers", () => {
  const { receiptPath, configPath, secretFile } = promptedRuntime();

  const envSecret = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA,
    "--config", configPath, "--secret-file", secretFile
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET }, encoding: "utf8" });
  assert.equal(envSecret.status, 1);
  assert.match(envSecret.stderr, /GOVERNANCE_FOUNDER_SECRET is set/);

  const noSecretFile = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA, "--config", configPath
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined }, encoding: "utf8" });
  assert.equal(noSecretFile.status, 1);
  assert.match(noSecretFile.stderr, /--secret-file is required/);

  const noConfig = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA, "--secret-file", secretFile
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined }, encoding: "utf8" });
  assert.equal(noConfig.status, 1);
  assert.match(noConfig.stderr, /--config is required/);

  const badSha = mintPrompted({ receiptPath, configPath, secretFile }, { sourceSha: "not-a-sha" });
  assert.equal(badSha.status, 1);
  assert.match(badSha.stderr, /source-sha/);

  const r4 = mintPrompted({ receiptPath, configPath, secretFile }, { extra: ["--risk-tier", "R4"] });
  assert.equal(r4.status, 1);
  assert.match(r4.stderr, /R4\/R5/);

  const dir = tempDir();
  const looseSecret = path.join(dir, "loose.secret");
  fs.writeFileSync(looseSecret, FOUNDER_SECRET, { mode: 0o644 });
  const loose = spawnSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA,
    "--config", configPath, "--secret-file", looseSecret
  ], { env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined }, encoding: "utf8" });
  assert.equal(loose.status, 1);
  assert.match(loose.stderr, /not be readable by group or other/);

  const tooLong = mintPrompted({ receiptPath, configPath, secretFile }, { extra: ["--ttl-seconds", "999999"] });
  assert.equal(tooLong.status, 1);
  assert.match(tooLong.stderr, /APPROVAL_TTL_EXCEEDED/);
});

test("the founder CLI prints only the approval artifact on stdout", () => {
  const { receiptPath, configPath, secretFile } = promptedRuntime();
  const out = execFileSync(process.execPath, [
    SCRIPT, "--receipt", receiptPath, "--source-sha", WORKERS_SHA,
    "--config", configPath, "--secret-file", secretFile
  ], {
    env: { ...process.env, GOVERNANCE_FOUNDER_SECRET: undefined },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"]
  });
  const parsed = JSON.parse(out);
  assert.equal(typeof parsed.signature, "string");
  assert.deepEqual(Object.keys(parsed.bound).sort(), ["expires_at", "issued_at", "nonce", "risk_tier", "scope_key", "source_sha"]);
});
