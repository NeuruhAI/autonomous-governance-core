// scripts/mint-ratification.mjs — the founder's ratification minter. The key
// comes from a file, never the environment, and the minted artifact is validated
// against the trust config exactly as loaded: a key that is not the configured
// founder secret must be refused with nothing printed.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validateRatification } from "../src/ratification.mjs";
import { FOUNDER_SECRET, makeV2TrustConfig, tempDir } from "./v2-helpers.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "mint-ratification.mjs");
const ARGS = ["--classes", "artifact_write,merge", "--max-tier", "R3", "--days", "7"];

function fixture({ secret = FOUNDER_SECRET, mode = 0o600 } = {}) {
  const dir = tempDir();
  const configPath = path.join(dir, "trust.json");
  const config = makeV2TrustConfig();
  fs.writeFileSync(configPath, JSON.stringify(config));
  const secretPath = path.join(dir, "founder.secret");
  fs.writeFileSync(secretPath, secret + "\n", { mode });
  fs.chmodSync(secretPath, mode);
  return { config, configPath, secretPath };
}

function mint(args, env = {}) {
  const clean = { ...process.env };
  delete clean.GOVERNANCE_FOUNDER_SECRET;
  return spawnSync(process.execPath, [SCRIPT, ...args], { env: { ...clean, ...env }, encoding: "utf8" });
}

test("the configured founder key mints a ratification that validates against the real config", () => {
  const { config, configPath, secretPath } = fixture();
  const r = mint([...ARGS, "--secret-file", secretPath, "--config", configPath]);
  assert.equal(r.status, 0, r.stderr);
  const minted = JSON.parse(r.stdout).runtime.mutation_ratification;
  assert.deepEqual(minted.ratified_action_classes, ["artifact_write", "merge"]);
  assert.equal(minted.max_ratified_tier, "R3");
  validateRatification(minted, config);
});

test("a wrong key is refused: signature does not verify, nothing printed", () => {
  const { configPath, secretPath } = fixture({ secret: "not-the-founder-secret-0123456789" });
  const r = mint([...ARGS, "--secret-file", secretPath, "--config", configPath]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refuse: .*signature does not verify/);
  assert.equal(r.stdout, "");
});

test("the key is never taken from the environment", () => {
  const { configPath, secretPath } = fixture();
  const withEnv = mint([...ARGS, "--secret-file", secretPath, "--config", configPath], { GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET });
  assert.equal(withEnv.status, 1);
  assert.match(withEnv.stderr, /GOVERNANCE_FOUNDER_SECRET is set/);
  assert.equal(withEnv.stdout, "");

  const envOnly = mint([...ARGS, "--config", configPath], { GOVERNANCE_FOUNDER_SECRET: FOUNDER_SECRET });
  assert.equal(envOnly.status, 1);
  assert.equal(envOnly.stdout, "");
});

test("--secret-file is required and must not be readable by group or other", () => {
  const { configPath, secretPath } = fixture({ mode: 0o644 });
  const missing = mint([...ARGS, "--config", configPath]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /--secret-file is required/);

  const loose = mint([...ARGS, "--secret-file", secretPath, "--config", configPath]);
  assert.equal(loose.status, 1);
  assert.match(loose.stderr, /chmod 600/);
  assert.equal(loose.stdout, "");
});

test("--config is required, so the key is always checked against the real config", () => {
  const { secretPath } = fixture();
  const r = mint([...ARGS, "--secret-file", secretPath]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--config is required/);
  assert.equal(r.stdout, "");
});
