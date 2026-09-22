#!/usr/bin/env node
// Mint the signed mutation ratification. FOUNDER-RUN, never committed.
//
// The ratification is signed with the same secret the launcher stamps into the
// trust config, so it cannot live in the repository: a committed ratification
// would either carry a placeholder signature that never verifies, or a real one
// that anyone with the repo could reuse. The founder mints it at launch.
//
//   node scripts/mint-ratification.mjs --secret-file ~/.neuruh/governance-founder.secret \
//     --classes artifact_write,report_write,test_run,git_commit,merge \
//     --max-tier R3 --days 30 --config config/governance-v2-adoption-trust.json
//
// The key is read from --secret-file (a regular file, not readable by group or
// other) and never from the environment: GOVERNANCE_FOUNDER_SECRET being set is a
// refusal, so a stale invocation fails loudly instead of leaking the key into
// the process environment. The artifact is validated against the UNMODIFIED
// --config, so a key that is not the configured approver's secret is refused and
// nothing is printed. On success it prints the whole runtime block ready to splice.

import fs from "node:fs";
import { signRatification, validateRatification, MAX_RATIFIABLE_TIER, RATIFICATION_SCHEMA_VERSION } from "../src/ratification.mjs";

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i === -1 ? fallback : process.argv[i + 1];
}

function refuse(message) {
  console.error("refuse: " + message);
  process.exit(1);
}

if (process.env.GOVERNANCE_FOUNDER_SECRET !== undefined) {
  refuse("GOVERNANCE_FOUNDER_SECRET is set; the key is read from --secret-file only (unset it)");
}

const secretFile = arg("secret-file", null);
if (!secretFile) refuse("--secret-file is required; a ratification is signed, not configured");

let secret;
try {
  const stat = fs.lstatSync(secretFile);
  if (!stat.isFile()) refuse("--secret-file must be a regular file");
  if (stat.mode & 0o077) refuse("--secret-file must not be readable by group or other (chmod 600)");
  secret = fs.readFileSync(secretFile, "utf8").trim();
} catch (error) {
  refuse("cannot read --secret-file: " + error.code);
}
if (!secret) refuse("--secret-file is empty");

const approver = arg("approver", "founder");
const classes = String(arg("classes", "")).split(",").map((c) => c.trim()).filter(Boolean);
const maxTier = arg("max-tier", "R3");
const days = Number(arg("days", "30"));
const configPath = arg("config", null);

if (!configPath) refuse("--config is required; the artifact is validated against the real trust config");

if (!classes.length) {
  console.error("refuse: --classes is required; a ratification names exactly what it ratifies");
  process.exit(1);
}

if (!Number.isFinite(days) || days <= 0) {
  console.error("refuse: --days must be a positive number");
  process.exit(1);
}

const now = Date.now();
const unsigned = {
  schema_version: RATIFICATION_SCHEMA_VERSION,
  ratified_by: approver,
  ratified_at: new Date(now).toISOString(),
  expires_at: new Date(now + days * 24 * 3600 * 1000).toISOString(),
  max_ratified_tier: maxTier,
  ratified_action_classes: classes
};

const ratification = signRatification(unsigned, secret);

// Validate against the real config exactly as loaded. The approver's secret is
// never substituted: if the key file is not the configured key, this refuses.
let config;
try {
  config = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch (error) {
  refuse("cannot read --config: " + error.message);
}

try {
  validateRatification(ratification, config);
} catch (error) {
  refuse(error.message);
}

console.log(JSON.stringify({ runtime: { ...config.runtime, mutation_ratification: ratification } }, null, 2));

console.error("minted: " + classes.join(", ") + " up to " + maxTier +
  " (ceiling " + MAX_RATIFIABLE_TIER + "), expiring " + ratification.expires_at);
