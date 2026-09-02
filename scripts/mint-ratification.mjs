#!/usr/bin/env node
// Mint the signed mutation ratification. FOUNDER-RUN, never committed.
//
// The ratification is signed with the same secret the launcher stamps into the
// trust config, so it cannot live in the repository: a committed ratification
// would either carry a placeholder signature that never verifies, or a real one
// that anyone with the repo could reuse. The founder mints it at launch, the
// same way the founder secret itself is supplied.
//
//   GOVERNANCE_FOUNDER_SECRET=... node scripts/mint-ratification.mjs \
//     --classes artifact_write,report_write,test_run,git_commit,merge \
//     --max-tier R3 --days 30 [--config config/governance-v2-adoption-trust.json]
//
// With --config it prints the whole runtime block ready to splice; without it,
// just the signed artifact. It refuses anything the validator would refuse, so
// a bad ratification is caught here rather than at boundary start-up.

import fs from "node:fs";
import { signRatification, validateRatification, MAX_RATIFIABLE_TIER, RATIFICATION_SCHEMA_VERSION } from "../src/ratification.mjs";

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i === -1 ? fallback : process.argv[i + 1];
}

const secret = process.env.GOVERNANCE_FOUNDER_SECRET;

if (!secret) {
  console.error("refuse: GOVERNANCE_FOUNDER_SECRET is required; a ratification is signed, not configured");
  process.exit(1);
}

const approver = arg("approver", "founder");
const classes = String(arg("classes", "")).split(",").map((c) => c.trim()).filter(Boolean);
const maxTier = arg("max-tier", "R3");
const days = Number(arg("days", "30"));
const configPath = arg("config", null);

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

// Validate against the real config when one is named, so the artifact is proven
// acceptable before it is pasted anywhere.
if (configPath) {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const probe = JSON.parse(JSON.stringify(config));
  probe.approvers = probe.approvers || {};
  probe.approvers[approver] = { secret, enhanced: true };

  try {
    validateRatification(ratification, probe);
  } catch (error) {
    console.error("refuse: " + error.message);
    process.exit(1);
  }

  console.log(JSON.stringify({ runtime: { ...config.runtime, mutation_ratification: ratification } }, null, 2));
} else {
  console.log(JSON.stringify(ratification, null, 2));
}

console.error("minted: " + classes.join(", ") + " up to " + maxTier +
  " (ceiling " + MAX_RATIFIABLE_TIER + "), expiring " + ratification.expires_at);
