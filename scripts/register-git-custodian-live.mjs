// NEURUH-O3-AUTHORITY-ACTUATION-20260913 — live trust-config splice.
//
// Registers the `git_custodian` component on the LIVE authorize surface by
// copying, byte for byte, the registration the founder already merged to
// canonical main (autonomous-governance-core d4268fd,
// config/governance-v2-adoption-trust.json): pin e36d1bf, ceiling R3,
// classes git_inspect / read / merge. Nothing is invented here; the block is
// read from a file the caller extracted from the canonical commit.
//
// Optionally splices a FOUNDER-MINTED ratification block (the output of
// scripts/mint-ratification.mjs --config <live>). This script never signs and
// never reads the founder secret: without --ratification the live ratification
// is left exactly as it is, so registration alone confers nothing above R0
// (every mutating class stays sealed MUTATION_NOT_RATIFIED).
//
// Precedent: .p2b-runtime/apply_t02_scope.mjs (T02, 2026-09-04) and the R12
// renewal splice (2026-09-05). Same idiom: validate with the repo's own
// loadTrustConfig, then atomic 0600 temp + rename. Dry-run unless --commit.
//
//   node scripts/register-git-custodian-live.mjs \
//     --live .p2b-runtime/trust.runtime.v2.json \
//     --canonical-block <05_canonical_git_custodian_block_d4268fd.json> \
//     [--ratification <06_minted_runtime_block.json>] [--commit]
import fs from "node:fs";
import path from "node:path";
import { loadTrustConfig } from "../src/trust.mjs";

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i === -1 ? fallback : process.argv[i + 1];
}

const livePath = arg("live", null);
const blockPath = arg("canonical-block", null);
const ratPath = arg("ratification", null);
const commit = process.argv.includes("--commit");

if (!livePath || !blockPath) {
  console.error("usage: --live <trust.runtime.v2.json> --canonical-block <block.json> [--ratification <minted.json>] [--commit]");
  process.exit(1);
}

const before = JSON.parse(fs.readFileSync(livePath, "utf8"));
const block = JSON.parse(fs.readFileSync(blockPath, "utf8"));
const after = JSON.parse(JSON.stringify(before));

const changed = [];
const added = [];

// ---- registration, copied from canonical main ------------------------------
for (const section of ["components", "expected_source_shas", "source_lineage"]) {
  if (!block[section] || !block[section].git_custodian) {
    console.error("refuse: canonical block lacks " + section + ".git_custodian");
    process.exit(1);
  }
  after[section] = after[section] || {};
  const key = section + ".git_custodian";
  if (after[section].git_custodian === undefined) added.push(key);
  else if (JSON.stringify(after[section].git_custodian) !== JSON.stringify(block[section].git_custodian)) changed.push(key);
  after[section].git_custodian = JSON.parse(JSON.stringify(block[section].git_custodian));
}

after.components.git_custodian._scope_note =
  "NEURUH-O3-AUTHORITY-ACTUATION-20260913: registration copied verbatim from " +
  "canonical main d4268fd config/governance-v2-adoption-trust.json (founder-merged " +
  "PR #2, 2026-09-02). Ceiling R3; classes git_inspect, read, merge only. A merge " +
  "still needs a live ratification naming `merge` at R3 AND either a FounderGrant " +
  "whose qualified_operations names the exact pull_request:<repo>#<n>, or one " +
  "scope_once founder approval. Registration alone admits nothing above R0.";

// ---- optional founder-minted ratification -----------------------------------
if (ratPath) {
  const minted = JSON.parse(fs.readFileSync(ratPath, "utf8"));
  const rat = minted.runtime ? minted.runtime.mutation_ratification : minted;
  if (!rat || rat.schema_version !== "gov.ratification.v1" || typeof rat.signature !== "string") {
    console.error("refuse: --ratification is not a signed gov.ratification.v1 block");
    process.exit(1);
  }
  if (JSON.stringify(after.runtime.mutation_ratification) !== JSON.stringify(rat)) {
    changed.push("runtime.mutation_ratification");
  }
  after.runtime.mutation_ratification = rat;
}

// ---- nothing else may move -----------------------------------------------------
const touched = new Set(["components", "expected_source_shas", "source_lineage", "runtime"]);
for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
  if (touched.has(key)) continue;
  if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) {
    console.error("refuse: unexpected drift in top-level key " + key);
    process.exit(1);
  }
}
if (JSON.stringify(before.components.founder_runtime) !== JSON.stringify(after.components.founder_runtime)) {
  console.error("refuse: founder_runtime component must not move");
  process.exit(1);
}
if (JSON.stringify(before.runtime.mode) !== JSON.stringify(after.runtime.mode) || after.runtime.mutation_ratified !== false) {
  console.error("refuse: runtime.mode / mutation_ratified must not move");
  process.exit(1);
}

// ---- validate with the real loader before anything is written ----------------
const tmp = path.join(path.dirname(livePath), ".o3-splice-" + process.pid + ".json");
fs.writeFileSync(tmp, JSON.stringify(after, null, 2) + "\n", { mode: 0o600 });
let validated;
try {
  validated = loadTrustConfig({ GOVERNANCE_TRUST_CONFIG: tmp });
} catch (error) {
  fs.unlinkSync(tmp);
  console.error("VALIDATE = FAIL: " + error.message);
  process.exit(1);
}

const summary = {
  mode: commit ? "COMMIT" : "DRY_RUN",
  added,
  changed,
  validate: "PASS",
  git_custodian: validated.components.git_custodian,
  pin: validated.expected_source_shas.git_custodian,
  founder_runtime_unchanged: JSON.stringify(before.components.founder_runtime) === JSON.stringify(after.components.founder_runtime),
  ratification: {
    changed: changed.includes("runtime.mutation_ratification"),
    classes: validated.runtime.mutation_ratification ? validated.runtime.mutation_ratification.ratified_action_classes : null,
    max_tier: validated.runtime.mutation_ratification ? validated.runtime.mutation_ratification.max_ratified_tier : null,
    expires_at: validated.runtime.mutation_ratification ? validated.runtime.mutation_ratification.expires_at : null
  }
};

if (!commit) {
  fs.unlinkSync(tmp);
  console.log(JSON.stringify(summary, null, 2));
  process.exit(0);
}

fs.renameSync(tmp, livePath);
fs.chmodSync(livePath, 0o600);
console.log(JSON.stringify(summary, null, 2));
