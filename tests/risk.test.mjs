// Consequence classification court: risk follows target, scope, externality,
// reversibility, blast radius, spend and production effect — never a broad
// syntactic tag. Escalators only ever raise the tier.
import test from "node:test";
import assert from "node:assert/strict";
import { actionFactsErrors, classifyRisk, featureBranchViolations } from "../src/risk.mjs";
import { makeFacts } from "./v2-helpers.mjs";

function tierOf(overrides, options) {
  return classifyRisk(makeFacts(overrides), options).tier;
}

test("observation stays R0", () => {
  assert.equal(tierOf({}), "R0");
  assert.equal(tierOf({ action_class: "git_inspect", target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" } }), "R0");
  assert.equal(tierOf({ action_class: "health", target: { type: "service", id: "governance" } }), "R0");
});

test("bounded local reversible writes are R1, not founder events", () => {
  assert.equal(
    tierOf({ action_class: "artifact_write", target: { type: "path", id: "/Users/x/Desktop/NEURUH_LIVE_PROOF_20260816/RESULT.md" } }),
    "R1"
  );
  assert.equal(
    tierOf({ action_class: "alias_repair", reversibility: "rollback_known", target: { type: "path", id: "/private/tmp/cli-config/aliases.zsh" } }),
    "R1"
  );
});

test("feature-branch development is R2 and its discipline is enforced", () => {
  const facts = makeFacts({
    action_class: "repo_edit",
    target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" },
    repository: "NeuruhAI/autonomous-governance-core",
    branch: "feature/governance-v2"
  });
  assert.equal(classifyRisk(facts).tier, "R2");
  assert.deepEqual(featureBranchViolations(facts), []);

  assert.ok(featureBranchViolations({ ...facts, branch: "main" }).length > 0);
  assert.ok(featureBranchViolations({ ...facts, force: true }).length > 0);
  assert.ok(featureBranchViolations({ ...facts, externality: "email" }).length > 0);
  assert.ok(featureBranchViolations({ ...facts, production_effect: "config" }).length > 0);
});

test("adoption operations are R3", () => {
  assert.equal(tierOf({ action_class: "merge", target: { type: "branch", id: "main" }, branch: "main" }), "R3");
  assert.equal(tierOf({ action_class: "deploy", target: { type: "service", id: "axon-worker" }, production_effect: "config" }), "R3");
  assert.equal(
    tierOf({ action_class: "service_restart", target: { type: "service", id: "axon-worker" }, production_effect: "service_restart" }),
    "R3"
  );
});

test("external consequence is R4 regardless of the mechanical action", () => {
  assert.equal(tierOf({ action_class: "external_message", externality: "sms", target: { type: "channel", id: "sms:+15551230000" } }), "R4");
  assert.equal(tierOf({ action_class: "spend", spend_usd: 100, target: { type: "service", id: "provider" } }), "R4");
  // Even a "bounded local write" that sends something out escalates.
  assert.equal(tierOf({ action_class: "artifact_write", externality: "publication", target: { type: "path", id: "/opt/neuruh/site/index.html" } }), "R4");
  assert.equal(tierOf({ action_class: "repo_edit", spend_usd: 3, target: { type: "repo", id: "x/y" }, repository: "x/y", branch: "feature/x" }), "R4");
  assert.equal(tierOf({ action_class: "customer_data_mutation", production_effect: "customer_data", target: { type: "database", id: "prod-users" } }), "R4");
});

test("destructive and privileged consequence is R5", () => {
  assert.equal(tierOf({ action_class: "force_push", target: { type: "branch", id: "main" }, branch: "main", force: true }), "R5");
  // Force on an otherwise-normal push escalates by consequence.
  assert.equal(tierOf({ action_class: "git_push", force: true, target: { type: "branch", id: "feature/x" }, branch: "feature/x" }), "R5");
  assert.equal(
    tierOf({ action_class: "db_drop", target: { type: "database", id: "prod-primary" }, reversibility: "irreversible", blast_radius: "broad", production_effect: "customer_data" }),
    "R5"
  );
  assert.equal(tierOf({ action_class: "reboot", target: { type: "service", id: "host" } }), "R5");
  assert.equal(tierOf({ action_class: "read", secret_access: true, target: { type: "path", id: "/Users/x/.ssh/id_ed25519" } }), "R5");
  // Secret path sensitivity escalates even a read.
  assert.equal(tierOf({ action_class: "read", target: { type: "path", id: "/Users/x/.ssh/id_ed25519" } }, { pathSensitivity: "secret" }), "R5");
  // Mutating canonical Governance state is constitutional.
  assert.equal(tierOf({ action_class: "repo_edit", target: { type: "path", id: "/x/autonomous-governance-core/config/p2b-canary-trust.json" }, repository: "NeuruhAI/autonomous-governance-core", branch: "feature/x" }, { pathSensitivity: "governance_canonical" }), "R5");
  // …but merely reading it is not.
  assert.equal(tierOf({ action_class: "read", target: { type: "path", id: "/x/autonomous-governance-core/config/p2b-canary-trust.json" } }, { pathSensitivity: "governance_canonical" }), "R0");
});

test("irreversibility and blast radius escalate", () => {
  assert.equal(tierOf({ action_class: "repo_edit", reversibility: "irreversible", target: { type: "repo", id: "x/y" }, repository: "x/y", branch: "feature/x" }), "R4");
  assert.equal(tierOf({ action_class: "repo_edit", reversibility: "irreversible", blast_radius: "broad", target: { type: "repo", id: "x/y" }, repository: "x/y", branch: "feature/x" }), "R5");
  assert.equal(tierOf({ action_class: "artifact_write", blast_radius: "broad", target: { type: "path", id: "/opt/neuruh/artifacts/out.md" } }), "R4");
});

test("unrecognized consequence fails closed at validation", () => {
  assert.ok(actionFactsErrors(makeFacts({ action_class: "file_modify" })).some((error) => /Unknown action_class/.test(error)));
  assert.ok(actionFactsErrors(makeFacts({ externality: "carrier_pigeon" })).length > 0);
  assert.ok(actionFactsErrors(makeFacts({ blast_radius: "galactic" })).length > 0);
  assert.ok(actionFactsErrors(makeFacts({ spend_usd: undefined })).length > 0);
  assert.ok(actionFactsErrors(makeFacts({ surprise: true })).some((error) => /Unknown facts field/.test(error)));
});
