// FounderGrant court: scoped, expiring, receipted, non-transferable,
// path-safe — and never a carrier of R4/R5 authority.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { grantAdmits, grantErrors, grantQualifiesOperation, verifyGrant } from "../src/grants.mjs";
import {
  FOUNDER_SECRET,
  LANE,
  T0,
  iso,
  makeFacts,
  makeGrant,
  makeProofRoot,
  makeV2TrustConfig,
  tempDir
} from "./v2-helpers.mjs";

const config = makeV2TrustConfig();

test("a well-formed grant validates and verifies", () => {
  const grant = makeGrant({ allowed_paths: [makeProofRoot()] });
  assert.deepEqual(grantErrors(grant), []);
  const verification = verifyGrant(grant, config, T0);
  assert.equal(verification.ok, true);
});

test("grants can never carry R4/R5 authority", () => {
  for (const [field, value, pattern] of [
    ["external_contact_permission", true, /external_contact_permission must be false/],
    ["destructive_permission", true, /destructive_permission must be false/],
    ["receipt_required", false, /receipt_required must be true/],
    ["allowed_action_classes", ["spend"], /R4\/R5 class/],
    ["allowed_action_classes", ["force_push"], /R4\/R5 class/],
    ["allowed_action_classes", ["external_message"], /R4\/R5 class/]
  ]) {
    const grant = makeGrant({ [field]: value });
    assert.ok(grantErrors(grant).some((error) => pattern.test(error)), field + "=" + JSON.stringify(value) + " must be refused");
  }
});

test("broad, secret and canonical-governance roots are refused at validation", () => {
  for (const root of [
    "/",
    "/Users",
    "/Users/jeramiehicks",
    "/Users/jeramiehicks/Desktop",
    "/Users/jeramiehicks/.ssh",
    "/Users/jeramiehicks/neuruh-repos/NeuruhAI/autonomous-governance-core/config"
  ]) {
    const grant = makeGrant({ allowed_paths: [root] });
    assert.ok(grantErrors(grant).some((error) => error.includes("allowed_paths root refused")), "must refuse root: " + root);
  }
});

test("unknown fields, wildcards and unknown action classes are refused", () => {
  assert.ok(grantErrors(makeGrant({ surprise: "field" })).some((error) => /Unknown grant field/.test(error)));
  assert.ok(grantErrors(makeGrant({ allowed_repos: ["NeuruhAI/*"] })).some((error) => /wildcards/.test(error)));
  assert.ok(grantErrors(makeGrant({ subject: { lane: "lane-*" } })).some((error) => /exact/.test(error)));
  assert.ok(grantErrors(makeGrant({ allowed_action_classes: ["file_modify"] })).some((error) => /unknown action class/.test(error)));
});

test("forged signature, unknown issuer and non-founder issuer are refused", () => {
  const tampered = { ...makeGrant(), spend_ceiling_usd: 1000 };
  assert.equal(verifyGrant(tampered, config, T0).reason_code, "GRANT_SIGNATURE_INVALID");

  const unknown = makeGrant({ issuer: "nobody" });
  assert.equal(verifyGrant(unknown, config, T0).reason_code, "GRANT_ISSUER_UNKNOWN");

  const reviewer = makeGrant({ issuer: "reviewer-c" }, { issuer: "reviewer-c", secret: "reviewer-c-secret-0123456789abcd" });
  assert.equal(verifyGrant(reviewer, config, T0).reason_code, "GRANT_ISSUER_NOT_ENHANCED");
});

test("expiry semantics: expired, not-yet-valid, and TTL beyond maximum", () => {
  const expired = makeGrant({ issued_at: iso(T0 - 7200 * 1000), expires_at: iso(T0 - 3600 * 1000) });
  assert.equal(verifyGrant(expired, config, T0).reason_code, "GRANT_EXPIRED");

  const future = makeGrant({ issued_at: iso(T0 + 3600 * 1000), expires_at: iso(T0 + 7200 * 1000) });
  assert.equal(verifyGrant(future, config, T0).reason_code, "GRANT_NOT_YET_VALID");

  const decade = makeGrant({ issued_at: iso(T0 - 1000), expires_at: iso(T0 + 10 * 365 * 24 * 3600 * 1000) });
  assert.equal(verifyGrant(decade, config, T0).reason_code, "GRANT_TTL_EXCEEDED");

  const bounded = makeV2TrustConfig();
  bounded.grant_max_ttl_seconds = 3600;
  const dayLong = makeGrant();
  assert.equal(verifyGrant(dayLong, bounded, T0).reason_code, "GRANT_TTL_EXCEEDED");
});

test("grants are non-transferable: wrong lane and wrong repo are hostile", () => {
  const grant = makeGrant();

  const wrongLane = grantAdmits(grant, makeFacts({ lane: "lane-t9-impostor", action_class: "repo_edit", target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" }, repository: "NeuruhAI/autonomous-governance-core", branch: "feature/x" }));
  assert.equal(wrongLane.ok, false);
  assert.equal(wrongLane.hostile, true);
  assert.equal(wrongLane.reason_code, "GRANT_LANE_MISMATCH");

  const wrongRepo = grantAdmits(grant, makeFacts({ action_class: "repo_edit", target: { type: "repo", id: "NeuruhAI/recipe-engine" }, repository: "NeuruhAI/recipe-engine", branch: "feature/x" }));
  assert.equal(wrongRepo.ok, false);
  assert.equal(wrongRepo.hostile, true);
  assert.equal(wrongRepo.reason_code, "GRANT_REPO_MISMATCH");
});

test("denied action classes beat allowed action classes", () => {
  const grant = makeGrant({ denied_action_classes: ["git_push"] });
  const admission = grantAdmits(grant, makeFacts({ action_class: "git_push", target: { type: "branch", id: "feature/x" }, repository: "NeuruhAI/autonomous-governance-core", branch: "feature/x" }));
  assert.equal(admission.ok, false);
  assert.equal(admission.hostile, true);
  assert.equal(admission.reason_code, "GRANT_ACTION_CLASS_DENIED");
});

test("path admission: inside root allows, outside root misses, symlink escapes deny", () => {
  const root = makeProofRoot();
  const grant = makeGrant({ allowed_paths: [root] });

  const inside = grantAdmits(grant, makeFacts({ action_class: "artifact_write", target: { type: "path", id: path.join(root, "RESULT.md") } }));
  assert.equal(inside.ok, true);

  const outside = grantAdmits(grant, makeFacts({ action_class: "artifact_write", target: { type: "path", id: "/private/tmp/elsewhere/RESULT.md" } }));
  assert.equal(outside.ok, false);
  assert.equal(outside.reason_code, "GRANT_PATH_NOT_GRANTED");
  assert.notEqual(outside.hostile, true);

  const escapeTarget = fs.realpathSync(tempDir());
  fs.symlinkSync(escapeTarget, path.join(root, "sneaky"));
  const escaped = grantAdmits(grant, makeFacts({ action_class: "artifact_write", target: { type: "path", id: path.join(root, "sneaky", "RESULT.md") } }));
  assert.equal(escaped.ok, false);
  assert.equal(escaped.hostile, true);
  assert.equal(escaped.reason_code, "PATH_ESCAPE");
});

test("spend ceiling, production permission and rollback requirement gate admission", () => {
  const grant = makeGrant({ spend_ceiling_usd: 5 });

  const overCeiling = grantAdmits(grant, makeFacts({ action_class: "build", spend_usd: 6, target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" }, repository: "NeuruhAI/autonomous-governance-core" }));
  assert.equal(overCeiling.reason_code, "GRANT_SPEND_CEILING_EXCEEDED");

  const production = grantAdmits(makeGrant(), makeFacts({ action_class: "repo_edit", production_effect: "config", target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" }, repository: "NeuruhAI/autonomous-governance-core", branch: "feature/x" }));
  assert.equal(production.reason_code, "GRANT_PRODUCTION_NOT_GRANTED");

  const aliasRoot = makeProofRoot("cli-config");
  const rollbackGrant = makeGrant({ rollback_required: true, allowed_paths: [aliasRoot] });
  const aliasFacts = makeFacts({ action_class: "alias_repair", reversibility: "rollback_known", target: { type: "path", id: path.join(aliasRoot, "aliases.zsh") } });
  const noPlan = grantAdmits(rollbackGrant, aliasFacts);
  assert.equal(noPlan.reason_code, "GRANT_ROLLBACK_REQUIRED");

  const withPlan = grantAdmits(rollbackGrant, { ...aliasFacts, rollback_plan: "restore aliases.zsh.bak (exact rollback known)" });
  assert.equal(withPlan.ok, true);
});

test("qualified operations bind target, rollback, preflight and postflight exactly", () => {
  const grant = makeGrant({
    allowed_action_classes: ["repo_edit", "service_restart"],
    allowed_services: ["axon-worker"],
    production_permission: true,
    qualified_operations: [
      {
        action_class: "service_restart",
        target: { type: "service", id: "axon-worker" },
        rollback: "restart previous label axon-worker@sha-e64c545",
        preflight: "health endpoint 200 before restart",
        postflight: "health endpoint 200 within 60s after restart"
      }
    ]
  });

  assert.deepEqual(grantErrors(grant), []);

  const exact = grantQualifiesOperation(grant, makeFacts({ action_class: "service_restart", target: { type: "service", id: "axon-worker" }, service_label: "axon-worker", production_effect: "service_restart" }));
  assert.equal(exact.ok, true);
  assert.equal(exact.operation.rollback, "restart previous label axon-worker@sha-e64c545");

  const otherService = grantQualifiesOperation(grant, makeFacts({ action_class: "service_restart", target: { type: "service", id: "qdrant" }, service_label: "qdrant", production_effect: "service_restart" }));
  assert.equal(otherService.ok, false);
  assert.equal(otherService.reason_code, "GRANT_OPERATION_NOT_QUALIFIED");

  const missingPostflight = makeGrant({
    qualified_operations: [{ action_class: "service_restart", target: { type: "service", id: "axon-worker" }, rollback: "r", preflight: "p", postflight: "" }]
  });
  assert.ok(grantErrors(missingPostflight).some((error) => /postflight is required/.test(error)));
});
