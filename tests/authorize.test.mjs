// The risk-scoped authorization court: every row of the Governance V2 test
// matrix, plus session-scope, prompt-idempotence and replay semantics.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { authorizeAction } from "../src/authorize.mjs";
import { verifyChain } from "../src/receipts.mjs";
import {
  FOUNDER_SECRET,
  T0,
  freshNonce,
  freshAuthorizeRuntime,
  iso,
  makeFacts,
  makeFounderApproval,
  makeGrant,
  makeProofRoot,
  tempDir
} from "./v2-helpers.mjs";

function proofWriteFacts(root, file = "RESULT.md", overrides = {}) {
  return makeFacts({
    action_class: "artifact_write",
    summary: "Write founder-authorized court artifact.",
    target: { type: "path", id: path.join(root, file) },
    reversibility: "reversible",
    ...overrides
  });
}

test("read Qdrant -> ALLOW (R0 observe, receipted)", () => {
  const { runtime, receiptsPath } = freshAuthorizeRuntime();
  const decision = authorizeAction(runtime, makeFacts());
  assert.equal(decision.decision, "allow");
  assert.equal(decision.reason_code, "AUTO_ALLOW_OBSERVE");
  assert.equal(decision.risk_tier, "R0");
  assert.equal(decision.execution, "NOT_CLAIMED_BY_GOVERNANCE");
  assert.ok(decision.decision_receipt_hash);
  assert.equal(verifyChain(receiptsPath).ok, true);
});

test("approved proof write under valid grant -> ALLOW; second write -> ALLOW without any founder prompt", () => {
  const { runtime } = freshAuthorizeRuntime();
  const root = makeProofRoot();
  const grant = makeGrant({ allowed_paths: [root] });

  const first = authorizeAction(runtime, proofWriteFacts(root, "RESULT.md"), { grant });
  assert.equal(first.decision, "allow");
  assert.equal(first.reason_code, "GRANT_BOUNDED_LOCAL");
  assert.equal(first.risk_tier, "R1");
  assert.equal(first.grant_id, grant.grant_id);
  assert.equal(first.founder_prompt, null);

  const second = authorizeAction(runtime, proofWriteFacts(root, "SCREENSHOT_INDEX.md"), { grant });
  assert.equal(second.decision, "allow");
  assert.equal(second.reason_code, "GRANT_BOUNDED_LOCAL");
  assert.equal(second.founder_prompt, null, "repeat write in approved scope must not re-prompt the founder");
});

test("reversible local alias repair under explicit grant -> ALLOW", () => {
  const { runtime } = freshAuthorizeRuntime();
  const root = makeProofRoot("cli-config");
  const grant = makeGrant({ allowed_paths: [root], rollback_required: true });

  const decision = authorizeAction(
    runtime,
    makeFacts({
      action_class: "alias_repair",
      summary: "Repair broken local CLI alias.",
      target: { type: "path", id: path.join(root, "aliases.zsh") },
      reversibility: "rollback_known",
      rollback_plan: "restore aliases.zsh.bak (exact rollback known)"
    }),
    { grant }
  );

  assert.equal(decision.decision, "allow");
  assert.equal(decision.reason_code, "GRANT_BOUNDED_LOCAL");
  assert.equal(decision.risk_tier, "R1");
});

test("feature-branch edit and normal feature push -> ALLOW under lane grant", () => {
  const { runtime } = freshAuthorizeRuntime();
  const grant = makeGrant();

  const edit = authorizeAction(
    runtime,
    makeFacts({
      action_class: "repo_edit",
      summary: "Edit owned repo on feature branch.",
      target: { type: "repo", id: "NeuruhAI/autonomous-governance-core" },
      repository: "NeuruhAI/autonomous-governance-core",
      branch: "policy/risk-scoped-founder-grants-20260816"
    }),
    { grant }
  );
  assert.equal(edit.decision, "allow");
  assert.equal(edit.reason_code, "GRANT_BOUNDED_DEVELOPMENT");
  assert.equal(edit.risk_tier, "R2");

  const push = authorizeAction(
    runtime,
    makeFacts({
      action_class: "git_push",
      summary: "Normal push to feature branch.",
      target: { type: "branch", id: "policy/risk-scoped-founder-grants-20260816" },
      repository: "NeuruhAI/autonomous-governance-core",
      branch: "policy/risk-scoped-founder-grants-20260816"
    }),
    { grant }
  );
  assert.equal(push.decision, "allow");
  assert.equal(push.reason_code, "GRANT_BOUNDED_DEVELOPMENT");
});

test("push to a protected branch is NOT feature development: founder required", () => {
  const { runtime } = freshAuthorizeRuntime();
  const grant = makeGrant();

  const decision = authorizeAction(
    runtime,
    makeFacts({
      action_class: "git_push",
      summary: "Push to main.",
      target: { type: "branch", id: "main" },
      repository: "NeuruhAI/autonomous-governance-core",
      branch: "main"
    }),
    { grant }
  );
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.risk_tier, "R3");
});

test("path escape -> DENY; symlink escape -> DENY", () => {
  const { runtime } = freshAuthorizeRuntime();
  const root = makeProofRoot();
  const grant = makeGrant({ allowed_paths: [root] });

  const traversal = authorizeAction(runtime, proofWriteFacts(root, "../escape.md", { target: { type: "path", id: root + "/../escape.md" } }), { grant });
  assert.equal(traversal.decision, "deny");
  assert.equal(traversal.reason_code, "PATH_ESCAPE");

  const outside = fs.realpathSync(tempDir());
  fs.symlinkSync(outside, path.join(root, "sneaky"));
  const symlink = authorizeAction(runtime, proofWriteFacts(root, path.join("sneaky", "escape.md")), { grant });
  assert.equal(symlink.decision, "deny");
  assert.equal(symlink.reason_code, "PATH_ESCAPE");
});

test("private-key path -> DENY per canonical policy, even under a grant or approval", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts({
    action_class: "read",
    summary: "Read a private key.",
    target: { type: "path", id: "/Users/x/.ssh/id_ed25519" }
  });

  const bare = authorizeAction(runtime, facts);
  assert.equal(bare.decision, "deny");
  assert.equal(bare.reason_code, "SECRET_ROOT_DENIED");

  const approval = makeFounderApproval(facts, runtime, { riskTier: "R5" });
  const approved = authorizeAction(runtime, { ...facts, nonce: freshNonce("fact") }, { founder_approval: approval });
  assert.equal(approved.decision, "deny");
  assert.equal(approved.reason_code, "SECRET_ROOT_DENIED");
});

test("seller SMS -> FOUNDER REQUIRED with one concise prompt", () => {
  const { runtime } = freshAuthorizeRuntime();
  const decision = authorizeAction(
    runtime,
    makeFacts({
      action_class: "external_message",
      summary: "Send seller outreach SMS.",
      target: { type: "channel", id: "sms:+15551230000" },
      externality: "sms"
    })
  );

  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_EXTERNAL");
  assert.equal(decision.risk_tier, "R4");

  const prompt = decision.founder_prompt;
  assert.ok(prompt);
  assert.equal(prompt.risk, "R4");
  assert.equal(prompt.contact, "sms");
  assert.equal(prompt.spend_usd, 0);
  assert.equal(prompt.production_effect, "read");
  assert.equal(prompt.approve_once, true);
  assert.equal(prompt.approve_scope_session, false, "external consequence is never session-approvable");
  assert.ok(typeof prompt.why_human_required === "string" && prompt.why_human_required.length > 0);
  assert.ok(typeof prompt.rollback === "string");
  assert.equal(prompt.grant_expiry, null);
});

test("$100 spend -> FOUNDER REQUIRED", () => {
  const { runtime } = freshAuthorizeRuntime();
  const decision = authorizeAction(
    runtime,
    makeFacts({ action_class: "spend", summary: "Provider spend.", spend_usd: 100, target: { type: "service", id: "provider-billing" } })
  );
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_EXTERNAL");
  assert.equal(decision.founder_prompt.spend_usd, 100);
});

test("production DB delete -> FOUNDER REQUIRED (R5, interactive every time)", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts({
    action_class: "db_drop",
    summary: "Drop production database.",
    target: { type: "database", id: "prod-primary" },
    reversibility: "irreversible",
    blast_radius: "broad",
    production_effect: "customer_data"
  });

  const decision = authorizeAction(runtime, facts);
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_DESTRUCTIVE");
  assert.equal(decision.risk_tier, "R5");
  assert.equal(decision.founder_prompt.approve_scope_session, false);

  // A session-scope approval at R5 is refused outright.
  const sessionApproval = makeFounderApproval(facts, runtime, { mode: "session_scope", riskTier: "R5" });
  const sessionAttempt = authorizeAction(runtime, facts, { founder_approval: sessionApproval });
  assert.equal(sessionAttempt.decision, "deny");
  assert.equal(sessionAttempt.reason_code, "SESSION_SCOPE_FORBIDDEN");
});

test("force push -> FOUNDER REQUIRED even inside a granted repo", () => {
  const { runtime } = freshAuthorizeRuntime();
  const grant = makeGrant();
  const decision = authorizeAction(
    runtime,
    makeFacts({
      action_class: "git_push",
      summary: "Force push.",
      force: true,
      target: { type: "branch", id: "feature/x" },
      repository: "NeuruhAI/autonomous-governance-core",
      branch: "feature/x"
    }),
    { grant }
  );
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_DESTRUCTIVE");
  assert.equal(decision.risk_tier, "R5");
});

test("qualified exact-label restart under explicit grant -> ALLOW; same restart without grant -> FOUNDER REQUIRED", () => {
  const { runtime } = freshAuthorizeRuntime();
  const grant = makeGrant({
    allowed_action_classes: ["service_restart"],
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

  const restartFacts = () =>
    makeFacts({
      action_class: "service_restart",
      summary: "Exact-label restart of axon-worker.",
      target: { type: "service", id: "axon-worker" },
      service_label: "axon-worker",
      production_effect: "service_restart",
      reversibility: "rollback_known",
      rollback_plan: "restart previous label axon-worker@sha-e64c545"
    });

  const qualified = authorizeAction(runtime, restartFacts(), { grant });
  assert.equal(qualified.decision, "allow");
  assert.equal(qualified.reason_code, "GRANT_QUALIFIED_ADOPTION");
  assert.equal(qualified.risk_tier, "R3");
  assert.equal(qualified.founder_prompt, null);

  const ungranted = authorizeAction(runtime, restartFacts());
  assert.equal(ungranted.decision, "founder_required");
  assert.equal(ungranted.reason_code, "FOUNDER_REQUIRED_NO_GRANT");
  assert.equal(ungranted.founder_prompt.approve_scope_session, true, "R3 may be session-approved for the exact scope");
});

test("expired grant -> FOUNDER REQUIRED with the expiry named", () => {
  const { runtime } = freshAuthorizeRuntime();
  const root = makeProofRoot();
  const expired = makeGrant({ allowed_paths: [root], issued_at: iso(T0 - 7200 * 1000), expires_at: iso(T0 - 3600 * 1000) });

  const decision = authorizeAction(runtime, proofWriteFacts(root), { grant: expired });
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "GRANT_EXPIRED");
  assert.equal(decision.grant_id, expired.grant_id);
  assert.equal(decision.founder_prompt.grant_expiry, expired.expires_at);
});

test("wrong lane and wrong repo -> DENY", () => {
  const { runtime } = freshAuthorizeRuntime();
  const root = makeProofRoot();
  const grant = makeGrant({ allowed_paths: [root] });

  const wrongLane = authorizeAction(runtime, proofWriteFacts(root, "RESULT.md", { lane: "lane-t9-impostor" }), { grant });
  assert.equal(wrongLane.decision, "deny");
  assert.equal(wrongLane.reason_code, "GRANT_LANE_MISMATCH");

  const wrongRepo = authorizeAction(
    runtime,
    makeFacts({
      action_class: "repo_edit",
      target: { type: "repo", id: "NeuruhAI/recipe-engine" },
      repository: "NeuruhAI/recipe-engine",
      branch: "feature/x"
    }),
    { grant }
  );
  assert.equal(wrongRepo.decision, "deny");
  assert.equal(wrongRepo.reason_code, "GRANT_REPO_MISMATCH");
});

test("approve once: founder_required, then the exact facts approved once -> ALLOW; replay -> DENY", () => {
  const { runtime, receiptsPath } = freshAuthorizeRuntime();
  const facts = makeFacts({
    action_class: "spend",
    summary: "Provider spend.",
    spend_usd: 42,
    target: { type: "service", id: "provider-billing" }
  });

  const ask = authorizeAction(runtime, facts);
  assert.equal(ask.decision, "founder_required");

  // The pending ask must not burn the facts nonce: the founder-approved
  // re-presentation of the SAME facts is not a replay.
  const approval = makeFounderApproval(facts, runtime, { riskTier: "R4" });
  const approved = authorizeAction(runtime, facts, { founder_approval: approval });
  assert.equal(approved.decision, "allow");
  assert.equal(approved.reason_code, "FOUNDER_APPROVED_ONCE");
  assert.deepEqual(approved.approver_ids, ["founder"]);

  // Replaying the allow (same facts, same approval) is denied.
  const replay = authorizeAction(runtime, facts, { founder_approval: approval });
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");

  // The approval binds these exact facts: different facts cannot reuse it.
  const otherFacts = { ...facts, nonce: freshNonce("fact"), spend_usd: 4200 };
  const misuse = authorizeAction(runtime, otherFacts, { founder_approval: approval });
  assert.equal(misuse.decision, "deny");
  assert.equal(misuse.reason_code, "APPROVAL_CONTENT_MISMATCH");

  assert.equal(verifyChain(receiptsPath).ok, true);
});

test("approve exact scope for session: identical scope stops prompting, different scope still asks", () => {
  const { runtime, clock } = freshAuthorizeRuntime();
  const restartFacts = (nonce, issuedAtMs = T0 - 1000) =>
    makeFacts({
      action_class: "service_restart",
      summary: "Exact-label restart of axon-worker.",
      target: { type: "service", id: "axon-worker" },
      service_label: "axon-worker",
      production_effect: "service_restart",
      nonce,
      issued_at: iso(issuedAtMs)
    });

  const ask = authorizeAction(runtime, restartFacts(freshNonce("fact")));
  assert.equal(ask.decision, "founder_required");
  assert.equal(ask.founder_prompt.approve_scope_session, true);

  const sessionFacts = restartFacts(freshNonce("fact"));
  const approval = makeFounderApproval(sessionFacts, runtime, { mode: "session_scope", riskTier: "R3" });
  const approved = authorizeAction(runtime, sessionFacts, { founder_approval: approval });
  assert.equal(approved.decision, "allow");
  assert.equal(approved.reason_code, "SESSION_SCOPE_APPROVED");
  assert.equal(approved.session_scope_used, true);

  // Same exact scope again: no new prompt, no new approval object needed.
  const repeat = authorizeAction(runtime, restartFacts(freshNonce("fact")));
  assert.equal(repeat.decision, "allow");
  assert.equal(repeat.reason_code, "SESSION_SCOPE_ACTIVE");
  assert.equal(repeat.founder_prompt, null);

  // A DIFFERENT scope is a different question.
  const differentService = authorizeAction(
    runtime,
    makeFacts({
      action_class: "service_restart",
      summary: "Restart qdrant.",
      target: { type: "service", id: "qdrant" },
      service_label: "qdrant",
      production_effect: "service_restart"
    })
  );
  assert.equal(differentService.decision, "founder_required");

  // Session approval expires with its window.
  clock.ms = T0 + 700 * 1000;
  const afterExpiry = authorizeAction(runtime, restartFacts(freshNonce("fact"), clock.ms - 1000));
  assert.equal(afterExpiry.decision, "founder_required");

  // The consumed session approval cannot be replayed to re-register the
  // scope: its one-time nonce is already spent.
  clock.ms = T0;
  const replayRegister = authorizeAction(runtime, restartFacts(freshNonce("fact")), { founder_approval: approval });
  assert.equal(replayRegister.decision, "deny");
  assert.equal(replayRegister.reason_code, "NONCE_REPLAYED");
});

test("no repeated identical prompts: same pending scope returns the same prompt id", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = () =>
    makeFacts({
      action_class: "external_message",
      summary: "Send seller outreach SMS.",
      target: { type: "channel", id: "sms:+15551230000" },
      externality: "sms",
      nonce: freshNonce("fact")
    });

  const first = authorizeAction(runtime, facts());
  assert.equal(first.founder_prompt.already_prompted, false);

  const second = authorizeAction(runtime, facts());
  assert.equal(second.decision, "founder_required");
  assert.equal(second.founder_prompt.already_prompted, true);
  assert.equal(second.founder_prompt.prompt_id, first.founder_prompt.prompt_id);
});

test("forged founder approvals die: bad signature, unknown approver, non-founder approver, tier mismatch", () => {
  const { runtime } = freshAuthorizeRuntime();
  const facts = makeFacts({ action_class: "spend", spend_usd: 10, target: { type: "service", id: "provider-billing" } });

  const forged = makeFounderApproval(facts, runtime, { riskTier: "R4", secret: "not-the-founder-secret-012345678" });
  assert.equal(authorizeAction(runtime, facts, { founder_approval: forged }).reason_code, "APPROVAL_SIGNATURE_INVALID");

  const unknown = makeFounderApproval(facts, runtime, { riskTier: "R4", approver: "nobody", secret: FOUNDER_SECRET });
  assert.equal(authorizeAction(runtime, { ...facts, nonce: freshNonce("fact") }, { founder_approval: unknown }).reason_code, "APPROVER_UNKNOWN");

  const weak = makeFounderApproval(facts, runtime, { riskTier: "R4", approver: "reviewer-c", secret: "reviewer-c-secret-0123456789abcd" });
  assert.equal(authorizeAction(runtime, { ...facts, nonce: freshNonce("fact") }, { founder_approval: weak }).reason_code, "APPROVER_NOT_ENHANCED");

  const wrongTier = makeFounderApproval(facts, runtime, { riskTier: "R1" });
  assert.equal(authorizeAction(runtime, { ...facts, nonce: freshNonce("fact") }, { founder_approval: wrongTier }).reason_code, "APPROVAL_RISK_MISMATCH");
});

test("mutating canonical Governance state is R5 founder-interactive even under a grant", () => {
  const { runtime } = freshAuthorizeRuntime();
  const decision = authorizeAction(
    runtime,
    makeFacts({
      action_class: "repo_edit",
      summary: "Edit canonical trust config.",
      target: { type: "path", id: "/Users/x/neuruh-repos/NeuruhAI/autonomous-governance-core/config/p2b-canary-trust.json" },
      repository: "NeuruhAI/autonomous-governance-core",
      branch: "feature/x"
    }),
    { grant: makeGrant() }
  );
  assert.equal(decision.decision, "founder_required");
  assert.equal(decision.reason_code, "FOUNDER_REQUIRED_DESTRUCTIVE");
  assert.equal(decision.risk_tier, "R5");
});

test("receipts: every outcome is chained; a poisoned chain fails closed", () => {
  const { runtime, receiptsPath } = freshAuthorizeRuntime();
  authorizeAction(runtime, makeFacts());
  authorizeAction(runtime, makeFacts({ action_class: "spend", spend_usd: 1, target: { type: "service", id: "provider-billing" } }));

  const chain = verifyChain(receiptsPath);
  assert.equal(chain.ok, true);
  assert.equal(chain.length, 2);

  runtime.receipts.poisoned = true;
  runtime.receipts.poison_reason = "tampered";
  const decision = authorizeAction(runtime, makeFacts());
  assert.equal(decision.decision, "deny");
  assert.equal(decision.reason_code, "RECEIPT_CHAIN_POISONED");
});
