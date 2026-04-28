import { recordDecision } from "./audit.mjs";
import { defaultPolicy, mergePolicy } from "./policy.mjs";
import { assertValidAction, assertValidPolicy } from "./validate.mjs";

function thresholds() {
  return {
    block: Number(process.env.DEFAULT_BLOCK_THRESHOLD || "80"),
    escalate: Number(process.env.DEFAULT_ESCALATE_THRESHOLD || "35")
  };
}

export function evaluateAction(action, policyOverride) {
  const policy = mergePolicy(defaultPolicy(), policyOverride);

  assertValidAction(action);
  assertValidPolicy(policy);

  const reasons = [];
  let risk = 0;

  if (policy.blocked_domains.includes(action.domain)) {
    risk += 90;
    reasons.push("Blocked domain: " + action.domain);
  }

  if (Array.isArray(policy.allowed_tools) && policy.allowed_tools.length > 0 && !policy.allowed_tools.includes(action.tool)) {
    risk += 30;
    reasons.push("Tool not allowlisted: " + action.tool);
  }

  const tags = Array.isArray(action.tags) ? action.tags : [];
  const approvalTags = tags.filter((tag) => policy.requires_approval_tags.includes(tag));

  if (approvalTags.length > 0) {
    risk += 35;
    reasons.push("Requires approval tag(s): " + approvalTags.join(", "));
  }

  const spend = Number(action.spend_usd || 0);
  const maxSpend = Number(policy.max_spend_usd || 0);

  if (spend > maxSpend) {
    risk += 40;
    reasons.push("Spend exceeds policy limit.");
  }

  if (tags.includes("external_message") && tags.includes("public_publish")) {
    risk += 15;
    reasons.push("External public messaging carries additional review risk.");
  }

  const score = Math.min(100, risk);
  const gate = thresholds();

  let decision = "allow";

  if (score >= gate.block) {
    decision = "block";
  } else if (score >= gate.escalate) {
    decision = "escalate";
  }

  const requiredNextSteps = [];

  if (decision === "block") {
    requiredNextSteps.push("Stop the action.");
    requiredNextSteps.push("Record the policy reason.");
    requiredNextSteps.push("Human owner must approve any override.");
  } else if (decision === "escalate") {
    requiredNextSteps.push("Pause before execution.");
    requiredNextSteps.push("Get human approval if action affects users, money, data, production, or public messaging.");
    requiredNextSteps.push("Log approval decision before continuing.");
  } else {
    requiredNextSteps.push("Proceed with normal logging.");
  }

  return recordDecision(action, {
    action_id: action.action_id,
    decision,
    risk_score: score,
    thresholds: gate,
    reasons: reasons.length ? reasons : ["No policy violations detected."],
    required_next_steps: requiredNextSteps
  });
}
