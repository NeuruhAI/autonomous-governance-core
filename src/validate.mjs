export function validatePolicy(policy) {
  const errors = [];

  if (!policy || typeof policy !== "object") {
    return ["Policy must be a JSON object."];
  }

  if (!policy.policy_id || typeof policy.policy_id !== "string") {
    errors.push("policy_id is required.");
  }

  if (!policy.name || typeof policy.name !== "string") {
    errors.push("name is required.");
  }

  if (!Array.isArray(policy.blocked_domains)) {
    errors.push("blocked_domains must be an array.");
  }

  if (!Array.isArray(policy.requires_approval_tags)) {
    errors.push("requires_approval_tags must be an array.");
  }

  if (policy.max_spend_usd !== undefined && typeof policy.max_spend_usd !== "number") {
    errors.push("max_spend_usd must be a number when provided.");
  }

  if (policy.allowed_tools !== undefined && !Array.isArray(policy.allowed_tools)) {
    errors.push("allowed_tools must be an array when provided.");
  }

  return errors;
}

export function validateAction(action) {
  const errors = [];

  if (!action || typeof action !== "object") {
    return ["Action must be a JSON object."];
  }

  if (!action.action_id || typeof action.action_id !== "string") {
    errors.push("action_id is required.");
  }

  if (!action.actor || typeof action.actor !== "string") {
    errors.push("actor is required.");
  }

  if (!action.tool || typeof action.tool !== "string") {
    errors.push("tool is required.");
  }

  if (!action.domain || typeof action.domain !== "string") {
    errors.push("domain is required.");
  }

  if (action.tags !== undefined && !Array.isArray(action.tags)) {
    errors.push("tags must be an array when provided.");
  }

  if (action.spend_usd !== undefined && typeof action.spend_usd !== "number") {
    errors.push("spend_usd must be a number when provided.");
  }

  if (!action.summary || typeof action.summary !== "string") {
    errors.push("summary is required.");
  }

  return errors;
}

export function assertValidPolicy(policy) {
  const errors = validatePolicy(policy);

  if (errors.length) {
    const error = new Error("Policy validation failed.");
    error.details = errors;
    throw error;
  }
}

export function assertValidAction(action) {
  const errors = validateAction(action);

  if (errors.length) {
    const error = new Error("Action validation failed.");
    error.details = errors;
    throw error;
  }
}
