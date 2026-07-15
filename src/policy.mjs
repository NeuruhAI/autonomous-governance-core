export function defaultPolicy() {
  return {
    policy_id: "default",
    name: "Default autonomous governance policy",
    blocked_domains: [
      "credential_exposure",
      "unauthorized_scraping",
      "regulated_decisioning",
      "secret_handling"
    ],
    requires_approval_tags: [
      "spend",
      "external_message",
      "legal",
      "financial",
      "medical",
      "production_write",
      "personal_data",
      "public_publish",
      "code_write",
      "file_modify",
      "worktree_execute",
      "git_commit"
    ],
    max_spend_usd: 0,
    allowed_tools: []
  };
}

export function mergePolicy(basePolicy, overridePolicy) {
  if (!overridePolicy) return basePolicy;

  return {
    ...basePolicy,
    ...overridePolicy,
    blocked_domains: overridePolicy.blocked_domains || basePolicy.blocked_domains,
    requires_approval_tags: overridePolicy.requires_approval_tags || basePolicy.requires_approval_tags,
    allowed_tools: overridePolicy.allowed_tools || basePolicy.allowed_tools
  };
}
