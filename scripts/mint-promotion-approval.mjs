#!/usr/bin/env node
// Mint ONE scope_once founder approval for ONE promotion prompt. FOUNDER-RUN.
//
// This is the human half of the promotion seam. When the live surface answers a
// git_custodian merge with `founder_required` (reason FOUNDER_REQUIRED_NO_GRANT),
// its receipt carries a `founder_prompt` whose `scope_key` names the exact
// action coordinates (lane, action class, pull request, repository, base
// branch). The founder decides, and this script turns that decision into the
// only artifact Governance will accept for it: a gov.founder.approval.v1 in
// mode `scope_once`, HMAC-signed with the founder secret, bound to
//
//   scope_key    the prompt's exact scope (never a wildcard, never a pattern)
//   source_sha   the executor identity the decision is made about
//   risk_tier    the classified tier (R3 for a protected-branch merge)
//   nonce        consumed exactly once through the nonce ledger
//   issued_at / expires_at   a window no longer than approval_max_ttl_seconds
//
// It is non-transferable across pull requests (APPROVAL_CONTENT_MISMATCH),
// across executor versions (APPROVAL_SOURCE_MISMATCH) and across time, and it
// never opens a session scope. The signed output goes into the promotion
// packet's optional `founder_approval` field; the executor presents it
// unchanged on its fresh /v2/authorize and merges only on the bound ALLOW.
//
//   GOVERNANCE_FOUNDER_SECRET=... node scripts/mint-promotion-approval.mjs \
//     --receipt <authorize receipt JSON carrying founder_prompt> \
//     --source-sha <40-hex executor identity> \
//     [--risk-tier R3] [--ttl-seconds 900] [--approver founder] \
//     [--config <trust config to validate against>]
//
// `--scope-key <sha256hex>` may replace `--receipt`. With `--config` the
// approval is verified against the real verifier before it is printed, with
// the founder secret stamped into a throwaway probe of that config; nothing is
// written anywhere.
//
// Never committed with a signature, never printed with the secret, never
// minted for a lane the approver is (SELF_APPROVAL is refused by the verifier).
import fs from "node:fs";
import { randomBytes } from "node:crypto";
import {
  FOUNDER_APPROVAL_SCHEMA_VERSION,
  signFounderApproval,
  verifyFounderApproval
} from "../src/authorize.mjs";
import { RISK_TIERS } from "../src/risk.mjs";

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i === -1 ? fallback : process.argv[i + 1];
}

function refuse(message) {
  console.error("refuse: " + message);
  process.exit(1);
}

const secret = process.env.GOVERNANCE_FOUNDER_SECRET;

if (!secret || secret.length < 16 || secret === "RESOLVED_AT_LAUNCH") {
  refuse("GOVERNANCE_FOUNDER_SECRET is required; a founder approval is signed, not configured");
}

const approver = arg("approver", "founder");
const receiptPath = arg("receipt", null);
let scopeKey = arg("scope-key", null);
const sourceSha = String(arg("source-sha", "")).toLowerCase();
let riskTier = arg("risk-tier", null);
const ttlSeconds = Number(arg("ttl-seconds", "900"));
const configPath = arg("config", null);

if (receiptPath) {
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const prompt = receipt.founder_prompt || (receipt.response && receipt.response.founder_prompt) || null;

  if (!prompt || typeof prompt.scope_key !== "string") {
    refuse("--receipt carries no founder_prompt.scope_key; only a founder_required receipt can be approved");
  }

  if (receipt.component === approver || receipt.lane === approver) {
    refuse("a lane cannot founder-approve its own action");
  }

  scopeKey = prompt.scope_key;
  riskTier = riskTier || prompt.risk || receipt.risk_tier || null;
}

if (!scopeKey || !/^[0-9a-f]{64}$/.test(scopeKey)) {
  refuse("--scope-key (or --receipt with founder_prompt.scope_key) must be a sha256 hex scope key");
}

if (!/^[0-9a-f]{40}$/.test(sourceSha)) {
  refuse("--source-sha must be the 40-hex executor identity the decision is about");
}

if (!RISK_TIERS.includes(riskTier)) {
  refuse("--risk-tier must be one of " + RISK_TIERS.join(", ") + " (the prompt's classified tier)");
}

if (riskTier === "R4" || riskTier === "R5") {
  refuse("R4/R5 are never approved by a minted artifact; they stay founder-interactive");
}

if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
  refuse("--ttl-seconds must be a positive integer");
}

const nowMs = Date.now();
const unsigned = {
  schema_version: FOUNDER_APPROVAL_SCHEMA_VERSION,
  approval_id: "fappr_" + randomBytes(12).toString("hex"),
  approver_id: approver,
  mode: "scope_once",
  bound: {
    scope_key: scopeKey,
    source_sha: sourceSha,
    risk_tier: riskTier,
    nonce: "fnonce_" + randomBytes(12).toString("hex"),
    issued_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + ttlSeconds * 1000).toISOString()
  }
};

const approval = signFounderApproval(unsigned, secret);

if (configPath) {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const probe = JSON.parse(JSON.stringify(config));
  probe.approvers = probe.approvers || {};
  probe.approvers[approver] = { secret, enhanced: true };

  const check = verifyFounderApproval(
    approval,
    { facts_hash: null, scope_key: scopeKey, risk_tier: riskTier, source_sha: sourceSha, lane: "(unknown until presented)", component: "(unknown until presented)" },
    probe,
    nowMs
  );

  if (!check.ok) {
    refuse(check.reason_code + ": " + check.detail);
  }
}

console.log(JSON.stringify(approval, null, 2));
console.error(
  "minted: scope_once approval " + approval.approval_id + " for scope " + scopeKey.slice(0, 12) +
    "… on source " + sourceSha.slice(0, 12) + " at " + riskTier + ", expiring " + approval.bound.expires_at +
    " (one-shot; consumed on first use)"
);
