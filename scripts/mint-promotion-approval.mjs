#!/usr/bin/env node
// Mint ONE scope_once founder approval for ONE promotion prompt. FOUNDER-RUN.
//
// The approval is signed from a founder secret supplied through a 0600
// --secret-file and validated against the unmodified trust config supplied by
// --config. The environment variable is deliberately forbidden so a stale,
// inherited, or accidentally logged process environment can never become the
// signing source.
//
// Never committed with a signature, never printed with the secret, never
// minted for R4/R5, and never widened beyond the exact prompted scope.

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

if (process.env.GOVERNANCE_FOUNDER_SECRET !== undefined) {
  refuse("GOVERNANCE_FOUNDER_SECRET is set; the key is read from --secret-file only (unset it)");
}

const secretFile = arg("secret-file", null);
const configPath = arg("config", null);
if (!secretFile) refuse("--secret-file is required; a founder approval is signed, not configured");
if (!configPath) refuse("--config is required; the artifact is validated against the real trust config");

let secret;
try {
  const stat = fs.lstatSync(secretFile);
  if (!stat.isFile()) refuse("--secret-file must be a regular file");
  if (stat.mode & 0o077) refuse("--secret-file must not be readable by group or other (chmod 600)");
  secret = fs.readFileSync(secretFile, "utf8").trim();
} catch (error) {
  refuse("cannot read --secret-file: " + error.code);
}
if (!secret || secret.length < 16 || secret === "RESOLVED_AT_LAUNCH") {
  refuse("--secret-file must contain a real founder secret (>=16 chars, not the placeholder)");
}

let config;
try {
  config = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch (error) {
  refuse("cannot read --config: " + error.message);
}

const approver = arg("approver", "founder");
const receiptPath = arg("receipt", null);
let scopeKey = arg("scope-key", null);
const sourceSha = String(arg("source-sha", "")).toLowerCase();
let riskTier = arg("risk-tier", null);
const ttlSeconds = Number(arg("ttl-seconds", "900"));

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

const check = verifyFounderApproval(
  approval,
  {
    facts_hash: null,
    scope_key: scopeKey,
    risk_tier: riskTier,
    source_sha: sourceSha,
    lane: "(unknown until presented)",
    component: "(unknown until presented)"
  },
  config,
  nowMs
);

if (!check.ok) {
  refuse(check.reason_code + ": " + check.detail);
}

console.log(JSON.stringify(approval, null, 2));
console.error(
  "minted: scope_once approval " + approval.approval_id + " for scope " + scopeKey.slice(0, 12) +
    "… on source " + sourceSha.slice(0, 12) + " at " + riskTier + ", expiring " + approval.bound.expires_at +
    " (one-shot; consumed on first use)"
);
