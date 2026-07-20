import { makeId } from "./id.mjs";
import { appendToChain, openChain } from "./receipts.mjs";

const auditLog = [];

// UP-2 durable audit: when GOVERNANCE_AUDIT_LOG names a JSONL path, every
// decision is also appended to a hash-chained ledger (the same chain idiom as
// decision receipts). The in-memory ring is unchanged for compatibility.
let durableChain = null;
let durableChainPath = null;

function maxAuditEntries() {
  return Number(process.env.MAX_AUDIT_ENTRIES || "1000");
}

function durableAuditChain() {
  const path = process.env.GOVERNANCE_AUDIT_LOG;

  if (!path) {
    durableChain = null;
    durableChainPath = null;
    return null;
  }

  if (!durableChain || durableChainPath !== path) {
    durableChain = openChain(path);
    durableChainPath = path;
  }

  return durableChain;
}

export function recordDecision(action, decision) {
  const entry = {
    ...decision,
    audit_id: makeId("audit"),
    action,
    created_at: new Date().toISOString()
  };

  const chain = durableAuditChain();

  if (chain) {
    // Durable append happens before the ring so a persistence failure is loud
    // instead of silently leaving only ephemeral state.
    appendToChain(chain, { kind: "evaluation_audit", ...entry });
  }

  auditLog.push(entry);

  const max = maxAuditEntries();

  while (auditLog.length > max) {
    auditLog.shift();
  }

  return entry;
}

export function listAuditLog() {
  return [...auditLog];
}

export function clearAuditLog() {
  auditLog.length = 0;
}
