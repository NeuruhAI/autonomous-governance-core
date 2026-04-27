import { makeId } from "./id.mjs";

const auditLog = [];

function maxAuditEntries() {
  return Number(process.env.MAX_AUDIT_ENTRIES || "1000");
}

export function recordDecision(action, decision) {
  const entry = {
    ...decision,
    audit_id: makeId("audit"),
    action,
    created_at: new Date().toISOString()
  };

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
