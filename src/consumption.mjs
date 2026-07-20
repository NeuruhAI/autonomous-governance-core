import { appendToChain, openChain } from "./receipts.mjs";

// One-time-use ledger for approval nonces and request nonces. Consumption is
// atomic within the process (synchronous check + synchronous durable append)
// and durable across restarts (hash-chained JSONL). A consumption attempt
// whose durability is uncertain — a failed or interrupted append — marks the
// nonce consumed in memory anyway: an uncertain nonce is never treated as
// safely unused. Recovery requires explicit operator ledger repair.

export function openConsumptionLedger(path) {
  const chain = openChain(path);
  const consumed = new Set();

  if (!chain.poisoned) {
    for (const entry of chain.entries) {
      if (entry.kind === "nonce_consumption" && typeof entry.nonce === "string") {
        consumed.add(entry.nonce);
      }
    }
  }

  return { chain, consumed, uncertain: new Set() };
}

// Returns { ok: true, entry } or { ok: false, reason_code }.
export function consumeNonce(ledger, { nonce, scope, decision_id, request_hash, consumed_at }) {
  if (typeof nonce !== "string" || nonce.length === 0) {
    return { ok: false, reason_code: "NONCE_MALFORMED" };
  }

  // A nonce already known consumed (or uncertain) reports that specific state
  // even when the ledger has since been poisoned.
  if (ledger.consumed.has(nonce)) {
    return {
      ok: false,
      reason_code: ledger.uncertain.has(nonce) ? "NONCE_UNCERTAIN" : "NONCE_REPLAYED"
    };
  }

  if (ledger.chain.poisoned) {
    return { ok: false, reason_code: "CONSUMPTION_LEDGER_POISONED" };
  }

  // Reserve before writing: even if the append below throws, this nonce can
  // never be presented again as fresh within this process.
  ledger.consumed.add(nonce);

  let entry;

  try {
    entry = appendToChain(ledger.chain, {
      kind: "nonce_consumption",
      nonce,
      scope,
      decision_id,
      request_hash,
      state: "consumed",
      consumed_at
    });
  } catch {
    ledger.uncertain.add(nonce);
    return { ok: false, reason_code: "CONSUMPTION_PERSISTENCE_FAILED" };
  }

  return { ok: true, entry };
}

export function isConsumed(ledger, nonce) {
  return ledger.consumed.has(nonce);
}
