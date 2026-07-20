import fs from "node:fs";
import { canonicalize, sha256Hex } from "./canonical.mjs";

// Hash-chained append-only JSONL ledger, mirroring the estate receipt idiom
// (aegis src/receipt.mjs): entry_hash = sha256(prev_hash + canonical(entry
// without entry_hash)), first entry chains from the literal root "GENESIS".
// Every entry additionally carries a strictly-increasing seq so reordering,
// insertion and interior deletion all break verification; truncation of the
// tail is detected by comparing against an externally held tip hash (each
// decision returns its receipt hash to the caller for exactly this purpose).

export const GENESIS = "GENESIS";

export function entryHash(prevHash, entryWithoutHash) {
  return sha256Hex(prevHash + canonicalize(entryWithoutHash));
}

export function sealEntry(entry, prevHash, seq) {
  const body = { ...entry, seq, prev_hash: prevHash };
  return { ...body, entry_hash: entryHash(prevHash, body) };
}

export function readChain(path) {
  if (!fs.existsSync(path)) return [];

  return fs
    .readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function verifyChain(path) {
  let entries;

  try {
    entries = readChain(path);
  } catch (error) {
    return { ok: false, length: 0, break_at: 0, error: "Unreadable chain: " + error.message };
  }

  let prev = GENESIS;

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const { entry_hash: recorded, ...body } = entry;

    if (entry.seq !== index) {
      return { ok: false, length: entries.length, break_at: index, error: "Sequence mismatch." };
    }

    if (entry.prev_hash !== prev) {
      return { ok: false, length: entries.length, break_at: index, error: "Chain link mismatch." };
    }

    let expected;

    try {
      expected = entryHash(prev, body);
    } catch (error) {
      return { ok: false, length: entries.length, break_at: index, error: "Uncanonical entry: " + error.message };
    }

    if (recorded !== expected) {
      return { ok: false, length: entries.length, break_at: index, error: "Entry hash mismatch." };
    }

    prev = recorded;
  }

  return { ok: true, length: entries.length, tip: prev };
}

export function verifyChainAgainstTip(path, expectedTipHash) {
  const result = verifyChain(path);

  if (!result.ok) return result;

  if (expectedTipHash && result.tip !== expectedTipHash && !(result.length === 0 && expectedTipHash === GENESIS)) {
    return { ...result, ok: false, error: "Tip hash mismatch (possible truncation)." };
  }

  return result;
}

// Stateful appender bound to one chain file. Loading verifies the whole chain;
// a broken chain poisons the appender so every later append fails closed until
// an operator repairs the ledger with explicit recovery evidence.
export function openChain(path) {
  const verification = verifyChain(path);

  const state = {
    path,
    poisoned: !verification.ok,
    poison_reason: verification.ok ? null : verification.error,
    seq: verification.ok ? verification.length : -1,
    tip: verification.ok ? (verification.length ? verification.tip : GENESIS) : null,
    entries: verification.ok ? readChain(path) : []
  };

  return state;
}

export function appendToChain(state, entry) {
  if (state.poisoned) {
    throw new Error("Chain is poisoned and append is refused: " + state.poison_reason);
  }

  const sealed = sealEntry(entry, state.tip, state.seq);
  const line = JSON.stringify(sealed) + "\n";

  try {
    fs.appendFileSync(state.path, line, { encoding: "utf8", flag: "a" });
  } catch (error) {
    // Uncertain durability: poison the in-memory chain so nothing else is
    // appended on top of an unknown tail state.
    state.poisoned = true;
    state.poison_reason = "Append failed: " + error.message;
    throw new Error("Receipt persistence failed: " + error.message);
  }

  state.seq += 1;
  state.tip = sealed.entry_hash;
  state.entries.push(sealed);

  return sealed;
}
