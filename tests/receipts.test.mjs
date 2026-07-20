import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { appendToChain, openChain, readChain, verifyChain, verifyChainAgainstTip, GENESIS } from "../src/receipts.mjs";
import { tempDir } from "./helpers.mjs";

function chainWithEntries(count) {
  const file = path.join(tempDir(), "chain.jsonl");
  const chain = openChain(file);
  for (let index = 0; index < count; index += 1) {
    appendToChain(chain, { kind: "test", index, payload: "entry-" + index });
  }
  return { file, chain };
}

test("empty chain verifies with GENESIS tip", () => {
  const file = path.join(tempDir(), "chain.jsonl");
  const result = verifyChain(file);
  assert.equal(result.ok, true);
  assert.equal(result.length, 0);
  assert.equal(verifyChainAgainstTip(file, GENESIS).ok, true);
});

test("appended chain verifies and links", () => {
  const { file } = chainWithEntries(5);
  const result = verifyChain(file);
  assert.equal(result.ok, true);
  assert.equal(result.length, 5);
  const entries = readChain(file);
  assert.equal(entries[0].prev_hash, GENESIS);
  assert.equal(entries[3].entry_hash, entries[4].prev_hash);
});

test("field tampering breaks verification", () => {
  const { file } = chainWithEntries(4);
  const entries = readChain(file);
  entries[1].payload = "tampered";
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  const result = verifyChain(file);
  assert.equal(result.ok, false);
  assert.equal(result.break_at, 1);
});

test("interior deletion breaks verification", () => {
  const { file } = chainWithEntries(4);
  const entries = readChain(file);
  entries.splice(1, 1);
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(file).ok, false);
});

test("reordering breaks verification", () => {
  const { file } = chainWithEntries(4);
  const entries = readChain(file);
  [entries[1], entries[2]] = [entries[2], entries[1]];
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(file).ok, false);
});

test("tail truncation is caught by the externally held tip", () => {
  const { file } = chainWithEntries(4);
  const entries = readChain(file);
  const tip = entries[3].entry_hash;
  fs.writeFileSync(file, entries.slice(0, 3).map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  assert.equal(verifyChain(file).ok, true);
  const guarded = verifyChainAgainstTip(file, tip);
  assert.equal(guarded.ok, false);
  assert.match(guarded.error, /truncation/i);
});

test("opening a tampered chain poisons appends (fail closed)", () => {
  const { file } = chainWithEntries(3);
  const entries = readChain(file);
  entries[0].payload = "tampered";
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  const chain = openChain(file);
  assert.equal(chain.poisoned, true);
  assert.throws(() => appendToChain(chain, { kind: "test" }), /poisoned/);
});

test("append failure poisons the chain instead of pretending success", () => {
  const missingDir = path.join(tempDir(), "missing", "chain.jsonl");
  const chain = openChain(missingDir);
  assert.equal(chain.poisoned, false);
  assert.throws(() => appendToChain(chain, { kind: "test" }));
  assert.equal(chain.poisoned, true);
});

test("backfill with a fabricated seq breaks verification", () => {
  const { file } = chainWithEntries(3);
  const entries = readChain(file);
  fs.writeFileSync(
    file,
    [JSON.stringify({ kind: "test", seq: 0, prev_hash: GENESIS, entry_hash: entries[0].entry_hash, backfilled: true }),
      ...entries.map((entry) => JSON.stringify(entry))].join("\n") + "\n"
  );
  assert.equal(verifyChain(file).ok, false);
});
