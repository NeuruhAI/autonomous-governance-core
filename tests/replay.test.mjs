import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createDecisionRuntime, decideRequest } from "../src/decision.mjs";
import { consumeNonce, openConsumptionLedger } from "../src/consumption.mjs";
import { readChain, verifyChain } from "../src/receipts.mjs";
import { T0, freshNonce, freshRuntime, iso, makeA5Request, makeApproval, tempDir } from "./helpers.mjs";

test("consumption is one-time: the second consume of a nonce is refused", () => {
  const ledger = openConsumptionLedger(path.join(tempDir(), "consumption.jsonl"));
  const first = consumeNonce(ledger, { nonce: "nonce-aaaaaaaaaaaa", scope: "approval", decision_id: "dec_1", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(first.ok, true);
  const second = consumeNonce(ledger, { nonce: "nonce-aaaaaaaaaaaa", scope: "approval", decision_id: "dec_2", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(second.ok, false);
  assert.equal(second.reason_code, "NONCE_REPLAYED");
});

test("consumption survives restart: a reopened ledger still refuses the nonce", () => {
  const file = path.join(tempDir(), "consumption.jsonl");
  const ledger = openConsumptionLedger(file);
  assert.equal(consumeNonce(ledger, { nonce: "nonce-bbbbbbbbbbbb", scope: "approval", decision_id: "dec_1", request_hash: "h", consumed_at: iso(T0) }).ok, true);

  const reopened = openConsumptionLedger(file);
  const replay = consumeNonce(reopened, { nonce: "nonce-bbbbbbbbbbbb", scope: "approval", decision_id: "dec_3", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("a failed consumption append marks the nonce uncertain, never safely unused", () => {
  const file = path.join(tempDir(), "missing-dir", "consumption.jsonl");
  const ledger = openConsumptionLedger(file);
  const attempt = consumeNonce(ledger, { nonce: "nonce-cccccccccccc", scope: "approval", decision_id: "dec_1", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(attempt.ok, false);
  assert.equal(attempt.reason_code, "CONSUMPTION_PERSISTENCE_FAILED");

  const retry = consumeNonce(ledger, { nonce: "nonce-cccccccccccc", scope: "approval", decision_id: "dec_2", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(retry.ok, false);
  assert.equal(retry.reason_code, "NONCE_UNCERTAIN");
});

test("a tampered consumption ledger poisons all further consumption", () => {
  const file = path.join(tempDir(), "consumption.jsonl");
  const ledger = openConsumptionLedger(file);
  consumeNonce(ledger, { nonce: "nonce-dddddddddddd", scope: "approval", decision_id: "dec_1", request_hash: "h", consumed_at: iso(T0) });

  const entries = readChain(file);
  entries[0].nonce = "nonce-swapped00000";
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");

  const reopened = openConsumptionLedger(file);
  const attempt = consumeNonce(reopened, { nonce: "nonce-eeeeeeeeeeee", scope: "approval", decision_id: "dec_2", request_hash: "h", consumed_at: iso(T0) });
  assert.equal(attempt.ok, false);
  assert.equal(attempt.reason_code, "CONSUMPTION_LEDGER_POISONED");
});

test("request nonce replay is refused within a runtime", () => {
  const { runtime } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  assert.equal(decideRequest(runtime, request, [approval]).decision, "allow");

  const replay = decideRequest(runtime, request, [approval]);
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("request nonce replay is refused across restarts via the receipts chain", () => {
  const { runtime, config, receiptsPath, consumptionPath } = freshRuntime();
  const request = makeA5Request();
  assert.equal(decideRequest(runtime, request, [makeApproval(request, runtime)]).decision, "allow");

  const reopened = createDecisionRuntime({
    config,
    receiptsPath,
    consumptionPath,
    now: () => T0
  });

  const replay = decideRequest(reopened, request, [makeApproval(request, reopened)]);
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("approval replay after a receipts wipe still dies on the durable consumption ledger", () => {
  const { runtime, config, consumptionPath } = freshRuntime();
  const request = makeA5Request();
  const approval = makeApproval(request, runtime);
  assert.equal(decideRequest(runtime, request, [approval]).decision, "allow");

  // Adversary discards the receipts chain to forget the request nonce; the
  // consumption ledger is the durable backstop.
  const rebuilt = createDecisionRuntime({
    config,
    receiptsPath: path.join(tempDir(), "fresh-receipts.jsonl"),
    consumptionPath,
    now: () => T0
  });

  const replay = decideRequest(rebuilt, request, [approval]);
  assert.equal(replay.decision, "deny");
  assert.equal(replay.reason_code, "NONCE_REPLAYED");
});

test("expired request is refused; future-dated request is refused", () => {
  const { runtime } = freshRuntime();

  const stale = decideRequest(runtime, makeA5Request({ issued_at: iso(T0 - 3_600_000), nonce: freshNonce("req") }));
  assert.equal(stale.decision, "deny");
  assert.equal(stale.reason_code, "REQUEST_EXPIRED");

  const future = decideRequest(runtime, makeA5Request({ issued_at: iso(T0 + 3_600_000), nonce: freshNonce("req") }));
  assert.equal(future.decision, "deny");
  assert.equal(future.reason_code, "REQUEST_TIME_INVALID");
});

test("consumption ledger chain stays verifiable after use", () => {
  const { runtime, consumptionPath } = freshRuntime();
  const request = makeA5Request();
  decideRequest(runtime, request, [makeApproval(request, runtime)]);
  const verification = verifyChain(consumptionPath);
  assert.equal(verification.ok, true);
  assert.equal(verification.length, 1);
});
