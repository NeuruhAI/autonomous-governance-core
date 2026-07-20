import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { consumeNonce, openConsumptionLedger } from "../src/consumption.mjs";
import { decideRequest } from "../src/decision.mjs";
import { verifyChain } from "../src/receipts.mjs";
import { T0, freshNonce, freshRuntime, iso, makeA5Request, makeApproval, tempDir } from "./helpers.mjs";

test("100 concurrent consume attempts on one nonce yield exactly one success", async () => {
  const file = path.join(tempDir(), "consumption.jsonl");
  const ledger = openConsumptionLedger(file);

  const attempts = await Promise.all(
    Array.from({ length: 100 }, (unused, index) =>
      Promise.resolve().then(() =>
        consumeNonce(ledger, {
          nonce: "contended-nonce-000",
          scope: "approval",
          decision_id: "dec_" + index,
          request_hash: "h",
          consumed_at: iso(T0)
        })
      )
    )
  );

  assert.equal(attempts.filter((attempt) => attempt.ok).length, 1);
  assert.equal(attempts.filter((attempt) => attempt.reason_code === "NONCE_REPLAYED").length, 99);
  const verification = verifyChain(file);
  assert.equal(verification.ok, true);
  assert.equal(verification.length, 1);
});

test("two different requests sharing one approval nonce: only the first allows", async () => {
  const { runtime } = freshRuntime();
  const sharedNonce = freshNonce("apr-shared");

  const requestA = makeA5Request({ nonce: freshNonce("req") });
  const requestB = makeA5Request({ nonce: freshNonce("req") });
  const approvalA = makeApproval(requestA, runtime, { nonce: sharedNonce });
  const approvalB = makeApproval(requestB, runtime, { nonce: sharedNonce });

  const [first, second] = await Promise.all([
    Promise.resolve().then(() => decideRequest(runtime, requestA, [approvalA])),
    Promise.resolve().then(() => decideRequest(runtime, requestB, [approvalB]))
  ]);

  const outcomes = [first.decision, second.decision].sort();
  assert.deepEqual(outcomes, ["allow", "deny"]);
});

test("interleaved decisions keep both chains verifiable", async () => {
  const { runtime, receiptsPath, consumptionPath } = freshRuntime();

  await Promise.all(
    Array.from({ length: 25 }, (unused, index) =>
      Promise.resolve().then(() => {
        const request = makeA5Request({ request_id: "req_c" + index, nonce: freshNonce("req") });
        return decideRequest(runtime, request, [makeApproval(request, runtime)]);
      })
    )
  );

  const receipts = verifyChain(receiptsPath);
  const consumption = verifyChain(consumptionPath);
  assert.equal(receipts.ok, true);
  assert.equal(receipts.length, 25);
  assert.equal(consumption.ok, true);
  assert.equal(consumption.length, 25);
});
