# Autonomous Governance Core

Governance guardrail for autonomous agent actions.

## What it does

This repo evaluates proposed autonomous actions before they run.

## UP-2: content-bound authority

Beyond the legacy evaluate path, the repo carries a canonical decision
boundary (`src/decision.mjs`) closing Governance UP-2:

- One canonical decision envelope (`gov.decision.v1`): identity, source SHA,
  mission/plan/step, correlation/causation, operation, tool, mutation class,
  exact target, canonical argument/request hashes, precondition hash,
  capability, nonce, expiry, one-time-use state, evidence refs and a
  hash-chained receipt.
- Content-bound approvals (`src/approval.mjs`): an approval authorizes exactly
  one canonical request. Any changed bound field, wildcard, expiry breach,
  forged or self-referential approver invalidates it. Approver identity and
  HMAC secrets come from trusted configuration (`src/trust.mjs`), never from
  the request.
- Replay resistance (`src/consumption.mjs`): durable hash-chained nonce
  consumption, atomic one-time use, uncertain consumption never treated as
  unused.
- Fail-closed boundary: unknown identity, SHA, policy version, capability,
  mutation class, ambiguous target/canonicalization, missing config, broken
  chains or failed persistence all deny.
- Receipts (`src/receipts.mjs`): append-only, tamper-evident, and never claim
  execution. Governance decides; AXON executes.

Legacy UP-2 hardening: caller-supplied policy overrides are ignored (env-gated
`GOVERNANCE_ALLOW_CALLER_POLICY`, default off), every evaluation echoes
`policy_id`/`policy_version`/`thresholds`, and decisions append to a durable
hash-chained audit log when `GOVERNANCE_AUDIT_LOG` is set. The
`/v1/evaluate` decision enum stays `allow | escalate | block`.

The `/v2/decide` endpoint stays closed unless `GOVERNANCE_DECISION_ENABLED=1`
AND a valid `GOVERNANCE_TRUST_CONFIG` loads. Live mutation is denied
unconditionally: the mutation path is not ratified.

Run the UP-2 suites:

    npm run test:unit

It can:

- Load a default governance policy.
- Evaluate an action.
- Return allow, escalate, or block.
- Record every decision in an audit log.
- Run as a local API.

## Decision meanings

allow:

The action has no policy issue.

escalate:

The action needs review before it runs.

block:

The action should not run unless a human owner explicitly overrides it.

## Install

No package install is required for the current MVP because it uses Node built-ins only.

Check the repo:

    npm run check

Show default policy:

    npm run policy

Evaluate sample action:

    npm run evaluate

Run local API:

    npm run dev

## API test

In one terminal:

    npm run dev

In another terminal:

    curl http://localhost:8848/health

Show policy:

    curl http://localhost:8848/v1/policy/default

Evaluate action:

    curl -X POST http://localhost:8848/v1/evaluate \
      -H "Content-Type: application/json" \
      --data-binary @samples/action.json

Show audit log:

    curl http://localhost:8848/v1/audit

## GitHub push

Use private first:

    git init
    git branch -M main
    git add .
    git commit -m "Initial autonomous governance core"
    gh repo create NeuruhAI/autonomous-governance-core --private --source=. --remote=origin --push

## Verification checklist

- npm run check passes.
- npm run policy returns the default policy.
- npm run evaluate returns escalate for the sample action.
- Blocked sample returns block during check.
- Audit log records every evaluation.
- Local API health endpoint works.
- Local API evaluate endpoint works.
- Policy is reviewed before connecting live agent actions.
- No real secrets are committed.
