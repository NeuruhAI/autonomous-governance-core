# Autonomous Governance Core

Governance guardrail for autonomous agent actions.

## What it does

This repo evaluates proposed autonomous actions before they run.

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
