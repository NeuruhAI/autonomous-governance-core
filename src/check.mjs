import fs from "node:fs";
import { clearAuditLog, listAuditLog } from "./audit.mjs";
import { evaluateAction } from "./evaluator.mjs";
import { defaultPolicy } from "./policy.mjs";

const requiredFiles = [
  "package.json",
  ".env.example",
  "README.md",
  "src/id.mjs",
  "src/policy.mjs",
  "src/validate.mjs",
  "src/audit.mjs",
  "src/evaluator.mjs",
  "src/cli.mjs",
  "src/server.mjs",
  "src/check.mjs",
  "samples/action.json",
  "samples/blocked-action.json"
];

const missing = requiredFiles.filter((file) => !fs.existsSync(file));

if (missing.length) {
  console.error("Missing files:");
  for (const file of missing) {
    console.error("- " + file);
  }
  process.exit(1);
}

const policy = defaultPolicy();

if (!policy.blocked_domains.includes("credential_exposure")) {
  console.error("Default policy missing credential_exposure blocked domain.");
  process.exit(1);
}

clearAuditLog();

const sampleAction = JSON.parse(fs.readFileSync("samples/action.json", "utf8"));
const sampleDecision = evaluateAction(sampleAction);

if (sampleDecision.decision !== "escalate") {
  console.error("Expected sample action to escalate.");
  console.error(JSON.stringify(sampleDecision, null, 2));
  process.exit(1);
}

const blockedAction = JSON.parse(fs.readFileSync("samples/blocked-action.json", "utf8"));
const blockedDecision = evaluateAction(blockedAction);

if (blockedDecision.decision !== "block") {
  console.error("Expected blocked action to block.");
  console.error(JSON.stringify(blockedDecision, null, 2));
  process.exit(1);
}

const audit = listAuditLog();

if (audit.length !== 2) {
  console.error("Expected 2 audit entries.");
  process.exit(1);
}

console.log(JSON.stringify({
  ok: true,
  checked: requiredFiles.length,
  sample_decision: sampleDecision.decision,
  blocked_decision: blockedDecision.decision,
  audit_entries: audit.length
}, null, 2));
