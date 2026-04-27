import fs from "node:fs";
import { listAuditLog } from "./audit.mjs";
import { evaluateAction } from "./evaluator.mjs";
import { defaultPolicy } from "./policy.mjs";

function readJson(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error("File not found: " + filePath);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function main() {
  const command = process.argv[2];
  const filePath = process.argv[3];

  try {
    if (command === "policy") {
      console.log(JSON.stringify(defaultPolicy(), null, 2));
      return;
    }

    if (command === "evaluate") {
      if (!filePath) {
        throw new Error("Missing action JSON path.");
      }

      const action = readJson(filePath);
      console.log(JSON.stringify(evaluateAction(action), null, 2));
      return;
    }

    if (command === "audit") {
      console.log(JSON.stringify({ entries: listAuditLog() }, null, 2));
      return;
    }

    console.error("Usage:");
    console.error("  node src/cli.mjs policy");
    console.error("  node src/cli.mjs evaluate samples/action.json");
    console.error("  node src/cli.mjs audit");
    process.exit(1);
  } catch (error) {
    console.error(error.message);

    if (error.details) {
      console.error(JSON.stringify(error.details, null, 2));
    }

    process.exit(1);
  }
}

main();
