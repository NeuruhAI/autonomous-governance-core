import http from "node:http";
import { listAuditLog } from "./audit.mjs";
import { evaluateAction } from "./evaluator.mjs";
import { defaultPolicy, policyVersion } from "./policy.mjs";
import { createDecisionRuntime, decideRequest } from "./decision.mjs";
import { authorizeAction, createAuthorizeRuntime } from "./authorize.mjs";
import { loadTrustConfig } from "./trust.mjs";

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk) => {
      body += chunk;

      if (body.length > 5_000_000) {
        reject(new Error("Request body too large."));
        request.destroy();
      }
    });

    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON body."));
      }
    });

    request.on("error", reject);
  });
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json"
  });

  response.end(JSON.stringify(payload, null, 2));
}

// UP-2: caller-supplied policy overrides are ignored unless the operator
// explicitly re-enables them. The governed party cannot weaken the ruleset.
function callerPolicyAllowed() {
  return process.env.GOVERNANCE_ALLOW_CALLER_POLICY === "1";
}

// The v2 decision boundary is closed unless explicitly enabled AND a valid
// trust configuration loads AND the server binds loopback. Any configuration
// problem keeps it closed.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const configuredHost = process.env.HOST || "127.0.0.1";

let decisionRuntime = null;
let decisionRuntimeError = "Decision endpoint is disabled (GOVERNANCE_DECISION_ENABLED != 1).";

// The risk-scoped authorize boundary shares every gate with /v2/decide and
// keeps its OWN chain files: one chain file must never have two appenders.
let authorizeRuntime = null;
let authorizeRuntimeError = "Authorize endpoint is disabled (GOVERNANCE_DECISION_ENABLED != 1).";

if (process.env.GOVERNANCE_DECISION_ENABLED === "1") {
  if (!LOOPBACK_HOSTS.has(configuredHost)) {
    decisionRuntimeError = "Decision boundary failed closed: decision runtime requires loopback binding, got HOST=" + configuredHost + ".";
    authorizeRuntimeError = decisionRuntimeError;
  } else {
    try {
      decisionRuntime = createDecisionRuntime({
        config: loadTrustConfig(process.env),
        receiptsPath: process.env.GOVERNANCE_RECEIPTS_LOG,
        consumptionPath: process.env.GOVERNANCE_CONSUMPTION_LOG
      });
      decisionRuntimeError = null;
    } catch (error) {
      decisionRuntime = null;
      decisionRuntimeError = "Decision boundary failed closed: " + error.message;
    }

    try {
      authorizeRuntime = createAuthorizeRuntime({
        config: loadTrustConfig(process.env),
        receiptsPath: process.env.GOVERNANCE_AUTHORIZE_RECEIPTS_LOG,
        consumptionPath: process.env.GOVERNANCE_AUTHORIZE_CONSUMPTION_LOG
      });
      authorizeRuntimeError = null;
    } catch (error) {
      authorizeRuntime = null;
      authorizeRuntimeError = "Authorize boundary failed closed: " + error.message;
    }
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", "http://localhost");

    if (request.method === "GET" && url.pathname === "/health") {
      sendJson(response, 200, {
        ok: true,
        service: "autonomous-governance-core",
        policy_version: policyVersion(defaultPolicy())
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/policy/default") {
      sendJson(response, 200, defaultPolicy());
      return;
    }

    // P2-B read contract: the live adapter reads the applied policy version
    // here (subset-tolerant on its side; policy_version is the required key).
    if (request.method === "GET" && url.pathname === "/v1/policy") {
      const policy = defaultPolicy();
      sendJson(response, 200, {
        ok: true,
        service: "autonomous-governance-core",
        policy_id: policy.policy_id,
        policy_version: policyVersion(policy)
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/audit") {
      sendJson(response, 200, {
        entries: listAuditLog()
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/v1/evaluate") {
      const body = await readJsonBody(request);
      const action = body.action || body;
      const policy = callerPolicyAllowed() ? body.policy : undefined;
      sendJson(response, 200, evaluateAction(action, policy));
      return;
    }

    if (request.method === "POST" && url.pathname === "/v2/decide") {
      if (!decisionRuntime) {
        sendJson(response, 403, {
          ok: false,
          error: decisionRuntimeError
        });
        return;
      }

      const body = await readJsonBody(request);
      sendJson(response, 200, decideRequest(decisionRuntime, body.request, body.approvals || []));
      return;
    }

    if (request.method === "POST" && url.pathname === "/v2/authorize") {
      if (!authorizeRuntime) {
        sendJson(response, 403, {
          ok: false,
          error: authorizeRuntimeError
        });
        return;
      }

      const body = await readJsonBody(request);
      sendJson(response, 200, authorizeAction(authorizeRuntime, body.facts, {
        grant: body.grant,
        founder_approval: body.founder_approval
      }));
      return;
    }

    sendJson(response, 404, {
      ok: false,
      error: "Not found."
    });
  } catch (error) {
    sendJson(response, 400, {
      ok: false,
      error: error.message,
      details: error.details || undefined
    });
  }
});

const port = Number(process.env.PORT || "8848");
// P1: execution services bind loopback only (no LAN exposure)
const host = configuredHost;

server.listen(port, host, () => {
  console.log("autonomous-governance-core listening on http://" + host + ":" + port);
});
