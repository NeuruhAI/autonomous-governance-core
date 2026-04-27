import http from "node:http";
import { listAuditLog } from "./audit.mjs";
import { evaluateAction } from "./evaluator.mjs";
import { defaultPolicy } from "./policy.mjs";

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

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", "http://localhost");

    if (request.method === "GET" && url.pathname === "/health") {
      sendJson(response, 200, {
        ok: true,
        service: "autonomous-governance-core"
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/policy/default") {
      sendJson(response, 200, defaultPolicy());
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
      const policy = body.policy;
      sendJson(response, 200, evaluateAction(action, policy));
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

server.listen(port, "0.0.0.0", () => {
  console.log("autonomous-governance-core listening on port " + port);
});
