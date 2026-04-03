import http from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ────────────────────────────────────────────────────────────────────

const HOST     = "127.0.0.1";
const PORT     = 4444;
const MCP_PATH = "/mcp";

// ── Logger (stdout so it's visible on the console) ───────────────────────────

const RESET   = "\x1b[0m";
const BOLD    = "\x1b[1m";
const DIM     = "\x1b[2m";
const CYAN    = "\x1b[36m";
const GREEN   = "\x1b[32m";
const YELLOW  = "\x1b[33m";
const RED     = "\x1b[31m";
const MAGENTA = "\x1b[35m";
const BLUE    = "\x1b[34m";

function ts() {
  return new Date().toISOString();
}

function log(color, label, message) {
  process.stdout.write(`${DIM}${ts()}${RESET} ${color}${BOLD}[${label.padEnd(10)}]${RESET} ${message}\n`);
}

function logJson(label, color, obj) {
  const lines = JSON.stringify(obj, null, 2).split("\n");
  process.stdout.write(`${color}${BOLD}  ▶ ${label}${RESET}\n`);
  for (const line of lines) {
    process.stdout.write(`    ${DIM}${line}${RESET}\n`);
  }
}

function logSection(title) {
  process.stdout.write(`\n${CYAN}${"─".repeat(64)}${RESET}\n`);
  process.stdout.write(`${CYAN}${BOLD}  ${title}${RESET}\n`);
  process.stdout.write(`${CYAN}${"─".repeat(64)}${RESET}\n`);
}

// ── Placeholder response ──────────────────────────────────────────────────────
// This is a mock server. It has no real AppSec knowledge about any repository.
// Replace resolveContext() with a real backend integration when available.

const SAMPLE_CONTEXTS = [
  {
    pattern: /payment|checkout|billing|commerce|shop/i,
    context: {
      repo_url: null,
      team: {
        name: "Payments Platform",
        email: "payments-team@company.com",
        slack_channel: "#team-payments",
        security_champion: "alice@company.com",
      },
      asset_classification: {
        tier: "Tier 1 — Mission Critical",
        data_sensitivity: "Restricted",
        data_types: ["Payment card data (PAN, CVV)", "Bank account numbers", "Transaction history"],
        criticality: "High",
        business_impact: "Revenue-generating; outage = direct financial loss",
      },
      compliance_scope: ["PCI-DSS v4.0 (SAQ D)", "SOC 2 Type II", "GDPR"],
      architecture_notes:
        "Microservices on Kubernetes (GKE). Payment processing delegated to Stripe; raw PANs never stored. Internal services communicate over mTLS via Istio service mesh. Secrets managed via HashiCorp Vault.",
      prior_findings: [
        {
          id: "APPSEC-2024-041",
          title: "Insecure Direct Object Reference in /api/orders/{id}",
          severity: "High",
          status: "Open",
          description: "Order IDs are sequential integers; authenticated users can access other users' orders by incrementing the ID.",
          reported: "2024-09-12",
          sla_due: "2024-10-12",
        },
        {
          id: "APPSEC-2024-028",
          title: "Webhook signature validation missing on /webhooks/stripe",
          severity: "High",
          status: "Remediated",
          description: "Stripe webhook events were accepted without verifying the Stripe-Signature header. Fixed in commit a3f91bc.",
          reported: "2024-07-03",
          remediated: "2024-07-18",
        },
        {
          id: "APPSEC-2023-117",
          title: "PCI scope creep — logging middleware capturing full request body",
          severity: "Critical",
          status: "Remediated",
          description: "Request body logging in dev middleware was left enabled in production, writing raw card data to CloudWatch logs.",
          reported: "2023-11-22",
          remediated: "2023-11-23",
        },
      ],
      known_exceptions: [
        {
          id: "EXC-2024-007",
          description: "TLS 1.1 still supported on legacy payment terminal integration endpoint /api/v1/terminal.",
          risk_accepted_by: "CISO",
          expiry: "2025-03-31",
          compensating_control: "IP allowlist restricted to terminal subnet 10.20.30.0/24",
        },
      ],
      penetration_tests: [
        { date: "2024-06-01", scope: "Full application + API", provider: "CrowdStrike", report_id: "PT-2024-06" },
      ],
    },
  },
  {
    pattern: /auth|identity|sso|login|iam|oauth|keycloak/i,
    context: {
      repo_url: null,
      team: {
        name: "Identity & Access Management",
        email: "iam-team@company.com",
        slack_channel: "#team-iam",
        security_champion: "bob@company.com",
      },
      asset_classification: {
        tier: "Tier 1 — Mission Critical",
        data_sensitivity: "Restricted",
        data_types: ["User credentials (hashed)", "OAuth tokens", "Session data", "MFA secrets"],
        criticality: "Critical",
        business_impact: "Auth outage affects all products; compromise = full account takeover",
      },
      compliance_scope: ["SOC 2 Type II", "GDPR", "ISO 27001"],
      architecture_notes:
        "Custom OAuth 2.0 / OIDC provider built on Node.js. Tokens signed with RS256 (2048-bit). Passwords hashed with bcrypt (cost=12). MFA via TOTP and WebAuthn.",
      prior_findings: [
        {
          id: "APPSEC-2024-055",
          title: "OAuth authorization code reuse not prevented",
          severity: "High",
          status: "Open",
          description: "Authorization codes can be exchanged for tokens more than once within their 10-minute validity window.",
          reported: "2024-10-30",
          sla_due: "2024-11-30",
        },
        {
          id: "APPSEC-2024-031",
          title: "Account enumeration via password reset timing",
          severity: "Medium",
          status: "Remediated",
          description: "Password reset response time differed by ~200ms for registered vs. unregistered emails.",
          reported: "2024-08-01",
          remediated: "2024-08-15",
        },
      ],
      known_exceptions: [],
      penetration_tests: [
        { date: "2024-04-15", scope: "Auth flows, OAuth, session management", provider: "NCC Group", report_id: "PT-2024-04" },
      ],
    },
  },
  {
    pattern: /health|medical|patient|clinic|ehr|hipaa/i,
    context: {
      repo_url: null,
      team: {
        name: "Clinical Data Platform",
        email: "clinical-eng@company.com",
        slack_channel: "#team-clinical",
        security_champion: "carol@company.com",
      },
      asset_classification: {
        tier: "Tier 1 — Mission Critical",
        data_sensitivity: "Restricted — PHI",
        data_types: ["Protected Health Information (PHI)", "Diagnoses", "Prescriptions", "Insurance data"],
        criticality: "Critical",
        business_impact: "HIPAA BAA in place; breach = regulatory penalty + reputational damage",
      },
      compliance_scope: ["HIPAA / HITECH", "SOC 2 Type II", "GDPR (EU patients)", "CCPA"],
      architecture_notes:
        "Django REST API on AWS. PHI stored in RDS (encrypted at rest with KMS). S3 buckets for medical images (SSE-S3). All PHI access logged to CloudTrail.",
      prior_findings: [
        {
          id: "APPSEC-2024-019",
          title: "PHI included in error messages returned to client",
          severity: "High",
          status: "Open",
          description: "Unhandled exceptions in the prescription endpoint return Django debug traces that include patient record data.",
          reported: "2024-05-20",
          sla_due: "2024-06-20",
        },
      ],
      known_exceptions: [
        {
          id: "EXC-2023-002",
          description: "Audit log retention is 90 days (HIPAA requires 6 years). Extended retention in Glacier pending budget approval.",
          risk_accepted_by: "VP Engineering",
          expiry: "2025-01-01",
          compensating_control: "Manual log export to S3 cold storage monthly",
        },
      ],
      penetration_tests: [],
    },
  },
];

const DEFAULT_CONTEXT = {
  repo_url: null,
  team: {
    name: "Engineering",
    email: "engineering@company.com",
    slack_channel: "#engineering",
    security_champion: "secchampion@company.com",
  },
  asset_classification: {
    tier: "Tier 2 — Business Important",
    data_sensitivity: "Internal",
    data_types: ["User account data", "Application logs", "Configuration"],
    criticality: "Medium",
    business_impact: "Service degradation affects internal users; no direct revenue impact",
  },
  compliance_scope: ["SOC 2 Type II"],
  architecture_notes: "No architecture notes on file. Assessment will rely on code inspection only.",
  prior_findings: [
    {
      id: "APPSEC-2024-002",
      title: "Missing security headers (CSP, HSTS, X-Frame-Options)",
      severity: "Medium",
      status: "Open",
      description: "HTTP responses do not include standard defensive headers. No Content-Security-Policy configured.",
      reported: "2024-01-10",
      sla_due: "2024-04-10",
    },
  ],
  known_exceptions: [],
  penetration_tests: [],
};

function resolveContext(repoUrl) {
  // Mock placeholder — no real AppSec data available for any repository.
  return {
    repo_url: repoUrl,
    status: "no_data",
    message: "This is a mock AppSec context server. No detailed information is available for the requested repository. The threat modeling agent should proceed based solely on its own code analysis.",
    team: null,
    asset_classification: null,
    compliance_scope: [],
    architecture_notes: null,
    prior_findings: [],
    known_exceptions: [],
    penetration_tests: [],
  };
}

// ── MCP Server factory ────────────────────────────────────────────────────────
// A new Server instance is created per request (stateless mode).

function createMcpServer() {
  const server = new Server(
    { name: "appsec_context", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    log(MAGENTA, "MCP", "tools/list");
    return {
      tools: [
        {
          name: "get_repo_context",
          description:
            "Returns AppSec context for a repository: team ownership, asset classification, compliance scope, prior security findings, known exceptions, and architecture notes.",
          inputSchema: {
            type: "object",
            properties: {
              repo_url: {
                type: "string",
                description: "The git remote URL of the repository (e.g. git@github.com:org/repo.git or https://github.com/org/repo)",
              },
            },
            required: ["repo_url"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    logSection(`MCP tools/call → ${name}`);

    if (name !== "get_repo_context") {
      log(RED, "ERROR", `Unknown tool: ${name}`);
      return { content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }], isError: true };
    }

    const repoUrl = args?.repo_url;
    if (!repoUrl) {
      log(RED, "ERROR", "Missing required argument: repo_url");
      return { content: [{ type: "text", text: JSON.stringify({ error: "Missing required argument: repo_url" }) }], isError: true };
    }

    log(CYAN, "LOOKUP", `repo_url = ${repoUrl}`);
    const context = resolveContext(repoUrl);

    log(YELLOW, "MOCK", context.message);

    const payload = JSON.stringify(context, null, 2);
    logJson("Response", GREEN, context);
    log(GREEN, "RESPONSE", `${payload.length} bytes  status=${context.status}`);

    return { content: [{ type: "text", text: payload }] };
  });

  return server;
}

// ── HTTP Server ───────────────────────────────────────────────────────────────

let requestCount = 0;

const httpServer = http.createServer(async (req, res) => {
  const reqId  = ++requestCount;
  const client = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
  log(BLUE, "HTTP", `#${reqId} ${req.method} ${req.url}  client=${client}`);

  if (req.url !== MCP_PATH) {
    log(YELLOW, "HTTP", `#${reqId} 404 — unknown path (expected ${MCP_PATH})`);
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", mcp_endpoint: `http://${HOST}:${PORT}${MCP_PATH}` }));
    return;
  }

  // Read and parse body
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString();

  let body;
  try {
    body = JSON.parse(raw);
    log(BLUE, "HTTP", `#${reqId} body method=${body?.method}  id=${body?.id}`);
    logJson("Request body", MAGENTA, body);
  } catch {
    log(RED, "HTTP", `#${reqId} 400 — invalid JSON body`);
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid JSON" }));
    return;
  }

  // Wrap res.end to log status + response body
  const originalEnd = res.end.bind(res);
  res.end = (...args) => {
    const body = args[0];
    log(GREEN, "HTTP", `#${reqId} → ${res.statusCode}  content-type=${res.getHeader("content-type") ?? "n/a"}`);
    if (body) {
      const text = Buffer.isBuffer(body) ? body.toString() : String(body);
      // SSE: log each event line; JSON: pretty-print
      if (res.getHeader("content-type")?.includes("text/event-stream")) {
        for (const line of text.split("\n").filter(Boolean)) {
          log(DIM, "SSE", line);
        }
      } else {
        try { logJson("Response body", GREEN, JSON.parse(text)); } catch { log(DIM, "HTTP", `body: ${text.slice(0, 200)}`); }
      }
    }
    return originalEnd(...args);
  };

  // Stateless: one MCP server + transport per request
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  const mcpServer = createMcpServer();
  await mcpServer.connect(transport);
  await transport.handleRequest(req, res, body);
});

// ── Startup ───────────────────────────────────────────────────────────────────

httpServer.listen(PORT, HOST, () => {
  const addr = httpServer.address();

  process.stdout.write(`
${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}
${CYAN}║  AppSec Context MCP Server (mock)  v1.0.0                    ║${RESET}
${CYAN}║  Transport: Streamable HTTP                                  ║${RESET}
${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}

${GREEN}${BOLD}  Bound     : http://${addr.address}:${addr.port}${RESET}
${GREEN}${BOLD}  Endpoint  : http://${addr.address}:${addr.port}${MCP_PATH}${RESET}
${DIM}  Tool      : get_repo_context(repo_url)${RESET}
${YELLOW}${BOLD}  Mode      : MOCK — no real AppSec data, placeholder response only${RESET}
${DIM}  Logging   : all requests and responses printed to stdout${RESET}

${CYAN}${"─".repeat(64)}${RESET}
${DIM}Waiting for MCP client connections…${RESET}

`);
});

httpServer.on("error", (err) => {
  log(RED, "ERROR", `HTTP server error: ${err.message}`);
  if (err.code === "EADDRINUSE") {
    log(RED, "ERROR", `Port ${PORT} already in use — kill the existing process or change PORT`);
  }
  process.exit(1);
});
