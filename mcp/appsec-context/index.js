import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Console logger (stderr so it doesn't interfere with stdio MCP transport) ──

const RESET  = "\x1b[0m";
const BOLD   = "\x1b[1m";
const DIM    = "\x1b[2m";
const CYAN   = "\x1b[36m";
const GREEN  = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED    = "\x1b[31m";
const MAGENTA = "\x1b[35m";

function ts() {
  return new Date().toISOString();
}

function log(color, label, message) {
  process.stderr.write(`${DIM}${ts()}${RESET} ${color}${BOLD}[${label}]${RESET} ${message}\n`);
}

function logSection(title) {
  process.stderr.write(`\n${CYAN}${"─".repeat(60)}${RESET}\n`);
  process.stderr.write(`${CYAN}${BOLD}  ${title}${RESET}\n`);
  process.stderr.write(`${CYAN}${"─".repeat(60)}${RESET}\n`);
}

function logJson(label, color, obj) {
  process.stderr.write(`${color}${BOLD}${label}:${RESET}\n`);
  process.stderr.write(JSON.stringify(obj, null, 2)
    .split("\n")
    .map(l => `  ${DIM}${l}${RESET}`)
    .join("\n") + "\n");
}

// ── Sample context data ───────────────────────────────────────────────────────

const SAMPLE_CONTEXTS = [
  {
    // Matches repos with "payment", "checkout", "billing", "commerce"
    pattern: /payment|checkout|billing|commerce|shop/i,
    context: {
      repo_url: null, // filled at runtime
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
          description: "Order IDs are sequential integers; authenticated users can access other users' orders by incrementing the ID. Horizontal privilege escalation.",
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
          description: "TLS 1.1 still supported on legacy payment terminal integration endpoint /api/v1/terminal — migration blocked by hardware vendor.",
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
    // Matches repos with "auth", "identity", "sso", "login", "iam"
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
        "Custom OAuth 2.0 / OIDC provider built on Node.js. Tokens signed with RS256 (2048-bit). Passwords hashed with bcrypt (cost=12). MFA via TOTP and WebAuthn. Redis-backed session store with 15-min idle timeout.",
      prior_findings: [
        {
          id: "APPSEC-2024-055",
          title: "OAuth authorization code reuse not prevented",
          severity: "High",
          status: "Open",
          description: "Authorization codes can be exchanged for tokens more than once within their 10-minute validity window. PKCE is implemented but code replay is not tracked.",
          reported: "2024-10-30",
          sla_due: "2024-11-30",
        },
        {
          id: "APPSEC-2024-031",
          title: "Account enumeration via password reset timing",
          severity: "Medium",
          status: "Remediated",
          description: "Password reset response time differed by ~200ms for registered vs. unregistered emails, enabling account enumeration.",
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
    // Matches repos with "health", "medical", "patient", "clinic", "ehr"
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
        "Django REST API on AWS. PHI stored in RDS (encrypted at rest with KMS). S3 buckets for medical images (SSE-S3). All PHI access logged to CloudTrail. VPC with private subnets; no direct internet access to data tier.",
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
  architecture_notes:
    "No architecture notes on file. Assessment will rely on code inspection only.",
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
  for (const entry of SAMPLE_CONTEXTS) {
    if (entry.pattern.test(repoUrl)) {
      return { ...entry.context, repo_url: repoUrl };
    }
  }
  return { ...DEFAULT_CONTEXT, repo_url: repoUrl };
}

// ── MCP Server ────────────────────────────────────────────────────────────────

const server = new Server(
  { name: "appsec_context", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async (request) => {
  logSection("LIST TOOLS REQUEST");
  logJson("Request", MAGENTA, request);

  const response = {
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

  logJson("Response", GREEN, response);
  return response;
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logSection("CALL TOOL REQUEST");
  logJson("Request", MAGENTA, request);

  const { name, arguments: args } = request.params;

  if (name !== "get_repo_context") {
    const err = { error: `Unknown tool: ${name}` };
    log(RED, "ERROR", `Unknown tool requested: ${name}`);
    logJson("Response", RED, err);
    return { content: [{ type: "text", text: JSON.stringify(err) }], isError: true };
  }

  const repoUrl = args?.repo_url;
  if (!repoUrl) {
    const err = { error: "Missing required argument: repo_url" };
    log(RED, "ERROR", "repo_url argument missing");
    logJson("Response", RED, err);
    return { content: [{ type: "text", text: JSON.stringify(err) }], isError: true };
  }

  log(CYAN, "LOOKUP", `Resolving context for: ${repoUrl}`);

  const context = resolveContext(repoUrl);

  const matched = SAMPLE_CONTEXTS.find(e => e.pattern.test(repoUrl));
  log(
    matched ? GREEN : YELLOW,
    matched ? "HIT" : "DEFAULT",
    matched
      ? `Matched pattern: ${matched.pattern} → ${context.team.name}`
      : "No pattern matched — returning default context"
  );

  const response = {
    content: [
      {
        type: "text",
        text: JSON.stringify(context, null, 2),
      },
    ],
  };

  logJson("Response", GREEN, response);
  return response;
});

// ── Startup ───────────────────────────────────────────────────────────────────

process.stderr.write(`
${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}
${CYAN}║  AppSec Context MCP Server (mock)  v1.0.0                    ║${RESET}
${CYAN}║  Transport: stdio                                            ║${RESET}
${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}

${DIM}  Tool     : get_repo_context(repo_url)${RESET}
${DIM}  Patterns : payment/checkout | auth/identity | health/medical | default${RESET}
${DIM}  Logging  : all requests and responses printed to stderr${RESET}

${CYAN}${"─".repeat(60)}${RESET}
${DIM}Waiting for MCP client connection…${RESET}

`);

const transport = new StdioServerTransport();
await server.connect(transport);
