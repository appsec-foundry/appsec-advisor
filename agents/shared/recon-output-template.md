# Recon Scanner Output Template

Used by `appsec-recon-scanner` Step 4. Defines the exact Markdown structure that gets written to `$OUTPUT_DIR/.recon-summary.md`. The orchestrator's Phase 5 reads this file every turn, so the template targets a hard cap of **200 lines** total output.

## Template

The agent fills in every `<placeholder>` and writes the resulting Markdown verbatim.

````markdown
# Reconnaissance Summary

| Field | Value |
|-------|-------|
| Scanned | <ISO 8601 timestamp> |
| Repo | <REPO_ROOT> |
| Agent | recon-scanner (<MODEL_ID>) |

## 1. Project Overview

<2-4 sentence summary of what this project is, derived from README and docs>

**Business context:** <from docs/business-context.md if found, otherwise "not available">
**Compliance scope:** <if mentioned in any doc, otherwise "not specified">

## 2. Tech Stack

| Category | Details |
|----------|---------|
| Languages | <languages with versions where known> |
| Frameworks | <frameworks with versions> |
| Runtime | <runtimes> |
| Build / Package | <package managers, build tools> |
| Database | <if discoverable from config or code> |

## 3. Package Manifests

| Path | Type | Direct dependencies |
|------|------|-------------------|
| <relative path> | <pip/npm/maven/etc> | <count> |

## 4. Directory Structure

```
<tree output from Step 2, max 60 lines>
```

## 5. Deployment & CI/CD

| Path | Type |
|------|------|
| <relative path> | <Docker/K8s/GitHub Actions/etc> |

**Platform:** <Docker / Kubernetes / AWS / GCP / Azure / on-prem / unknown>
**CI/CD:** <tool name or "not found">

## 6. Configuration Files

| Path | Key settings |
|------|-------------|
| <relative path> | <notable config keys — NO secret values> |

## 7. Security-Relevant Code

### 6.1 Auth & Session
**Mechanism:** <e.g., "JWT via jsonwebtoken library", "Session cookies via express-session">
**Key files:** <file:line references>
**Observations:**
- <1-3 bullet points about what was found — auth flow, token handling, session config>

### 6.2 Authorization
**Mechanism:** <e.g., "RBAC via custom middleware", "Spring Security @PreAuthorize">
**Key files:** <file:line references>
**Observations:**
- <1-3 bullets>

### 6.3 Data Access
**Pattern:** <e.g., "TypeORM with repository pattern", "Raw SQL queries">
**Key files:** <file:line references>
**Observations:**
- <1-3 bullets — parameterized queries? ORM? raw SQL?>

### 6.4 Input Handling
**Key files:** <file:line references>
**Observations:**
- <validation present? sanitization? mass assignment risk?>

### 6.5 Serialization
**Key files:** <file:line references>
**Observations:**
- <safe deserialization? untrusted input parsed?>

### 6.6 Crypto & Secrets
**Key files:** <file:line references>
**Observations:**
- <algorithms used? key management? hardcoded secrets noted by file:line only>

### 6.7 Error Handling
**Key files:** <file:line references>
**Observations:**
- <stack traces exposed? generic error pages? logging of sensitive data?>

### 6.8 Dangerous Sinks
**Key files:** <file:line references>
**Observations:**
- <eval/exec usage? DOM manipulation? command injection risk?>

### 6.9 OAuth / OIDC
**Key files:** <file:line references>
**Deterministic findings (Cat 9):**

| Severity | File | Line | Subcategory | Evidence |
|----------|------|------|-------------|----------|
| <High/Medium/Info> | <path> | <line/-> | <oauth-implicit-flow / oauth-code-without-pkce / oidc-missing-nonce / ...> | <helper evidence text> |

If none: `No OAuth / OIDC patterns detected.`

**Observations:**
- <flows used? PKCE? state parameter validation?>
- **Frontend integrations (Sprint 2C — list separately even when there is no backend OAuth):** when the codebase contains an SPA with a Google / Auth0 / Azure / NextAuth / generic-OIDC client-side login button, enumerate it here even when the *server* has no OAuth code. List each provider once with: provider name, integration mechanism (redirect / popup / implicit / PKCE), scope of token use (frontend-only social login vs. backend session exchange), and the file:line where the `clientId`, redirect URL, or SDK call is declared. Without this, downstream Phase 8 catalogues `Google OAuth` only when the *server* sees the callback — frontend-only Google sign-ins (e.g. `userService.oauthLogin(accessToken)` calling `googleapis.com/oauth2/v1/userinfo`) are silently dropped from `security_controls[]` and the §6.3 IAM section ends up missing the OAuth flow entirely (observed in the 2026-04-27 juice-shop run).

### 6.10 SPA / BFF
**Key files:** <file:line references>
**Deterministic findings (Cat 10):**

| Severity | File | Line | Subcategory | Anti-pattern |
|----------|------|------|-------------|--------------|
| <High/Medium/Info> | <file> | <line> | <spa-without-bff-candidate / spa-token-browser-storage / ...> | <anti_pattern or —> |

**Observations:**
- <token storage? cookie config? BFF pattern?>

### 6.11 Exposed Routes
**Key files:** <file:line references>
**Observations:**
- <debug endpoints? admin panels? health checks public?>

### 6.12 Hardcoded Secrets
**Matches:** <n> (<n> Critical, <n> High)
**Findings:**

| Severity | File | Line | Type | Snippet |
|----------|------|------|------|---------|
| <Critical/High> | <file> | <line> | <Password/API key/Token/Private key/Cloud credential/DB credential> | <4 chars>**** |

### 6.13 AI / LLM Integration
**LLM detected:** <yes/no>
**Key files:** <file:line references>
**Observations:**
- <SDK/provider used: OpenAI, Anthropic, Google, Azure, local model, etc.>
- <Framework: LangChain, LlamaIndex, AutoGen, CrewAI, custom, etc.>
- <Prompt patterns: system prompts hardcoded? template-based? user input concatenated into prompts?>
- <Vector DB: Chroma, Pinecone, pgvector, FAISS, etc. — or none>
- <Agent/tool-use: does the LLM have tool access? what tools? unrestricted?>
- <API key handling: env var? hardcoded? vault?>

**LLM components identified:**

| Pattern | Files | Detail |
|---------|-------|--------|
| LLM SDK / provider | <file:line> | <provider + model used> |
| Prompt construction | <file:line> | <how user input enters prompts — direct concat? template? sanitized?> |
| Vector / embedding DB | <file:line> | <DB type + what's indexed> |
| Agent / tool-use | <file:line> | <tools available, permission model> |
| Model config | <file:line> | <temperature, max_tokens, model selection> |

### 6.14 CI/CD Supply Chain
**CI/CD pipelines found:** <yes/no>
**Key files:** <file:line references>
**Observations:**
- <GitHub Actions pinned to SHA? Tag-only references found?>
- <GitLab CI images pinned? Third-party templates used?>

**Unpinned actions/images:**

| File | Line | Reference | Risk |
|------|------|-----------|------|
| <file> | <line> | <action/image ref> | <not SHA-pinned / tag-only / latest> |

### 6.15 Container Base Images
**Dockerfiles found:** <yes/no>
**Key files:** <file:line references>
**Observations:**
- <Base images pinned to digest? Using latest? Official images?>

**Findings:**

| File | Line | Image | Issue |
|------|------|-------|-------|
| <file> | <line> | <image:tag> | <unpinned / latest / no digest / non-official> |

### 6.16 Dependency Confusion
**Private registry configured:** <yes / no / partial>
**Key files:** <file:line references>
**Observations:**
- <Scoped packages used? Private registry in .npmrc/.pypirc? Dual-source risk?>

### 6.17 Postinstall Scripts
**Install hooks found:** <yes/no>
**Key files:** <file:line references>
**Observations:**
- <What do the hooks do? Network requests? File system access? Compilation only?>

### 6.18 Security Headers & CORS
**Key files:** <file:line references>
**Observations:**
- <CSP header present? Restrictive or permissive (unsafe-inline, unsafe-eval)?>
- <CORS: origin allowlist? wildcard? credentials allowed cross-origin?>
- <X-Frame-Options, X-Content-Type-Options, Referrer-Policy present?>
- <Using helmet or equivalent security header middleware?>

### 6.19 Frontend Framework & XSS Patterns
**Framework detected:** <React <version> / Angular <version> / Vue <version> / Svelte / Next.js / Nuxt / none>
**Key files:** <file:line references>
**Deterministic findings (Cat 19):**

| Severity | File | Line | Subcategory | Anti-pattern |
|----------|------|------|-------------|--------------|
| <High/Info> | <file> | <line> | <frontend-sanitizer-bypass / frontend-unsafe-html-sink / ...> | <anti_pattern or —> |

**Observations:**
- <Framework-specific XSS bypasses found? (dangerouslySetInnerHTML, v-html, bypassSecurityTrust, etc.)>
- <Sanitizer configuration — default or customized?>
- <Template injection risk from user data in framework templates?>

### 6.20 DOM-Based XSS Sources
**Key files:** <file:line references>
**Deterministic findings (Cat 20):**

| Severity | Source | Sink | Subcategory |
|----------|--------|------|-------------|
| <High/Info> | <file:line> | <sink_line or —> | <dom-xss-source-sink-candidate / dom-xss-source> |

**Observations:**
- <User-controlled DOM sources found? (location.hash, URLSearchParams, useParams, etc.)>
- <Do any sources flow to known sinks from 7.8? List file:line pairs for source→sink paths>

### 6.21 Client-Side Secrets
**Key files:** <file:line references>
**Observations:**
- <Frontend env var prefixes exposing values to browser? (REACT_APP_, NEXT_PUBLIC_, VITE_, etc.)>
- <Third-party API keys in frontend code? (Firebase, Google Maps, Stripe, etc.)>
- <Sensitive vs public-safe keys — which are genuinely risky?>

### 6.22 WebSocket & Real-Time
**Key files:** <file:line references>
**Observations:**
- <WebSocket/Socket.IO endpoints found? Using ws:// or wss://?>
- <Authentication on WebSocket connections? Origin validation?>
- <Deterministic Cat 22 subcategories: websocket-cleartext, websocket-missing-auth-candidate, websocket-origin-validation-gap?>

### 6.23 postMessage & iframe
**Key files:** <file:line references>
**Observations:**
- <postMessage listeners found? Origin validated in handler?>
- <iframes present? Sandbox attribute set? Allow attribute restrictive?>
- <Deterministic Cat 23 subcategories: postmessage-wildcard-target, message-listener-no-origin-check, iframe-missing-sandbox, iframe-permissive-sandbox, window-opener-noopener-missing?>

### 6.24 Client-Side Routing & Auth Guards
**Key files:** <file:line references>
**Observations:**
- <Client-side route guards found? (canActivate, beforeEach, PrivateRoute, etc.)>
- <Are guards backed by server-side authorization, or client-only?>
- <Mobile Cat 29 architecture signals routed here when present: exported Android components, custom schemes/app links, WebView bridges/debug/file access, ATS/cleartext, token storage, accept-all TLS. Mirror Cat 29 transport/storage details in 7.18/7.21 as applicable; do not create §6.33.>

### 6.25 Cross-Repository & SaaS Dependencies
**SCM sibling projects:** <n found>

| Name | Source | Interface | Repo hint | Confidence |
|------|--------|-----------|-----------|------------|
| <e.g., auth-service> | `docker-compose.yml:12` | REST API | `../auth-service` | high |
| <e.g., notification-svc> | `src/clients/notification.ts:5` | gRPC | `K8s DNS: notification-svc.default.svc` | medium |

**SaaS integrations:** <n found>

| Name | Source | Interface | Confidence |
|------|--------|-----------|------------|
| <e.g., Stripe> | `package.json (stripe@14.x)` | SDK | high |
| <e.g., Auth0> | `.env.example:AUTH0_DOMAIN` | REST API | high |
| <e.g., Sentry> | `src/app.ts:22 (@sentry/node)` | SDK | high |

If no SCM siblings or SaaS integrations are found, write: `No cross-repository or SaaS dependencies detected.`

### 6.26 Ecosystem Supply Chain Hygiene
**Ecosystems detected:** <comma-separated list, e.g., npm, Python (pip), Go>

**CI install integrity:**

| Ecosystem | Lockfile | Lockfile committed | CI install command | Integrity flag | Script control |
|-----------|---------|-------------------|-------------------|---------------|----------------|
| <e.g., npm> | `package-lock.json` | <yes/no/.gitignored> | <`npm ci` / `npm install` / not found> | <`--ignore-scripts` present? yes/no> | <`.npmrc ignore-scripts=true`? yes/no> |
| <e.g., Python> | `requirements.txt` | <yes/no> | <`pip install --require-hashes` / `pip install` / not found> | <`--require-hashes` / `--no-deps`? yes/no> | — |
| <e.g., Go> | `go.sum` | <yes/no> | <`go mod verify` in CI? yes/no> | <`GONOSUMCHECK` set? yes/no> | — |

**Install cooldown / minimum release age** (Cat 26 Step 7 — refuses dependency versions younger than a minimum age; primary defense against fast-propagation 2025 attacks):

| Ecosystem | Cooldown configured | Mechanism / value |
|-----------|---------------------|-------------------|
| <e.g., npm> | <yes / no / pnpm v11 default-on> | <`.npmrc minimumReleaseAge=1440` / `npmMinimalAgeGate` / `--exclude-newer` / none> |

If no cooldown on any JS/Python ecosystem: `No install cooldown configured — newly published (potentially compromised) versions are installable immediately.`

**Dependency management tooling:**
- <Renovate: `renovate.json` found at `<path>` — covers: npm, Docker, GitHub Actions / not found>
- <Dependabot: `.github/dependabot.yml` found — covers: npm, pip / not found>
- <Neither Renovate nor Dependabot detected>

**SCA tooling in CI:**

| Tool | Evidence | Blocking |
|------|----------|----------|
| <e.g., Snyk> | `.github/workflows/security.yml:15` | <yes — fails on High+ / advisory only / unknown> |
| <e.g., npm audit> | `.github/workflows/ci.yml:42` | <yes / no> |

If no SCA tooling detected: `No SCA tooling found in CI workflows.`

**Ecosystem-specific risks:**
- <e.g., Python: `--extra-index-url` used in `requirements.txt:3` — dual-source risk>
- <e.g., Go: `GONOSUMCHECK=*` in `.env` — disables module checksum verification>
- <e.g., npm: `npm install` used in `Dockerfile:12` instead of `npm ci`>
- <e.g., Rust: `Cargo.lock` not committed but project has binary targets>

### 6.27 GitHub Actions Workflow Security

Only when `.github/workflows/*.yml` files exist. **Workflows scanned:** <N files under `.github/workflows/`>.

**Workflow inventory:**

| Workflow file | `permissions:` block | Default token scope | `pull_request_target` used | 3rd-party actions SHA-pinned | Debug flags |
|---|---|---|---|---|---|
| `.github/workflows/ci.yml` | <present / absent> | <contents:read / write-all / unspecified> | <yes / no> | <all / partial / none> | <ACTIONS_STEP_DEBUG set? yes/no> |

**`pull_request_target` findings:**

| File | Line | Sub-pattern | Severity |
|------|------|-------------|----------|
| <file> | <line> | <PR HEAD checkout / secrets in run / script injection / benign> | <Critical / High / Informational> |

If no `pull_request_target` triggers found: `None — no pull_request_target trigger in any workflow.`

**`permissions:` block audit:**

| File | Job/Workflow | `permissions:` state | Write scopes | Severity |
|------|--------------|----------------------|--------------|----------|
| <file> | <job-name or "top-level"> | <write-all / explicit writes / read-all / minimal / missing (default)> | <comma-separated list of `write` scopes, or "—"> | <Critical / High / Medium / Info> |

Summarize: `<N> workflows with no explicit permissions block (inherit repo default), <N> with write-all, <N> with least-privilege read-only defaults.`

**Script-injection candidates:** List any workflow that expands `${{ github.event.pull_request.title }}`, `${{ github.event.issue.body }}`, `${{ github.event.comment.body }}`, or `${{ github.head_ref }}` directly inside a `run:` block (as opposed to via `env:`). Format: `<workflow-file>:<line> <expression>`.

**`pull_request_target` + fork-checkout combo:** List any workflow using `on: pull_request_target` together with `actions/checkout@… ref: ${{ github.event.pull_request.head… }}`. Critical RCE-via-PR vector. If none: `No pull_request_target + fork-checkout combination detected.`

**Self-hosted runners:**

| File | Line | Label expression | Repo visibility | Severity |
|------|------|------------------|-----------------|----------|
| <file> | <line> | <`self-hosted` / `[self-hosted, linux]` / ...> | <public / private / unknown> | <Critical / High / Medium> |

If no `self-hosted` entries found: `None — all workflows use GitHub-hosted runners.`

### 6.27a Public-Repo Contribution Exposure

Only when repository visibility is **public** or **unknown** (independent of whether any workflow file exists — Cat 27d). For a **private/internal** repo, render: `Repo is private/internal — external-contribution threat does not apply.`

| Signal | Observed |
|--------|----------|
| Repo visibility | <public / unknown (annotate source)> |
| `CODEOWNERS` present | <yes (path) / no> |
| `CONTRIBUTING` / PR template present | <yes (path) / no> |
| Branch protection / required review | Not verifiable from source — verify out-of-band |
| PR dependency-review gate | <`actions/dependency-review-action` present (path) / absent> |
| Verdict | <High: public, no CODEOWNERS / Medium: public, CODEOWNERS present / High: visibility unknown> |

This block is the evidence source for the untrusted-external-contribution Tampering/EoP threat (see STRIDE analyzer supply-chain patterns).

### 6.28 Container Runtime Hardening

Only when `Dockerfile` exists.

- **Base image pinning:** `FROM <image>:<tag>@sha256:<digest>?` — record whether a digest is present for every `FROM` line.
- **USER directive:** record the final `USER <name/uid>` value. Flag when empty or root/0.
- **HEALTHCHECK:** present / absent.
- **Install privilege flags:** `--unsafe-perm` / `--ignore-scripts` / neither in any `RUN npm install` / `RUN pip install` / similar.
- **Capability drops:** any `--cap-drop=ALL` / `--security-opt=no-new-privileges`? (usually surfaced at `docker run` time, but flag if the Dockerfile has `ENTRYPOINT ["sh", "-c", …]` that could bypass).

### 6.29 docker-compose Security

Only when `docker-compose*.yml` exists.

For each service, flag:
- `privileged: true` — container escape equivalent
- `/var/run/docker.sock` mounted — daemon control
- `network_mode: host` — isolation broken
- `cap_add` entries — capabilities added without matching `cap_drop`
- `user: root` or no user directive
- Hardcoded credentials in `environment:` blocks (not pulled from secrets)

### 6.30 Artifact Signing & Provenance

Only when `.github/workflows/*.yml` or `Dockerfile` exist.

- **Container image signing:** search for `cosign`, `sigstore/cosign-installer`, `actions/attest-build-provenance`, `notation sign`. Record tool + target workflow + whether signing runs on every release.
- **SBOM generation:** search for `cyclonedx`, `syft`, `anchore/sbom-action`, `spdx-sbom-generator`. Record tool + whether SBOM is published as an artifact + whether consumers can verify against it.
- **SLSA provenance:** search for SLSA-generator actions, `slsa-framework/slsa-github-generator`. Record level if present.

If none found for any of the three: `No container signing / SBOM / SLSA provenance pipeline detected.`

**Publish authentication & package provenance** (Cat 27e — only when a package-publish step exists):

| Publish target | Auth model | Package provenance/attestation |
|----------------|-----------|--------------------------------|
| <npm / PyPI / none> | <Trusted Publishing (OIDC) / long-lived token (`NPM_TOKEN` / `TWINE_PASSWORD` / `password:`)> | <PEP 740 attestation / npm `--provenance` / none> |

If a long-lived publish token is used: `Long-lived publish token in CI — stealable credential enables registry publish-hijack; no package provenance. Adopt Trusted Publishing (OIDC) to fix both.` If no publish step exists: `Repo does not publish a package — publish-auth check N/A.`

### 6.31 Service-to-Service & Cloud-IAM Authentication

Complements §6.1 (which is biased toward user-facing web auth) by enumerating authentication mechanisms used between services or between an application and a cloud platform. Without this section, Phase 8 has no evidence to emit `kind: mechanism` rows for serverless apps, mesh-internal services, webhook receivers, or anything else where the auth principal is a machine identity.

**Detection patterns** (run as a single combined `rg`/`grep` call, one row per detected mechanism):

| Mechanism | Patterns to search for |
|---|---|
| **Mutual TLS / Client-Cert** | `requestCert\s*[:=]\s*true`, `rejectUnauthorized\s*[:=]\s*true`, `ssl_client_certificate`, `ssl_verify_client`, `tls\.RequireAndVerifyClientCert`, `kind:\s*PeerAuthentication`, Envoy `validation_context`, `mtls`/`mTLS` strings in IaC |
| **Webhook HMAC verification** | `stripe-signature`, `X-Hub-Signature(-256)?`, `Webhook-Signature`, `crypto\.timingSafeEqual`, `hmac\.compare_digest`, `compute_signature`, `verifySignature`, `Svix-Signature`, `X-Slack-Signature` |
| **API-Key / Bearer (non-JWT)** | `x-api-key` (header lookup or middleware), `Authorization:\s*Bearer\s+(?!eyJ)`, `apiKeyAuth`, `apiKey\s*=\s*req\.header`, `req\.headers\[['"]authorization`, `passport-headerapikey`, `tsoa.*Security` |
| **AWS IAM / SigV4** | `assumeRole`, `STS::AssumeRole`, `aws_iam_role`, `aws-sdk.*Signer`, `SignatureV4`, `Lambda execution role` references, `serverless\.yml.*iamRoleStatements`, IAM policy JSON in IaC, `AWS_ROLE_ARN` env var |
| **GCP Service Account** | `google\.auth`, `GOOGLE_APPLICATION_CREDENTIALS`, `iam\.serviceAccountKey`, `roles/iam\.serviceAccountUser`, `service_account.json` |
| **Azure Managed Identity** | `DefaultAzureCredential`, `ManagedIdentityCredential`, `AZURE_CLIENT_ID`/`AZURE_TENANT_ID` (without secret), `WorkloadIdentityCredential` |
| **Kubernetes ServiceAccount / IRSA** | `serviceAccountName:`, `automountServiceAccountToken:`, `eks\.amazonaws\.com/role-arn` annotation, `iam\.gke\.io/gcp-service-account`, `azure\.workload\.identity` |
| **Service-Mesh Identity (SPIFFE/SPIRE)** | `spiffe://`, `spire-agent`, Istio `kind:\s*RequestAuthentication`, `kind:\s*AuthorizationPolicy` with `principals`, Linkerd `policy\.linkerd\.io`, Consul Connect `intentions` |
| **Anonymous / no-auth routes** | Routes registered without any auth middleware (negative finding — list count of such routes per component) |

**Mechanisms detected:** <list of detected names from the table above; or `none — application appears to be user-auth only`>

| Mechanism | Evidence (file:line) | Notes |
|---|---|---|
| Mutual TLS | `deploy/istio/peer-auth.yaml:8` | mesh-wide STRICT mTLS via PeerAuthentication |
| Webhook HMAC verification | `routes/stripe.ts:22` | uses `stripe.webhooks.constructEvent` |
| AWS IAM Role (Lambda execution role) | `serverless.yml:34` | role `paymentsLambdaRole` with `dynamodb:*` |
| Anonymous routes | 4 routes (see §6.11) | `/health`, `/metrics`, `/static/*`, `/swagger.json` |

If no mechanisms are detected, write a single line: `No service-to-service or cloud-IAM authentication detected — application uses user-facing authentication only (see §6.2 and §6.3).`

**Why this matters:** Phase 8's `security_controls[]` schema uses a `kind: mechanism` discriminator (see `phase-group-architecture.md` → "Phase 8 output schema") so v2 §6 can distinguish end-to-end identity mechanisms from primitives. For non-web architectures (serverless, mesh services, batch workers, webhook receivers), this recon evidence drives the relevant H4 subcontrols under §6.2 Identity and Authentication Controls and §6.3 Session and Token Controls.

### 6.32 AI Coding Assistant & IDE Agent Configurations

**Assistants detected (files committed into the repo):**

| Assistant | Files / directories present | Count |
|-----------|-----------------------------|-------|
| Claude Code | <`.claude/` contents: CLAUDE.md, settings.json, settings.local.json, hooks.json, agents/, skills/, commands/> | <N> |
| Cursor | <`.cursor/rules` / `.cursorrules` / `.cursor/mcp.json`> | <N> |
| Windsurf | <`.windsurfrules` / `.windsurf/workflows/` / `.windsurf/rules/`> | <N> |
| Continue.dev | <`.continue/instructions.md` / `.continue/config.*` / `.continue/assistants/`> | <N> |
| Codeium | <`.codeium/instructions.md` / `.codeiumignore`> | <N> |
| GitHub Copilot | <`.github/copilot-instructions.md` / `.github/prompts/`> | <N> |
| Aider | <`.aider.conf.yml` / `CONVENTIONS.md`> | <N> |
| Kiro | <`.kiro/steering/` / `.kiro/specs/`> | <N> |
| Generic / MCP | <`AGENTS.md` / `.mcp.json` / `mcp.json`> | <N> |

If none: `No AI assistant configurations committed to the repo.`

**Dangerous permission patterns (Cat 28b):**

| File | Line | Pattern | Severity |
|------|------|---------|----------|
| <`.claude/settings*.json`> | <line> | <`Bash(*:*)` / `Bash(sudo …)` / `Write(*)` / `WebFetch(domain:*)`> | <Critical / High / Medium> |

If none: `No overly-broad permissions detected.`

**Hooks executing arbitrary shell (Cat 28c):**

| File | Hook event | Command fragment | Risk class | Severity |
|------|------------|------------------|------------|----------|
| <file> | <PreToolUse / PostToolUse / UserPromptSubmit / …> | <first 80 chars of the command> | <network-egress / command-injection / benign> | <Critical / High / Info> |

If none: `No hook definitions found.`

**MCP servers (Cat 28d):**

| Config file | Server name | Transport | Origin | Severity |
|-------------|-------------|-----------|--------|----------|
| <`.mcp.json` / `.cursor/mcp.json` / …> | <server id> | <stdio / http / sse> | <local binary / public registry (npx/uvx) / remote URL> | <Critical / High / Info> |

If none: `No MCP server configurations found.`

**Bundled third-party agents / skills / commands (Cat 28e):**

| Path | Kind | Tools requested (frontmatter) | Shell/network in body? | Upstream framework | Severity |
|------|------|-------------------------------|------------------------|---------------------|----------|
| <file> | <agent / skill / command / workflow / rule> | <Bash, Write, Edit, Agent, …> | <yes / no> | <aider-template / unknown> | <Critical / High / Medium> |

If none: `No bundled third-party AI agents, skills, or commands found.`

**Prompt-injection red flags in instruction files (Cat 28f):**

| File | Line | Matched pattern class | Evidence snippet | Severity |
|------|------|----------------------|------------------|----------|
| <file> | <line> | <instruction-override / destructive-command-in-instruction / encoded-payload> | <first 60 chars of the match> | <Critical / High> |

If none: `No prompt-injection red flags detected in instruction files.`

**Anti-pattern — device/symlink settings (Cat 28g):**

- <`.claude/settings.json` is `<type>` (e.g. `character special file`) — real config lives in `.claude/settings.local.json` — informational>
- If regular file / not present: `Informational — normal file layout.`

## 8. Dangerous Sinks & Secrets (Flagged)

| Severity | File | Line | Category | Context |
|----------|------|------|----------|---------|
| <Critical/High> | <file> | <line> | <Dangerous sink/Hardcoded secret> | <1-sentence description> |

## 9. Preliminary Components

Based on the directory structure, tech stack, and code analysis, these are the identifiable components:

| ID (suggested) | Name | Technology | Role | Entry points |
|----------------|------|-----------|------|-------------|
| <slug> | <name> | <framework / language> | <1-sentence role> | <routes, ports, protocols> |

## 10. Preliminary Asset Candidates

A first-pass asset inventory derived from manifests, schemas, config files, and the security-relevant code scan. The orchestrator's Phase 5 uses this as the starting point — it enriches and classifies, but does not re-discover.

**Derivation rules:**
- **Data assets** — populate from database schemas (`*.sql`, Prisma schema, GraphQL schema, JPA entities, SQLAlchemy models), DTOs/request models, and any PII-adjacent terms in code (email, address, ssn, dob, payment, iban, card). Cite the defining file:line.
- **Code / IP assets** — populate from each package manifest (`package.json` name, `pyproject.toml`, `pom.xml` artifactId, `go.mod` module, etc.) plus any directory that contains proprietary algorithm code (ML models, pricing engines, recommender systems) detected from directory names or README descriptions.
- **Infrastructure assets** — populate from deployment artifacts (Dockerfile images, docker-compose services, k8s manifests, Terraform resources) and config files identifying databases, message queues, caches, object stores, secrets stores.
- **Availability assets** — populate from any user-facing or revenue-path component identified in Section 9 (APIs, frontends, payment flows), and any SLO/SLA reference in docs.

| Tier | Suggested asset | Evidence (file or section) | Preliminary classification | Rationale |
|------|-----------------|---------------------------|---------------------------|-----------|
| Data | <e.g., User PII> | `prisma/schema.prisma:42` | Confidential | email, password_hash, address fields |
| Data | <e.g., Payment records> | `src/models/Order.ts:18` | Restricted | card_last4, billing_address |
| Code | <e.g., Pricing engine> | `src/pricing/` + `package.json` | Internal | proprietary logic module |
| Infrastructure | <e.g., Postgres 15> | `docker-compose.yml:14` | Confidential | holds user and order data |
| Infrastructure | <e.g., Redis session store> | `config/session.ts:8` | Internal | auth session tokens |
| Availability | <e.g., Checkout API> | Section 9 component `checkout-api` | Restricted | revenue path |

**Rules:**
- Cap at 12 rows total. Prioritize Data tier first, then Infrastructure, then Code, then Availability.
- If a tier has zero candidates from the recon, write a single row `| <tier> | _none detected_ | — | — | — |` — never omit the tier entirely.
- **Classification is preliminary** — mark any row derived purely from naming conventions (not direct schema evidence) with `(preliminary)` suffix so Phase 5 knows to verify.
- Do not invent assets. If the repo is a thin proxy with no data layer, the Data tier can contain only `_none detected_`.
````

## Section rules (apply when filling the template)

- If a category (7.1–7.32) has zero grep matches, write only: `No matches found.` — no subsections.
- For categories with matches: write **only the key files table and 1-2 bullet observations**. Omit lengthy code excerpts — file:line references are sufficient for the orchestrator to read source when needed.
- Section 8 (Dangerous Sinks & Secrets) is a **deduplicated** extract of the most critical findings from 7.8 and 7.12. All Critical-severity secrets from 7.12 **must** appear here. Cap at 10 rows.
- Section 9 is a best-effort component list. The orchestrator will refine it.
- **Keep the entire file under 200 lines.** This file is loaded into the orchestrator's context for all remaining turns — every extra line costs tokens across 50+ turns. Be maximally concise.

## Numbering history (for cross-references in existing reports)

Older recon-summaries used a different sub-section ordering. The current canonical numbering is:

- **7.27** — GitHub Actions Workflow Security (merged: was split as "7.27 Workflow Hardening" + a duplicate "7.27 Workflow Security").
- **7.28** — Container Runtime Hardening (was previously the second "7.28" alongside an unrelated AI Coding Assistant section).
- **7.31** — Service-to-Service & Cloud-IAM Authentication (merged: detection-pattern catalogue + output-table example were two separately-numbered "7.31" blocks).
- **7.32** — AI Coding Assistant & IDE Agent Configurations (was misnumbered as "7.28" alongside Container Runtime).

Old reports may reference `§6.27 Workflow Hardening` or `§6.28 AI Coding Assistant`. Map them to the new numbers when reading historical artefacts.
