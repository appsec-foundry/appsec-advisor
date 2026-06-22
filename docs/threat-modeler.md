# Threat Modeler

`/appsec-advisor:create-threat-model` analyzes a repository, derives a security-relevant architecture model from the implementation, and applies STRIDE to produce structured review input for AppSec and engineering teams.

→ [Back to README](../README.md)

## Contents

- [What you get](#what-you-get)
- [Example report: OWASP Juice Shop](#example-report-owasp-juice-shop)
- [What it checks](#what-it-checks)
- [Usage examples](#usage-examples)
- [Assessment depth & cost control](#assessment-depth--cost-control)
- [Repo-local context](#repo-local-context)
- [Cross-repo context](#cross-repo-context)
- [Architecture](#architecture)
- [Workflow commands](#workflow-commands)

## What you get

An assessment produces a security architecture and threat model report grounded in the repository. The report covers architecture observations, trust boundaries, STRIDE findings, risk-ranked threats, affected components, remediation guidance, and generated diagrams.

Findings are rendered from structured artifacts and checked before release, so the Markdown report and machine-readable export stay consistent.

**Default outputs**

- `threat-model.md` — human-readable report for engineers, architects, and security reviewers.
- `threat-model.yaml` — structured export used for automation and incremental reruns.

**Optional deliverables**

| File | Enable with | Description |
|---|---|---|
| `threat-model.pdf` | `--pdf` | Print-ready PDF report: automatic cover page, page-numbered table of contents, rendered diagrams, content-aware tables. Requires `pandoc` + `weasyprint`; diagrams additionally need `mmdc` and a Chrome/Chromium for Puppeteer. Missing deps abort with a clear message — pass `--no-mermaid` to export without diagrams. |
| `threat-model.html` | `--html` (or `export-threat-model --formats html`) | Self-contained HTML5 (pandoc-only, no weasyprint) with a centered, readable screen layout and rendered diagrams — for browser viewing, wiki attachments, or as a styling-pipeline input. Diagrams need `mmdc` + Chrome (same as PDF); without them they stay as code. |
| `threat-model.sarif.json` | `--sarif` | SARIF v2.1 output for code scanning integrations. |
| `pentest-tasks.yaml` | `--pentest-tasks` | Endpoint catalog and test plan for AI pentesters such as Strix, including finding verification plus architecture-driven probes. |

All optional deliverables can also be generated after an assessment. This is useful when CI runs the analysis in one job and publishes exports in another, or when you re-export after approved, schema-valid updates to `threat-model.yaml`:

```text
# Generate every export format from an existing threat-model.yaml / .md
/appsec-advisor:export-threat-model

# Single format
/appsec-advisor:export-threat-model --formats sarif
/appsec-advisor:export-threat-model --formats html
/appsec-advisor:export-threat-model --formats pentest --pentest-target https://staging.example.com
```

SARIF and pentest-tasks are produced deterministically from `threat-model.yaml` — no LLM tokens spent. PDF and HTML are converted from `threat-model.md`: HTML needs only `pandoc`, PDF additionally needs `weasyprint`. Mermaid diagrams are rendered to vector graphics by `mmdc` (`@mermaid-js/mermaid-cli`), which drives a headless **Chrome/Chromium via Puppeteer** — install one (`npx puppeteer browsers install chrome`, or `apt install chromium` and set `PUPPETEER_EXECUTABLE_PATH`). The PDF exporter's preflight aborts with a clear message if any required tool is missing or non-functional; run `/appsec-advisor:export-threat-model --check-only` to verify the toolchain, or pass `--no-mermaid` to export without diagrams.

## Example report: OWASP Juice Shop

The following example shows the output of a thorough-mode assessment against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

**Full example:** [OWASP Juice Shop threat model report](../examples/threat-modeler/threat-model-juice-shop-thorough.md)

The report shows the architecture diagram, trust boundaries, STRIDE findings, evidence links, abuse-case scenarios, mitigation register, and attack-path discussion in a format that developers review after a run.

Example security posture diagram from the report:

![Threat Model Juice Shop Standard](../examples/threat-modeler/threat-model-juice-shop-thorough.figure1.svg)

## What it checks

Before running STRIDE, `appsec-advisor` performs a reconnaissance pass that collects security-relevant signals from the repository. Those signals give the analysis a concrete starting point: routes, trust boundaries, auth flows, risky sinks, security controls, deployment files, and supply-chain configuration.

| Area | What is inspected |
|---|---|
| **Security Architecture** | Data flows, trust boundaries, service boundaries, compartmentalization, and security-relevant architectural patterns. |
| **Authentication & Access Control** | JWT handling, OAuth/OIDC flows, session handling, role checks, authorization middleware, and client-side access guards. |
| **Input Handling & Injection** | SQL/NoSQL query construction, unsafe deserialization patterns, request validation, and user-controlled input reaching sensitive sinks. |
| **Cryptography & Secrets** | Hardcoded secrets, weak hashing or crypto choices, key handling patterns, and sensitive configuration values. |
| **Frontend Security** | XSS-prone patterns, unsafe browser storage, client-side exposure of sensitive data, and security-relevant bundle content. |
| **Operations & Configuration** | CORS configuration, security headers, exposed management/debug endpoints, verbose errors, and stack-trace leakage. |
| **Supply Chain** | Dependency and lockfile signals, unpinned GitHub Actions, container image pinning, and build/deployment configuration. |
| **GenAI / LLM Security** | Prompt-injection surfaces, tool or agent boundaries, vector-store access patterns, LLM API usage, and OWASP LLM Top 10 related risks. |
| **Threat Actors** | Actor-driven threat classes: insider threats (privileged dev/ops), supply-chain actors (build-time compromise), B2B-partner abuse, and adjacent-tenant attacks in multi-tenancy architectures. Each finding is attributed to a threat actor class; the report includes an actor table and actor-adjusted likelihood scores. |
| **Abuse Cases** | Scenario-level attack chains verified against the codebase — end-to-end paths from entry point through exploitation to impact, with per-step verdicts and deterministic chain verdicts (fully viable / partially blocked / mitigated). |

> [!NOTE]
> The reconnaissance checks provide the starting context for the STRIDE analysis. They are not intended to replace a dedicated SAST, SCA, secrets, or IaC scanner. Instead, the findings are used as entry points for deeper reasoning across related files, flows, and trust boundaries.

## Usage examples

Run these commands directly within the Claude Code interface.

```text
# Show help text
/appsec-advisor:create-threat-model --help

# High-fidelity audit
/appsec-advisor:create-threat-model --assessment-depth thorough

# Rebuild: force a fresh scan by wiping all caches and intermediate model data
/appsec-advisor:create-threat-model --full --rebuild

# Dry run: preview the execution plan and agent routing without writing files
/appsec-advisor:create-threat-model --dry-run
```

### Focused analysis

Target specific components to reduce noise and optimize token usage. This is the recommended approach for large mono-repos or rapid iterations.

```text
# Focus on a logical service by name
/appsec-advisor:create-threat-model focus on the authentication service

# Target a specific directory path
/appsec-advisor:create-threat-model focus on the /services/payment-gateway
```

### With requirements catalog

Ground the threat model in your organization's security requirements catalog. The plugin fetches a structured YAML from a URL, grades the codebase against each requirement, and incorporates compliance findings into the report. See [`docs/harvester.md`](harvester.md) for how to produce that YAML from existing Confluence, Antora, or wiki pages.

```text
# Run threat model with requirements fetched from a URL
/appsec-advisor:create-threat-model --requirements https://URL/appsec-requirements.yaml

# Use the bundled mock server to test the loop locally before connecting a real catalog
python3 scripts/mock-server.py
/appsec-advisor:create-threat-model --requirements http://127.0.0.1:4444/requirements.yaml
```

Once `requirements_yaml_url` is set in `skills/audit-security-requirements/config.json`, the `--requirements` flag is optional — every subsequent run picks up the catalog automatically.

### Scanning external repositories

Run the analysis against a repository other than the current working directory using `--repo` and `--output`.

```text
# Scan a repository located outside the current working directory
/appsec-advisor:create-threat-model --repo ../another-api --output ./audits/another-api
```

For cross-repo context, declare related services in `docs/related-repos.yaml`; see [Cross-repo context](#cross-repo-context) below.

> [!TIP]
> For the current flag reference, run `/appsec-advisor:create-threat-model --help` or read [`skills/create-threat-model/HELP.txt`](../skills/create-threat-model/HELP.txt).

## Assessment depth & cost control

Assessment depth controls how much of the repository is reviewed and how much validation the report gets before it is handed back. Choose by review intent first; the model mix is selected automatically.

### Analysis modes

The plugin supports three assessment depths. Pick the lightest mode that still matches the risk of the change.

Within a run, *which* components get a full STRIDE pass is criteria-driven, not a fixed per-depth count:

- **quick** — frontend, auth surface, internet-exposed, and exposure-unknown components (reachability not provably internal);
- **standard** — the above plus CI/CD & deployment pipelines and stores holding credentials, PII, or payment data;
- **thorough** — the above plus proven-internal components, with deeper per-component analysis.

The analyzed count follows the repo's attack surface, not a hard cap. (Component counts in the benchmarks below predate this selection.)

| Mode | Best fit | What changes | Juice Shop benchmark |
|---|---|---|---|
| **Quick** `--assessment-depth quick` | Fast feedback, pre-commit checks, early design iterations. | Reduced-depth pass; **skips** attack-chain (abuse-case) validation and the final QA review. Early signal — rerun at standard before release decisions. | **Cost** ~ $8.49<br>**Time** ~ 33 min<br>**Findings** 14 threats / 3 components<br>Critical 4, High 8, Medium 2<br>[sample report](../examples/threat-modeler/threat-mode-juice-shop-quick.md) |
| **Standard** *(default)* | Normal threat models and security reviews. | Full-depth analysis with attack-chain validation and a full QA review. The engineering-review default. | **Cost** ~ $32<br>**Time** ~ 121 min net compute (~40 min wall-clock)<br>**Findings** 80 findings / 9 components<br>Critical 11, High 39, Medium 21, Low 9<br>[sample report](../examples/threat-modeler/threat-model-juice-shop-thorough.md) |
| **Thorough** `--assessment-depth thorough` | Pre-release reviews, high-risk services, major architecture changes. | Everything in standard, plus deeper per-component analysis and an extra architecture-review pass. Best when missed architecture risk is expensive. | **Cost** ~ $43+ †<br>**Time** ~ 100 min<br>**Findings** 102 findings / 10 components<br>Critical 22, High 66, Medium 12, Low 2<br>[sample report](../examples/threat-modeler/threat-model-juice-shop-thorough.md) |

> [!NOTE]
> Benchmark numbers come from a single Node.js/Express reference app (OWASP Juice Shop) and vary substantially with repository size, language/framework mix, model routing, and cache effects. Treat the figures as ballpark orientation, not as predictions for your repo. **Incremental scans** are used automatically when an existing model is available and typically reduce token usage by 70–90%.
>
> The **standard** figures reflect the 2026-06-22 Juice Shop run (standard depth, `--reasoning-model opus`) driven from a Sonnet session. STRIDE ran on **verified Opus** — `model: opus` was passed explicitly to every parallel STRIDE Agent call, closing the silent-Sonnet-fallback gap identified in earlier runs. 9 components analyzed (incl. Web3/NFT surface), 80 findings, net API compute ~121 min, wall-clock ~40 min for Stage 1 (parallel STRIDE). The **thorough** figures reflect an earlier 2026-06-22 run with 102 findings / 10 components. **† Which model actually ran STRIDE could not be verified** for that thorough run: the hook `model` fields are cosmetic/frontmatter-defaulted, and `/cost` under-reports sub-agent Opus usage. Triage is the one stage with a real Opus record (`claude-opus-4-8`); the STRIDE execution model is unknown, so the ~$43 cost should be treated as indicative only. The linked sample reports predate this run. (To run the reasoning core on Sonnet instead, see **Reasoning model** below.)
>
> The figures above also include the **orchestration layer**, which runs in your interactive session's model (see the tip below). The standard Juice Shop run above is ~$32 from a Sonnet session; the same run driven from an Opus session is ~$47 — the ~$15 difference is purely the added cost of running orchestration on Opus instead of Sonnet (the analysis sub-agents are routed the same way either way, so only the orchestration share grows). In relative terms the orchestration layer is roughly **40–50% of an Opus-driven run** (here ~$20 of ~$47), so driving the session with Opus adds on the order of **+25–55% to the total** — not a fixed surcharge but a *proportional* one that **grows with run length and repo size** (the orchestrator re-reads its accumulating cached context on every dispatch, so longer/larger runs carry a bigger absolute premium). None of it deepens the analysis.

### Reasoning model

`--reasoning-model` sets which foundation model runs the **threat-reasoning core** (STRIDE, triage, merge). The rest of the pipeline is routed independently of the tier.

| Tier | STRIDE · triage · merge | When to use |
|---|---|---|
| `sonnet-economy` | Sonnet · Sonnet · Sonnet | Cheapest — same core as `sonnet`, but helper agents drop to Haiku. **Default at quick**; opt-in at standard/thorough. |
| `sonnet` | Sonnet · Sonnet · Sonnet | Like `sonnet-economy`, but helper agents stay on Sonnet. |
| `opus-cheap` | Sonnet · Sonnet · **Opus** | Opus only on the cheap merge step — a middle ground (opt-in). |
| `opus` | **Opus** · **Opus** · **Opus** | **Default at standard/thorough** (resolved config). *Intended* for best calibration/coverage, but **the benefit is not yet validated** — observed runs silently fell back to Sonnet for STRIDE because the parallel dispatch omitted the Agent `model` param (a `stride_model_mismatch` run-issue now flags this). Treat Opus-vs-Sonnet cost/quality claims as provisional. |

`--no-opus` forbids Opus everywhere (downgrades `opus`/`opus-cheap` to Sonnet; overrides all other sources, including the org profile and `APPSEC_DISABLE_OPUS=1`).

Which model each role runs on:

| Role | Model |
|---|---|
| Reasoning core (STRIDE · triage · merge) | per tier above |
| Recon, context, config scanners | Haiku |
| QA reviewer | Sonnet |
| Orchestrator | Sonnet |
| Session driver | your interactive session model |

> [!TIP]
> The reasoning model and the session model are separate, separately-billed knobs: `--reasoning-model` sets the analysis core; the session model drives orchestration (see the session-model tips below).

### Budget guardrails

You can set hard limits to avoid unexpected runtime or API usage. When a limit is reached, the process stops gracefully with `SIGTERM`.

| Interactive plugin | Headless / CI | Meaning |
|---|---|---|
| `--max-wall-time` | `--max-duration` | Maximum runtime |
| `--max-cost` | `--max-budget` | Maximum API spend |

Example:

| Mode | Time limit | Cost limit | Example |
|---|---|---|---|
| **Interactive plugin** | `--max-wall-time` | `--max-cost` | `/appsec-advisor:create-threat-model --max-cost 5 --max-wall-time 30m` |
| **Headless / CI** | `--max-duration` | `--max-budget` | `./scripts/run-headless.sh --incremental --max-duration 1800 --max-budget 5` |

> [!NOTE]
> Cost limits only apply when using an `ANTHROPIC_API_KEY`. When running on a standard Claude subscription, there is no per-token API billing, so cost limits are ignored. Time limits remain active in both modes.

For very large repositories, the advisor automatically switches to an optimized scanning strategy to avoid context window overflows.

> [!TIP]
> **The session model only changes the orchestration layer** — the analysis sub-agents are auto-routed by depth/repo size either way. Sonnet is enough to drive the pipeline (it is a deterministic playbook), so for routine and incremental runs start from a Sonnet session (`/model sonnet`, `/clear` first); Opus orchestration costs ~5× more *per token on that layer* — which works out to roughly **+25–55% on the total run** (a proportional share that scales with run length and repo size, not a fixed amount) — and only buys higher reliability on long, branchy runs (first runs, large repos, recovery paths) — insurance against a mis-orchestrated run, not better analysis.

## Repo-local context

Two optional files let the owning team feed the threat model directly. Commit them to the scanned repository; the scan reads both at the start of every run. Neither is required, and both are read as the team's input — useful as context, but never enough on their own to suppress a finding the code evidence supports.

### Business context — `docs/business-context.md`

Free-form Markdown, read verbatim (up to 200 lines). Use it to state what the code can't show: which flows are revenue-critical, what regulatory drivers apply, where the crown-jewel data lives, and which failure scenarios would hurt most. The analysis uses it to weight severity and priority — the same SQL injection reads differently on a marketing page than on a payment path once that context is on the table.

### Known threats — `docs/known-threats.yaml`

A list of threats the team already knows about: prior pentest findings, accepted risks, or issues you want every run to re-check. The file is schema-validated up front, so a malformed entry stops the run early instead of being dropped silently.

```yaml
threats:
  - id: PT-2025-001
    title: Stored XSS in product reviews
    stride: Tampering
    component: web-frontend
    severity: High
    status: open
    description: Review body rendered without sanitization.
    evidence: src/reviews/render.ts:42
```

Each entry's `status` decides what the scan does with it:

| `status` | What the scan does |
|---|---|
| `open` | Re-reads the cited evidence and includes the threat if it still holds |
| `mitigated` | Verifies the mitigation is actually present in the code |
| `accepted` | Records it under accepted risks, without re-checking |
| `false-positive` | Skips it entirely |

Optional fields per entry: `evidence` (`file:line`), `pentest_ref`, `accepted_risk`, `mitigation_ref`.

## Cross-repo context

`appsec-advisor` scans one repository at a time. If your service calls another service, you can still give the scan useful cross-repo context.

Declare the services this repo depends on in `docs/related-repos.yaml`.

> **Note:** Actor pull from `related-repos.yaml` is not supported. Declaring a related repo does not import its actor definitions. `ACT-D-07` (compromised-third-party-service) is activated only when the scan detects external API calls in the repo itself, not through `related-repos.yaml` declarations.

### Add context for services you call

If this repo calls another internal service, add that service's threat model to `docs/related-repos.yaml`:

```yaml
related:
  - name: payments-api
    threat_model: ../payments-api/docs/security/threat-model.yaml
    interface: POST /api/v1/payments
```

On the next scan, `appsec-advisor` uses that upstream threat model as context for the local component that calls `payments-api`.

`threat_model:` accepts a local path or `https://...` URL. For private repos, use `auth_env:` to name an environment variable that contains the fetch header.

The `interface:` value is matched against the upstream model's `attack_surface[].entry_point`. When it matches, the scan can use upstream details such as protocol, authentication requirement, handling component, and documented controls.

Imported data is treated as the upstream team's claim, not as verified evidence. It can raise new hypotheses, but it must not suppress local findings.

### Declare assumptions about the upstream service

If this repo relies on a specific upstream guarantee, declare it explicitly:

```yaml
    expected_auth: JWT
    expected_validation: schema
```

If the upstream threat model documents something different, the scan can raise a cross-repo hypothesis at that boundary. For example, expecting `JWT` while the upstream model documents `api-key` can seed an authentication-related finding.

These fields are optional. Without them, the scan still uses the upstream model as context, but it does not perform this expectation check.

## Architecture

`appsec-advisor` runs as a staged pipeline rather than one large prompt. Each stage has a narrow task, and the final report is generated from validated, structured data.

- **Repository-driven input:** The pipeline starts from the code repository and extracts application context, components, routes, controls, IaC config, and trust actors.

- **Multi-agent threat analysis:** Specialized agents analyze threats per component using STRIDE and a shared threat library.

- **Evidence-backed output:** Findings are merged, deduplicated, and verified against code evidence before being reported.

- **Prioritized threat model:** Valid threats are triaged into priority levels and rendered into `threat-model.md` and `.yaml`.

- **Quality gates:** Deterministic QA checks run by default; optional architect review adds deeper technical validation.

![Threat Model Pipeline](images/threat-model-pipeline.png)

## Workflow commands

Helpers for the threat model lifecycle — run after `create-threat-model` completes or to recover from interrupted runs.

| Command | Purpose |
|---|---|
| `/appsec-advisor:publish-threat-model` | Make selected report files trackable in git after the publish checks pass. |
| `/appsec-advisor:export-threat-model` | Re-export an existing threat model into PDF, HTML, SARIF, and/or pentest-tasks. Deterministic — no LLM tokens spent. |
| `/appsec-advisor:threat-model-health` | Check whether the current threat model is fresh, stale, missing, or blocked by run debris. |
| `/appsec-advisor:clean-run-state` | Remove stale run-state after an interrupted or crashed assessment. |
| `/appsec-advisor:fix-run-issues` | Apply safe auto-fixes for issues recorded by the previous run, or print manual repair guidance. |
| `/appsec-advisor:status` | Show plugin version, configuration, and last-run state. |
| `/appsec-advisor:check-permissions` | Check or update the Claude Code permissions needed for unattended runs. |
