# Threat Modeler

`/appsec-advisor:create-threat-model` derives an architecture model from a repository and applies STRIDE. The result is a security review for engineering and AppSec teams.

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

The Markdown and YAML outputs are generated from the same validated data.

**Default outputs**

- `threat-model.md` — human-readable report for engineers, architects, and security reviewers.
- `threat-model.yaml` — structured export used for automation and incremental reruns.

**Optional deliverables**

| File | Enable with | Description |
|---|---|---|
| `threat-model.pdf` | `--pdf` | PDF with a cover page, table of contents, and rendered diagrams. Requires `pandoc` and `weasyprint`. |
| `threat-model.html` | `--html` | Self-contained HTML for browsers and wiki attachments. Requires `pandoc`. |
| `threat-model.sarif.json` | `--sarif` | SARIF v2.1 output for code scanning integrations. |
| `pentest-tasks.yaml` | `--pentest-tasks` | Endpoint catalog and test plan for supported pentest tooling. |

Optional formats can also be generated from an existing assessment:

```text
# Generate every export format from an existing threat-model.yaml / .md
/appsec-advisor:export-threat-model

# Single format
/appsec-advisor:export-threat-model --formats sarif
/appsec-advisor:export-threat-model --formats html
/appsec-advisor:export-threat-model --formats pentest --pentest-target https://staging.example.com
```

SARIF and pentest tasks are generated from `threat-model.yaml` without model calls. PDF and HTML are converted from `threat-model.md`. Diagram rendering also requires `mmdc` and Chrome or Chromium. Check the export dependencies with:

```text
/appsec-advisor:export-threat-model --check-only
```

Use `--no-mermaid` to export PDF or HTML without rendered diagrams. To enable strict Mermaid validation during assessments, install the optional parser with `npm install --prefix "$CLAUDE_PLUGIN_ROOT/scripts"`.

## Example report: OWASP Juice Shop

The [OWASP Juice Shop example](../examples/threat-modeler/threat-model-juice-shop-thorough.md) shows a complete thorough assessment with evidence links, abuse cases, and attack paths.

Example security posture diagram from the report:

![Threat Model Juice Shop Thorough](../examples/threat-modeler/threat-model-juice-shop-thorough.figure1.svg)

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
| **Threat Actors** | Insider, supply-chain, partner, and adjacent-tenant threats where they apply. |
| **Abuse Cases** | Attack chains from entry point to impact, with each step checked against the repository. |

> [!NOTE]
> These checks provide context for STRIDE. They do not replace dedicated SAST, SCA, secrets, or IaC scanners.

## Usage examples

Run these commands directly within the Claude Code interface.

```text
# Show help text
/appsec-advisor:create-threat-model --help

# Deeper assessment
/appsec-advisor:create-threat-model --assessment-depth thorough

# Force a fresh scan and discard cached run state
/appsec-advisor:create-threat-model --full --rebuild

# Preview the run without writing files
/appsec-advisor:create-threat-model --dry-run
```

### Focused analysis

Target specific components to reduce cost and review time on large monorepos or during iteration.

```text
# Focus on a logical service by name
/appsec-advisor:create-threat-model focus on the authentication service

# Target a specific directory path
/appsec-advisor:create-threat-model focus on the /services/payment-gateway
```

### With requirements catalog

Use `--requirements` to include your organization's security requirements. See the [harvester guide](harvester.md) for creating the catalog YAML from Confluence, Antora, or other HTML pages.

```text
# Run threat model with requirements fetched from a URL
/appsec-advisor:create-threat-model --requirements https://URL/appsec-requirements.yaml

# Use the bundled mock server to test the loop locally before connecting a real catalog
python3 scripts/mock-server.py
/appsec-advisor:create-threat-model --requirements http://127.0.0.1:4444/requirements.yaml
```

Once `requirements_yaml_url` is set in the plugin's skill configuration, the `--requirements` flag is optional — every subsequent run picks up the catalog automatically.

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

Assessment depth controls coverage, review depth, runtime, and cost.

### Analysis modes

Choose the lightest mode that fits the decision the report will support.

Within a run, *which* components get a full STRIDE pass is criteria-driven, not a fixed per-depth count. Each depth includes everything from the lighter one:

| Component criterion | quick | standard | thorough |
|---|:---:|:---:|:---:|
| Role-floor: frontend, auth, AI/LLM surface | ✓ | ✓ | ✓ |
| Internet-exposed | ✓ | ✓ | ✓ |
| Exposure-unknown (reachability not provably internal) | ✓ | ✓ | ✓ |
| CI/CD & deployment pipelines | | ✓ | ✓ |
| Crown-jewel stores (credentials, PII, payment, secrets) | | ✓ | ✓ |
| File-upload surface | | ✓ | ✓ |
| Real-time channels | | ✓ | ✓ |
| Proven-internal (reachable but not exposed) | | | ✓ |

Thorough increases both component coverage and per-component analysis depth.

The number of analyzed components follows the repository's attack surface rather than a per-depth target.

### Cost by depth

These OWASP Juice Shop runs anchor on three measured points from July 2026 — **quick** ($18.03, 68 minutes), **standard** ($34.14), and a full **thorough** run (about $47, 103 minutes) — all with the Claude Code session (the orchestrator) on **Sonnet 4.6**, the recommended economy setup. The standard runtime (~85 minutes) is estimated from the quick and thorough anchors. They compare modes but do not predict the exact bill for another repository.

| Mode | Best fit | Review depth | API cost (USD) and time |
|---|---|---|---|
| **Quick** `--assessment-depth quick` | Early feedback and low-risk changes | Reduced analysis; skips abuse-case validation and final model-based QA | $18.03 and 68 minutes ([sample](../examples/threat-modeler/threat-model-juice-shop-quick.md)) |
| **Standard** *(default)* | Normal threat models and security reviews | Full analysis, abuse-case validation, and QA | $34.14 and ~85 minutes (time est.) ([sample](../examples/threat-modeler/threat-model-juice-shop-standard.md)) |
| **Thorough** `--assessment-depth thorough` | High-risk services and major releases | Deeper component analysis and architecture review | About $47 and 103 minutes ([sample](../examples/threat-modeler/threat-model-juice-shop-thorough.md)) |

> [!NOTE]
> Cost and runtime vary with repository size, stack, cache state, and model selection. Incremental scans commonly use 70–90% fewer tokens when a previous model is available.

`--stride-cap N` limits non-Critical findings per STRIDE category and component. It is off by default. In the same standard benchmark, a cap of 2 reduced the finding count from 83 to about 52 and saved roughly $4. The selected cap is recorded in the report.

### Reasoning model

`--reasoning-model` sets which foundation model runs the **threat-reasoning core** (STRIDE, triage, merge). The rest of the pipeline is routed independently of the tier.

| Tier | STRIDE · triage · merge | When to use |
|---|---|---|
| `sonnet-economy` | Sonnet 4.6 · Sonnet 5\* · Sonnet 5\* | Default for quick and standard. Helper tasks use Haiku. **\*Standard buy-back:** at `standard`, triage + merger (and renderer + abuse-verifier) resolve to Sonnet 5; STRIDE stays Sonnet 4.6. `quick` is all-Sonnet 4.6. |
| `sonnet` | Sonnet · Sonnet · Sonnet | Keeps helper tasks on Sonnet. |
| `opus-cheap` | Sonnet · Sonnet · **Opus** | Uses Opus only for merging. |
| `opus` | **Opus** · **Opus** · **Opus** | Default for thorough. Costs noticeably more than the economy default for a similar finding count — the Opus reasoning tier is what makes a thorough run more expensive than a standard one. |

`--stride-model`, `--triage-model`, and `--merger-model` override one part of the selected tier. Each accepts either a tier alias (`sonnet` / `opus`) or an explicit version id (e.g. `claude-sonnet-5`, `claude-sonnet-4-6`) to pin an exact model regardless of the session — the bare `sonnet` alias otherwise follows the host session model. Direct flags take precedence over the matching `APPSEC_*_MODEL` environment variables. `--no-opus` disables all Opus selections (alias or `claude-opus-*` id).

> **`--merger-model` caveat.** STRIDE and triage run as separate model-pinned sub-agents, so their pins always take effect. The merge, however, runs **inline/deterministic** (`merge_threats.py` + inline judgment) on the everyday `sonnet-economy` path — a separate `appsec-threat-merger` sub-agent is only dispatched on the opt-in *hybrid* path, which activates when `--merger-model` (or `APPSEC_MERGER_MODEL`) resolves to an **Opus** id, or at `--assessment-depth thorough`. Setting `--merger-model claude-sonnet-5` at standard therefore has **no effect** — there is no merger sub-agent to pin. The effective-routing table shown at scan start marks the merger row `inline unless hybrid/Opus` accordingly.

**Per-role model routing (2026-07-05).** The pipeline no longer leaves any subagent on the bare `sonnet` alias (which silently follows your session). Each role gets a concrete model per depth:

| Role | Agents | quick | standard | thorough |
|---|---|---|---|---|
| Reasoning — discovery | STRIDE | Sonnet 4.6 | Sonnet 4.6 | Opus |
| Reasoning — judgment | triage, merge | Sonnet 4.6 | **Sonnet 5** | Opus |
| Quality showcase | renderer, abuse-verifier | Sonnet 4.6 | **Sonnet 5** | **Sonnet 5** |
| Mechanical / contract | qa-content, qa-routine | Sonnet 4.6¹ | Sonnet 4.6¹ | Sonnet 4.6 |
| Deterministic helpers | context-resolver, recon-scanner, config-scanner | Haiku | Haiku | Haiku |
| Session | orchestrator | follows session² | follows session² | follows session² |

¹ qa-routine (mechanical link/anchor fixes) runs on Haiku at quick/standard. ² the orchestrator *is* the session model — the plugin can't pin it; see *Session Model* below.

The rationale: STRIDE stays on 4.6 (Sonnet 5 measured *worse* discovery recall); triage/merge/renderer/abuse-verifier get Sonnet 5 where a benchmark showed a real gain (severity calibration, dedup, CISO framing, decisive verdicts) — at standard *and* thorough; the mechanical stages stay on cheap 4.6. Two caveats: (1) these are **explicit-id pins** that only take effect on the **headless path** — an *interactive* run's subagents inherit the session model regardless; and (2) the **merger pin stays inert at standard** (the merge is inline — see the `--merger-model` caveat above). The whole split is skipped when you opt into the explicit `sonnet` tier (`--reasoning-model sonnet`, latest Sonnet everywhere).

For standard assessments, using Opus only for triage costs just slightly more than the all-Sonnet baseline, while the full Opus tier costs substantially more:

```text
/appsec-advisor:create-threat-model --reasoning-model sonnet-economy --triage-model opus --stride-cap 2
```

The report records the resolved model mix in *Run Statistics*.

### Session Model

By default the pipeline keeps the token-heavy work cheap. The analysis stages (STRIDE, triage, and the merge) run on a fixed model tier that does not follow your session, and on quick and standard that tier is the lower-cost Sonnet-4.6. So the bulk of a routine scan never costs Sonnet-5 rates, whatever session you launch it from.

The one part the defaults can't set for you is the **session model**, the model the main Claude Code loop itself runs on, and it is the biggest single cost driver. It pays for the dominant cache-read of a full run and for every agent that isn't pinned to something else: the orchestrator, the Stage-2 renderer, the abuse-case verifier, and content-QA. A running session can't switch its own model, so this is a Claude Code setting rather than a plugin flag.

Running the session on **Sonnet-4.6** roughly **halves** the cost of a run versus Sonnet-5 for the same report (see *Background: why Sonnet 4.6 costs less* below for the reason). Set it:

- **Interactive:** `/model claude-sonnet-4-6` before launching the scan, or add `"model": "claude-sonnet-4-6"` to `.claude/settings.json` (project-scoped) or `~/.claude/settings.json` (global). The scan warns at start when it detects a **non**-4.6 host (Sonnet-5 or Opus) and prints the exact restart command; the effective per-agent routing is shown in the Pre-flight box.
- **Headless / CI:** `scripts/run-headless.sh` **defaults** the session to `claude-sonnet-4-6` (the economy default) — no flag needed. Override per run with `--model <id>`.

**As a rule of thumb: run the session on Sonnet-4.6 and pin *up* only the few stages where Sonnet-5 clearly pays off; never run the session on Sonnet-5 for quality.** On a 4.6 session everything runs on Sonnet-4.6 (or Haiku for the deterministic helpers); no agent silently runs on Sonnet-5. A Sonnet-5 session is strictly more expensive for the same result, because you then pay Sonnet-5 rates for the dominant cache-read plus the orchestrator, renderer, abuse-verifier and content-QA, while STRIDE/triage/merger stay 4.6 either way.

| Stage | Pin to Sonnet-5? | Why |
|---|---|---|
| Triage (severity) | ✅ `--triage-model claude-sonnet-5` | better severity calibration |
| Renderer (§7 + MS) | ✅ `APPSEC_RENDERER_MODEL=claude-sonnet-5` | sharper CISO framing |
| Abuse-case verifier | ✅ `APPSEC_ABUSE_VERIFIER_MODEL=claude-sonnet-5` | decisive verdicts (no "inconclusive") |
| STRIDE | ❌ keep 4.6 | 4.6 has **better** recall *and* is cheaper |
| Merger | ❌ | runs inline on the default path (pin has no effect) |
| Helpers / content-QA | ❌ | Haiku / no measurable Sonnet-5 gain |

These buy-backs are cheap: triage, renderer and the verifier are small token slices, so the run stays close to a pure-4.6 cost while gaining Sonnet-5 quality where it actually helps. Interactively, `--triage-model` works as a flag; the two `APPSEC_*_MODEL` pins must sit in the `.claude/settings.json` `"env"` block (an inline `VAR=… /command` does not reach the skill). Headless, all three can be passed inline before `run-headless.sh`.

#### Background: why Sonnet 4.6 costs less

A threat-model scan is token-heavy and largely mechanical: it reads an entire repository into context and emits structured fragments, so the bill is dominated by the number of tokens processed (mostly cached input re-read across the run), not by hard reasoning. Sonnet 5 and Sonnet 4.6 are billed at comparable per-token rates, but Sonnet 5 uses an updated tokenizer that represents the same source text with **more** tokens — in this project's A/B runs, roughly 30 % more for the same repository and report. Because the work is token-bound rather than reasoning-bound, that difference flows straight through to cost: the same assessment simply costs more on Sonnet 5 for equivalent output.

Sonnet 5's edge is reasoning *quality* — sharper severity calibration, outcome-first framing, and more decisive verdicts — not token efficiency. So the economical setup keeps the token-heavy, mechanical majority (the reasoning core, the orchestrator, the deterministic helpers) on Sonnet 4.6 and spends Sonnet 5 only on the few stages where its reasoning measurably improves the result. This is also why STRIDE stays on 4.6: threat *discovery* depends on recall, where 4.6 matched or beat Sonnet 5 in the measurements while costing less.

### Budget guardrails

Set hard limits for runtime and API cost:

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

> [!TIP]
> The interactive session model is billed separately from `--reasoning-model`. Running the session itself on Opus added about 25–55% to measured total cost without changing the analysis model. Use a Sonnet session for routine runs.

## Repo-local context

Two optional files add team-owned context. Neither file can suppress a finding supported by repository evidence.

### Business context — `docs/business-context.md`

Use this Markdown file for facts the code cannot show: critical flows, regulatory scope, sensitive data, and high-impact failure scenarios. The first 200 lines are read.

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

> **Note:** Actor pull from `related-repos.yaml` is not supported. Declaring a related repo does not import its actor definitions. The compromised-third-party-service actor is activated only when the scan detects external API calls in the repo itself, not through `related-repos.yaml` declarations.

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

Imported data is context, not verified evidence. It can suggest findings but cannot suppress local evidence.

### Declare assumptions about the upstream service

If this repo relies on a specific upstream guarantee, declare it explicitly:

```yaml
    expected_auth: JWT
    expected_validation: schema
```

If the upstream threat model documents something different, the scan can raise a cross-repo hypothesis at that boundary. For example, expecting `JWT` while the upstream model documents `api-key` can seed an authentication-related finding.

These fields are optional. Without them, the scan still uses the upstream model as context, but it does not perform this expectation check.

## Architecture

The pipeline extracts architecture and security signals, runs STRIDE by component, verifies evidence, and renders the validated results. The final report does not come from a single free-form model response.

![Threat Model Pipeline](images/threat-model-pipeline.png)

## Workflow commands

Use these commands after an assessment or to recover an interrupted run.

| Command | Purpose |
|---|---|
| `/appsec-advisor:publish-threat-model` | Make selected report files trackable in git after the publish checks pass. |
| `/appsec-advisor:export-threat-model` | Re-export an existing threat model into PDF, HTML, SARIF, or pentest tasks without model calls. |
| `/appsec-advisor:threat-model-health` | Check whether the current threat model is fresh, stale, missing, or blocked by run debris. |
| `/appsec-advisor:clean-run-state` | Remove stale run-state after an interrupted or crashed assessment. |
| `/appsec-advisor:fix-run-issues` | Apply safe auto-fixes for issues recorded by the previous run, or print manual repair guidance. |
| `/appsec-advisor:status` | Show plugin version, configuration, and last-run state. |
| `/appsec-advisor:check-permissions` | Check or update the Claude Code permissions needed for unattended runs. |

Outside of a Claude Code session (e.g. in CI setup), use the equivalent Makefile target:

```sh
make setup-target [REPO=<path>] [SCOPE=project|local|user]
```

`REPO` defaults to the current directory. `SCOPE` controls which `settings.json` file is written (`project` = `.claude/settings.json`, default).
