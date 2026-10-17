# Design proposal: provider-neutral assessment engine

**Status:** proposal, not implemented. No requirement or decision has been written for it; steps that change the product promise need operator confirmation first (see [Decisions to confirm](#decisions-to-confirm)).

**Scope:** the deterministic controller path (`orchestration_controller.py assess`), not the legacy skill/agent path selected with `APPSEC_SINGLE_REPO_CONTROLLER=0`.

**Goal:** run the security assessment with model hosts other than `claude -p` (for example Bedrock, the Anthropic API, or OpenAI models), let users configure hosts and models in one place, and make the assessment installable as a Python package that the Claude Code plugin integrates instead of containing.

## Current state

The facts in this section were checked against the code on 2026-10-17. Line numbers refer to that state.

### Model calls already pass through one seam

- `run-headless.sh:285` hands repository assessments to `orchestration_controller.py assess`; Claude Code is involved only as the `claude -p` model transport.
- Every model exchange goes through the `Transport` protocol (`scripts/runtime/analyst_host.py:142`): `invoke(system, prompt, schema, timeout_s, should_stop) -> HostReply(payload, usd)`.
- `claude -p` is constructed in exactly one place on this path: `_assessment_cli_host_factory` (`orchestration_controller.py:3520`) builds `ClaudeCliTransport`. No other module under `scripts/orchestrator`, `scripts/runtime`, or `scripts/contexts` starts `claude`.
- All roles obtain their transport through that factory (`orchestration_controller.py:915`, `:1353`, `:1378`), and `assess_repositories(argv, *, host_factory=None, …)` (`:4046`) already accepts an injected factory; tests use fake hosts through it.
- `ClaudeCliTransport` runs without tools, project configuration, or session persistence and enforces `--json-schema` and `--max-budget-usd`.

### Claude-specific parts on this path

- Error vocabulary and hints: `API_ERROR_CODES` (`analyst_host.py:78`) is generic, but `_FAILURE_HINTS` (`:96`) names the Claude login and account.
- Cost: `_reported_usd` (`analyst_host.py:123`) reads `total_cost_usd` from the CLI result object. The CLI reports a list-price estimate.
- Host options: `effort`, `max_thinking_tokens`, and `short_cache` (`FORCE_PROMPT_CACHING_5M`) are Claude CLI options.
- Authentication preflight: `run-headless.sh:277` checks `claude auth status` in subscription mode before the controller starts.
- Environment: the transport drops only `GIT_`, `APPSEC_`, `OUTPUT_DIR`, `CLAUDE_CODE_SESSION`, and `CLAUDE_SESSION` variables (`analyst_host.py:59`), so `CLAUDE_CODE_USE_BEDROCK` and `AWS_*` reach the child process.

### Where models are chosen

- Agent frontmatter (`model: sonnet` in every `agents/*.md`) does not apply on this path. The controller strips the frontmatter and uses the body as the prompt (`assessment_stage2.py:144`, `_agent_body`). Stage 2 was checked directly; Stage 1 roles take their model from the resolved configuration in the same way.
- Role to configuration key: `SEMANTIC_ROLE_MODEL_KEYS` (`orchestration_controller.py:193`) and `RENDERER_MODEL_KEYS` (`assessment_stage2.py:50`).
- Configuration key to model ID: `resolve_config.py` resolves depth defaults with concrete Claude IDs in code (`resolve_reasoning_model`, `:772`), the `--reasoning-model` tier switch, and about 13 `APPSEC_*_MODEL` environment overrides (`:833`, `:912`, `:1150`).
- `actor_discovery_model` falls back to `"sonnet"` inside the controller (`orchestration_controller.py:893`), outside the resolver.

### Depth controls two different things

- Model selection: `quick` and `standard` use `sonnet-economy`, `thorough` uses `opus` for STRIDE, triage, and merger; renderer and abuse verifier get Sonnet 4.6 at `quick` and Sonnet 5 otherwise.
- Amount of work: evidence-verifier cap (`resolve_evidence_verifier_cap`, `:524`), abuse-case verification (`:546`), and cheap STRIDE (`:573`).

### Budget is denominated in USD

`AssessmentBudget` (`scripts/runtime/assessment_jobs.py:46`) requires `max_usd` and `call_usd`, and `accepted()` (`:90`) computes `max(cost, usd)`. A transport that cannot report a numeric cost breaks the completion reserve required by REQ-FLW-008.

## Proposed design

### Host profiles

A host profile bundles everything provider-specific: transport class, tier-to-model-ID mapping, price table, authentication preflight, supported features (schema dialect, effort, caching), and failure hints. Profiles ship in a data file such as `data/model-hosts.yaml`.

| Profile | Transport | Notes |
|---|---|---|
| `claude-cli` | `ClaudeCliTransport` | Current default. |
| `claude-cli/bedrock` | `ClaudeCliTransport` | Same transport with `CLAUDE_CODE_USE_BEDROCK=1`, Bedrock inference-profile IDs, and an AWS credential preflight. Cost stays the CLI list-price estimate. |
| `anthropic-api`, `openai-api` | new API transports | Tool-less by construction; cost from tokens and the price table. |

The Codex CLI is not a suitable transport unless its tools can be proven disabled. It runs as an agent with a shell tool, and `--sandbox read-only` still permits reading outside the working directory, which conflicts with REQ-TRU-004. A direct OpenAI API transport covers OpenAI models without that exposure. Codex details are from documentation knowledge and were not verified against a current Codex release.

### Transport contract

Every transport satisfies the same contract, verified by one parametrized contract test suite against a faked endpoint without network access:

- Returns a schema-valid payload or raises `TransportError`; the controller validates the payload itself.
- Maps provider errors to `API_ERROR_CODES`; failure hints come from the profile.
- Sets `usd` on every call, including failed calls that consumed tokens.
- Enforces the call ceiling before the call. API transports derive `max_tokens` from `ceiling` and price and refuse a call whose minimum cost exceeds the ceiling.
- Has no tools, file access, or network access beyond the model endpoint.
- Honors `timeout_s` and `should_stop` with `HostTimeout` and `HostCancelled`.

A profile whose schema dialect cannot express a response schema (for example the OpenAI strict subset) stops the run before the first model call.

### Unified model configuration

One schema-validated file, for example `~/.config/appsec-advisor/models.yaml`, selects the host and maps roles to tiers per depth:

```yaml
host: claude-cli
tiers:
  reasoning: claude-opus-5-5
  standard:  claude-sonnet-5-5
  economy:   claude-haiku-5-5
profiles:
  quick:
    stride_analyzer: standard
    renderer: economy
    recon_scanner: economy
  standard:
    stride_analyzer: standard
    renderer: standard
    recon_scanner: economy
  thorough:
    stride_analyzer: reasoning
    triage_validator: reasoning
    threat_merger: reasoning
    renderer: standard
roles:
  evidence_verifier: claude-sonnet-4-6
prices:
  claude-opus-5-5: {input: 0.0, output: 0.0}
```

The `prices` values are placeholders.

Resolution order: depth selects the profile, the profile maps each role to a tier, and the host maps the tier to a model ID. Each level accepts overrides with the precedence CLI flag, environment variable, user configuration, host default, depth default. Existing `APPSEC_*_MODEL` variables and `--reasoning-model` remain as overrides.

Rules:

- Roles name tiers, not model IDs. The current depth matrix with Claude IDs moves out of `resolve_config.py` into the default profiles.
- `resolve_assessment` is the only resolution point, including `actor_discovery_model`.
- Unknown roles, tiers, unavailable IDs, or an API host model without a price stop the run before the first model call.
- Depth keeps controlling the amount of work in the resolver; the model configuration controls only which model does it.
- Resolved host, role, tier, and model ID enter the `AssessmentState` identity (`orchestration_controller.py:897`), so `--resume` never mixes hosts, and appear in the report's run statistics.
- Repository content is untrusted. A configuration file in the target repository must not select a host, because that would let the analyzed repository decide where its code and the operator's context are sent. `host` comes only from user configuration, the organization profile, or the CLI, and the organization profile can restrict hosts and models with an allow-list.

### Prices and cost reporting

- `claude-cli` profiles need no price table; the CLI reports cost.
- API profiles use the bundled price table with a stated date; user `prices` only override it.
- A model without a price on an API host is refused (fail closed), because the budget cannot be enforced without it.
- Console and run statistics label cost as an estimate and name its source (host-reported or price table with date).
- A token-denominated budget would avoid prices but changes the budget logic, `--max-budget-usd`, cost display, and the wording of REQ-FLW-008. It is out of scope for the first step.

### Engine and plugin separation

The controller is already a standalone Python program inside the plugin: it locates its files relative to itself (`PLUGIN_ROOT = SCRIPT_DIR.parent`, `orchestration_controller.py:71`) and reads agent prompts as plain files.

Target shape:

```text
pip install appsec-advisor
appsec-assess --repo . --host claude-cli/bedrock --depth thorough
```

- Engine (Python package): controller, scanners, validators, renderers, exports, schemas, data, templates, role prompts, host profiles, and model configuration.
- Claude Code plugin: skills, hooks, and interactive parts (business-context dialog, `review-threat-model`, `ask-threat-model`, coach). It calls the engine instead of containing it.
- Other integrations (CI action, editor extensions) can use the same engine later.

Constraints:

- A marketplace plugin install does not run `pip install`. Default: the plugin vendors the engine at the same version. Alternative: the plugin requires an installed engine and checks a compatibility range fail closed at start.
- Package data (`data/`, `schemas/`, `templates/`, prompts) must load through `importlib.resources` instead of `SCRIPT_DIR.parent`.
- Role prompts become plain prompt files; Claude Code agent definitions reference or are generated from them, so no frontmatter is maintained that has no effect on the engine path.
- Interactive questions need an engine-level interface (answers file or CLI prompts); headless already accepts context without questions (REQ-BIZ-010).
- PyPI publication requires trusted publishing, signed builds or attestations, pinned dependencies, and a release process aligned with [the release runbook](../../releasing.md).
- pandoc, weasyprint, and mmdc remain optional external tools with explicit errors.
- The legacy skill/agent path stays in the plugin until it is removed. Other skills (for example `authnz-review`, `verify-requirements`) need an individual decision whether they are engine or plugin functions.

A separate repository is not recommended until the engine has a different release cadence or owners; contracts, schemas, requirement bindings, and tests would otherwise have to stay synchronized across repositories.

## Implementation order

1. Confirm the requirement and decision wording with the operator.
2. Draw the engine boundary in this repository: a boundary test that the engine path reads no `CLAUDE_*` variables and no files under `skills/` or `hooks/`, and resources loaded through `importlib.resources`.
3. Introduce host profiles, the unified model configuration, and the transport contract suite with `claude-cli` as the only profile. No behavior change.
4. Add `claude-cli/bedrock` as a profile: environment, ID mapping, and preflight.
5. Add `pyproject.toml` entry point `appsec-assess`, locally installable; the plugin calls the engine and vendors it.
6. Add an API transport (for example `openai-api`) with fixture replay and an `eval-threat-model` run per depth as acceptance.
7. Publish to PyPI with a signed release.

Steps 2–5 keep current behavior for Claude Code users. Each additional host profile needs its own quality evidence per depth before the depth levels are promised on it.

## Open questions

- 29 Python files under `scripts/` read `CLAUDE_PLUGIN_ROOT` or `CLAUDE_PROJECT_DIR`. Which of them lie on the controller path has not been checked; this is the first task of step 2.
- Whether other entry points (for example the threat-analyst CLI) construct their own transports has not been traced.
- A Bedrock run through `run-headless.sh` probably fails at the `claude auth status` preflight (`run-headless.sh:277`); this has not been tested.
- Prompt caching and `effort` support on Bedrock vary by model and need measurement.

## Decisions to confirm

These change the product promise and need confirmed wording before implementation:

- Requirement: assessments can run on configured model hosts other than Claude Code, with Claude Code as default and the isolation obligations of the transport contract.
- Requirement or decision: the target repository cannot select the model host; organization profiles can restrict hosts and models.
- Decision: the assessment engine is a separately installable Python package that the Claude Code plugin integrates, kept in this repository.
