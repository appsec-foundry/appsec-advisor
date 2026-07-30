# Implementation plan — Copilot threat-modeling MVP

- Date: 2026-07-30
- Status: Plan only — no code yet.
- Scope: GitHub Copilot CLI repository integration, while preserving the
  existing Claude Code plugin.
- Decision: Build a second, thin host adapter over the existing deterministic
  analysis and rendering core. Do not create a one-to-one copy of the Claude
  runtime prompts.

## Goal

Deliver an experimental Copilot repository skill that can run a full threat
model for a target repository and produce the same primary contracted outputs:

```text
threat-model.md
threat-model.yaml
threat-model.sarif.json
```

The MVP supports `quick` and `standard` full scans. It preserves the existing
schemas, stable-ID rules, evidence requirements, severity caps, redaction,
deterministic renderer, and QA gates.

The target command is:

```text
/create-threat-model --depth standard --yaml --sarif
```

Copilot may expose a skill by name rather than the Claude plugin namespace.
Document the final invocation only after validating it in the supported Copilot
CLI version.

## Verified basis

The existing product separates valuable deterministic contracts from the Claude
control plane:

- `scripts/` owns validation, merging, stable IDs, rendering, exports, cleanup,
  and release gates.
- `schemas/`, `data/`, and `tests/fixtures/` define and test output contracts.
- The `create-threat-model` control plane is Claude-specific: routing and
  runtime instructions live in `skills/create-threat-model/`; specialization
  lives in `agents/*.md`; lifecycle integrations live in
  `.claude-plugin/plugin.json`, `.claude/settings.json`, and
  `hooks/hooks.json`.
- The current primary analyst prompt cannot be copied into one Copilot custom
  agent profile: `agents/appsec-threat-analyst.md` is about 151,000 characters,
  `agents/appsec-stride-analyzer.md` about 64,000, and
  `skills/create-threat-model/SKILL-impl.md` about 375,000. The Copilot
  custom-agent prompt limit itself is an external claim and is verified in
  Phase 0, not here.
- The full run is not four analysis stages. Recon covers Phases 1, 2, 2.5, 2.6
  and 2.7; architecture modeling covers Phases 3, 3b, 4, 5, 6, 7 and 8; STRIDE
  is Phase 9; posture, evidence verification and triage are Phases 10, 10a and
  10b; rendering and finalization are Phase 11.

The implementation must preserve the deterministic layer as the authority.
LLM agents may only produce or review contracted intermediate files. They must
not write `threat-model.md`, `threat-model.yaml`, SARIF, or final exports
directly.

## MVP scope

### In scope

1. A repository skill under `.github/skills/create-threat-model/`.
2. Copilot agent profiles for recon, architecture modeling, trust-boundary
   analysis, component STRIDE analysis, triage, fragment rendering, and QA.
3. Full runs at `quick` and `standard` depth.
4. Existing deterministic preflight, schema validation, path/URL guards,
   known-secret redaction, composition, QA, YAML, and SARIF export.
5. AI Secure Coding Baseline installation/checking and the existing
   requirements source/report/gate commands where enabled by configuration.
6. A minimal session-start and telemetry hook adapter when the required Copilot
   hook payloads are supported.
7. Fixture-backed contract tests for the Copilot surface and an E2E replay.

### Explicitly out of scope

- Incremental analysis and carry-forward state.
- Abuse-case fan-out and architect-review repair loops.
- The sampled LLM evidence verifier of Phase 10a. Its deterministic floor,
  `scripts/validate_evidence_lines.py`, stays mandatory, so no finding ships
  with an unresolved evidence pointer.
- Per-phase cost routing and exact Sonnet/Opus selection parity.
- PDF, Threat Dragon, and pentest-task exports.
- Live watchdog/status UI parity.
- Claude package archive generation, namespaced commands, and Claude settings.
- Copilot organization packaging or organization-wide distribution.
- Any relaxation of validation, redaction, schema, evidence, or severity rules.

Do not add an output mode that is less safe than the existing full pipeline
merely to simplify the first Copilot integration.

## Target architecture

```text
                    shared deterministic core
  scripts/  schemas/  data/  templates/  tests/fixtures/
                              |
          +-------------------+-------------------+
          |                                       |
  hosts/claude or existing Claude files     hosts/copilot
  Claude skills, agents, hooks              .github/skills, agents, hooks
          |                                       |
     Claude Code runtime                     Copilot CLI runtime
```

The repository does not need a literal `hosts/` directory in the first patch.
The required architectural boundary is semantic:

- A shared command may inspect host-specific configuration only through an
  explicit host or capability input. It must not infer the host by probing
  Claude paths or environment variables.
- Host adapters resolve asset roots, translate runtime lifecycle events, select
  agents, and present user interaction.
- All host adapters invoke the same deterministic commands and exchange the
  same schema-validated sidecars.

Introduce a small host descriptor only if it removes repeated branching. Do not
add a generic abstraction framework before two concrete callers need it.

## Required artifact and safety contracts

1. Continue using the existing sidecar graph: component inventory, recon
   summary, trust-boundary artifacts, `.stride-*.json`,
   `.threats-merged.json`, triage sidecars, fragments, and QA status.
2. Preserve public `T-NNN` / `F-NNN` identity behavior. Incremental behavior
   is out of scope, but a new host must not alter full-run allocation.
3. `compose_threat_model.py --strict` remains the only composer of
   `threat-model.md`, and no agent may write that file. Deterministic passes
   still mutate it afterwards in the order AGENTS.md pins: `apply_prose_fixes.py`,
   then `qa_checks.py autofix`, then `render_completion_summary.py
   --patch-placeholders` as the only post-review mutation. A Copilot render
   state that stops after the composer ships unpatched placeholders.
4. `build_threat_model_yaml.py` remains the only builder of
   `threat-model.yaml`, and no agent may write that file. The auto-emitters run
   after it and enrich the built document; rebuilding the YAML discards their
   output, so the emitter pass must follow every build.
5. Existing path guards, URL guards, secret scanning/redaction, and
   post-scan secret checks remain mandatory on every Copilot path.
6. Repository content, hook configuration, imported reports, and external
   context remain untrusted data, never agent instructions.
7. Copilot hooks are observability and ergonomics mechanisms. They are not
   security boundaries and cannot replace deterministic enforcement.

## Implementation phases

### Phase 0 — Capability spike and compatibility record

Before production changes, create a short-lived Copilot CLI compatibility
fixture outside the product flow. Verify the installed and supported Copilot
version can:

1. Discover a repository skill in `.github/skills`.
2. Discover repository custom agents in `.github/agents`.
3. Invoke a selected custom agent from a skill or provide an acceptable
   bounded alternative.
4. Run the required shell and file tools under explicit approvals.
5. Run repository hooks from `.github/hooks` and expose the event payloads
   needed by telemetry.
6. Handle a user decision without relying on Claude `AskUserQuestion`
   semantics.
7. Run multiple component analyses with bounded parallelism, or reliably fall
   back to serial processing.
8. Accept a custom-agent prompt of a known maximum size. Record the documented
   limit and whether an oversized prompt fails loudly or is truncated
   silently; Phase 3 sizing depends on the answer.

Record the exact supported capability, fallback, and version in a concise
internal compatibility note. Do not assume that custom-agent availability
implies programmable subagent fan-out.

**Exit criterion:** a checked-in design decision names the supported Copilot
execution mode and the serial fallback. No MVP work may depend on unverified
subagent dispatch semantics.

### Phase 1 — Make the deterministic core host-neutral

Audit every production command used by the MVP for:

- `CLAUDE_PLUGIN_ROOT`;
- `.claude-plugin/plugin.json`;
- `.claude/settings.json`;
- Claude transcript paths;
- assumptions about Claude task or hook data; and
- hard-coded plugin-root discovery.
- embedded shell commands in repair plans, event payloads, and user-facing
  remediation strings.

The audit must produce a caller-to-command matrix. About 28 scripts mention
`CLAUDE_PLUGIN_ROOT` today, so state the reachable subset explicitly before
editing. Do not broaden every script preemptively: only commands reachable from
the MVP state machine are in scope, plus their direct metadata, permission, and
repair-plan dependencies.

For each affected command, prefer an existing explicit `--plugin-root`
argument. Where none exists, add a narrowly named `--asset-root` or
`--plugin-root` argument with a safe default only for the existing Claude
caller. Centralize metadata resolution in a shared helper rather than copying
path discovery.

The following current seams require explicit design changes:

1. `orchestration_controller.py:_missing_permissions_action()` currently calls
   the Claude-specific `check_permissions.effective_allow()` unconditionally
   on both full and rerender preparation paths. Introduce an explicit
   permission-provider/capability input. Preserve the current Claude gate
   exactly; require a tested Copilot provider that validates the documented
   skill tool policy and never treats an absent `.claude/settings.json` as a
   successful Claude configuration.
2. `build_threat_model_yaml.py:_plugin_version()` reads
   `.claude-plugin/plugin.json` directly and does not import `plugin_meta.py`;
   the two are independent readers. Generalize the `plugin_meta.py` seam and
   route `_plugin_version()` through it, so both hosts emit consistent product
   and analysis version metadata without requiring Copilot to ship a fake
   Claude manifest. Generalizing `plugin_meta.py` alone changes nothing in the
   YAML builder.
3. QA repair plans currently embed `$CLAUDE_PLUGIN_ROOT` commands. Replace
   agent-consumed command strings with an explicit asset-root value or a
   structured remediation action resolved by the host adapter. A Copilot
   repair consumer must never expand an unset Claude variable into a relative
   `/scripts/...` path.
4. The baseline checker currently proves that a baseline is loaded through
   Claude instruction discovery. Define a Copilot instruction-discovery
   strategy and make baseline verification host-aware. Do not interpret its
   existing "unloaded Copilot candidate" result as proof that a Copilot
   session has the baseline in context.

Do not change behavior for the existing Claude invocation. Add regression tests
for both the default path and an explicitly supplied root.

**Exit criterion:** the deterministic preflight, controller, renderer, YAML
builder, QA gate, host-specific baseline check, and requirements gate can run
against an explicit asset root. The Claude route must retain its existing
permission failure and metadata behavior.

### Phase 2 — Define the Copilot skill entry point

Two repository mechanisms already treat `.github/` as infrastructure rather
than product, and both must be decided before the first Copilot file lands.
They apply equally to `.github/agents/` in Phase 3 and `.github/hooks/` in
Phase 6.

1. The repair agent refuses any change touching `.github/`
   (`.github/workflows/repair-agent.yml:362`). Product files placed there stay
   permanently outside the automated repair loop. Carving a path exception into
   that check is not an option: it is a security boundary and AGENTS.md forbids
   weakening it. Accept the exclusion and record it, or host the Copilot surface
   outside `.github/` if Copilot discovery allows it.
2. `.github` is a top-level exclude in the internal packaging build
   (`scripts/package_internal_plugin.py:34`), so an organization build would
   drop the entire Copilot surface without a warning. Decide whether the MVP
   ships in org builds. If it does, the exclusion needs a narrowed rule and the
   package-surface manifest must account for the Copilot files; if it does not,
   state that in the user document rather than leaving a silent omission.

Add:

```text
.github/skills/create-threat-model/SKILL.md
```

The skill must:

1. Describe a precise activation condition and supported arguments.
2. Resolve the repository root and output directory through deterministic
   commands, never from repository-provided instruction text.
3. Run the existing route/config/preflight commands.
4. Print only stable, concise progress and final artifact locations.
5. Refuse unsupported MVP modes with an actionable deterministic error.
6. State that source changes and final reports are written only through their
   existing controlled paths.

Keep the skill prompt short. It must route to phase-local resources, not embed
the Claude `SKILL-impl.md` orchestration body. If Copilot does not support a
reliable skill-relative environment variable, resolve its path from a
host-controlled launcher or pass it as an explicit argument. Never search
arbitrary home directories for the first matching checkout.

**Exit criterion:** Copilot discovers the skill and the skill runs the
deterministic preflight against the E2E fixture without starting an analysis.
The repair-loop exclusion and the packaging decision are recorded.

### Phase 3 — Split analysis into bounded Copilot agents

Create Copilot-compatible agent profiles with prompts below the documented
limit:

```text
.github/agents/appsec-recon.agent.md
.github/agents/appsec-architecture.agent.md
.github/agents/appsec-trust-boundary.agent.md
.github/agents/appsec-stride.agent.md
.github/agents/appsec-triage.agent.md
.github/agents/appsec-render.agent.md
.github/agents/appsec-qa.agent.md
```

These seven profiles absorb the work of twenty Claude agents. Architecture
modeling and trust-boundary analysis get their own profiles because they own
contracted report sections and their own sidecars; folding them into recon
drops Sections 1 through 6 from the output.

Each profile must name only the tools it needs and declare its read/write
authority. Reuse shared prose and contract resources where they are genuinely
host-neutral. Translate tool instructions such as `Read`, `Grep`, `Write`,
`Agent`, and Claude task calls into Copilot's actual tools and execution model.

Agent responsibilities:

| Agent | Inputs | Sole output authority |
|---|---|---|
| Recon | target source, deterministic scanner output | recon/context sidecars, actor sidecar |
| Architecture | recon sidecars, architecture-coverage artifacts | `.components.json`, `.data-flows.json`, `.assets.json`, `.attack-surface-overrides.json`, `.security-controls.json` |
| Trust boundary | component inventory and data flows | trust-boundary candidate and canonical artifacts |
| STRIDE | one dispatch manifest entry and scoped evidence | one `.stride-<component>.json` |
| Triage | merged threats and deterministic severity data | triage/mitigation sidecars |
| Render | validated structured artifacts and section contract | fragment files only |
| QA | rendered report, YAML, contract outputs | QA status and repair plan only |

Attack walkthroughs have no sidecar contract today; Phase 4 authors them as
report prose. For the MVP the render agent writes them as a fragment from the
architecture and threat sidecars, so no agent writes into the report itself.

Initially dispatch STRIDE serially unless Phase 0 proves safe fan-out. Preserve
the per-component isolation contract even when serial: each call receives one
component manifest and cannot write another component's sidecar.

**Exit criterion:** every agent can produce its sidecar for the synthetic
fixture; schema failures stop the pipeline before the next stage.

### Phase 4 — Implement the MVP state machine

Extend the deterministic orchestration controller, or add a narrowly scoped
host-neutral companion, with these states:

```text
preflight -> recon -> architecture -> stride -> merge -> triage
          -> render -> qa -> finalize -> complete
```

`architecture` covers Phases 3 through 8 including trust boundaries. `merge`
runs the deterministic merge and the evidence-line validation floor.
`finalize` runs the post-compose
mutation chain named in the artifact contracts; without it the report ships
unpatched placeholders and unenriched YAML.

The controller must persist an explicit state record with:

- current state;
- input/output paths;
- completed component IDs;
- command/agent attempt count;
- failure category; and
- terminal result.

It must reject invalid transitions and report incomplete output as failure.
The Copilot skill invokes one transition at a time; it does not infer completion
from assistant prose. A failed or interrupted run remains diagnosable without
being presented as a successful threat model.

Keep the existing Claude controller path working. Do not mix host conditionals
through the current large runtime instructions; use the controller state record
as the cross-host handoff.

**Exit criterion:** an injected failure in recon, architecture, STRIDE, merge,
triage, render, QA, or finalize produces a non-success terminal record and no
falsely successful final report.

### Phase 5 — Integrate baseline and requirements capabilities

Wire the existing AI Secure Coding Baseline and requirements flow into Copilot:

1. Resolve organization/profile configuration through the shared resolver.
2. Install or load the baseline only through existing guarded commands.
3. Run `baseline_check.py` before analysis where existing configuration
   requires it, after extending it with the host-specific instruction
   discovery contract from Phase 1.
4. Fetch and validate requirements through the existing guarded source path.
5. Run `requirements_gate.py` at the same logical gate point as the MVP
   controller.

Do not port Claude-specific `setup-target` behavior. The controller permission
provider is mandatory, not optional: it must represent Copilot's approved
tools/trust policy without weakening the existing Claude permission gate.
Document Copilot's tool approval and trust model instead. Do not expose remote
baseline or requirements sources unless the existing URL allowlist accepts
them.

`org-profile.yaml` is only partly host-neutral today. Resolve its presets,
baseline, requirements, actor, and context blocks through the shared resolver.
For the MVP, profiles declaring `hooks`, Claude package-surface policy, or
Claude-only skill-toggle behavior must be rejected with an explicit
unsupported-feature error or have those blocks omitted through a separately
validated host projection. Do not silently accept a profile while dropping its
security-relevant policy. `validate_org_profile.py` currently requires
`${CLAUDE_PLUGIN_ROOT}/org-profile/` for profile hooks and reads
`.claude-plugin/package-surface.json`; leave those semantics unchanged for the
Claude host.

**Exit criterion:** enabled baseline and requirements configurations pass or
fail the Copilot run exactly through their current deterministic exit behavior.

### Phase 6 — Add minimal Copilot hooks

Add a repository hook configuration under `.github/hooks/` only after Phase 0
confirms the supported schema and event payloads.

MVP hook responsibilities:

- session start: optional banner;
- user prompt submitted: non-authoritative guidance or telemetry;
- pre/post tool use: structured telemetry only.

Port `agent_logger.py` through a dedicated adapter that normalizes Copilot event
payloads into the existing `scripts/event_log.py` format. Do not make a hook
failure fatal unless the equivalent deterministic command would already be
fatal. Do not use a hook to inject untrusted repository text into an agent
prompt.

`security_steering.py` and `skill_policy_gate.py` require separate design
validation. If Copilot cannot safely provide their semantics, keep the MVP
policy in skill instructions plus deterministic gates and mark automatic
steering unsupported.

**Exit criterion:** hooks validate against Copilot's schema; logging remains
well-formed; disabling hooks does not bypass any product security invariant.

### Phase 7 — Test, replay, and document

Add focused tests for:

1. Copilot skill frontmatter, supported arguments, and resource paths.
2. Every Copilot agent profile: required metadata, tool allowlist, prompt-size
   limit, output authority, and absence of Claude-only commands.
3. Copilot hook schema and event adapter behavior.
4. Explicit asset-root behavior in shared scripts.
5. Controller transitions, interruption, and failure paths.
6. Baseline and requirements integration, including the host-specific baseline
   discovery result and the controller permission-provider decision.
7. Version metadata and repair-plan command generation across both hosts.
8. The finalize state: prose fixes, QA autofix, and placeholder patching run in
   the pinned order, and the auto-emitters run after every YAML build.
9. The packaging decision for the Copilot surface, asserted against the
   package-surface manifest so a silent drop fails the build.

Keep `scripts/e2e_fixture.sh` as a Claude-only regression check: it invokes
`run-headless.sh` and requires the `claude` CLI. It proves the shared core
continues to work for Claude, but cannot validate the Copilot surface.

Add a distinct Copilot E2E replay path against the same fixture and oracle. It
may use a scripted Copilot CLI invocation only if Phase 0 validates reliable
non-interactive execution. Otherwise define a repeatable approved interactive
procedure that captures the generated artifacts before the deterministic oracle
runs. The Copilot acceptance path must validate:

- required sections;
- schema-valid YAML and SARIF;
- no placeholders;
- no secret leakage;
- report composition only through the deterministic renderer;
- valid references and anchors;
- severity and evidence gates; and
- no writes outside allowed output paths.

Add an English user document that states supported Copilot versions, supported
MVP modes, setup/trust requirements, expected outputs, and the known
limitations below.

**Exit criterion:** targeted tests, `make lint`, and `make test` pass, and the
Claude regression replay and the distinct Copilot replay both satisfy the
existing structural assertions.

## Risks, side effects, and required mitigations

| Risk | Impact | Mitigation and proof |
|---|---|---|
| Copilot cannot deterministically fan out to custom agents | Lost throughput or incomplete coverage | Use serial per-component dispatch first; require a manifest-completeness gate before triage. |
| Copilot custom-agent prompt limit | Prompt truncation silently drops safety rules | Split agents by phase; test profile size; retain shared contracts as explicit resources. |
| Different tool and permission semantics | Unsafe writes or repeated interactive failures | Use minimal tool allowlists; preserve Python path guards; document trust/approvals; test rejected tool paths. |
| Mandatory Claude permission gate blocks Copilot | Every controller preparation aborts before analysis | Add and test an explicit host-specific permission provider; preserve the current Claude provider and failure text. |
| Model selection differs by host | Cost, quality, or review-depth drift | Treat model routing as host-specific; record the actual model in run metadata; do not claim Claude model parity. |
| Claude metadata leaks into Copilot reports | `plugin_version` and `analysis_version` silently become wrong, affecting compatibility decisions | Generalize `plugin_meta.py`; test YAML metadata for both hosts. |
| Claude paths in repair sidecars | Copilot repair steps execute invalid or unintended paths | Emit host-resolved structured remediation; test all agent-consumed command strings. |
| Architecture stages read as part of recon | Sections 1–6, trust boundaries, and the STRIDE component manifest never get produced | Give architecture and trust boundaries their own states and agent profiles; assert their sidecars before STRIDE starts. |
| Render state stops after the composer | Placeholders and unenriched YAML ship as a finished report | Model the post-compose chain as its own state; test the pinned mutation order. |
| Copilot surface lives under `.github/` | The repair loop cannot touch it, and an organization build drops it silently | Record the repair-loop exclusion instead of weakening the Gate; decide and test the packaging rule before the first file lands. |
| Hook event mismatch | Missing telemetry or misleading success state | Make telemetry additive; state transitions and gates remain deterministic. |
| Copied prompts diverge | Claude and Copilot findings/report quality drift | Share contracts/prose where possible; keep only host adapters separate; add cross-host fixture checks. |
| Weaker MVP path bypasses safety checks | Security regression | Define mandatory scripts per state; add negative tests for skipped redaction, schema, and QA gates. |
| Copilot environment or cloud execution differs from local CLI | Unsupported scripts/dependencies or data exposure | Scope MVP to Copilot CLI first; do not claim cloud-agent support until a separate environment compatibility review completes. |
| Organization profile is already partly Claude-specific | Copilot profiles can fail validation or silently lose hook/policy behavior | Project only supported blocks for the MVP; reject unsupported blocks explicitly; preserve existing Claude validation. |
| Existing E2E fixture is Claude-only | A passing replay gives false confidence in the Copilot adapter | Retain it as a Claude regression; add a separate Copilot replay against the same oracle. |
| Anthropic pricing leaks into Copilot telemetry | Cost estimates are false or budget gates make wrong decisions | Exclude cost/budget scripts from the MVP execution graph; add Copilot pricing only through a separately validated provider. |

## Deferred work after MVP

1. Incremental runs and stable-ID carry-forward replay.
2. Bounded parallel STRIDE, the sampled evidence verifier, and abuse-case
   verifier waves.
3. QA repair and architect-review repair loops.
4. PDF, Threat Dragon, and pentest-task exports.
5. Copilot-native organization profile overlay and packaging/distribution.
6. Equivalent run-status/watchdog UX.
7. Model/depth routing evaluation and budget telemetry.

Each deferred item requires a separate plan and fixture replay. Do not silently
enable it because an underlying Claude capability exists.

## Functional-parity statement

The MVP targets the security-critical report path, not feature-count parity.
Expected capability levels are:

| Area | MVP target | Mature Copilot target |
|---|---:|---:|
| Deterministic scanning, contracts, rendering, YAML/SARIF | 90–100% | 95–100% |
| Recon, architecture, trust boundaries, STRIDE, triage, QA analysis | 65–80% | 80–90% |
| Baseline and requirements gates | 80–90% | 90–100% |
| Hooks, telemetry, interactive UX | 40–60% | 70–85% |
| Claude packaging and per-stage model routing | 0–30% | 40–60% |
| Whole product feature set | about 65% | about 80–85% |

These are planning estimates, not release claims. The fixture replay and
capability spike determine whether the measured implementation meets them.

## Execution order for a follow-on agent

1. Read this plan, `AGENTS.md`, `CONTRIBUTING.md`, and the referenced
   controller, skill, agent, hook, schema, and test files before editing.
2. Complete Phase 0 and record results before choosing a dispatch design.
3. Implement phases in order. Do not start an agent-profile port before the
   asset-root contract is proven.
4. For each phase, add tests before or with behavior changes and run the
   smallest relevant test subset.
5. Run the synthetic fixture replay for each change that affects deterministic
   analysis, rendering, or contracts.
6. Stop and revise this plan if Copilot's verified lifecycle cannot support a
   stated assumption. Do not emulate unsupported behavior with fragile prompt
   conventions.

## Evidence index

- Claude plugin metadata: `.claude-plugin/plugin.json`
- Claude runtime control plane: `skills/create-threat-model/SKILL.md`,
  `SKILL-full-runtime.md`, `SKILL-impl.md`, and thin stage files
- Claude agents: `agents/appsec-*.md`, especially
  `agents/appsec-threat-analyst.md` and `agents/appsec-stride-analyzer.md`
- Claude hooks: `hooks/hooks.json`
- Claude permissions: `.claude/settings.json`,
  `data/required-permissions.yaml`
- Full-run phase set and sidecar contracts: `agents/phases/phase-group-recon.md`,
  `phase-group-architecture.md`, `phase-group-threats.md`,
  `phase-group-finalization.md`, `schemas/fragments/`
- Deterministic report contracts: `data/sections-contract.yaml`, `schemas/`,
  `scripts/compose_threat_model.py`, `scripts/build_threat_model_yaml.py`,
  `scripts/qa_checks.py`
- Post-compose mutation chain: `scripts/apply_prose_fixes.py`,
  `scripts/qa_checks.py autofix`, `scripts/render_completion_summary.py`,
  `scripts/validate_evidence_lines.py`
- Host seams named in Phase 1: `scripts/orchestration_controller.py:783`,
  `scripts/check_permissions.py:134`, `scripts/build_threat_model_yaml.py:117`,
  `scripts/plugin_meta.py`, `scripts/qa_checks.py:2458`,
  `scripts/baseline_check.py:106`, `scripts/validate_org_profile.py:338`
- Baseline: `scripts/install_baseline.py`, `scripts/baseline_check.py`,
  `config.json`
- Requirements: `scripts/fetch_requirements.py`,
  `scripts/requirements_report.py`, `scripts/requirements_gate.py`
- Existing packaging behavior: `scripts/package_internal_plugin.py:34`
  (`.github` top-level exclude), `docs/internal-plugin-packaging.md`
- Repair-loop path refusal: `.github/workflows/repair-agent.yml:362`
