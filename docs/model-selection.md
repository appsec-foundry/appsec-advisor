<a id="model-selection-cost--context-window"></a>
# Model selection, cost, and context window

Model selection differs between the main Claude Code session and the subagents it dispatches. This guide describes the defaults, overrides, and measured cost trade-offs for `create-threat-model`. The routing implementation is in [`scripts/resolve_config.py`](../scripts/resolve_config.py).

## The two halves of a run

The plugin selects subagent models. You select the model for the main session, which orchestrates the assessment.

| Role | Work | Model selection |
|---|---|---|
| Subagents | STRIDE analysis, triage, merging, rendering, QA, reconnaissance, configuration scanning, and abuse-case verification | Plugin defaults and per-stage overrides, subject to the interactive dispatch limitation below. |
| Orchestrator | Coordinates the assessment and report production | `/model` in an interactive session or `run-headless.sh --model` in a headless run. A skill cannot change its session model; `ORCHESTRATOR_MODEL` is informational. |

<a id="subagents--model_matrix-author-controlled-default"></a>
## Subagent defaults

`MODEL_MATRIX` maps reasoning tiers to STRIDE, triage, and merger models:

| Tier | STRIDE / triage / merger | Default use |
|---|---|---|
| `sonnet-economy` | `claude-sonnet-4-6`, with the per-role exceptions below | quick and standard |
| `sonnet` | `sonnet` alias, currently Sonnet 5 | Opt-in through `--reasoning-model sonnet` |
| `opus-cheap` | Sonnet for STRIDE and triage; Opus for merging | Opt-in |
| `opus` | Opus for all three roles | thorough; opt-in at other depths |

The default role assignments are:

| Role | Agents | quick | standard | thorough |
|---|---|---|---|---|
| Discovery | STRIDE | Sonnet 4.6 | Sonnet 4.6 | Opus |
| Judgment | triage, merger | Sonnet 4.6 | Sonnet 5 | Opus |
| Report authoring and verification | renderer, abuse-verifier | Sonnet 4.6 | Sonnet 5 | Sonnet 5 |
| QA | qa_content, qa_routine | Sonnet 4.6; Haiku for qa_routine | Sonnet 4.6; Haiku for qa_routine | Sonnet 4.6 |
| Coordination | orchestrator | Session model | Session model | Session model |

The explicit `sonnet` tier selects the latest Sonnet instead of this version split. `EXTENDED_MODEL_MATRIX` supplies the Haiku defaults for context resolution, reconnaissance, configuration scanning, and routine QA, subject to depth-specific routing.

**Interactive dispatch limitation:** exact model IDs apply on the headless path and the hybrid-merger path. The interactive Agent tool accepts tier aliases only; its `sonnet` alias follows the session model. Selecting an exact Sonnet version in the resolved configuration therefore does not guarantee that version runs interactively.

### Why the default is cost-pinned to Sonnet 4.6

The recorded benchmarks found lower cost with Sonnet 4.6 for the same assessment. Sonnet 5 improved merging, triage, and report authoring, but missed findings during STRIDE discovery. The defaults retain 4.6 for STRIDE and use Sonnet 5 for the standard-depth judgment and authoring stages. See [Benchmarks](#benchmarks) for the measured scope.

### Override precedence (highest wins)

```text
--stride-model / --triage-model / --merger-model      (CLI: sonnet | opus)
  APPSEC_STRIDE_MODEL / _TRIAGE_MODEL / _MERGER_MODEL  (environment: exact model ID)
    MODEL_MATRIX[tier]                               (plugin default)
```

- Use `--reasoning-model sonnet` to select the latest Sonnet tier.
- Use `--reasoning-model opus` for Opus reasoning.
- Set `APPSEC_STRIDE_MODEL=claude-sonnet-5` to request an exact model for one stage. Environment variables accept exact IDs; the per-stage CLI flags accept only `sonnet` or `opus`. An `env` block in `settings.json` applies the variables to subsequent runs. The interactive dispatch limitation still applies.

<a id="orchestrator--the-session-model"></a>
## Orchestrator model

Set the interactive session model through `/config`, `settings.json`, or `/model` before starting the assessment. The skill shows cost and repository-size advice. If you choose to switch models, it stops and prints a `claude --model <X>` restart command; it cannot change the active session itself.

For headless runs, pass `--model` to `scripts/run-headless.sh`. The wrapper launches `claude -p --model <X>` and skips the interactive recommendation prompt when `APPSEC_HEADLESS=1`.

### Repo-size recommendation (advisory)

The preflight recommendation uses the repository's source-file count:

| Repository size | Recommended session model | Reason |
|---|---|---|
| Fewer than 2500 source files | `claude-sonnet-4-6` | Lower measured cost; the context window usually covers the run. |
| At least 2500 source files | `claude-sonnet-5` | The larger context window reduces the risk of mid-run compaction and incomplete finalization. |

When the detected interactive session differs from the recommendation, the skill asks whether to keep it or switch. Keeping the current model is allowed. The threshold is defined by `ORCHESTRATOR_SONNET5_FILE_THRESHOLD` in `resolve_config.py`.

<a id="context-window-caveat--dont-cheap-out-the-orchestrator"></a>
## Context window

The orchestrator accumulates context throughout the assessment. A smaller context window can force compaction during a large run and affect finalization. Subagents have bounded, component-specific context and do not accumulate the full session history. Account for this difference when choosing a session model for a large repository.

<a id="benchmarks--measured-effects-of-sonnet-5-vs-sonnet-46"></a>
## Benchmarks

The measurements below come from standard-depth full scans of one Node/Express repository, OWASP Juice Shop. They describe those runs, not expected costs or quality for every repository. The source analyses are the [Sonnet comparison](internal/analysis/plan-model-routing-transparency-2026-07-04.md) and the [model-placement comparison](analysis/analysis-model-placement-orchestrator-vs-stride-2026-06-21.md), whose section 10 contains the validated Opus A/B run.

<a id="cost--the-session-model-dominates"></a>
### Session cost

| Session model | Total cost | Recorded usage |
|---|---|---|
| Sonnet 5 | About $60 | About 124 million cache-read tokens in the main session |
| Sonnet 4.6 | About $30 | About 30% fewer tokens for the same work |

The comparison used the same input and output token prices for both models. It attributed the difference to tokenization, adaptive thinking, and repeated reads of the growing session context. Session-model choice had a larger cost effect than per-agent overrides in these runs.

<a id="per-agent-quality--where-sonnet-5-helps-where-it-hurts"></a>
### Per-agent results

| Agent | Observed result with Sonnet 5 compared with 4.6 | Default reflected by the result |
|---|---|---|
| `appsec-threat-merger` | 0 versus 8 duplicate file:line collisions | Sonnet 5 at standard depth |
| `appsec-triage-validator` | 10 versus 15 Critical findings; the analysis judged 5's calibration better | Sonnet 5 at standard depth |
| `appsec-threat-renderer` / `appsec-ms-renderer` | Management prose focused on outcomes | Sonnet 5 at standard depth |
| `appsec-secarch-renderer` | Section 7 controls tied to evidence | Sonnet 5 at standard depth |
| `appsec-abuse-case-verifier` | 4.6 reintroduced `inconclusive` verdicts | Sonnet 5 outside quick depth |
| `appsec-stride-analyzer-v2` | Missed path traversal, an SSRF sink, and prompt injection; collapsed the LLM chatbot component | Sonnet 4.6 at quick and standard depth |
| `qa_content`, orchestrator | No observed quality difference | Sonnet 4.6 / session model |
| recon / config / context | Extraction tasks | Haiku |

### Opus (older validated A/B, §10 of the placement analysis)

Opus reasoning for STRIDE, triage, and merging cost $40.78 versus $30.01 for `sonnet-economy`, an increase of $10.77 (36%), with no measured quality or coverage gain in that comparison. Using Opus for the orchestrator increased total cost by 25–55% without an observed analytical benefit. Standard depth defaults to `sonnet-economy`; thorough uses Opus reasoning.

### Practical recipe

For a repository below the size threshold, use a Sonnet 4.6 session and the default role assignments. For headless runs requiring explicit overrides, set `APPSEC_MERGER_MODEL`, `APPSEC_TRIAGE_MODEL`, and `APPSEC_RENDERER_MODEL` to `claude-sonnet-5`, while retaining Sonnet 4.6 for STRIDE. For larger repositories, consider the session context window before reducing cost.

## Quick recipes

| Goal | Setting |
|---|---|
| Use the standard model mix | Keep the default `sonnet-economy` tier. |
| Request another reasoning tier for one run | `--reasoning-model sonnet` or `--reasoning-model opus` |
| Request an exact model for one stage | `APPSEC_STRIDE_MODEL=claude-sonnet-5`, subject to dispatch support |
| Set the interactive orchestrator | `/model` before the run, or `/config` for the default |
| Set the headless orchestrator | `run-headless.sh --model <model-id>`; choose a sufficient context window for the repository |
