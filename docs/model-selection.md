<a id="model-selection-cost--context-window"></a>
# Model selection, cost, and context window

This guide describes the model defaults, overrides, and measured cost trade-offs of `/appsec-advisor:appsec-analyzer` and `scripts/run-headless.sh`. The routing implementation is in [`scripts/runtime/resolve_config.py`](../scripts/runtime/resolve_config.py).

## Roles and their models

The controller calls each role's model directly. No Claude Code session orchestrates the run, so the model of the session that starts an assessment does not affect it. Every role has a fixed model version, and the first lines of each run name the models it uses.

| Role | Work | Model setting |
|---|---|---|
| Discovery | Repository reconnaissance | `recon_scanner_model`, `APPSEC_RECON_SCANNER_MODEL` |
| Analysis | Architecture, trust boundaries, and controls | `orchestrator_model`, `APPSEC_ORCHESTRATOR_MODEL` |
| STRIDE | Finding threats per component | `stride_model`, `--stride-model`, `APPSEC_STRIDE_MODEL` |
| Judgment | Merging, triage, and post-STRIDE synthesis | `merger_model` and `triage_model`, `--merger-model`, `--triage-model`, `APPSEC_MERGER_MODEL`, `APPSEC_TRIAGE_MODEL` |
| Verification | Evidence verification | `evidence_verifier_model`, `APPSEC_EVIDENCE_VERIFIER_MODEL` |
| Abuse cases | Deriving and verifying abuse cases | `abuse_verifier_model`, `APPSEC_ABUSE_VERIFIER_MODEL` |
| Architect review | Reviewing findings before prioritization | `architect_model`, `--architect-model` |

<a id="subagents--model_matrix-author-controlled-default"></a>
## Role defaults

`MODEL_MATRIX` maps reasoning tiers to STRIDE, triage, and merger models:

| Tier | STRIDE / triage / merger | Default use |
|---|---|---|
| `sonnet-economy` | `claude-sonnet-4-6`, with the per-role exceptions below | quick and standard |
| `sonnet` | Latest Sonnet | Opt-in through `--reasoning-model sonnet` |
| `opus-cheap` | Sonnet for STRIDE and triage; Opus for merging | Opt-in |
| `opus` | Opus for all three roles | thorough; opt-in at other depths |

The default role assignments are:

| Role | quick | standard | thorough |
|---|---|---|---|
| Discovery | Sonnet 5.5 | Sonnet 5.5 | Sonnet 5.5 |
| STRIDE | Sonnet 5.5 | Sonnet 5.5 | Opus |
| Judgment (triage, merger) | Sonnet 4.6 | Sonnet 5.5 | Opus |
| Abuse-case verification | Sonnet 4.6 | Sonnet 5.5 | Sonnet 5.5 |

The tier's STRIDE default is Sonnet 4.6. The controller runs STRIDE on the latest Sonnet at quick and standard depth instead, because Sonnet 4.6 returns no STRIDE result through its single-call exchange. Repricing the calls of a measured Juice Shop controller run at Sonnet 4.6 rates gave about $17 instead of the $11 it cost. The run prints each role's model at the start and warns when an explicit setting puts STRIDE on Sonnet 4.6.

Repository discovery also runs on the latest Sonnet instead of the Haiku default. Discovery must return validated components and cited interfaces; Haiku stopped at the thinking limit or repeated a rejected result until the call limit. `APPSEC_RECON_SCANNER_MODEL` or `--model` still selects another model.

The explicit `sonnet` tier selects the latest Sonnet instead of this version split.

### Why judgment stays on Sonnet 4.6 at quick depth

The recorded benchmarks found lower cost with Sonnet 4.6 for the same assessment. Sonnet 5 improved merging, triage, and report authoring, but missed findings during STRIDE discovery. The defaults therefore use the latest Sonnet, currently Sonnet 5.5, for the standard-depth judgment stages and keep Sonnet 4.6 at quick depth. The benchmarks measured Sonnet 5; Sonnet 5.5 has not been benchmarked separately. See [Benchmarks](#benchmarks) for the measured scope.

### Override precedence (highest wins)

```text
--stride-model / --triage-model / --merger-model      (CLI: sonnet | opus)
  --model <id>                                       (every role not set by a per-stage flag)
    APPSEC_<ROLE>_MODEL                              (environment: exact model ID)
      MODEL_MATRIX[tier]                             (plugin default)
```

- Use `--reasoning-model sonnet` to select the latest Sonnet tier.
- Use `--reasoning-model opus` for Opus reasoning.
- Use `--no-opus` to turn every Opus selection into Sonnet.
- Set `APPSEC_STRIDE_MODEL=claude-sonnet-5-5` to request an exact model for one stage. Environment variables accept exact IDs; the per-stage CLI flags accept only `sonnet` or `opus`. Set the variables in the environment that starts the run.

<a id="orchestrator--the-session-model"></a>
## Session model

The assessment does not use the Claude Code session model. `/model` and `/config` change only the session in which you ask questions or review results. To change the models of an assessment, pass `--model <id>` or the per-stage flags above to `/appsec-advisor:appsec-analyzer` or `scripts/run-headless.sh`.

<a id="context-window-caveat--dont-cheap-out-the-orchestrator"></a>
## Context window

No session accumulates context over the assessment. Each model call receives a bounded set of source excerpts and earlier results for one task, and large components are split into several bounded jobs. Repository size therefore affects the number of calls and the cost more than the context window of any one model.

<a id="benchmarks--measured-effects-of-sonnet-5-vs-sonnet-46"></a>
## Benchmarks

The measurements below come from standard-depth full scans of one Node/Express repository, OWASP Juice Shop, with the earlier session-orchestrated pipeline. They describe those runs, not expected costs or quality for every repository or for the current controller. The source analyses are the [Sonnet comparison](internal/analysis/plan-model-routing-transparency-2026-07-04.md) and the [model-placement comparison](analysis/analysis-model-placement-orchestrator-vs-stride-2026-06-21.md), whose section 10 contains the validated Opus A/B run.

<a id="cost--the-session-model-dominates"></a>
### Session cost

| Session model | Total cost | Recorded usage |
|---|---|---|
| Sonnet 5 | About $60 | About 124 million cache-read tokens in the main session |
| Sonnet 4.6 | About $30 | About 30% fewer tokens for the same work |

The comparison used the same input and output token prices for both models. It attributed the difference to tokenization, adaptive thinking, and repeated reads of the growing session context. The current controller has no such session.

<a id="per-agent-quality--where-sonnet-5-helps-where-it-hurts"></a>
### Per-agent results

| Agent | Observed result with Sonnet 5 compared with 4.6 | Default reflected by the result |
|---|---|---|
| `appsec-threat-merger` | 0 versus 8 duplicate file:line collisions | Latest Sonnet at standard depth |
| `appsec-triage-validator` | 10 versus 15 Critical findings; the analysis judged 5's calibration better | Latest Sonnet at standard depth |
| `appsec-abuse-case-verifier` | 4.6 reintroduced `inconclusive` verdicts | Latest Sonnet outside quick depth |
| `appsec-stride-analyzer-v2` | Missed path traversal, an SSRF sink, and prompt injection; collapsed the LLM chatbot component | Sonnet 4.6 in the earlier pipeline; the controller uses the latest Sonnet because 4.6 returns no result there |

### Opus (older validated A/B, §10 of the placement analysis)

Opus reasoning for STRIDE, triage, and merging cost $40.78 versus $30.01 for `sonnet-economy`, an increase of $10.77 (36%), with no measured quality or coverage gain in that comparison. Standard depth defaults to `sonnet-economy`; thorough uses Opus reasoning.

## When to use the latest Sonnet

Use `--reasoning-model sonnet` when quality matters more than cost. It puts finding, rating and merging threats on the latest Sonnet. It is not a pure upgrade: in the earlier benchmark, Sonnet 5 missed some findings that 4.6 caught. STRIDE already runs on Sonnet 5.5 at quick and standard depth without any setting.

In every other case, stay on the default.

## Quick recipes

| Goal | Setting |
|---|---|
| Use the standard model mix | Keep the default `sonnet-economy` tier. |
| Request another reasoning tier for one run | `--reasoning-model sonnet` or `--reasoning-model opus` |
| Request an exact model for one stage | `APPSEC_STRIDE_MODEL=claude-sonnet-5-5` |
| Use one model for every role | `--model <model-id>` |
| Avoid Opus | `--no-opus` |
