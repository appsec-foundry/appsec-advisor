# Threat Analyst improvement: implementation recommendation

Date: 2026-10-11
Status: implemented on 2026-10-11 except where the implementation status below says otherwise. The "Current state" table describes the code before the change.

## Implementation status

| Item | State | Where |
|---|---|---|
| 1.1 Opus ban | Done in 876bd016 | `analyst_controller.py` `_check_model_policy` |
| 1.2 Model per mode | Effective model is recorded in `costs.model` and shown in the report; the default stays Sonnet until the evaluation justifies a change | `render_analyst_report.py` |
| 1.3 Threat model in reviews and hypothesis checks | Done; CI examples read the model from the base commit, so a change cannot choose its context (REQ-ANA-004) | `appsec-analyst-cli` `_default_threat_model`, `examples/analyst/` |
| 1.4 Richer projection | Done: reader `F-NNN` ids, controls, cited files, mitigations, actors, boundary controls, security controls; focus components first; 96 KiB bound with counted omissions | `build_analyst_context.py` `_project` |
| 2 Deterministic context | Done for relative imports (JavaScript, TypeScript, Python) and threat-model evidence of touched components, bounded by `context_files`. Route-inventory middleware is not used: it scans the live tree, while the analyst reads a frozen snapshot | `select_analyst_context.py` |
| 3 Question, recommendations, related threats, routing | Done | schema, contract, validator, renderer, `ask-threat-model`, `help` |
| 4 `--explore` | Done as a controller-run `claude -p` with `Read,Grep,Glob` confined by `--restricted` to a redacted copy of the frozen view, instead of a subagent dispatched by the parent model. REQ-ANA-010 changed and REQ-ANA-011 added with operator approval | `analyst_host.py`, `build_analyst_snapshot.py` `export_view` |
| 0 Evaluation | `scripts/validators/eval_analyst.py` and `tests/fixtures/analyst-eval/cases.yaml`; configuration D became "Opus with `--explore`" because a main-session answer cannot be scripted. Results below | |

### Evaluation results (2026-10-11, configurations A, C, E)

| Config | Seeded weaknesses found | Serious findings on benign changes | Design themes covered | USD | Seconds |
|---|---|---|---|---|---|
| A analyst, Sonnet | 6/6 | 0 | 31/32 | 1.15 | 428 |
| C analyst, Sonnet, `--explore` | 6/6 | 0 | 29/32 | 1.20 | 452 |
| E Opus directly, read-only tools, no plugin | 6/6 | 0 | 30/32 | 1.35 | 530 |

The first pass exposed two runner defects and one analyst defect, all fixed before the table above: the runner answered optional questions, which the job rejects; and the change validator rejected a removed-control finding whose proposed code sat in `evidence` instead of `comparison` (the removed CSRF middleware), so A and C first scored 5/6. Validation failures now name the failed rule in the result's limitations.

Conclusions: with the richer threat-model context, recommendations, focus question, and surrounding-code selection, the default analyst on Sonnet matches a direct Opus question on this set at lower cost, so the Sonnet default stays. `--explore` passed none of the kill criterion's bars on this set: the fixture repository has eight files, so there is little to explore, and the keyword score rewards generic design themes over code-specific advice. It stays opt-in, interactive only, and unchanged in scope; a decision to promote it needs a run against a larger repository. Keyword matching is a coarse proxy; read the recorded results before acting on a one-point difference.
| `appsec-reviewer-cli` | Preflight refuses repository-owned Claude configuration unless `--trust-mode trusted`; a checked-in verdict is deleted before the review, so it can no longer pass `--fail-on`; tools are listed explicitly | `scripts/appsec-reviewer-cli` |

## Decision summary

`/appsec-advisor:analyze-threats` stays one command with two engines behind it. The default engine remains the controller (`scripts/orchestrator/analyst_controller.py`) driving a tool-less `claude -p`; it is the only engine in CI and the only one whose results serve as evidence for others. A new opt-in option, `--explore`, runs the analysis in a read-only subagent that explores the repository itself; it is interactive only. Both engines share context preparation, question packages, response schema, validation, rendering, feature files, and model policy, so a user sees one result format.

A prototype comes first. `--explore` is built out only if it beats a direct Opus question with repository access, and the controller-only analyst, on a small evaluation set. Independently, the controller gains richer threat-model context, deterministic context selection, a focus question for reviews, and a recommendations field, because those improve every result including CI.

The engine choice follows the consequence of manipulation, not the trust in an author. Interactively, a read-only agent misled by repository content produces bad advice the developer sees. In CI, the job holds secrets and publishes or gates on its result, so one crafted merge request, from a compromised account or a dependency update, could exfiltrate data or steer the verdict. The controller costs little there.

## Current state (verified)

| Area | Observation | Location |
|---|---|---|
| Host session | `claude -p` without tools, MCP, project configuration, or persistence; one JSON envelope per call | `scripts/runtime/analyst_host.py:150-192` |
| Rationale | One host call for skill and CI; `--safe-mode`/`--restricted` kept a hostile repository's `CLAUDE.md`, hooks, and MCP configuration away from the model in the spike | `docs/proposals/security-advisor-threat-analyst-wp1-results.md`, "Host spike" |
| Model | Default `sonnet`; `--model` accepts any alias matching a regex; no effort level is passed | `analyst_host.py:47`, `scripts/appsec-analyst-cli:56-67` |
| Org Opus cap | Before Phase 1.1, `policy.disable_opus` (decision `MD-6`) was read only by `resolve_config.py` and `resolve_org_profile.py`; the analyst never checked it, and `answer` called the model with the `--model` of its own command line instead of the job's | `grep disable_opus scripts/`, `appsec-analyst-cli:249-250` |
| Loop | At most 4 host calls, 2 evidence rounds of up to 5 paths, 2 question rounds | `data/analyst-limits.yaml`, `analyst_controller.py` `_analyze` |
| Design mode | Reads no source (REQ-ANA-010); schema forces `findings` and `evidence_requests` to zero items | `analyst_host.py:93-96` |
| Review context | Only the changed files are admitted up front; surrounding code arrives only if the model requests it | `scripts/contexts/build_analyst_snapshot.py` `capture` |
| Review question | A review takes no question; a concrete question needs hypothesis mode, which has no diff and needs the user to name every relevant path | `appsec-analyst-cli` `build_parser` |
| Threat model use | Loaded automatically only for interactive design and abuse-case checks; a review uses it only with explicit `--threat-model`; the CI example passes none | `appsec-analyst-cli` `_abuse_case_claim`, `_scope`; `examples/analyst/github-actions.yml:45` |
| Threat model projection | Threats: `id, title, component, stride, risk, _status, cwe` (up to 500); components: `id, name, description, paths, sensitive_data`; boundaries with assumption and verdict. No mitigations, controls, actors, or data flows | `scripts/contexts/build_analyst_context.py:46-48`, `_threat_model` |
| Output shape | No field for a recommended design or control, no link to existing threat-model findings | `schemas/analyst-response.schema.json` |
| Core questions | About 14 entries adapted from aiscb | `data/analyst-questions.yaml` |
| Quality evidence | No comparison against a baseline exists; work package 6 is open and limits are `provisional` | `wp1-results.md:232` |
| Routing | `ask-threat-model` does not point design questions to the analyst; `help` lists it only for planned features and changes | `skills/ask-threat-model/SKILL.md`, `skills/help/SKILL.md:71-72` |

## Engine selection

| Invocation | Engine |
|---|---|
| Any invocation without `--explore` | Controller, as today |
| Interactive with `--explore`: free-text design question, `--design-file`, `--worktree`, `--staged`, `--base/--head` with or without a focus question, a question about existing code without `--path` | Read-only subagent |
| `--explore` with `--ci` or any non-interactive invocation | Rejected, exit 2 |
| `--explore` while the organization profile forbids repository exploration | Rejected, exit 2; never silently replaced |
| `appsec-analyst-cli … --ci` | Always the controller |

The plugin cannot detect whether a repository or merge request is trustworthy. The documentation states the assumption: `--explore` is for the developer's own repository and colleagues' changes; a foreign repository, a fork merge request, or a result meant as evidence uses the default engine.

## Phase 0: prototype and evaluation set (first)

Without a measurement every later phase is a guess, and the AGENTS.md rule against raising limits blindly applies to evidence rounds and budgets as well.

- Fixture: a neutral repository with a committed `threat-model.yaml`, or a synthetic-repo fixture that has one. No target-specific names (`data/test-target-vocabulary.yaml`).
- Cases: about 8 design questions with expected threat themes; about 6 changes with one seeded weakness each (missing object-level authorization, SSRF through a new fetch, mass assignment, secret written to a log, removed CSRF check, privilege check moved to the client), each also asked as a merge request with a concrete question; 2 benign changes that must produce no finding.
- Prototype: a minimal `prepare` step that writes the job envelope, an agent definition, and a minimal `finalize` step that validates the agent's JSON. No user-facing flag yet.
- Configurations: A controller as today; B controller with `--model opus`; C prototype subagent; D the main session answering itself with the same `prepare`/`finalize`; E a direct Opus question in an interactive session without the plugin.
- Metrics: recall of the seeded weakness, false findings on benign changes, system specificity of scenarios, usefulness of questions, cost, wall time.
- Scoring: deterministic parts in a script with its own test; an LLM judge only for specificity, following the find-then-adversarially-verify pattern of `eval-threat-model`. Manual and paid, never part of `make check`.

Kill criterion: if C is not clearly better than E on design questions and merge requests with a question, `--explore` is not built out. D is the fallback if it matches C at lower complexity.

## Phase 1: correctness and quick wins (no product-promise change)

1. **Enforce the organization Opus cap in the analyst.** Done in the working tree: admission refuses an Opus host model under `policy.disable_opus` or `APPSEC_DISABLE_OPUS` (exit 2, not a silent downgrade, so a result never names a model other than the one requested); `answer` rechecks the policy before its model call; the CLI transport always uses the job's admitted model. Guards in `tests/test_analyst_controller.py` and `tests/test_analyst_cli.py`: profile ban, environment ban with a full release id, a negative case for other models and unbanned Opus, the resumed job, and the CLI transport.
2. **Choose the default model per mode from Phase 0.** Keep model and effort in one resolver, report the effective model in the result header.
3. **Use the existing threat model in interactive reviews and hypothesis checks,** with `--isolated` to opt out, as the design and abuse-case paths already do. In CI keep it explicit and add `--threat-model` to `examples/analyst/github-actions.yml` and `gitlab-ci.yml`.
4. **Project a relevant, richer threat model.** Add mitigations (id, title, status, linked threats), actors, and boundary controls. In review and hypothesis mode select the components whose `paths` intersect the admitted files plus their boundaries and threats; in design mode all components in compact form plus the highest-risk open threats. Bound the projection by bytes and list omissions in `sources`. Guards: an oversized model, a model without mitigations, a review touching no known component.

## Phase 2: deterministic context selection in the controller

The model cannot ask for code it does not know exists. Deterministic code takes the first exploration step from the frozen snapshot, under the existing limits and redaction. This is the CI counterpart to `--explore`.

- Review mode: before the first call, admit with a recorded reason the auth or middleware files that `scripts/analyzers/route_inventory.py` links to a changed handler, one hop of direct imports from changed files, and the source locations that threat-model findings on touched components cite. Each addition is a `context` entry, counts against `admitted_files` and `job_kib`, and appears in coverage.
- Hypothesis mode: the same selection only inside the selected paths; REQ-ANA-009 stays binding.
- Evidence rounds keep their limits. Log how often a review ends incomplete on a round or call limit; raise a limit only on measured need.
- Guards: a weakness in middleware outside the diff, a variant with different names and framework, a negative case that must not admit an unrelated large directory.

## Phase 3: questions and advice in the result

1. **Focus question for reviews:** `review --base/--head` (and interactive `--worktree`/`--staged`) accepts an optional question that the analysis answers against the change. This closes the gap between review (change, no question) and hypothesis (question, no change).
2. **`recommendations`** in the response schema: control or design option, reason, trade-off, linked scenario or finding ids, requirement ids. Change atomically in schema, contract (`skills/analyze-threats/references/analysis-contract.md`), validator, renderer, and tests.
3. **`related_threats`** on scenarios and findings: ids from the delivered threat-model projection, validated by the controller and by `finalize`. It connects the result to the existing model without changing it (REQ-ANA-003).
4. **Routing:** `ask-threat-model` points design questions to `/appsec-advisor:analyze-threats`; `help` names design advice and `--explore`.

## Phase 4: `--explore` (only after Phase 0 passes)

- **Flow:** the skill runs `prepare`, which creates the job, writes the envelope (threat-model projection, requirements, business context, packages, the question or change scope), and prints the agent name, the model resolved through the `MD-6` policy, and the job path. The skill dispatches the agent with exactly these values; the dispatch instruction is imperative, because prose dispatch has been lost before in this plugin's pipeline. The agent writes its JSON result to the job. `finalize` accepts only a result bound to that job's id, validates schema, quotes every evidence excerpt against the frozen commit, renders with the shared renderer, and closes the job. A missing or invalid result ends the job incomplete, never complete (REQ-ANA-002).
- **Agent:** read-only (`Read`, `Grep`, `Glob`; no `Bash`, `Write` beyond the job result, or network). Reads of key and environment files are denied with the same patterns the snapshot excludes. Whether a hook can record the agent's reads deterministically, instead of relying on its self-reported file list, is unverified and part of the prototype.
- **Result header:** "Advice with repository access, N files read", with the file list in coverage. A concrete suspicion in the advice may offer the matching `--hypothesis` check as a next step; it never starts on its own.
- **Organization control:** a profile switch that forbids `--explore`.
- **Contract work:** REQ-ANA-010 gains the opt-in. Proposed direction, to be shown to the operator with exact wording before writing: the default design analysis still reads no source; with `--explore` an interactive analysis may read repository source and lists what it read. New permission inventory entries and agent-definition tests (`tests/test_agent_definitions.py`) are required.

## CI integration

- `appsec-analyst-cli review --ci` stays controller-only. Phases 1 to 3 improve CI results directly.
- Update the examples: pass `--threat-model`, choose the model through organization policy, and state that the job must not run on `pull_request_target` or otherwise hand secrets to fork code.

## Related finding: `appsec-reviewer-cli` runs a tool-using agent on merge-request code

`scripts/appsec-reviewer-cli:75` runs `claude -p "/appsec-advisor:verify-requirements …" --permission-mode bypassPermissions` in the merge-request checkout. The `appsec-reviewer` agent has `Read`, `Grep`, `Bash`, and `Write`; there is no `--safe-mode` and no isolation from project configuration. Crafted code in a merge request can therefore attempt prompt injection that leads to Bash commands without a permission prompt, in a job that holds the API key. Unverified: whether a merge request's `.claude/settings.json` hooks load in this mode; the threat-model CI path already refuses target settings, this CLI does not. This is pre-existing and out of this proposal's scope, but it follows the same rule as the engine selection above. Recommended: move its CI path to the controller engine or harden it to the same level, and consider one CI product that checks requirements and threats in one run.

## Requirement and decision touchpoints

| Phase | Requirements | Decisions | Operator approval needed |
|---|---|---|---|
| 0 | none | none | no |
| 1 | REQ-ANA-004 unchanged; the Opus cap implements `MD-6` | `MD-6` | no |
| 2 | REQ-ANA-009 stays binding for hypothesis scope | none | no |
| 3 | REQ-ANA-008 and REQ-ANA-010 unchanged; schema and report change | none | no |
| 4 | REQ-ANA-010 gains the `--explore` opt-in | possibly a decision on the engine selection rule | yes |

## Recommended order

Commit Phase 1.1. Then Phase 0 with the prototype. Then Phase 1.2 to 1.4, Phase 2, and Phase 3, each re-measured with the same set. Build Phase 4 only if the prototype passed the kill criterion. Handle the `appsec-reviewer-cli` finding as a separate ticket.
