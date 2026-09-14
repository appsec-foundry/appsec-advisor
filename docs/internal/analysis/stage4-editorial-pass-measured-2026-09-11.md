# Stage 4 editorial pass: first measured run and how to build it faster

State on 2026-09-11, branch `feature/figure1-dfd`, after `a528be34`. This continues `stage4-editorial-pass-2026-08-30.md`, which redesigned Stage 4 as an editorial pass and asked the first real run for three numbers: blocks rewritten, actions rejected, turns used. Two runs have now executed the stage on juice-shop2, one on 2026-08-30 (session `8192d6a5`) and one on 2026-09-11 (session `90aba1e5`). Every claim below was checked against the code, the runs' `.agent-run.log` and sub-agent transcripts, or a timed replay of the deterministic steps on a copy of the 2026-09-11 output directory.

## What the stage is today

Stage 4 runs once, at thorough depth by default, after the Stage-3 QA gate. `build_editorial_context.py` projects the prose the pass may rewrite into `.dispatch-context/editorial/blocks.json`, `check_editorial_diff.py snapshot` records the guarded files, and `architect_structural_checks.py all` produces advisory warnings for the receipt. One `appsec-architect-reviewer` dispatch on Sonnet reads the projection and `agents/shared/prose-style.md`, then writes one `plan.json`. `apply_editorial_plan.py` performs every write, `check_editorial_diff.py verify --restore` reverts the whole pass when anything but wording moved, and the canonical tail re-renders. `render_editorial_receipt.py` writes `.architect-status.json` and one `EDITORIAL_PASS` log line. The agent judges nothing, opens nothing but the projection and the style rules, and edits nothing itself.

The deterministic layer is sound. The applier locks every action to the field's current value, the guard pins identifiers, locators, numbers, headings and list lengths, rejected actions never abort the run, and a QA regression costs the polish rather than the run. The problems below are in the shape of the one LLM dispatch, in what the stage reports when that dispatch fails, and in one gate rule the stage inherited unexamined.

## Measured

### Projection and deterministic steps, 2026-09-11

Prep, from `QA_GATE` at 14:16:50Z to `AGENT_SPAWN` at 14:17:52Z: 62 seconds of wall clock, of which the three scripts take about 6 seconds in replay. The rest is orchestrator turn latency.

Projection: 232 blocks, 59,725 characters of prose, 101 KB on disk. The prose is 59% of the serialized bytes; block ids, file paths, field addresses and labels are 25 KB, and pretty-printing adds another 14 KB. By source: `threat-model.yaml` 30.9 KB across 20 findings, their linked mitigations and the verdict; `.fragments/security-architecture.md` 26.6 KB in 64 paragraphs; the two Management-Summary fragments 2.2 KB in 12 fields. Block length runs from 18 to 996 characters, median 215. The file is long enough that the `Read` tool returns it in two calls.

Deterministic tail, replayed on a copy of the output directory against the live repository:

| Step | Seconds |
|---|---|
| `build_editorial_context.py` | 0.7 |
| `check_editorial_diff.py snapshot` | 0.0 |
| `architect_structural_checks.py all` | 5.2 |
| `compose_threat_model.py --strict` | 4.8 |
| `apply_prose_fixes.py` | 0.8 |
| `qa_checks.py gate` | 5.0 |
| `section_integrity.py` | 0.2 |
| `qa_checks.py unmasked_secrets` | 0.4 |
| `check_editorial_diff.py verify` | 0.1 |
| Total | 17.2 |

### The agent, 2026-08-30: worked

Model `claude-sonnet-4-6`, 227 blocks. Seven tool calls to log, read the style rules and read the projection, then one `Write` of 20.8 KB carrying 28 actions, produced in a single message of 5,450 output tokens, then the completion log. Dispatch to completion 8 minutes 35 seconds. That run's `.agent-run.log` was overwritten by the later run, so the applier's acceptance of those 28 actions is not on record.

### The agent, 2026-09-11: produced nothing in 41 minutes

Same model, 232 blocks. The same five reads finished at 14:18:14Z. Then four consecutive API calls, at 14:28:03Z, 14:38:16Z, 14:48:26Z and 14:58:49Z, each ended with `stop_reason=max_tokens` after exactly 32,000 output tokens, every one of them a thinking token: no text, no tool call. The harness retried the request three times before surfacing `max_output_tokens` to the orchestrator. The prompt cache had expired between calls, so each retry re-wrote about 52,000 input tokens. Cost of the pass: about 128,000 output tokens and 170,000 cache-write tokens for zero actions, plus 41 minutes of wall clock during which the watchdog logged `RUN_IDLE` four times, since a sub-agent generating one message emits nothing it can see.

The orchestrator then followed §2 of the stage instruction, "an Agent error is non-fatal", ran the applier against a missing plan, found the guard clean, and closed the stage. The receipt printed `No rewrite needed across 232 blocks`; the log line reads `EDITORIAL_PASS offered=232 proposed=0 applied=0 apply_report_missing=true`; `.architect-status.json` says `pass`. The run's completion summary shows no trace of a failed stage.

The two runs differ in nothing the plugin controls. Whether the model drafts 28 rewrites inside a tool call or drafts 232 of them in thinking first is model variance on an identical prompt shape, and the shape allows both. A pass whose entire output is one message is bounded by the output cap, and its thinking shares that cap.

## Findings

### F1. One message for the whole plan is the failure, not the model

The 2026-08-30 design estimated "roughly six tool calls" and set the turn ceiling to 30. Both hold, and neither is the constraint. The constraint is that a single `Write` must carry every rewrite, so the message that produces it grows with the number of blocks the model decides to touch, and the thinking that precedes it grows with the number of blocks the model decides to read closely. At 232 blocks that message has no room to fail gracefully: a truncated JSON, a killed sub-agent, or a thinking budget that swallows the cap all lose every action, because `load_plan` rejects an unparseable plan whole and no partial plan exists.

The fix is to bound the output per message, not to raise the cap. `CLAUDE_CODE_MAX_OUTPUT_TOKENS` would move the wall, and the plugin does not control the environment the harness inherits in any case. Two changes bound it structurally:

- **Chunked plans.** The applier accepts `plan.json`; let it accept `plan-*.json` and merge them in name order. The agent instruction then says: write at most 20 actions per file, write each file as soon as its actions are ready, never hold rewrites back for a final message. Each `Write` ends a message, which resets the output budget, and a pass that dies after three chunks has delivered three chunks. `render_editorial_receipt.py` sums the chunks.
- **Shards in parallel.** `build_editorial_context.py` can emit `blocks-1.json` through `blocks-N.json`, split by source (`threat-model.yaml` findings and mitigations, the §6 fragment, the Management-Summary fragments), and the skill dispatches N reviewers in one message, the way Stage 1c fans out STRIDE and Stage 2 renders §7 and the Management Summary in parallel. The snapshot and guard stay single because they cover files, not blocks. Wall clock divides by the shard count, a lost shard costs a third of the polish rather than all of it, and the per-shard projection fits one `Read`.

Chunking is the smaller change and removes the all-or-nothing loss; sharding is the wall-clock lever. They compose.

### F2. The receipt calls a failed dispatch a clean bill of health

`render_editorial_receipt.py` already refuses to print "no rewrite needed" for a plan the applier rejected, with a comment explaining why. It does not apply the same care to a plan that never existed: with `apply_report_missing=true` and `edits_proposed=0` it falls into the final branch and prints `No rewrite needed across 232 blocks`. `.architect-status.json` has to say `pass`, because `_status_passes` in the controller would re-dispatch the stage for any other value, and the 2026-08-30 document accepted that. The console line and the `EDITORIAL_PASS` log line have no such constraint. Both should say that the pass produced no plan, and `aggregate_run_issues.py` should surface it as a run issue, so that a stage which cost 41 minutes and delivered nothing is visible at the end of the run.

### F3. Stage 4 aborts a run whose QA gate exited 3 before the pass ran

`SKILL-thin-stage4.md` §3 treats a QA gate exit of `1`, `2` or `3` after the re-render as "the rewrite disagrees with a gate the pre-edit report passed": restore the snapshot, re-render, and treat a second non-zero exit as a hard abort. The premise is false for exit `3`. `qa_checks.py gate` returns `3` for status `manual_review`, and `SKILL-thin-stage3.md` §2 does not require that exit to become `0`: it dispatches the QA reviewer, and a `.qa-status.json` of `pass` that survives `qa_release_gate.py` closes Stage 3. The 2026-09-11 run took exactly that path: `QA_GATE verdict=pass gate_exit=3 repairs=1 dispatched=1 open_actions=1`, the open action being F-066 `reference_format` with disposition `manual_review_item`. The replayed gate on the unedited bytes exits `3` for the same reason.

The rule did not fire on this run only because no plan was applied and `files_touched` stayed empty. On a run where the pass succeeds, the tail after `apply_editorial_plan.py` exits `3`, the stage restores and re-renders, the gate exits `3` again, and the instruction says abort. Every thorough run whose Stage 3 ends in a triaged `manual_review` is in the same position, and that is the common case, since a `manual_review` item is by definition one the fixer could not clear.

The fix is to compare against the pre-edit gate rather than against zero. `.qa-status.json` already records `gate_exit`; the prep step can additionally keep the pre-edit `.qa-repair-plan.json`. A re-render result counts as a regression only when the exit code rises or the set of blocking action ids grows. Restore then applies to regressions alone, and a second identical `3` is the run's known state, not an abort.

### F4. The verbatim `find` lock doubles the output for no information the applier lacks

Every action quotes the block's text back as `find`. The projection already carries a stable `id` per block and is immutable while the pass runs, so the applier could resolve `id` to the text it projected and use that as the optimistic lock, with the same "must equal the field's current value" check against disk. The agent then emits `id`, `replace` and `rationale`. On the 2026-08-30 plan that is roughly half of the 20.8 KB, and a whole class of rejections disappears: a `find` that differs from the projected text by one transcribed backtick or space is today a stale lock and a silently dropped rewrite. `find` can stay accepted for a plan that carries it; the schema needs `id` as an alternative required key and the applier one lookup.

### F5. The projection spends 40% of its bytes on addressing and formatting

Of 101 KB on disk, 60 KB is prose. The rest is `id`, `file`, `path` and `label` per block plus indentation, and the agent reads all of it. A line-oriented projection, one header line per block carrying the id and label and the text below it, would cut the input by a third, fit one `Read`, and read better for a model than nested JSON does. This is worth less than F1 and F4 because input tokens are the cheaper side of the pass, and it changes the format the agent quotes from, so it belongs after F4 rather than before.

### F6. Selection offers every block, including the ones the agent is told to leave alone

The builder's selection is deliberately blunt: verdict, Management Summary and the whole §6 narrative always, plus the worst 20 findings at or above `high` and their mitigations. The agent instruction then says "leave a block alone when it is already clear" and "a short plan is a good plan". Both are right, but every offered block is paid for on the input side and, on 2026-09-11, in thinking. A deterministic pre-ranker could score blocks on the signals the agent's own "What to change" section names, since most of them are lexical: the AI-padding list `prose-style.md` already carries, passive constructions, nominalizations of the "performs validation of" kind, sentences over a length threshold, a subject of "the application" where the block names a component, a mitigation step without a location while the block has a locator. Blocks with no signal drop out, or the cap becomes a budget in characters instead of a count of findings.

What this loses is the "technical precision" class of rewrite, which no lexical rule sees. The 28 actions of the 2026-08-30 plan are the evidence to decide with: compare their block ids against a lexical scorer and see what fraction the scorer would have dropped. If it is small, ship the ranker with a character budget; if not, keep the projection and take F1 and F4.

### F7. Smaller levers, and one non-lever

The advisory structural pre-pass takes 5 seconds and does not feed the agent; it can run concurrently with the dispatch. The deterministic tail is 17 seconds end to end and is not where time goes. The model is Sonnet by default and `APPSEC_ARCHITECT_MODEL` overrides it; because the guard reverts anything but wording, a Haiku pass is a safe experiment whose only cost is a higher rejection rate, which the receipt already reports.

### F8. Maintenance debt the redesign left behind

`agents/shared/architect-{coherence-rules,coverage-signals,depth-matrix,repair-classifier}.md` have no consumer; the 2026-08-30 document kept them so a deep review could return behind a flag. `architect_structural_checks.py` still documents a `REVIEW_SCOPE=judgment` pass that no longer exists, and `data/breach-vector-taxonomy.yaml` still names the reviewer's Check 8. `tests/test_agent_definitions.py` keeps a turn floor of 12 with a comment that the first measured run replaces it; the measured runs used 9 and 5 tool calls. None of this costs runtime; it costs the next reader.

## Recommendation, in order

1. F1, chunked plans, before the next thorough run: applier glob plus an instruction change. It is the reason the stage delivered nothing today, and it makes every later change safe to measure.
2. F2 with it: the receipt and the run-issue aggregator must name a pass that produced no plan.
3. F3 before a run where the pass succeeds, since that is when the abort fires.
4. F4, then F1's sharding half once plans are small.
5. Decide F6 from the 2026-08-30 plan, not in advance. Leave F5, F7 and F8 for a maintenance pass.

None of these changes a requirement in `specs/requirements.md` or a decision in `docs/internal/decisions.md`; the stage keeps its contract of rewriting wording and nothing else.
