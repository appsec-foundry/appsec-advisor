# Session handoff — run 5, and what it left open, 2026-08-17

Continues `session-handoff-2026-08-16.md`. That note ends with three aborted
runs and twelve fixes. Two runs have since completed end to end. This note is
enough to continue without the original session.

## Landed on dev

```
f7530e65  fix: name an option in a positional slot as an option
b6e7b8d8  fix: replay the walkthrough selection over the pool the renderer used
416d1dc6  feat: keep the orchestrator out of the plugin's implementation at runtime
75ee939c  docs: record what the dispatch payload costs and where run facts come from
98d4597d  docs: measure where a run's tokens go
b23832fc  docs: update the standard benchmark to a v0.5.2-dev measurement
```

`make lint` is red only on `tests/test_context_routing.py`, unchanged from
before. Full suite green: 12,925 passed, 93 skipped.

## What the two completed runs settled

All four checkpoints from the previous note passed twice: dispatch replay, the
wave-2 evidence gate, evidence verification (`total_threats` 69 then 66), and
the title cleaner. None of the three abort signatures recurred.

Run 5 closed at **$25.39**, 54 threats in the YAML (66 merged), 9 Critical,
eleven sections.

The three fixes landed today were measured against the same stretch of the
pipeline, `PHASE_END … controller compose` through the QA gate result:

| | run 4 | run 5 |
|---|---|---|
| elapsed | 20 min | 4.5 min |
| `qa_checks.py` misinvocations | 3 | 0 |
| reads under `scripts/` | 3 files, 2 greps, 4 probes | 0 |
| context compactions | 2 | 0 |
| QA outcome | fail + repair plan | pass |

**P3 was not load-bearing in run 5.** Replaying the old and new gate logic over
run 5's own `threat-model.yaml` produced identical expectations — the reserved
slots went to base Criticals, so no elevated finding displaced one. The fix is
correct and revert-verified by test; this run simply did not exercise it.

## Open, ranked by measured size

Full numbers in `analysis-where-the-tokens-go-2026-08-17.md`.

**1. Split the STRIDE analyzer per category group.** The analyzers are 57% of
the run's 25.6M cache reads. The split point already exists — the analyzer logs
`Writing STRIDE findings Spoofing+Tampering` and then the other four. Two
agents of ~20 turns should come to about 1M where one agent of 41 turns costs
2.9M. Run the experiment before building it: split one analyzer, compare its
two `cache_read` values against `api-server`'s 2,934,055.

**2. Recon.** 146k context per turn, double every other role, and its 513-line
summary rides along downstream. Five runs produced 477 / 530 / 500 / 513 / 513
against a target of 200, twice at exactly 513 on different models — the length
comes from the mandated 7.1–7.32 sub-section structure, not model verbosity. A
producer retry would loop against a structure that cannot meet the target.
Either the target or the structure changes; that is a product decision.

**3. `web3-nft` attempt-1 wrote nothing.** 40,313 output tokens, 33 tool uses,
no attempt artifact and no output. The retry path caught it and attempt-2
delivered. Why the work never landed is not determinable from outside the
agent. Worth a look because a full budget produced nothing.

**4. `ORCHESTRATION_GATE_WARN: evidence context is stale for
.threats-merged.json`.** A best-effort gate failed and the run continued
(`orchestration_controller.py:1897`). All 54 threats carry evidence, cwe and
component, so nothing obvious was lost — but the event carries only `str(exc)`
and not the script name, so what was skipped is unknown. Name the step in the
event.

**5. 66 merged threats became 54 in the YAML.** Twelve consolidated, against
eight in run 4. Consolidation is by design via `data/consolidation-groups.yaml`;
the jump is large enough to check before anyone compares the two runs on
content.

**6. F16 — component naming drift.** Five runs, five schemes. Run 5 produced
`api-server`, `angular-spa`, `auth-guard`, `ci-cd-pipeline` where run 4 had
`juice-shop-backend`, `juice-shop-frontend`, `juice-shop-auth`, `github-ci`.
The only stable IDs are the ones `finalize_component_inventory` injects —
`realtime-channel`, `web3-nft`. `canonicalize_component_id` still has no
caller. The drift reaches the dispatch action id: wave 1's differs between
runs, wave 2's (injected components only) is identical.

**7. Agent-authored run facts.** Own note,
`analysis-agent-authored-artifact-facts-2026-08-16.md`. Confirmed a second
time: `.evidence-verification.json` carried `2026-08-16T00:00:00Z` in run 4 and
`2026-08-17T00:00:00Z` in run 5 — midnight of the respective day, with
`model_id: claude-sonnet-4-6` against the controller's `sonnet` both times.

**8. Diagnostics that mislead.** Three instances, same class:
- `RUN_IDLE` states the run is "almost certainly on a slow model/API response
  … not a hang". In run 5 it was a 4h51m wait for a 5-hour usage window to
  reset. The message sends the reader the wrong way.
- `TELEMETRY_MISMATCH … terminal call carries no child output tokens` fired
  once as a race that resolved four seconds later (`angular-spa`) and once for
  a genuine absence (`web3-nft`). Indistinguishable at the time.
- `qa_checks.py` reporting an unknown flag as a missing file — fixed in
  `f7530e65`, but the same shape may exist in other positional CLIs.

**9. `refuted: 0`.** Across two runs the evidence verifier sampled 77 threats,
verified 68, marked 9 ambiguous and refuted none. It discriminates but never
rejects. Either the findings are uniformly sound or the role has no effective
path to reject one.

**10. Agents probe their own tooling.** Seven `--help` or bare invocations in
run 5, across `log_event.py`, `budget_watchdog.py` and `qa_checks.py`. Each
costs a turn where the message is clear and a misdiagnosis where it is not. The
prompts could carry the exact invocation line.

**11. Stale `§7 Security Architecture` literals.** The rendered report is
correct — `## 6. Security Architecture`, and zero occurrences of
`§7 Security Architecture` in the text. But the literal survives in
`SKILL-thin-stage2.md:31`, `SKILL-impl.md:2977`,
`snapshot_preserved_sections.py:8`, `walkthrough_renderer.py:1491` and three
places in `compose_threat_model.py`, and it reaches the console through the
dispatch description. A compose pass normalizes the output; the sources
mislead a reader.

**12. Item C**, from the previous note, is measured and small: `artifact_receipts`
are 12,717 bytes of a 35,796-byte dispatch action. Not worth a contract change
at this scale. Details in `analysis-dispatch-action-payload-2026-08-16.md`.

## How to work on this

Unchanged from the previous note, and it earned its place again today: **revert
the fix in place and re-run its test**, and **replay against a real run's
artifacts, not a fixture**. Replaying the walkthrough gate over run 5's own
YAML is what showed P3 was not exercised — a fixture would have said nothing.

Two traps found today:

- Measuring on a copy of an output directory needs the whole state reset, not
  part of it. Clearing the stride outputs but not the routing ledger hits the
  replay guard; clearing neither finds no pending work. Start from a fresh
  `cp -a` each time.
- Mid-run `SESSION_STOP … cost=` is orchestrator-only and does **not** add
  cleanly to the per-agent records — summing them overstates the bill by about
  a third. Take cost from the run's closing summary.

Never edit plugin files while a scan runs; the runtime reads them live.
`APPSEC_PLUGIN_DEV=1` lifts the new read gate when the plugin itself is the
work.
