# Run a2a0e355 — independent re-measurement

Second opinion on `docs/internal/run-a2a0e355-analysis.md`. **Untracked working note, not a decision record.** Every number below was re-derived from the same run and transcript on 2026-08-29; nothing was carried over from the first analysis.

Method note: the first analysis measured transcript blocks as `len(json.dumps(block))`. That convention is reproduced here (it gives 330,749 B against its 342,886 B, and matches its per-category figures to within a percent), but raw text bytes and cl100k token counts are reported alongside, because the choice of unit turns out to matter for the headline claim.

## Confirmed without change

The compaction record is exact. One boundary, row 658 of 2,801, `trigger=auto`, `preTokens=167596`, `postTokens=22753`, `cumulativeDroppedTokens=144843`, `durationMs=95874`. Every row in the file carries `isSidechain: false`, so subagent context never entered this window.

`verify_receipt_hashes` writes no state. `grep -rn "receipts_verified\|verified_receipts\|verification_marker" scripts/ agents/ skills/ data/ schemas/` returns nothing, the function itself only returns a `run_gate` action, and the run's `.agent-run.log` contains zero lines matching `receipt`. Unlike `_emit`, it does not even append a log event. Nothing downstream consumes evidence that it ran.

The persistence claim holds and is slightly stronger than stated. The transcript contains 16 `verify-receipts` calls echoing 104 `--receipt` pairs, 102 unique, over 92 distinct paths. `.context-routing-plan.json` carries 114 `deliveries[].source_receipt` entries, 109 unique pairs over 95 paths. Exactly one echoed path is absent from the ledger: `.context-routing-plan.json` itself. That is a self-reference, not a coverage gap — the controller reads the plan directly and never needs it echoed. The stated blocker for server-side verification ("one echoed path was not in the ledger, so persistence would need to be provably complete first") therefore mostly dissolves.

Requirements integration is clean, and the check can be widened. 73 rows in §7b, all unique, exactly the 73 catalog ids, no catalog id missing. Status 31 FAIL / 24 UNVERIFIABLE / 14 PARTIAL / 3 N/A / 1 PASS, priority 61 MUST / 12 SHOULD, zero priority mismatches against the catalog. Blueprints: 12, 68 sections, 51 distinct requirement ids referenced, zero dangling. Instead of checking only the finding cross-references in §7b, this pass slugified every heading GFM-style and checked all 1,234 internal links in the document: **0 dead anchors across 197 distinct targets**.

The YAML defect and its fix are real. The published run artefact `threat-model-…v0.6.0b2.yaml` has no `requirements_compliance` key. The regenerated `threat-model.yaml` has it, with `total: 73, pass: 1, fail: 31, partial: 14, unverifiable: 24, not_applicable: 3` — identical to the Markdown table.

The evidence-coverage numbers reproduce exactly, and there are more of them than reported. Running `aggregate_run_issues.evidence_coverage_shortfall` over the run: backend-api 4/85 (4.7%), database 1/26 (3.8%), frontend-spa 19/426 (4.5%) — the three flagged. Not flagged but also thin: web3-nft 1/4, realtime-channel 2/2, auth-session 4/9, hacking-instructor 5/17. `.run-issues.json` holds the reported 7 issues.

## Corrected

### The receipt round-trip is not 38%, and not 38% of the context window

Two separate problems with the claim.

First, the 40,290 B object is mis-filed. It is not a Bash tool result and not a chained command's output. It is a **Read of a spilled tool-result file**, `~/.claude/projects/…/a2a0e355-…/tool-results/b74u5ucvj.txt` (37,074 B on disk, 40,294 B as it entered context with line numbers). It holds a `dispatch_parallel` action with **67** `sha256` fields, not 155. Nothing anywhere in the transcript carries 155. This also means the "`Read` of the SKILL runtime files — 69,450 B, 4 calls" row is three SKILL files (24,124 B) plus this one spilled action (40,294 B).

Second, and more consequential: the 113,808 B attributed to "boundary action JSONs" is the **whole** controller action, not its receipts. Across the 15 action objects that entered the window before the boundary (104,777 B in total, close to the reported figure), receipts are a minority:

| Key | Bytes | Tokens |
|---|---|---|
| `dispatch_jobs` | 41,677 | 12,445 |
| `artifact_receipts` | 35,024 | 11,097 |
| `dispatch_values` | 13,623 | 4,384 |
| everything else | 14,453 | 4,470 |

`dispatch_jobs`, `dispatch_values`, `context_plan` and `run_plan` are the payload the dispatch needs. No receipt refactor removes them.

The honest total for everything receipt-shaped that reached the orchestrator before the compaction:

| Component | Bytes | Tokens (cl100k) |
|---|---|---|
| `verify-receipts` commands (the echo) | 16,752 | 6,397 |
| `verify-receipts` results | 2,521 | 745 |
| `artifact_receipts` + `receipts` inside actions | 35,842 | 11,344 |
| **Total** | **55,115** | **~18,500** |

That is **16.1%** of the 342,886 B denominator the first analysis used, and **11.0%** of the 167,596-token window the compaction actually acted on. The two framings differ because the transcript is roughly two thirds of the window: the system prompt, tool schemas, `CLAUDE.md`, the skill files loaded by the harness and the thinking text are all outside it. A share of the transcript is not a share of the window, and the question this was asked to answer is about the window.

Related: the "thinking 13.8%" row is not reasoning. All 197 thinking blocks in the file have an **empty** `thinking` field and a ~1.5 KB `signature`; the 47,338 B is signature bytes. The real thinking text is in the window and is not measurable from the transcript at all, so the composition table both mislabels that row and undercounts the category.

Removing the entire receipt round-trip would have taken the window from 167,596 to roughly 149,000 tokens. That very likely delays this compaction rather than preventing it. **The receipt work should not be justified as a compaction fix.**

### The "37% of a stage's compute" figure is dispatch count, not milliseconds

Retracted from an earlier draft of this note, which said the figure did not reproduce. It does: `record_stage_stats.py` carries its provenance in the comment `e2670ccb` left behind — "silently discarded 3 of 8 STRIDE dispatches on run a2a0e355 — 37% of that stage's compute". 3 of 8 is 37.5% of *dispatches*. Reading it as milliseconds and finding 0.7%, 2% and 45% by three extraction methods measured the wrong quantity. The wording is loose, the number is sound, and the defect it names was fixed.

What the same row does still show is a different, live defect. The persisted STRIDE row claims `dispatch_count: 37` while the hook log holds **8** `AGENT_SPAWN` events for `appsec-stride-analyzer-v2` — and every other variant in the run matches its spawn count exactly (1=1, 7=7). The cause is the `--since-iso` fallback: a window captured after the wave had spawned matches nothing, `_derive_dispatch_stats` degrades to deriving from the whole log, and the accumulate merge then *sums* that whole-log population once per call.

`recorded_dispatch_count: 5` against `dispatch_count: 37` is not evidence of anything. The two fields count different things by design — merge calls versus summed spawn events — so the consistency check this note first proposed on that pair does not survive. The check that does is the one against the hook log, which has no threshold and no ambiguity.

### Two failing tests, not three, and one is environmental

Full suite at clean `HEAD` (`78b97663`, working tree carrying only the untracked analysis note): **2 failed, 13,674 passed, 96 skipped, 555 s**.

- `test_context_prompt_budgets.py::test_each_live_prompt_surface_stays_within_budget` — `stride_analyzer_role: 12764 > 12000 bytes`. Genuine, pre-existing. This is one test, not the two separately named.
- `test_context_routing.py::test_catalog_runtime_bindings_and_schemas_are_packaged` — `shutil.Error: [Errno 13] Permission denied` on `.bashrc`, `.zshrc`, `.gitconfig`, `.mcp.json` and other dotfiles while copying the repo root into a build directory. This is the Bash sandbox deny list, not the code. The packaging test does not currently run under the sandbox and its result is not evidence either way.
- `test_e2e_pipeline.py::test_compose_matches_golden` **passes**. The formatter work it was failing against is not in the tree.

## New: what the thin routing actually costs

The first analysis calls this the only open question whose answer could change the report, and calls it unknown. Part of it is answerable from the run that already exists, at no cost.

Every threat in the eight `.stride-<component>.json` files carries an `evidence` object with a `file`. Cross-referencing those against the `source_slices` of each component's delivered bundle:

| Component | Threats | Bundle files | Cited, in bundle | Cited, outside bundle |
|---|---|---|---|---|
| auth-session | 8 | 4 | 2 | 1 |
| backend-api | 15 | 4 | 3 | 3 |
| ci-cd-pipeline | 7 | 15 | 4 | 1 |
| database | 6 | 1 | 0 | 3 |
| frontend-spa | 9 | 19 | 6 | 1 |
| hacking-instructor | 1 | 5 | 1 | 0 |
| realtime-channel | 6 | 2 | 1 | 0 |
| web3-nft | 6 | 1 | 1 | 4 |

**13 of 31 distinct cited files (42%) were never delivered by the routing.** For `database` the figure is 3 of 3: its single delivered file, `data/datacreator.ts`, is cited by nothing, while every threat it produced cites `lib/insecurity.ts`, `models/user.ts` and similar files it went and found. Inverting: **33 of the 51 delivered files were never cited by any threat.**

A file can inform an analyst without being cited, so this is a signal rather than a proof. But it points the open question the other way. The bundle is not a ceiling on findings — the analysts read past it, and for the thinnest components they got everything that way. The sharper question is what the routing is buying when 42% of the evidence actually used bypassed it and two thirds of what it delivered went uncited. `evidence_coverage_shortfall` currently measures the wrong side of that: it counts files delivered, not files used.

This does not close the "does wider routing find more" question. It does downgrade it, and it costs a re-run to answer while the citation measurement above costs nothing.

## Assessment of §5, "the pattern"

The observation is true for all six cases and the prescription is mostly sound, but the framing overstates what six cases can carry.

The sample is self-selected. All six were found by one method: read the run's artefacts and check them against each other. That method can only surface defects shaped like cross-artifact inconsistency in a green run. Crashes, mis-scored severities, hallucinated findings and prompt-quality regressions are structurally invisible to it. "The pattern behind every defect found" is therefore close to a tautology — it is the pattern behind every defect this search could find. That is not a wrong conclusion, but it is not evidence that the *next* defect will have this shape.

The narrower claim survives the bias and is worth stating on its own: **the run's success signal is stage-local. Nothing reconciles what a stage produced against what a later stage consumed or published.** That is a statement about a missing class of invariant, it is supportable without appeal to the six cases, and it implies the same fix.

One of the four proposed checks does not survive as stated. The receipt row is circular — "no marker exists yet" is the §2 fix restated, not a consistency check. The stage-stats row survives, but not on the field pair this note first named: `recorded_dispatch_count` and `dispatch_count` count different things by design. The invariant that holds is against the hook log — a variant cannot have dispatched more agents than the run spawned.

## What was implemented

Verifying each recommendation before writing it changed two of them.

**A source fix, not just a check.** `record_stage_stats._merge_accumulate` now takes a whole-log-derived `dispatch_count` instead of adding it, and caps the row at that population from then on. The provenance travels with the value: `_derive_dispatch_stats`'s fallback marks its result `dispatch_count_scope: "full_log"`. Two tests pin it — five accumulate calls against an eight-spawn log now record 8, and window-derived counts still sum.

**Three reconciliations in `aggregate_run_issues.py`**, each fired against the real run before being written:

| Check | On run a2a0e355 |
|---|---|
| `dispatch_count_inconsistent` | `stride_analyzer`: 37 claimed against 8 spawn events |
| `routing_effectiveness` | `database`: none of the 3 files its 6 threats cite came from the 1 file routing delivered |
| `requirements_export_inconsistent` | silent now; fires on the export as the run originally published it (73 declared, 0 exported) |

`routing_effectiveness` fires only when a component produced threats and *none* of their evidence came from its bundle. A file can inform an analyzer without being cited, so the ambiguous middle stays quiet: `web3-nft`, with one citation in the bundle and four outside, is not reported.

**Receipt verification is enforced.** `verify-receipts --action-id` resolves what to re-hash from `deliveries[].source_receipt`, so the 92 echoed pairs are no longer needed; against the run's own plan the id resolves to 44 of the 45 pairs the echo carried, and the 45th is the plan itself, whose bytes the lookup checks against its exact-byte receipt before reading a delivery. The controller records each verification, names the pending dispatch in `.pending-dispatch.json`, and every command in `_SEMANTIC_RETURN_COMMANDS` refuses to advance a dispatch with no record. The echoed form still works and still satisfies the gate, but only when it covered everything the plan admitted.

Three things the verification pass caught in that implementation, none of which the tests would have found later:

- Action ids derive from job ids, which repeat across runs, so a marker left in a reused output directory would have satisfied a later run's gate. Both files are now cleared at `context_v2_begin`, where the plan itself resets, and are in the cleanup whitelist.
- A mistyped action id aborted the run. The plan is intact and a corrected call fixes it, so it now rejects (exit 3); a plan that changed after its receipt still aborts (exit 2). `UnknownActionError` carries that split.
- One test passed for the wrong reason — a hand-built plan fixture failed delivery-schema validation before reaching the assertion. The negative cases now mutate a plan the real producer wrote.

A missing verification rejects rather than aborts on the same reasoning: the run is untouched, the orchestrator verifies and repeats the boundary. Ending a 98-minute run over a protocol omission would make the guard more expensive than what it guards.

**The thin-runtime headroom guard was fixed on the way past.** Editing `SKILL-thin-stage1-v2.md` failed `test_thin_runtimes_have_headroom_for_operational_detail`, which reserves 10% of each surface's ceiling so exact command lines survive compaction. That surface sat 11 bytes under the threshold while 651 bytes remained to its hard ceiling — the guard blocked before it could warn. The guard also scoped itself to `thin_stage*`, which left out `thin_full_runtime` at 13,226 of 13,250 bytes: the tightest surface in the set was the one nothing warned about. The guard now covers every thin runtime, and both ceilings were raised (13,250 → 15,500 and 6,400 → 6,800) through the ratchet in `test_context_prompt_budgets.py`, which exists so a budget cannot grow inside a prompt edit. This adds no room in practice: the aggregate gates measure real bytes and sit at 96% of `thin_full_pre_stage2_max_bytes`, so about a kilobyte is all the thin control surface can actually gain. What changed is that the per-file ratchet warns again instead of blocking.

## What is left

The wider-routing re-run. It is still worth doing and it is still a paid experiment, but it now has a metric that can read its result, and the cheap half of the question is answered above and points away from "thin routing costs findings".

## Reproduction

Measurement scripts were written to the session scratchpad, not the repository. Each figure above is reproducible from `~/.claude/projects/-home-mrohr-juice-shop3/a2a0e355-….jsonl` (rows 0–657 are pre-boundary), `/home/mrohr/juice-shop3/docs/security/`, and `scripts/aggregate_run_issues.py`. The three numbers most worth re-deriving before acting on them are the 11.0% window share, the 42% outside-bundle citation share, and the 37 claimed dispatches against 8 spawn events.
