# Run a2a0e355 — pipeline analysis

Findings from analysing one full `create-threat-model` run and the plugin code
behind it. **Working note, not a decision record.** Written by a
Claude Code session on 2026-08-29 against plugin `dev`.

> **Read this as claims, not facts.** Every section names the command that
> reproduces it. A fresh session should re-derive anything it intends to act
> on — two of the numbers in the first draft of this analysis were wrong
> (see *Corrections* at the end), and both were caught only by re-measuring.

## The run

| | |
|---|---|
| Run ID | `a2a0e355-dca7-4e3f-a0ad-ad58ca8fa136` |
| Slug | `juice-shop-standard-req-v0.6.0b2` |
| Repo | `/home/mrohr/juice-shop3` (OWASP Juice Shop) |
| Output | `/home/mrohr/juice-shop3/docs/security` |
| Invocation | `--slug … --keep-runtime-files --skip-context --requirements appsec-requirements-example.yaml` |
| Result | 50 threats (8 Critical), 8 components, QA pass, 97m 57s wall |
| Transcript | `~/.claude/projects/-home-mrohr-juice-shop3/a2a0e355-….jsonl` |

Runtime artefacts were kept (`--keep-runtime-files`), so every measurement
below can be re-run against the real output directory.

## 1. The auto-compaction

One compaction, automatic, at the Stage 1d → Stage 2 boundary.

| | |
|---|---|
| Timestamp | `2026-08-28T21:53:59Z` |
| Trigger | `auto` |
| Before / after | 167,596 → 22,753 tokens |
| Dropped | 144,843 (86%) |
| Duration | 95.9 s |
| Subagents compacted | **0 of 47** |

```bash
python3 - <<'PY'
import json
f='<transcript>.jsonl'
for line in open(f, encoding='utf-8', errors='replace'):
    d = json.loads(line)
    if d.get('subtype') == 'compact_boundary':
        print(json.dumps(d.get('compactMetadata'), indent=2))
PY
```

The report was rendered from a context that had lost 86% of the analysis. It
came out correct because the write-first architecture put everything on disk —
the compaction was survivable, not free (95.9 s, plus cache re-reads).

### What filled the window

Transcript content before the boundary: **342,886 B**. (Static overhead —
system prompt, tool schemas, `CLAUDE.md` — is not in the transcript and is not
measured here; it accounts for the gap to 167,596 tokens.)

| Share | Bytes | What |
|---|---|---|
| 60.1% | 206,088 | `tool_result` |
| 13.8% | 47,338 | thinking |
| 10.9% | 37,442 | `tool_use:Bash` |
| 5.9% | 20,183 | `tool_use:Agent` |

Within `tool_result`, by producer:

| Bytes | n | avg | What |
|---|---|---|---|
| 69,450 | 4 | 17.4 KB | `Read` of the SKILL runtime files |
| 113,808 | 27 | — | boundary action JSONs (largest single **40,290 B**, 155 `sha256` fields) |
| 19,103 | 5 | 3.8 KB | `wait_stride_progress` |

And of the 30,930 B of Bash *commands* the orchestrator wrote, **16,752 B (54%)
was `verify-receipts`** — echoing hashes back.

**Receipt round-trip total: ~130 KB, ≈38% of the measured transcript.**

## 2. The receipt round-trip is unenforced and near-redundant

`verify_receipt_hashes` (`scripts/orchestration_controller.py`) is a genuine
TOCTOU guard: it re-hashes an action's admitted artefacts immediately before
dispatch. Three things are true about it:

1. **It writes no state.** No marker records that it ran.
   ```bash
   grep -rn "receipts_verified\|verified_receipts\|verification_marker" scripts/
   # → no matches
   ```
2. **Nothing checks that it ran.** An orchestrator that skips `verify-receipts`
   proceeds unimpeded. This is a plausible LLM failure and would be invisible.
3. **91 of the 92 echoed receipt paths are already persisted** by the
   controller itself, in `.context-routing-plan.json` under
   `deliveries[].source_receipt` (`artifact_path` + `sha256`, 114 entries).

So the plugin spends ~38% of the orchestrator's window carrying hashes the
controller already has, to run a check nobody verifies happened.

**Proposed direction (not implemented):** move the verification server-side —
the controller re-hashes from its own record at the dispatch gate and refuses
the action on mismatch. That makes the control *mandatory* instead of
optional and removes the context cost. It is a boundary-protocol change:
the thin runtimes currently instruct the orchestrator to call
`verify-receipts` as "the last filesystem operation", and one echoed path was
not in the ledger, so persistence would need to be provably complete first.

**Recommended first step:** add the enforcement marker alone. It is small, it
reveals whether the round-trip is honoured in practice, and it de-risks the
larger refactor by producing data.

## 3. Requirements & blueprint integration

**Markdown report — clean.** Verified against the catalog:

| Check | Result |
|---|---|
| Requirement rows in §7b | 73, all unique — matches catalog exactly |
| Status distribution | 31 FAIL · 24 UNVERIFIABLE · 14 PARTIAL · 3 N/A · 1 PASS = 73 |
| Priority | 61 MUST + 12 SHOULD = 73 |
| Finding cross-references | 37, **0 dead anchors** |
| Blueprint lines | 43 — **0 unknown IDs, 0 mis-assignments, 0 invented section titles** |
| Catalog integrity | 12 blueprints / 68 sections / 71 refs → 51 req IDs, **0 dangling** |

Every `BP-xxx ↔ REQ-ID` pairing in the report is backed by the catalog's own
cross-reference.

**YAML export — was broken, now fixed (`b0cd06ef`).** `threat-model.yaml` had
no `requirements_compliance` key at all; `build_threat_model_yaml.py` never
emitted it, and `render_completion_summary.py` reads its counts from there —
hence `0 checked | 0 pass | 0 fail | 0 partial` on a run that assessed 73.

## 4. Open: is the thin evidence routing costing findings?

Three components were analysed from under 5% of their in-scope files:

| Component | Files with evidence | In scope |
|---|---|---|
| backend-api | 4 | 85 |
| database | 1 | 26 |
| frontend-spa | 19 | 426 |

`aggregate_run_issues.py` flags this, but only in the completion stage — after
the report is written. The controller now also reports it as an advisory
receipt at STRIDE dispatch time (`5c7dff30`), sharing one threshold function
with the aggregator.

**This is the only open item whose answer could change what the report says
about the application.** It is currently *unknown*, not merely unfixed. The
run-diagnostician classified it as model judgment rather than a code defect
(the schema allows up to 16 focus paths; the prompt forces no narrowness), and
there is no measurement either way.

**Recommended:** re-run one component with wider routing and diff the
findings. "No new findings" closes the question; "three new criticals"
reorders every other priority here.

## 5. The pattern behind every defect found

Each of these was invisible in a run that reported success:

- model version pins silently inert (the Agent tool rejects the configured id)
- `BASH_WARN` truncating its own diagnostic payload
- evidence coverage measured after it could matter
- 37% of a stage's compute discarded, reported as a routine skip with exit 0
- `requirements_compliance` missing from the YAML → summary said 0, report said 73
- the TOCTOU check unenforced, with no signal if skipped

`aggregate_run_issues.py` is the designed channel and caught only part of it
(7 issues, 2 of them noise). All four substantive findings were deterministically
detectable:

| Check | Signal |
|---|---|
| report ↔ YAML reconciliation | report says 73 requirements, YAML says 0 |
| stage stats ↔ component durations | stats 3.29M ms, components 5.29M ms |
| model pin expressibility | already emitted as `model_pins_dropped`; not surfaced as an issue |
| receipt verification | no marker exists yet (see §2) |

**If only one structural change is made, it is these four consistency checks.**
They catch the class of failure that made this whole analysis necessary.

## 6. Committed during this analysis

Branch `dev`. All verified with the full suite (13,655 passing).

| Commit | What |
|---|---|
| `5c7dff30` | Model alias emitted as data (`<role>_model_alias`, `model_pins_dropped`); kernel SKILL names the log-event vocabulary; `BASH_WARN` reports the diagnostic line; evidence coverage measured at dispatch |
| `e2670ccb` | A reused accumulation id no longer discards a stage measurement |
| `4e0c182c` | A STRIDE poll round is reported only when it says something new |
| `b0cd06ef` | Requirements assessment exported into `threat-model.yaml` |

`dispatch_values` `maxProperties` was raised 80 → 96 (emitted set reached 79;
`MAX_ACTION_BYTES` is the real size guard at 2.9 KB of 64 KB). Rationale is a
`$comment` in `schemas/orchestration-action.schema.json` — worth a second
opinion.

## 7. Pre-existing, not caused by this work

- `agents/appsec-stride-analyzer-v2.md` is **12,773 B against a 12,000 B
  budget** and 3,185 tokens against a `[2500, 3000]` band — over budget at
  `HEAD`, independent of any local change. Two tests fail permanently because
  of it. Permanently red tests erode the suite that caught three mistakes
  during this analysis.
- `tests/test_e2e_pipeline.py::test_compose_matches_golden` fails against
  in-flight prose/code-formatter work.
- `scripts/redact_known_secrets.py:47` has an unsorted import block (ruff I001).

## Corrections

Two claims in the first draft were wrong and were caught by re-measuring:

1. *"The requirements catalog is empty (0 requirements, 0 blueprints)."* False.
   The 46-byte file was `.requirements.yaml` in the **repo root**; the real
   78 KB catalog is in the output directory. The parser also looked for a
   top-level `requirements` key, but they are nested under `categories[]`.
2. *"`record_stage_stats.py` emits 4.7 KB per call."* False. The 23.9 KB
   outlier was a boundary action JSON from a Bash call that had chained
   several commands together.

Neither survived a second measurement. Treat every number above the same way.
