# Stage 4: from architect review to editorial pass

State on 2026-08-30, after `afe1f53f`, `c12a513a` and `c76131d7`. Implemented and unmeasured: no run has executed the new stage yet.

Stage 4 no longer reviews the report. It rewrites its prose once, on Sonnet, and judges nothing. Every claim below was checked against the code or against the measured run in `/home/mrohr/juice-shop2/docs/security`.

## Why the review had to go

Measured from `.agent-run.log` of the thorough juice-shop2 run:

| Step | Window | Duration | Result |
|---|---|---|---|
| Architect round 1, deterministic pre-pass | 08:17:01 → 08:17:33 | 32 s | 14 findings (checks 1, 3, 5, 6, 12, 13, 14, 15) |
| Architect round 1, LLM checks 2, 4, 7–11 | 08:17:33 → 08:29:06 | 11 min 33 s | 29 findings, 1 technical defect |
| Fragment fixer | 08:30:04 → 08:31:27 | 1 min 23 s | 3 actions, `gate_exit_code: 0`, converged |
| Architect round 2 (verification) | 08:32:54 → 08:49:06 | 16 min 12 s | 26 findings, 0 technical defects, pass |
| **Stage 4 total** | 08:16:55 → 08:49:06 | **32 min** | one repaired fragment |

A second thorough run the same afternoon took 40 minutes for the same shape, and a parallel cost analysis put the Stage-4 loop at 431k tokens — a fifth of the run — for four fragment edits, of which the architect alone was 349k.

Three findings decided the rework.

**The second pass confirmed what was already verified.** The runtime required a full re-review after every repair, so 16 minutes and 168k Opus tokens went into turning `repair_required` into `pass` on a repair the fixer had already checked with `gate_exit_code: 0`.

**The review's output reached nobody.** It found real things — the Management Summary counting 59 findings against a register of 76, no P1 mitigation for any effective-Critical finding, a missing browser-to-API trust boundary, an unmodelled LLM service — and wrote them to `.architect-review.md`, which no deliverable reads. `grep` across `scripts/`, `skills/` and `agents/` finds only runtime cleanup, `publish_threat_model.py`, `postscan_secret_check.py`, and one completion-summary line suggesting the reader open the file. The same observations recurred in two consecutive runs.

**Nobody owned the language.** `apply_prose_fixes.py` applies seven regex fix classes and explicitly declines paragraph restructuring; `agents/shared/prose-style.md` binds the authoring roles, but each sees only its own slice. Tone across sections, redundancy between the Management Summary and §6, and clumsy sentences were unowned.

## How the stage works now

`SKILL-thin-stage4.md`, one pass, no loop:

1. `build_editorial_context.py` writes the projection; `check_editorial_diff.py snapshot` records the guarded files; `architect_structural_checks.py all` runs as an advisory pre-pass. No agent so far, 32 seconds.
2. One dispatch of `appsec-architect-reviewer`, `run_in_background: false`. It reads `shared/prose-style.md` and the projection, writes one plan, and holds no `Edit` tool.
3. `apply_editorial_plan.py` performs every write, `check_editorial_diff.py verify --restore` checks it, and the canonical tail re-renders: strict compose, prose fixes, QA gate, section integrity, secret gate.
4. `render_editorial_receipt.py` writes `.architect-status.json` and prints what happened.

Nothing judges, so nothing is re-judged. A QA gate that rejects the edited bytes triggers `check_editorial_diff.py restore` and one re-render of the original: a failed polish costs the polish, never the run.

`.architect-status.json` stays the stage's status artifact, so the controller gate at `orchestration_controller.py:6681`, runtime cleanup, `check_state.py`, `baseline_state.py`, `publish_threat_model.py`, `aggregate_run_issues.py` and the completion summary need no change.

## What it may touch

The report's prose has three producers and only one is worth an editor's time.

**Deterministic templates — out of reach.** Before every compose the controller runs `pregenerate_fragments.py --force --only system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md` (`orchestration_controller.py:6346`), so an edit there dies at the next compose. §3 belongs here too: `walkthrough_renderer.py` renders the walkthroughs from the yaml plus per-CWE templates.

**`threat-model.yaml` free text — the main surface.** `scenario`, `evidence_summary`, `impact_description` and `breach_distance_reason` are read by `_build_threat_card` (`compose_threat_model.py:14538`, fields at 14771–14921) into the §8 cards. `mitigations[].steps` and `mitigations[].verification` come from `hydrate_mitigation_details.py`, which states that authored fields always win, so an edit survives re-hydration. The yaml is stable after Stage 2: `build_threat_model_yaml.py` runs from one place (`orchestration_controller.py:6174`) and only against a `meta._bootstrap` stub, and `--write-yaml` in the completion summary is a display flag (`render_completion_summary.py:1322`).

**LLM-authored fragments.** `.fragments/security-architecture.md`, `.fragments/ms-verdict.json`, `.fragments/ms-anti-patterns.json`.

Editable, and nothing else:

- `threats[].scenario`, `.evidence_summary`, `.impact_description`, `.breach_distance_reason`
- `mitigations[].steps`, `mitigations[].verification`
- the `verdict` block's prose fields
- prose paragraphs of `.fragments/security-architecture.md`
- prose fields of `.fragments/ms-verdict.json` and `.fragments/ms-anti-patterns.json`

Out of reach by construction: identifiers, titles, severities and scores, evidence entries and `file:line` locators, requirement links, the unproven marking REQ-MOD-009 demands, numbers and link targets. `threats[].title` stays out because `_canonical_finding_title` derives the §8 heading from CWE and evidence anyway, and where the raw title survives it feeds `_FNNN_REGISTER_ROW` (`compose_threat_model.py:1596`), `_MD_THREAT_ROW_RE` (`qa_checks.py:9908`), the §3 headings and TOC anchors. `mitigations[].title` stays out because `recommend_fixes.py` and the §3 "Primary mitigation" line match on it.

## What it is allowed to improve

Language: over-long sentences, passives that hide the actor, nominalizations, AI padding, openers restating the heading, a point made twice.

Technical precision within what the block already says: a mechanism described vaguely where the block's own evidence names it exactly, a consequence stated before its cause, a remediation step that says what to change but not where, a subject of "the application" where the block names the component.

The line: it sharpens a claim the block already makes. It never adds one, never widens or narrows its scope, never re-rates anything, and never changes how certain a claim is — a hedge stays a hedge. Mitigations carry their own floor: REQ-RPT-005 and `validate_mitigation_quality.py` require two ordered steps and a verification instruction on every P1/P2 fix card, so steps are never merged, dropped or reordered.

It edits toward `agents/shared/prose-style.md`, the anchor the authoring agents already write to, and is listed in `AGENT_FILES_AUTHORING_PROSE` so that stays wired.

## The guard

`check_editorial_diff.py` snapshots before and verifies after.

Outside the editable allow-list, the yaml and the JSON fragments must stay deep-equal — which also pins list lengths, so a dropped mitigation step is a structural violation. Inside an editable field, identifiers, link targets, URLs, paths, `file:line` locators and numbers survive as unchanged multisets. A filled field may not be blanked. Markdown headings stay byte-identical, because anchors, the TOC and the controls-covered links are built from them.

Invariants are read with backticks stripped. `prose-style.md` Rule 6 requires code tokens to be fenced, so a rewrite that obeys the style adds backticks the original lacked; pinning the fenced form would revert exactly the improvements the pass exists to make. A separate check catches a span that disappears in any form.

`verify --restore` rolls back on violation and exits 2; `restore` rolls back unconditionally, for a later gate that rejects bytes the guard itself accepted.

## Cost, honestly

Removed and measured: 40 minutes of wall clock in the last run, of which 15 minutes and 168k Opus tokens were the confirmation pass; the architect as a whole was 349k tokens, 16% of the run's subagent total.

Added and estimated: one Sonnet dispatch reading a 51 KB projection plus the 20 KB style anchor, writing a plan whose size grows with the number of rewrites. Roughly six tool calls. Turn ceiling 100 → 30, floor 90 → 12, model default Opus → Sonnet.

That is arithmetic, not a measurement. The first real run should produce three numbers: how many of the offered blocks were rewritten, how many the applier or guard rejected, and how many turns the pass used. The turn floor came down because the role changed, not because a run proved 12 sufficient — `tests/test_agent_definitions.py:88` records that every shipped turn-kill was a budget set too small.

STRIDE remains the larger cost at 795k tokens, 36%. Stage 4 is not where the run's expense mostly lives.

## What the change costs in coverage

Checks 2, 4, 7, 8, 10 and 11 no longer run. Mapping the measured run's warnings:

| Survives (deterministic detection) | Lost with the LLM checks |
|---|---|
| MS/register count mismatch (Check 3) | Weakness-register aggregation (Check 7) |
| Duplicate mitigations across priority tiers (Check 12) | Rating coherence (Check 10) |
| §6 verdicts understating defeated controls (Check 14) | Trust-boundary gaps (Check 2) |
| BFF anti-pattern mandate (Check 15) | Uncovered CORS and archive extraction (Check 4) |

Roughly half survive for free. The deterministic checks still run every Stage 4, and their warning titles now reach the receipt instead of a dotfile nobody opens.

The four `agents/shared/architect-{coherence-rules,coverage-signals,depth-matrix,repair-classifier}.md` have no consumer after this change. They are left in place: restoring the deep review behind its own flag should be a wiring job, not a rewrite.

## Built

| Artifact | Purpose |
|---|---|
| `scripts/build_editorial_context.py` | projects the editable blocks to `.dispatch-context/editorial/blocks.json`, only addresses the guard admits |
| `scripts/apply_editorial_plan.py`, `schemas/editorial-plan.schema.json` | the only writer; allow-listed addresses, `find` as optimistic lock, exactly-once Markdown match |
| `scripts/check_editorial_diff.py` | `snapshot`, `verify [--restore]`, `restore` |
| `scripts/render_editorial_receipt.py` | writes `.architect-status.json`, prints the receipt including the advisory warnings |
| `agents/appsec-architect-reviewer.md` | 754 lines → 82; tools `Read`, `Write`, `Bash`; Sonnet; 30 turns |
| `skills/create-threat-model/SKILL-thin-stage4.md` | one pass, no repair loop |

Projection size against the real run at the defaults (`--max-findings 20`, floor `high`): 228 blocks, 51 KB — 153 from the yaml, 63 §6 paragraphs, 12 from the Management-Summary fragments, against 541 editable fields and 104 KB unbounded. The §6 filter skips headings, tables, fences, HTML, list items, the mechanical bold labels (`**Status:**`, `**Implemented controls:**`) and `FROZEN` regions, and requires a sentence of at least 80 characters once a bold label is stripped.

Runtime state lives under `.dispatch-context/editorial/`, which `runtime_cleanup.py` already reaps, so no cleanup-whitelist entry is owed. `Bash(*)` covers the new scripts, so `data/required-permissions.yaml` needs no entry.

## Open

- The first measured run. Until it exists, the turn ceiling, the `--max-findings` cap and the claim that the polish is worth its dispatch are all estimates.
- Should `architect_structural_checks.py all` run at every depth rather than only in Stage 4? It costs 32 seconds, and its quality-bar and verdict-plausibility detection never runs at `quick` or `standard` today.
- Should the deep checks return behind their own flag? `--architect-review` now means "run the editorial pass at `standard`" and can no longer carry that second meaning.
- Rename or not. `appsec-architect-reviewer` no longer reviews. The id appears in the turn-budget test, the logging table, `resolve_config` keys, the completion-summary regexes at `render_completion_summary.py:690–719` and the cost model, so the rename is a separate, mechanical change.
- May the editor shorten a section, or only rephrase within it? Shortening interacts with `agents/shared/sec7-quality-bar-rules.md` and the substance verdicts in `section_integrity.py`.

## Follow-ups the measured runs surfaced

- The same finding is published on two incompatible severity axes: 🔴 Critical in the Management Summary, 🟡 Medium in §8. A composer defect, unreachable for a fragment fixer, and the most damaging of these for a reader.
- The composer demotes three fragment-declared `#### 6.2.N` headings to bold paragraphs and renumbers OAuth to 6.2.1; the fragment is correct, so regenerating it reproduces the defect.
- `sec7_v2_no_legacy_flows` matches the canonical control name "OAuth 2.0 Authorization Code Flow with PKCE" at `architect_structural_checks.py:1261` — a false positive that returns every run.
- Mitigation priority keys off raw risk, so two low-effort Critical fixes sat in the P3 backlog.
- A completed run in `/home/mrohr/juice-shop` left `.appsec-lock` unreleased; a watchdog kept heartbeating for ten hours and the next run there would block on it.

All five are unverified here.
