# Analysis — Context-window compaction on thorough runs

**Date:** 2026-07-16
**Trigger:** A thorough full run of `create-threat-model` on OWASP Juice Shop
(plugin v0.5.0-beta, orchestrator session on Sonnet 4.6) had its context window
compacted mid-run (during Stage 2). Question raised: is compaction problematic,
and should the orchestrator run on a larger (1M) context window to avoid it?

**Verdict:** For this pipeline compaction is **largely benign**. Do **not** move
the orchestrator to a 1M-context session to avoid it — the cost increase
(~1.5–2×) is not justified by the marginal risk that compaction actually
carries here. The correct, cheap hardening is deterministic gate-enforcement of
every finalization step (already largely in place), not a bigger window.

## What compaction loses vs. what survives

The pipeline is **filesystem-authoritative, not conversation-authoritative** —
this is a deliberate design property (see `SKILL-full-runtime.md` §6: *"the
filesystem is authoritative — if context was compacted or a return is ambiguous,
run the same `next` call and use its action to re-establish the current stage.
Never infer a completed stage solely from conversation memory."*).

- **Compaction loses:** the conversation narrative — tool outputs, agent return
  text, the running story of what was done.
- **Compaction does NOT touch:** the artifacts (all on disk under `$OUTPUT_DIR`)
  or the resumable state (`.appsec-checkpoint`, `orchestration_controller`
  state, the durable `.skill-config.json`, `.stage-stats.jsonl`).

On resume the orchestrator re-derives "where are we + what is pending" **from
disk** via the mandatory finalize gate (`orchestration_controller.py next`), not
from memory. In the 2026-07-16 run the resume was clean: it re-established the
Stage 2→3 boundary correctly, ran every remaining stage, and produced a correct
report (§1–11 contiguous, priorities labeled, all gates green). That is the
design working, not luck.

## The one real residual risk

A step that lives **only** in the orchestrator's procedural memory and is **not**
enforced by a deterministic gate can be dropped by a compaction summary. This is
exactly the historical `renumber_sections` / `style_priority_circles`
finalization-skip bug — both of those scripts have since been **removed**;
section numbering and priority styling are now deterministic inside
`compose_threat_model.py`, so that specific bug class is closed. The plugin has
been systematically de-risking compaction by moving finalization into
deterministic gates: the mandatory finalize gate, `section_integrity.py`,
`assert_completeness.py`, and recompose-from-fragments.

Compaction becomes genuinely risky only when:
1. it happens **repeatedly** in one run (thrashing → more overhead + higher
   chance of a lossy summary), or
2. a post-Stage-2 step exists that is orchestrator-memory-only (not
   gate/checkpoint covered).

Keeping (2) at zero is the real safeguard — and it is cheap.

## Cost comparison — why a 1M window is the wrong fix

| Option | Cost impact | Effect on compaction |
|---|---|---|
| 1M-context session (Sonnet 4.6 1M / Opus 4.8 1M) | **~1.5–2× the run** — every turn re-reads a larger cached prefix (matches the "Sonnet 5 ≈ 2×" finding in `docs/threat-modeler.md`) | eliminated |
| Let it compact (status quo) | one summarization call + one cold-cache turn; context is then **smaller** → subsequent turns are cheaper | benign, self-limiting |

Economically, **compaction is the cheaper path.** Paying 1.5–2× to avoid a
benign, self-limiting mechanism is a bad trade.

## Why output-stream trimming was also rejected

The obvious "reduce what the orchestrator holds" lever — routing deterministic
gate stdout to files instead of the orchestrator context — was measured and
rejected. The gate outputs are already small or already redirected:

| Gate call | stdout | Σ per run |
|---|---|---|
| `qa_checks.py repair_plan` | ~100 tok | ~150 |
| `qa_checks.py autofix` | ~10 tok | ~20 |
| `compose_threat_model.py` | ~260 tok | ~700 |
| `orchestration_controller.py next` | ~730 tok | ~2 200 |
| `qa_checks.py all` / `unmasked_secrets` | — | already `> file` |

Total addressable ≈ **3 000 tokens** across a whole run. Context growth is
dominated by the **27 agent dispatches** (each STRIDE/abuse dispatch prompt is
~1–2k tokens; plus SKILL slices ~20k; plus the SessionStart context-mode hook
~12k), summing toward ~150–180k on a 200k window. Trimming ~3k (~2%) neither
prevents nor meaningfully delays compaction, so the change is not worth the
skill-body churn. The dispatch prompts themselves cannot be safely trimmed (the
per-component params are needed for analysis quality), and the returns are
**already terse** — every one of the 18 pipeline agents returns a one-line
status only (findings live in `.stride-*.json` etc., not in the return text),
per `shared/completion-contract.md`. The #1 driver is already mitigated.

## Recommendation

- **Do not** run the orchestrator on a 1M-context session to avoid compaction.
- **Do** keep every finalization step gate-enforced and disk-re-derivable
  (status: largely done). The only maintenance rule that matters: never add a
  post-Stage-2 step that lives only in orchestrator memory.
- Treat mid-run compaction on a 200k session as expected and benign for thorough
  runs. It is a graceful mechanism, not a defect.
