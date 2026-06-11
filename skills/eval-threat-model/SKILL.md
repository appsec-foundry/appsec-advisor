---
name: eval-threat-model
description: Developer/test skill that grades the SEMANTIC quality of a produced threat model (plausibility, severity proportionality, STRIDE coverage, mitigation actionability, missed surfaces) via a find→adversarial-verify loop over a frozen run. Complements the structural pytest/qa_checks suite; does NOT re-run the pipeline.
---

# eval-threat-model

Evaluate the **quality** of an already-produced threat model, not its structure. The pytest suite and `qa_checks.py` already prove the output is schema-valid, renders, and is cross-reference-clean. They cannot tell you whether the threats are *plausible*, the severities *proportional*, the STRIDE coverage *complete*, or the mitigations *actionable*. This skill does, by evaluating a **frozen run** (default: the bundled fixture) — no expensive pipeline re-run.

It runs a find→verify loop: per rubric dimension, one judge surfaces candidate defects, then a second, independent judge tries to **refute** them (refute-by-default). Only positively-grounded defects survive into `EVAL-REVIEW.md`. A deterministic Python harness (`scripts/eval_threat_model.py`) does the loading, signal computation, and scoring; the agents do only the irreducibly-semantic judging.

## Inputs

Parse from the user's invocation; all optional:

- `RUN_DIR` — dir holding `threat-model.yaml`. Default: `$CLAUDE_PLUGIN_ROOT/tests/fixtures/e2e/frozen-run`. For a real assessment, point it at the run's `OUTPUT_DIR` (dev-team default `docs/security/`, else your `--output` path), or `tests/fixtures/e2e/_last-run` for an E2E run. **`--keep-runtime-files` is NOT required:** the three inputs this skill reads — `threat-model.yaml`, `.threats-merged.json` (cwe/source/evidence enrichment), `.recon-summary.md` (recon context) — are all in `runtime_cleanup.py`'s `NEVER`-delete set, so a completed run leaves them in place regardless. (The harness degrades gracefully if the two sidecars are absent — judges then work from `threat-model.yaml` prose alone.)
- `OUT` — eval working/output dir. Default: `$PWD/.eval-out`.
- `REPO` — optional target repo root. When set, judges may read the actual code to ground plausibility/missed-surface; when absent they judge from the brief.

## Procedure

### Step 1 — Prepare the brief (deterministic)

```bash
RUN_DIR="${RUN_DIR:-$CLAUDE_PLUGIN_ROOT/tests/fixtures/e2e/frozen-run}"
OUT="${OUT:-$PWD/.eval-out}"
REPO_ARGS=()
[ -n "$REPO" ] && REPO_ARGS+=(--repo "$REPO")

python3 "$CLAUDE_PLUGIN_ROOT/scripts/eval_threat_model.py" prepare \
  --run-dir "$RUN_DIR" --out "$OUT" "${REPO_ARGS[@]}"
PREP_EXIT=$?
[ "$PREP_EXIT" -ne 0 ] && { echo "eval-threat-model: prepare failed ($PREP_EXIT)"; exit "$PREP_EXIT"; }
```

The dimensions are fixed (5): `stride_coverage`, `severity_proportionality`, `threat_plausibility`, `recommendation_actionability`, `missed_surface`.

### Step 2 — JUDGE fan-out (5 parallel sub-agents)

**Dispatch five `appsec-eval-judge` sub-agents — one per dimension — via the Agent tool, in parallel. Do NOT inline the judging yourself.** Inlining collapses the independent-verify guarantee and burns one serial context; the value of this skill is N independent judges. Each dispatch:

```
agent: appsec-eval-judge
MODE=JUDGE
DIMENSION=<one of the five>
BRIEF_PATH=<OUT>/brief.json
OUT_DIR=<OUT>
REPO_ROOT=<REPO if set, else omit>
MODEL_ID=sonnet
```

Each writes `<OUT>/judge-<DIMENSION>.json`. Wait for all five.

### Step 3 — VERIFY fan-out (5 parallel sub-agents)

After all judge files exist, dispatch five **fresh** `appsec-eval-judge` sub-agents (independent instances = the adversarial check) — one per dimension, in parallel:

```
agent: appsec-eval-judge
MODE=VERIFY
DIMENSION=<one of the five>
BRIEF_PATH=<OUT>/brief.json
OUT_DIR=<OUT>
REPO_ROOT=<REPO if set, else omit>
MODEL_ID=sonnet
```

Each reads `judge-<DIMENSION>.json` and writes `<OUT>/verify-<DIMENSION>.json` (refute-by-default).

### Step 4 — Aggregate + score (deterministic)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/eval_threat_model.py" aggregate --out "$OUT"
AGG_EXIT=$?
```

`aggregate` keeps only `real`-verdict candidates plus the deterministic findings, scores them, and writes `<OUT>/EVAL-REVIEW.md` + `<OUT>/eval-results.json`. Exit code: `0` = no confirmed High/Critical defect, `1` = at least one (gate-able in CI), `2` = usage error.

### Step 5 — Report

Relay **only**: the harness headline (confirmed counts + dropped-by-verify count), the `EVAL-REVIEW.md` path, and the aggregate exit code. Do not re-summarize every finding — the report is the source of truth. If `AGG_EXIT == 1`, surface the confirmed High/Critical titles so the user sees what to act on.

## Notes

- This is a **test/dev** skill — never auto-triggered, not part of `create-threat-model`. Run it manually after a pipeline change to catch quality regressions a frozen fixture would otherwise hide.
- Cost is bounded: 10 sub-agents over a compact brief, no STRIDE/recon re-run.
- The judges are skeptics; an empty `EVAL-REVIEW.md` ("no confirmed defects") is a real, valid result, not a failure.
