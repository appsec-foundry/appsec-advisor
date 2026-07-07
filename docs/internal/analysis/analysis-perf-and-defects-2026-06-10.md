# Performance & Defect Audit — 2026-06-10

Three parallel audits (Python hotspots, orchestration, defect verification) against
repo @ `41d6b90`, measured empirically against real juice-shop artifacts (427 KB report,
300 KB threat-model.yaml, 68 threats, 26 Mermaid diagrams).
Verification status: read-only, no changes made.

---

## P1 — Functional bug (silent): abuse-chain severity fold is a no-op in the default run

**Status: OPEN.** The activation hook (Step 3b2, `SKILL-impl.md:2456-2460`) has
landed, but `triage_compute_ranking.py:981-982` exits cleanly when
`APPSEC_TRIAGE_DETERMINISTIC=1` is not in the *shell* env — and nothing sets it
there (no env prefix, no `--force`; `|| true` swallows the message; the user-global
settings.json contains only `CLAUDE_PLUGIN_ROOT`/`TZ`). Net: verified
abuse chains **never** raise `effective_severity`/§1/§8 ranking.

This is the documented env-var-doesn't-reach-skill-Bash gotcha in a new form.

**Fix direction:** an `APPSEC_TRIAGE_DETERMINISTIC=1` prefix or `--force` on the
3b2 call; better: gate on an artifact marker instead of an env var (e.g.
`.triage-flags.json` ranking block).

## P2 — Perf HIGH: export_pdf.py spawns mmdc/Chrome per diagram, serially

`scripts/export_pdf.py:315-345`: every ```mermaid``` block →
`subprocess.run(["mmdc", ...])` = Node+Puppeteer+Chrome boot (~2–5 s) per
diagram. 26 diagrams ≈ **1–2+ min** of serial Chrome starts per export.
The batch pattern already exists: `scripts/mermaid_validate.mjs --batch-json`
(qa_checks.py:4175 does ONE Node spawn for all blocks).
**Fix:** batch the diagrams through one Puppeteer session (or a 4-way pool ≈ 4×).

## P3 — Token/wall-clock waste: ms-architecture-assessment.json is authored every run but never rendered

The render path is dead (the MS compose loop `compose_threat_model.py:8191-8210` does
not include `architecture_assessment`; the contract `sections-contract.yaml:523-528` says
"merged"). **But** the producer side is fully live:

- Renderer agent contractually obligated (`appsec-threat-renderer.md:31,:123,:170,:267`)
- both Stage-2 dispatch paths (`SKILL-impl.md:2578,:2624`)
- `qa_checks.py:8497-8499` REQUIRED_FRAGMENTS **unconditional**
- `validate_ms_compactness.py:83-119` word-limit gate on a never-rendered fragment
- schema + `validate_fragment.py:75,:179`

LLM tokens every Stage-2 + 3 gates for zero output bytes. Removal must be
bidirectional (AGENTS.md §4) across: agent def, SKILL-impl (2×), qa_checks
(REQUIRED_FRAGMENTS + repair-plan ref :2118), validate_ms_compactness,
validate_fragment, schema, compose mappings (:135,:154-156,:6309-6336,:13748),
templates. A deliberate cleanup task, not a drive-by.

**Related:** `qa_checks.py:~2118-2127` `forbidden_ms_heading` remediation names the
outdated MS order ("…/ Architecture Assessment /…") and points
`fragments_to_rewrite` at the dead fragment → can send the fragment-fixer astray
(family bug_stage2_repair_loop_wrong_fragment).

## P4 — Structural: the Stage-1 head fan-out lives on Level-1 (platform-filtered)

`appsec-threat-analyst.md:461-467` instructs the Level-1 analyst to
dispatch context-resolver/recon-scanner/config-scanner in parallel — nested
dispatch is filtered at runtime (Issue #4182) → degrades to serial/inline,
consistent with the measured ~6m24 recon monolith. STRIDE/abuse/render were
all hoisted to Level-0, this fan-out was not. Expected gain 1–3 min
(recon-scanner is the long pole). **Verify live before investing** whether Level-1 dispatch
is currently inlined.

## P5 — Structural: analyst-B = full-analyst respawn for a mostly deterministic tail

`SKILL-impl.md:2011`: Phase 9-merge→10→10b→11(1–3) = mostly script plumbing, but runs
as a full analyst (300 maxTurns, 1440-line prompt), ~3–6 min of serial
merge-barrier tail. **Fix:** a lean merge-coordinator (fragment-fixer pattern)
or hoist the deterministic chain into skill-Bash, keeping only the Phase-10 judgment in
a small agent (the seam exists: appsec-threat-merger).

## P6 — Perf MED: agent_logger hook ~48 ms × Pre+Post on every tool call

`hooks/hooks.json`: 4 events → `python3 scripts/agent_logger.py`; 48 ms median
(12 ms interpreter + ~35 ms imports). Real run: 1246 PostToolUse → ≥2500 spawns
≈ **~2 min cumulative per scan** (3–5 % of a 40–60-min run), also fires in every
dev session. **Fix:** lazy imports (hashlib/re/datetime in branches) + an early exit
before imports for filtered events; the interpreter floor stays.

## P7 — Perf LOW: compose without CSafeLoader + double re-parse

13× `yaml.safe_load` (pure Python) = 1.27 s of a ~3.5–4 s compose run;
threat-model.yaml (300 KB) is parsed from disk TWICE in `main()` (L15104/L15191)
(comment L15101 admits it); the taxonomy is parsed 3×, cached only 1×
(L12731 bypasses `_TAXONOMY_CACHE`). CSafeLoader is available and 11×
faster — qa_checks already has the fix (`_fast_yaml_load` L229), compose never
adopted it. ~1.2 s × 2–6 invocations/pipeline. Trivial, risk-free.

## P8 — Lint: 114 Ruff errors in committed code

`make lint` FAILS: 44 F401, 37 I001, 17 UP037, 6 F541, **3 F821**, 2 E702, 2 B033;
108 auto-fixable. F821 highlights:
- `compose_threat_model.py:3293` — `... if False else None # late init below`,
  an undefined name behind a dead guard (pure confusion)
- `pregenerate_fragments.py:3103,:3267` — `Optional` without an import (saved only by
  `from __future__ import annotations`)

pytest collection clean (3751 tests, 4.85 s, no collection errors).

## P9 — Latent: qa_checks `_replay_absence_grep` without a cache, default path `["."]`

`qa_checks.py:2552-2611`: per absence claim a full `os.walk`+read of the
search_paths, no cache across claims. OK today (tight paths, 1.06 s total), but
empty `search_paths` default to `["."]` = N full-repo scans on monorepos.
**Fix:** memoize (base→filelist, path→text) per check_evidence_integrity call.

## Resolved / no longer open

- **§7 numbering drift (7.9 AI/LLM): NOT reproducible on the v2 path.**
  `_SECARCH_SUBSECTIONS` is v1-only (consumer is only `gen_security_architecture`);
  v2 has `_V2_SUBSECTIONS` (pregenerate:4649), congruent with the contract
  (7.9 = Cryptography). Only a residual confusion risk from two lists in one file.
- **Phase-10b triage burn: FIXED** (differently than planned) — no `--apply` needed;
  10b is deterministic + a ~30s ranking agent; deterministic-triage makes
  triage_compute_ranking the severity owner.
- **fragments_to_rewrite scope: FIXED** — a hard whitelist
  (phase-group-finalization.md:588-601) + a lean appsec-fragment-fixer
  (maxTurns=30) instead of a full analyst; drift-guarded.
- **STRIDE `\!` escapes: FIXED deterministically** —
  `merge_threats.py:125-165` `_strip_invalid_json_escapes` + pre-merge validation
  with batched re-dispatch.
- **Requirements-compliance §: FIXED** (cd88c74) — meta.check_requirements is
  set, the fragment authored, the skill wired, the E2E fixture renders §7b.
  Edge case: `--rerender` over a pre-cd88c74 yaml still does not render §7b
  (compose reads only the yaml meta, no skill-config fallback).
- **All repair/QA loops capped** (max 1+2+3+3), no unbounded loops;
  budget-flag clears present; agent context hygiene defended.
- **Measured clean (CLEAN):** qa_checks all 1.06 s; pregenerate 0.74 s;
  merge 0.38 s; triage 0.05 s; all remaining scripts sub-second.

## Odds and ends

- Dead template pair `templates/fragments/management-summary.md.j2`
  (0 references, includes the dead architecture-assessment path).
- Stale docstring `pregenerate_fragments.py:21` (lists ms-architecture-assessment as
  "pregenerated" — it is LLM-authored).
- §7 unbundling still open: the secarch role authors all 13 subsections in
  ONE dispatch (single stall point, ~5 min); split 2–3 sub-roles per the
  secarch/ms pattern — the gain is stall variance rather than the mean.
- Stage-2 inline-shortcut retry re-dispatches the full renderer (max 2×, worst
  +10 min) — justifiable, low priority.

## Recommended order

1. **P1** (functional bug, 1-line fix + test) — the feature is otherwise dead.
2. **P2** (batch export_pdf — minutes per export).
3. **P8** (`ruff check --fix` + 3 F821 manually — cheap, hygienic).
4. **P7** (CSafeLoader in compose — trivial).
5. **P6** (agent_logger lazy imports — ~1–2 min/run).
6. **P3** (architecture-assessment cleanup — a deliberate bidirectional task).
7. **P4/P5** (structural, verify live first or larger rework).
