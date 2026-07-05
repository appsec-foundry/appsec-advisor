# Refactoring Plan: Maintainability, Quality, Performance

**Status:** Proposal, not implemented
**Created:** 2026-05-12
**Updated:** 2026-05-13 (follow-up) — **Quick wins R2/R3/R6/R10 merged** (background in `bugs.md` / session audit, **not** part of this plan): `compose_threat_model.RenderContext._build_label_index` replaces three linear loops in `lookup_label` (compose +19 LOC), `_PrePass.contract` now actually used — 5 redundant contract loaders removed from `qa_checks` (qa_checks −14 LOC), `check_infobox_completeness` required-set aligned with `sections-contract.yaml` (`license` in, `description` out), `check_toc_closure` builds the lowercase anchor set once up front. Strategy unchanged; pure drift correction of line numbers/LOC in the plan text (see tables below). 2026-05-13 — **M10 added** (`eval_condition` → deterministic pattern resolver) as a Phase D item after a security review: the regex sandbox pattern is not exploitable today, but for an AppSec plugin it is not "obviously correct" and collides with the untrusted-repo direction newly documented in `SECURITY.md`. A trace across all 5 call sites showed: only bare-name bool lookups reach `eval()` today — a 15-LOC pattern resolver replaces `eval()` entirely instead of just taming it via an AST walker. Four YAML fields that look like conditions but are read by no Python code are documented as a follow-up cleanup recommendation. `eval()` entry removed from "Deliberately not in the plan". 2026-05-12 — Semgrep track (C2) dropped, Phase D (tooling/docs/consolidation) added after a verification pass against the current repo state. M5 (`from __future__ import annotations`) dropped — the plan attested itself "semantically empty", zero verifiable benefit. Verification refresh: stale LOC figures updated to HEAD, subheading count corrected on `phase-group-finalization.md` (49 → 51), Open Question 4 answered empirically (phase prompts predominantly human-edited), M1↔A0 sequence clarified as orthogonal with the recommendation "pre- and post-M1 baseline".
**Goals:** Maintainability ↑, quality ↑, performance measurably held, risk low
**Guiding principle:** The plugin should be improvable by humans — structured, not vibe-coded.

---

## Starting point (verified)

### What is good

- **Deterministic render pipeline:** the LLM only writes fragments, the final `threat-model.md` is rendered from `sections-contract.yaml` + `compose_threat_model.py`. A hard gate (`check_inline_shortcut.py`) enforces this.
- **Lazy loading of phase groups:** the orchestrator (`agents/appsec-threat-analyst.md:390, 412, 432`) loads phase-group files only at phase boundaries, plus a fast-path no-op exit for incremental runs.
- **Substring-based drift guards:** `tests/test_dispatch_prompt_cache_order.py` and `test_agent_definitions.py` (23 tests) check frontmatter, marker order, mandatory sections.
- **Test discipline:** 92 test files, 2698 test cases (`pytest --collect-only -q -p no:cacheprovider`), many "promise-keeping" tests against schemas and agent contracts.
- **Structured phase-group files:** `phase-group-finalization.md` has 51 subheadings (46× `###` + 5× `####`) across 2009 lines — not vibe coding, but structured long-form text.

### What hurts

| Pain point | Verified number |
|---|---|
| `compose_threat_model.py` | 6989 LOC, 41+ functions, 7 manifest readers |
| `qa_checks.py` | 5212 LOC, 6+ check categories, shared regex/label-index state |
| `phase-group-finalization.md` | 2009 LOC ≈ 44k tokens |
| `phase-group-architecture.md` | 1557 LOC ≈ 34k tokens |
| `phase-group-threats.md` | 1631 LOC ≈ 33k tokens |
| `appsec-qa-reviewer.md` | 1715 LOC ≈ 43k tokens |
| `appsec-stride-analyzer.md` | 581 LOC ≈ 16k tokens |
| Fragment ↔ producer ↔ schema | Implicit relation across several registries (`compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py`, `sections-contract.yaml`), no dedicated drift test |
| Drift guards | Substring-based, catch no semantic drift |
| STRIDE coverage | LLM-probabilistic, no deterministic ground truth |
| `eval()` with restricted builtins | 2× (`compose_threat_model.py:382`, `qa_checks.py:1114`) — regex prefilter, input plugin-shipped today. Replaced in **M10** by a deterministic pattern resolver; `eval()` leaves the codebase entirely. |

---

## Recommended sequence

```
Core plan (substantive):  A0 (0.5–1d) → A1 (1–1.5d) → A2 (0.5–1d) → B1 pilot (3–4d) → C1 (1d)
Parallel track (Phase D): M1 (1d) → M2 (0.5h) → M3a (15m) → M6 (1h)
                          → M7 (0.5h) → M4 (1–2h) → M8 (1h) → M9 (0.5h) → M3b (15m, later)
```

**Core plan: 6–8 days**, spread across 5–6 PRs.
**Phase D: ~2 days** spread across 8 small PRs, mostly parallel and independent of the core plan.

**Full B1** remains sensible, but only after the pilot and after measurement data from A0. After the verification pass, Semgrep is **removed from the plan entirely** (see "Deliberately not in the plan").

Each phase is valuable on its own. Stopping after Phase A, after the B1 pilot, or after Phase D is possible without prior work being wasted.

---

## Phase A — Foundation + baseline

### A0 — Consolidate the measurement baseline (before any performance claims)

**Effort:** 0.5–1 day
**Risk:** low

**Status (2026-05-29):** `scripts/measure_run.py` + `tests/test_measure_run.py` exist and are green — the consolidator folds `.stage-stats.jsonl`, `verify_run_costs.py --json` (cumulative-safe) and `.hook-events.log` signals into a single `.run-metrics.json`. Verified bugfix: `_read_hook_events` only matched `reason=`, but the real emitter (`agent_logger.py:1684`) writes `stop_reason=` → the stop-reason metric was **always empty** on real logs. Parser extended to `(?:stop_)?reason=`, test fixture switched to the real log format. Capture runbook: `docs/baselines/README.md`. **Open (manual, costs one run each):** actually record the 2-repo baseline and check it in under `docs/baselines/`.

**What:** merge existing telemetry into a reproducible run measurement. This is **not a greenfield parser**: the repo already has `scripts/record_stage_stats.py`, `scripts/verify_run_costs.py`, `scripts/cost_running_total.py`, `.stage-stats.jsonl`, `.hook-events.log`, `SESSION_STOP` and `ASSESSMENT_TOKENS`.

The baseline should capture:
- Tokens per phase (input/output, with cache-hit/miss breakdown)
- Tokens/cost per stage and, where possible, per agent
- Wall time per stage and phase
- Stop reasons (`max_turns`, `unknown`, `end_turn`) and retry/repair hints
- Context-window utilization at peak (e.g. Phase 11)

**Why:** without a baseline we claim effects we cannot prove. All following performance statements need before/after numbers. Especially important: `SESSION_STOP` lines are cumulative; naive summation yields wrong costs. `verify_run_costs.py` already knows these pitfalls.

**Deliverable:**
- `scripts/measure_run.py` or an extension of an existing helper — reads `.stage-stats.jsonl`, `.hook-events.log`, `.agent-run.log` and `verify_run_costs.py --json`, writes `.run-metrics.json`
- `tests/test_measure_run.py` — smoke test against a frozen log sample
- A **baseline measurement** on 2 repos (Juice Shop + one internal use case), checked in under `docs/baselines/`

**Success criteria:** script runs, output stably reproducible, no naive double-counting of cumulative `SESSION_STOP` lines, baseline documentation exists.

**Sequence relative to M1 (Phase D):** A0 and M1 are orthogonal — `ruff format`/lint only touches `scripts/`/`tests/`/`hooks/`, not the agent `.md` files the LLM reads during assessments. M1 changes neither tokens nor cache hits nor wall time measurably. Clean discipline: record the A0 baseline once on pre-M1 HEAD (= today), run it **again** after the M1 merge ("post-M1 baseline"), and run all later comparisons (A2, B1) against the post-M1 variant. If the pre/post difference is negligible (expected), discard the pre-snapshot. If the difference is significant: investigate what M1 unintentionally changed — you want to see that gap early. Cost: one extra assessment run per test repo.

---

### A1 — Fragment registry linter

**Effort:** 1–1.5 days
**Risk:** low

**What:** new script `scripts/check_fragment_registry.py` + CI integration.

**Approach:**

1. Parser for `data/sections-contract.yaml`: extracts all sections with `fragment_type ∈ {data, hybrid, markdown}` and their `fragment:` / `schema:` path.
2. Cross-check:
   - For `data`/`hybrid`: does `schemas/fragments/<id>.schema.json` exist?
   - Do the hardcoded maps agree?
     - `compose_threat_model.py:_SECTION_FRAGMENT_MAP`
     - `compose_threat_model.py:_KNOWN_JSON_FRAGMENT_SCHEMAS`
     - `validate_fragment.py:FRAGMENT_SCHEMAS`
     - `validate_fragment.py:_FRAGMENT_FILENAMES`
     - `qa_checks.py:CONTRACT_SECTION_FRAGMENTS`
   - Does every JSON fragment file have a registry mapping?
   - Conversely: every schema in `schemas/fragments/` is registered and explicable either in the contract or in an optional JSON-fragment map.
3. Add an explicit drift test. The composer comment refers to `tests/test_qa_fragment_map.py`, but this file does not currently exist; either create this test or correct the comment.
4. Only afterwards, optionally add producer detection. AST search for `Path(...) / "<literal>"`, `f".fragments/{...}.json"` etc. is useful, but more prone to false positives than the registry reconciliation.
5. Exit code 1 on drift, clear error message with file+line.
6. Test in `tests/test_fragment_registry.py` or `tests/test_qa_fragment_map.py` that runs the script against the current repo state.
7. CI integration: first as a **warning** in `.github/workflows/`, escalate to fail after 4 weeks.

**Value:**
- **Maintainability:** documents the most important implicit relation in the plugin as executable code.
- **Quality:** drift is caught in the PR, not at runtime at the end customer.
- **Performance:** no direct effect.

**Risks:**
- Producer detection via AST can produce false positives. → allow-list mechanism with a clear comment per entry.
- A CI gate that goes red on legitimate patterns is frustrating. → warning-first strategy.

**Success criteria:** linter runs clean on the current codebase. Artificially inserted drift (schema deleted, fragment path wrong, map entry changed only in `compose_threat_model.py`) is detected.

---

### A2 — Extract manifest readers

**Effort:** 0.5–1 day
**Risk:** low

**What:** `scripts/compose_threat_model.py` lines 1146–1683 (7 `_read_*` functions + helpers) → new module `scripts/_manifest_readers.py`.

**Affected functions:**
- `_read_package_json` (npm)
- `_read_project_manifest` (top-level dispatch)
- `_read_pyproject_toml`
- `_read_cargo_toml`
- `_read_go_mod`
- `_read_pom_xml`
- `_read_gradle`
- `_read_readme_description`
- `_read_readme_tags`
- `_read_license_file`
- `_format_author`, `_derive_homepage`, `_derive_runtime`, `_extract_repo_url`

**Approach:**

1. Before the move: grep for `@lru_cache`, `_CACHE`, `_CONST` at module level within the functions to be moved. If present, move them at the same time.
2. Move functions into the new module, passing `ctx: RenderContext` dependencies through as plain parameters.
3. Cut the API realistically:
   - `read_project_manifest(ctx) -> dict`
   - either additional exports for `format_author`, `read_license_file`, `derive_homepage`, `derive_runtime`, `extract_repo_url`, `read_readme_tags`
   - or a higher-level API `enrich_project_metadata(ctx, project, meta, remote_url) -> dict`, so that `_render_infobox()` no longer needs the private helpers directly.
4. Existing tests in `test_compose_threat_model.py` stay unchanged (they test via the public API). Optional: new unit tests per reader in `test_manifest_readers.py`.
5. **Discipline:** the move PR does **nothing but** move — no refactor, no rename, no logic change. Otherwise it destroys `git blame`.

**Value:**
- **Maintainability:** blueprint for the later section-renderer extraction. `compose_threat_model.py` from 6989 → ~6451 LOC.
- **Quality:** improved test ergonomics (pure functions without a `RenderContext` fixture mock).
- **Performance:** no direct effect.

**Risks:**
- `git blame` churn for 7 functions. Mitigation: move-only PR, `git log --follow` stays functional.
- Merge conflicts on open branches. Mitigation: scan open branches before the merge, wave through quickly.
- Hidden module state. Mitigation: pre-grep (see step 1).
- Too tight a public-API cut. `_render_infobox()` uses several helpers directly; `read_project_manifest(ctx)` alone is not enough without a small adjustment of the API boundary.

**Success criteria:** `compose_threat_model.py` LOC drops by ≥500. All existing tests green. Public API unchanged.

---

## Phase B — Structure the prompts

### B1 — Modularize the phase-group prompts

**Effort:** pilot 3–4 days; full implementation 12–18 days total, in 4 sub-PRs.
**Risk:** medium — prompt restructuring can subtly change LLM behavior.

**What:** split each `agents/phases/phase-group-*.md` into a directory structure:

```
agents/phases/phase-group-finalization/
├── README.md           # Index: when to read what
├── instructions.md     # Procedural steps (small, ~400 LOC)
├── contracts.md        # Output schemas, invariants, validation rules
├── examples.md         # Concrete walkthrough examples (lazy-load on demand)
└── edge-cases.md       # Case distinctions, "what to do when X" (lazy-load on demand)
```

Backwards compatibility: `agents/phases/phase-group-finalization.md` stays as a shim that points to the directory (or inlines the most important files).

**Order of the sub-PRs:**

1. **B1.1 — Pilot: `phase-group-architecture`** (3–4 days). Medium-sized phase group, no critical path. Proves out the pattern. Allow stop/pivot after this PR.
2. **B1.2 — `phase-group-threats`** (3–4 days). Touches STRIDE dispatch, the most important phase.
3. **B1.3 — `phase-group-finalization`** (4–6 days). Largest phase group, most critical output (fragment authoring, changelog, SARIF).
4. **B1.4 — `phase-group-recon`** (1–2 days). Smallest, least effort. Optional, since it is only 4k tokens anyway.

**Approach per sub-PR:**

1. **Before restructuring:** freeze golden output on 2 repos (Juice Shop, internal use case). Check in under `tests/golden/<phase-group>/`.
2. **Split:** use subheadings as natural cut lines (49 in finalization!). Content assignment:
   - **instructions.md** — everything under `### Phase X.Y` with procedural verbs
   - **contracts.md** — all `Schema:`, `Fragment must encode:`, `Output format:` blocks
   - **examples.md** — all `#### <concrete-example>` sub-subheadings (e.g. `7.3.1 Password Login Flow`)
   - **edge-cases.md** — all `**When X**`, `**If Y**`, `Fallback:` sections
3. **Orchestrator adjustment:** extend the `appsec-threat-analyst.md` phase-group read calls with optional sub-file reads. For the pilot, be conservative first: the shim reads the same content as before, but from several files. Only after the golden diff and the A0 measurement, selectively reduce to `instructions.md` + `contracts.md`. Load `examples.md` / `edge-cases.md` conditionally or just-in-time on ambiguity.
4. **Adjust drift guards:** update `test_dispatch_prompt_cache_order.py` and `test_agent_definitions.py` paths.
5. **After restructuring:** re-run on the 2 repos. Diff against the golden output. **Acceptance criterion:** diff is only cosmetic (whitespace, section IDs if new, line numbers). Substantive diffs in threats, findings, mitigations are **blockers**.

**Value:**
- **Maintainability (main gain):** a person who wants to modify Phase 11 reads 400 LOC of instructions instead of 2009 LOC of mixed content. Examples and edge cases are separately viewable.
- **Quality:** edge cases become visible instead of hidden in prose paragraphs. Clearer audit trail.
- **Performance (secondary, not guaranteed):** possible context-window headroom if subfiles are truly loaded selectively. The gain is probably smaller than a pure file-size calculation suggests, because Stage 2 is now handled by the lean `agents/appsec-threat-renderer.md` and no longer blindly needs the entire finalization prompt. Only claim token savings after the A0 measurement.

**Risks:**
- **LLM behavior drift:** mitigated by golden-output diffing (see above). On a diff: revert, try a different split.
- **Loader complexity in the orchestrator:** mitigated by a conservative default (read all sub-files except `examples.md`/`edge-cases.md`).
- **Long restructuring phase:** 4 sub-PRs over several weeks. Mitigated by a clear target architecture in an issue description that all sub-PRs reference.
- **Overestimated performance ROI:** mitigated by pilot + A0 measurement. If the active Stage-2 context barely shrinks, assess B1 as pure maintainability work and do not sell it as a cost lever.

**Success criteria:**
- Per phase group: golden output stays substantively identical.
- LOC volume per file ≤ 800 after the split.
- Context-window utilization in Phase 11 drops measurably (see A0 baseline).

---

### B2 — Structure `appsec-qa-reviewer.md` (deferred)

**Effort:** 2 days
**Risk:** medium

**Status:** **removed** from the current sequence. Rationale:
- QA reviewer runs only 1–2× per run (instead of 30+ turns like the orchestrator in Phase 11)
- Context-window pressure clearly lower
- Maintainability gain exists, but lower ROI than the phase-group restructuring

**Revisit when:**
- B1 successfully completed and the pattern proven
- QA-reviewer repair loops exhaust budget more often (monitorable via A0 metrics)

---

## Phase C — Quality and performance layer

### C1 — Structural drift guards

**Effort:** 1 day
**Risk:** low

**What:** extend the existing substring asserts with:

1. **Token-count bounds per prompt file.** Via AST or heuristic (chars/4). Failure: "Prompt X grew from N to M tokens (>15% increase) — review intended?"
2. **Required-section presence instead of only required strings.** Example: `instructions.md` MUST have a `## Phase N` heading for every phase step declared in `sections-contract.yaml`.
3. **Optional (deferred):** LLM-as-judge test (Sonnet reads prompt + 5 structural questions). Gated, runs only in nightly CI. Only sensible after B1.

**Value:**
- **Maintainability:** regression protection for the investment from B1.
- **Quality:** catches subtle prompt degradations (token bloat, deleted sections).
- **Performance:** token bounds prevent silent bloat regressions.

**Risks:**
- Token-count bounds too tight → false positives on legitimate extensions. Mitigation: 20% tolerance per file, override possible via a comment in the test.

**Success criteria:** artificially inserted bloat (+30% tokens) or deleted phase sections trigger a test failure.

---

---

## Phase D — Cross-cutting measures (tooling, docs, consolidation)

**Total effort:** ~2 days spread across 8 small PRs
**Risk:** low to none

These measures are not phase-gated like A/B/C. They can mostly run in parallel and independently. All findings verified against the repo state on 2026-05-12.

### Verified gaps (findings)

| Finding | Verified reality |
|---|---|
| No linter / formatter | No `pyproject.toml`, no `ruff.toml`, no `.editorconfig`. 47k LOC Python, 67 scripts without static analysis. |
| No pytest config | No `pytest.ini`, no `[tool.pytest.ini_options]`. Only standard markers (`parametrize`, `skipif`) in use. |
| Coverage not in CI | `pytest-cov>=5` is in `tests/requirements-test.txt`, but CI runs `pytest` without `--cov` → no baseline value available. |
| 5 different YAML loaders | `migrate_v3_to_v4`, `triage_compute_ranking`, `architect_structural_checks`, `slice_taxonomy`, `render_completion_summary` each with different error semantics (raise vs. None vs. `{}` vs. caller-default vs. dict-type-check + import-fallback). |
| Fragment-registry paths documented centrally nowhere | 4 maps scattered across 3 files. `AGENTS.md` Rule 4 has the workflow, but not the concrete paths. |
| No `docs/internal/runbooks/adding-a-section.md` doc | Walkthrough for new sections is missing entirely. |
| `CONTRIBUTING.md` (62 lines) without a code-style expectation | No mention of lint/type-hints/pre-commit. |

---

### M1 — Introduce `pyproject.toml` + ruff

**Effort:** ~1 day (incl. cleanup PR)
**Risk:** low

**What:** new `pyproject.toml` with ruff config, one-shot cleanup PR, CI step before pytest.

**Config anchor:**
```toml
[tool.ruff]
line-length = 120
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.ruff.format]
quote-style = "double"
```

**Verified basis:**
- `line-length = 120` → only **56 lines >120 characters** in 47k LOC.
- `quote-style = "double"` matches **17283 of 18024** strings (96%).
- `target-version = "py310"` matches the CI matrix (Python 3.10–3.12).

**Approach:**
1. Create `pyproject.toml` (also home for M2).
2. One-shot cleanup PR: `ruff check --fix scripts/ tests/ hooks/` + `ruff format scripts/ tests/ hooks/`. **Review the diff manually**, do not merge blindly — especially `UP` auto-fixes (e.g. `Optional[X]` → `X | None`).
3. CI step in `.github/workflows/tests.yml` **before** pytest:
   ```yaml
   - name: Lint (ruff)
     run: ruff check scripts/ tests/ hooks/
   - name: Format check (ruff)
     run: ruff format --check scripts/ tests/ hooks/
   ```

**Value:**
- **Maintainability (main gain):** noticeable on every PR. Currently a 47k-LOC codebase has no static analysis at all.
- **Quality:** `F`/`B` catch real bugs (unused imports, mutable default args, suspicious patterns).
- **Performance:** no effect.

**Risks:**
- Auto-fix can subtly change semantics (rare, but the `UP` rule modernizes idioms). Mitigation: split the cleanup PR into a small, readable diff — one rule family per commit.

**Success criteria:** `ruff check` clean, CI-gated, pull requests go red on violations.

---

### M2 — Tighten the pytest configuration

**Effort:** 30 min
**Risk:** low

**What:** in the `pyproject.toml` from M1:
```toml
[tool.pytest.ini_options]
addopts = "--strict-markers --strict-config"
filterwarnings = ["error::DeprecationWarning:scripts"]
```

**Verified basis:** tests use only standard markers (`parametrize`, `skipif`) → `--strict-markers` breaks nothing. `filterwarnings` is scoped to `scripts/` → no library warnings.

**Risks:** latent DeprecationWarnings in our own code could turn CI red. Mitigation: run `pytest -W error::DeprecationWarning:scripts` locally first.

---

### M3 — Coverage in two steps

**Effort:** 15 min each (step A now, step B after ≥4 weeks / 10 green runs)
**Risk:** none (step A), low (step B)

**What:**
- **Step A:** extend CI with `--cov=scripts --cov-report=term-missing`. **No** fail-under gate.
- **Step B:** after enough data, set the lowest measured value as `--cov-fail-under=N` — as a floor, not aspirational.

**Verified basis:** `pytest-cov>=5` is already in `tests/requirements-test.txt`, but CI does not invoke it → no baseline value available. The 2-step approach resolves the chicken-and-egg problem.

---

### M4 — Consolidate YAML loaders

**Effort:** 1–2 h spread across 5 mini-PRs
**Risk:** low per PR

**What:** new module `scripts/_yaml_io.py` (separate from `_atomic_io.py` — read/write separation):

```python
_RAISE = object()
def load_yaml(path: Path, *, default=_RAISE):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if default is _RAISE: raise
        return default
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        if default is _RAISE: raise
        return default
    return data
```

**Verified call-site migration** (5 files, each its own semantics decision):

| File | Current semantics | New call |
|---|---|---|
| `migrate_v3_to_v4.py` | raise on error | `load_yaml(p)` |
| `triage_compute_ranking.py` | caller-default | `load_yaml(path, default=default)` |
| `architect_structural_checks.py` | None on error | `load_yaml(path, default=None)` |
| `slice_taxonomy.py` | `{}` when empty, str path | `load_yaml(Path(path), default={})` |
| `render_completion_summary.py` | `{}` + dict-type-check + import-fallback | `load_yaml(path, default={})` + isinstance outside |

**Risks:** `render_completion_summary._load_yaml` has a defensive `try: import yaml` with a `{}` fallback. Before migrating, clarify whether `yaml` is really a mandatory dependency everywhere (hint: in `scripts/requirements.txt`). If historically optional: keep the local wrapper there, still use the helper for the other 4.

**Value:** a single source of truth for default behavior. Prevents the next silent divergence.

---

### M6 — Module map in the two monoliths

**Effort:** 1 h
**Risk:** none

**What:** extend the existing module docstrings in `compose_threat_model.py` and `qa_checks.py` with a line-number index, e.g.:

```
Module map:
    L60–131    Exceptions & RenderContext
    L132–281   Helper utilities
    L282–367   eval_condition (sandboxed)
    L368–577   Jinja environment
    ...
    L1146–1683 Manifest readers (Phase A2 extraction target)
    ...
```

**Verified basis:** both files already have ~30 `# -----` section-divider comments each. Only the navigable overview at the top is missing.

**Risks:** line numbers age. Mitigation: name coarse ranges ("L1100–1700") instead of each function individually. Optional as a follow-up step: a small generator script.

---

### M7 — Fragment-registry paths in `schema-invariants.md` (§4f)

**Effort:** 30 min
**Risk:** none

**What:** append a new section §4f to `docs/internal/contracts/schema-invariants.md` that lists all 4 registry maps with file + line. In `AGENTS.md` Rule 4, reference §4f in a sub-bullet.

**Verified paths:**
- `_SECTION_FRAGMENT_MAP` — `scripts/compose_threat_model.py:89`
- `_KNOWN_JSON_FRAGMENT_SCHEMAS` — `scripts/compose_threat_model.py:106`
- `FRAGMENT_SCHEMAS` — `scripts/validate_fragment.py:39`
- `_FRAGMENT_FILENAMES` — `scripts/validate_fragment.py:58`
- `CONTRACT_SECTION_FRAGMENTS` — `scripts/qa_checks.py:1131`

**Dependency:** if A1 (registry linter) is implemented, §4f should reference it. If A1 is dropped: keep §4f as a purely descriptive map without mentioning the linter.

---

### M10 — `eval_condition` → deterministic pattern resolver (remove eval())

**Effort:** 1–2 h
**Risk:** none

**What:** replace both `eval()` calls (`compose_threat_model.py:382`, `qa_checks.py:1114`) with a 15-LOC pattern resolver that accepts only three explicit patterns. No more `eval()` in the codebase.

Currently only a regex prefilter (`_COND_SAFE_TOKENS`) protects it — that lets through e.g. `().__class__.__bases__[0].__subclasses__()`, because all characters belong to the whitelist. No real exploit today (conditions come from `data/sections-contract.yaml`, plugin-shipped), but:

- The code is not obviously correct: any reviewer pauses at `eval(expr, {"__builtins__": {}}, …)` with a regex sandbox.
- `SECURITY.md` currently documents "untrusted-repo mode" as planned — this spot would be an open footgun there if conditions ever become user-configurable.

**Actually reachable conditions** (trace across all 5 call sites, verified against `data/sections-contract.yaml` HEAD):

Exclusively bare-name bool lookups from `document.order[].condition`:
- `check_requirements`, `compose_warned`, `render_security_architecture`, `triage_has_warnings`
- `run_warned` (still commented out in the YAML, plan-relevant for M2.15)

The call site `compose_threat_model.py:1800` via `sub_sections[].conditional` is unreachable today because `threat_register.sub_sections: []` is empty (`sections-contract.yaml:1033`). The code comment there speculates about a future `low_category_count > 0` — the migration path is a derived bool in the `eval_context` (`low_category_present = low_category_count > 0`), not numeric arithmetic in the YAML.

**Three explicitly supported patterns** (cover the patterns *documented* in the YAML, not just those actively eval'd today):

1. Bare name → `bool(env.get(name))`
2. `not <name>` → `not bool(env.get(name))`
3. `<name> in [<items>]` / `<name> not in [<items>]` → membership, bare items become implicit string literals

Numeric comparisons (`<`, `>`, `==`), `and`/`or` combos and function calls are deliberately **not** supported. Whoever needs that must place the derived bool in `eval_context` — more self-documenting and easier to test than YAML-inline arithmetic.

**Deliverable:**

- New module `scripts/_safe_cond.py` with `resolve_condition(expr: str, env: dict) -> bool` (~15 LOC, no `eval`, no `compile`, no `ast`). Unknown patterns raise `ContractError`.
- `compose_threat_model.py:364-384` calls `_safe_cond.resolve_condition` and keeps the `ContractError` wrapper for the existing error semantics. The `eval_condition()` function stays as a thin adapter so the 4 call sites remain unchanged.
- `qa_checks.py:1106-1116` calls the same helper. The previous duplicate code goes away.
- `tests/test_safe_cond.py` with:
  - **Positive cases**: all bare-name conditions that actually occur in `sections-contract.yaml` yield correct bool values against a realistic `env`. Plus the patterns documented in the YAML `not X` and `X in [a, b]` (even though they do not currently run through `eval_condition` — future-proofing).
  - **Adversarial cases**: `().__class__.__bases__[0].__subclasses__()`, `__import__('os').system('id')`, `x.upper()`, `[x for x in range(10)]`, `lambda: 1`, `1+1` — all must raise `ContractError`.
  - **Edge cases**: empty string, whitespace only, syntax error, unknown name (handled today as `None` → stays that way).

**Risks:** behavior drift on conditions that today's `eval()` sandbox accidentally interprets differently. Mitigation: positive cases against the conditions currently occurring in the repo, drift becomes visible.

**Verified basis:**
- 4 call sites in `compose_threat_model.py`: lines 1728, 1800, 6056, 6061 (1800 unreachable today due to empty `sub_sections`).
- 1 call site in `qa_checks.py`: line 1035 (via `_safe_eval_cond`).
- `eval_context` variable inventory: `compose_threat_model.py:5969-6006`.
- Current regex whitelist: `compose_threat_model.py:361`, `qa_checks.py:1110`.
- Full conditions list (HEAD): `grep -hE "condition: " data/sections-contract.yaml` → 8 unique strings, of which **only** `check_requirements`, `compose_warned`, `render_security_architecture`, `triage_has_warnings` reach `eval_condition`.

**Recommended follow-up cleanup (optional side PR, not part of M10):** remove four YAML fields that look like conditions but are not reached by `eval_condition`:
- `intro_conditional.condition: "verdict_severity in [yellow, red]"` (`sections-contract.yaml:463`) — the same logic is redundantly hardcoded in `compose_threat_model.py:3424`; the YAML field is not read.
- `required_patterns_condition: "not skip_attack_walkthroughs"` (`sections-contract.yaml:657`) — orphan field, no Python consumer findable (`grep -r` in the repo, HEAD).
- `per_critical_subsection_condition: "not skip_attack_walkthroughs"` (`sections-contract.yaml:659`) — same situation as the previous one.
- `conditional: "len(changelog) > 0"` on the `changelog` section (`sections-contract.yaml:240`) — the section is pre-skipped in `compose_threat_model.py:1726` via `if sid in ("infobox", "changelog", "toc"): continue`; the renderer has its own `if not changelog: return ""` path.

These fields give the impression that the plugin can evaluate operator comparisons and `in [list]` patterns, even though in today's code reality they are dead. The cleanup makes the contract file self-documenting and fits the strict M10 grammar.

**Dependency:** none. Can merge in parallel with any other Phase D item.

---

### M8 — `docs/internal/runbooks/adding-a-section.md`

**Effort:** 1 h
**Risk:** none

**What:** new file with a step-by-step walkthrough for a new section in `threat-model.md`:
1. Declaration in `data/sections-contract.yaml`.
2. If `fragment_type ∈ {data, hybrid}`: schema in `schemas/fragments/<id>.schema.json` + all 4 registries (link to §4f from M7).
3. Renderer function in `compose_threat_model.py`.
4. Test in `tests/test_compose_threat_model.py`.
5. Anchor linkifier in `qa_checks.py:linkify_anchors`, if a new ID class — see `schema-invariants.md` §4a.

**Risks:** docs age with the code. Mitigation: keep it short, above all name the paths; details stay in the sources.

---

### M9 — Extend `CONTRIBUTING.md`

**Effort:** 30 min
**Risk:** none, but sequence-bound

**What:** three new sections:
- `## Code style` — points to `ruff check` / `ruff format` (M1)
- `## Adding components` — links M7 (`schema-invariants.md` §4f) and M8 (`adding-a-section.md`)
- `## Type hints` — "New public functions take type hints; mypy is not yet enforced"

**Dependency:** must **not** merge before M1+M7+M8, otherwise the document holds dead references.

---

### Phase D order

| # | Measure | Effort | Dependency |
|---|---|---|---|
| 1 | M1 ruff + pyproject.toml | 1 day | — |
| 2 | M2 pytest strict | 30 min | M1 (home) |
| 3 | M3a coverage in CI without gate | 15 min | — |
| 4 | M6 module map | 1 h | — |
| 5 | M7 §4f registry paths | 30 min | optional A1 reference |
| 6 | M10 `eval_condition` → pattern resolver | 1–2 h | — |
| 7 | M4 YAML loader (5 mini-PRs) | 1–2 h | — |
| 8 | M8 adding-a-section.md | 1 h | M7 |
| 9 | M9 CONTRIBUTING.md | 30 min | M1, M7, M8 |
| 10 | M3b coverage floor | 15 min | M3a + ≥4 weeks |

**Total: ~2 days + 1–2 h** without the wait for M3b. The largest single item is M1 (~50% of the phase).

---

## Deliberately not in the plan

| Item | Rationale |
|---|---|
| `from __future__ import annotations` across the board | Formerly M5. The 5 affected scripts (`agent_logger.py`, `harvest-requirements.py`, `security_steering.py`, `slice_taxonomy.py`, `mock-server.py`) use no `get_type_hints` / Pydantic / `@dataclass` — annotation lazification is semantically empty. Consistency theater without verifiable benefit. If a future script touch actually introduces introspection, add it locally there. |
| Split `qa_checks.py` | High coupling (shared regex/label-index state), high refactoring risk. Tackle only after Phase B, once you are in the groove. |
| Semgrep (any variant) | Removed from the plan entirely. A pinned ruleset loses the Semgrep value (current rules); advisory-only mode is unstable under pressure; ownership for ruleset maintenance is unclear; "auditability" has cheaper solutions (structured evidence fields in the LLM output). |
| Prompts → YAML/code | Radical, untested. Evaluate only after B1 with a prototype. |
| Semantic LLM-as-judge drift tests | Cost-intensive. Only sensible after B1. |
| Introduce `mypy` | 47k LOC without prior type discipline → weeks of `Any` cleanup. Not low-risk. If at all: prototype on a small module after Phase D. |
| Pre-commit hooks | Only sensible once ruff is in CI (M1). Otherwise local hooks fight against drifting config. Phase 2 of tooling. |
| Pull scripts into a package (`scripts/__init__.py`) | Import-path migration for 67 files + 92 test files. High churn risk, low daily benefit. |
| Rename dash scripts (`harvest-requirements.py`, `mock-server.py`) | Not importable as a Python module, but renaming would break callers. Code smell, non-blocker. |

---

## Expected effects

| Metric | Baseline (A0 measures) | After plan | Source of the gain |
|---|---|---|---|
| LOC in the largest file | 6989 (`compose_threat_model.py`) | ~6451 | A2 |
| LOC in the largest prompt file | 2009 (`phase-group-finalization.md`) | ≤800 per sub-file | B1 |
| Tokens in Phase 11 | ~44k | ~25–30k active context | B1 |
| Context-window headroom | decreasing | +30–40k tokens | B1 |
| Token cost per run | Baseline | **do not commit in advance**; expected to be low single-digit % without further STRIDE changes | B1, if selective loading actually takes hold |
| Wall time per run | Baseline | **do not commit in advance**; just measure | A0 + B1 |
| Drift detection in CI | Substring | Structural + token bounds | C1 |
| Static analysis | not present | ruff lint + format as a CI gate | M1 |
| Coverage visibility | not measured in CI | `--cov` in CI, floor value after 4 weeks | M3 |
| Registry-drift visibility | implicit across 4 maps | documented in §4f + machine-checkable via A1 | M7 + A1 |
| Onboarding docs | Workflow without concrete paths | `adding-a-section.md` + extended `CONTRIBUTING.md` | M8 + M9 |

**Important:** performance effects are hypotheses. A0 measures them. If reality deviates from the estimate: document it and adjust the plan, do not ignore it.

---

## Maintainability scale (verified)

| State | Scale 1–10 |
|---|---|
| Today | ~5.5 |
| After Phase D (tooling/docs/consolidation) | ~6–6.5 |
| After Phase D + Phase A (A0+A1+A2) | ~6.5–7 |
| After Phase D + B1 | ~7.5 |
| After Phase D + B1 + C1 | ~7.5–8 |

Delta: ~2–2.5 points across the full plan. The biggest single jump comes not from B1, but from the interplay of **M1 (lint gate) + A1 (registry linter) + M7 (registry docs)** — after that the two most common silent defect sources (style drift, registry drift) are machine-gated.

The scale numbers are ballpark figures and should not be over-interpreted.

---

## Open questions before starting

1. **Are golden-output tests politically acceptable?** B1 depends on it. If test-run costs are a problem, there are alternative verification strategies (structural-level diff instead of full output).
2. **Which two repos are the "canonical" test cases?** Juice Shop is obvious, the second one must be chosen — ideally a repo with a different profile (e.g. Python instead of JS, microservices instead of a monolith).
3. **Should B2 (QA reviewer) ever be pulled in?** If repair loops exhaust budget in practice, yes. Otherwise defer indefinitely.
4. ~~**Who edits phase prompts in practice — humans or primarily Claude?**~~ **Answered 2026-05-12.** Git history for `agents/phases/phase-group-*.md`: one author (Matthias Rohr), `Co-Authored-By: Claude` in 5 of ~40 commits (all from recent M3.4 sprints with substantial logic refactors). Commit-size profile: mostly 1–100 LOC, occasionally 100–200 LOC. Ratio roughly ~85% human / ~15% Claude-assisted. → **B1 maintainability ROI confirmed**: the argument "humans read 400 LOC more easily than 2009 LOC" holds here; B1 is releasable as a maintainability investment (still only claim the performance effect after the A0 measurement).

---

## Sources (verified during plan creation and update)

**Core plan (A/B/C):**
- Lazy-load mechanism: `agents/appsec-threat-analyst.md:202, 245, 388-432`
- Drift-guard style: `tests/test_dispatch_prompt_cache_order.py` (substring asserts), `tests/test_agent_definitions.py` (frontmatter validation, 23 tests)
- Phase-group structure: `agents/phases/phase-group-finalization.md` (51 subheadings: 10× `##` + 46× `###` + 5× `####`; 2009 LOC)
- Budget-exhaustion incident: `tests/test_agent_definitions.py:24-28` (comment on the 75→120-turn increase)
- Fragment-registry gap: `data/sections-contract.yaml` (11 fragments declared) vs. `schemas/fragments/` (7 schemas) — the difference is legitimate due to `fragment_type: markdown`/`computed`, but **no** automatic cross-check is present.
- Fragment-registry reality: `compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py` and `sections-contract.yaml` contain several overlapping maps. `compose_threat_model.py:84` refers in a comment to `tests/test_qa_fragment_map.py`, which does not currently exist.
- Stage-2 renderer: `agents/appsec-threat-renderer.md` is already lean and does not load the whole finalization prompt; B1 is therefore primarily maintainability, not guaranteed performance.
- Measurement paths: `record_stage_stats.py`, `verify_run_costs.py`, `cost_running_total.py`, `.stage-stats.jsonl`, `.hook-events.log`, `SESSION_STOP`, `ASSESSMENT_TOKENS`.
- `eval()` sites: `scripts/compose_threat_model.py:382`, `scripts/qa_checks.py:1114`
- Monolith sizes: measured via `wc -l` — `compose_threat_model.py` 6989, `qa_checks.py` 5212, `validate_fragment.py` 317
- Token estimates: bytes/4 as an approximation

**Phase D (tooling/docs/consolidation):**
- No linter config: existence check over `pyproject.toml`, `ruff.toml`, `.ruff.toml`, `setup.cfg`, `.editorconfig` — all missing.
- Quote style: `grep` over `scripts/*.py` yields 17283 double-quoted vs. 741 single-quoted strings.
- Line lengths: `awk 'length>120'` → 56 lines, `length>100` → 288 lines in 47k LOC `scripts/`.
- pytest markers: only `parametrize` and `skipif` from `grep "@pytest.mark\." tests/`.
- pytest-cov availability: `tests/requirements-test.txt` contains `pytest-cov>=5.0`. CI workflow `.github/workflows/tests.yml` calls `pytest tests/ -v --tb=short` without `--cov`.
- YAML-loader inventory: 5 hits for `^def _?load_yaml\b` in `scripts/`, each with a different signature and error semantics.
- Registry paths (`M7`): grep-verified on `_SECTION_FRAGMENT_MAP` (compose:89), `_KNOWN_JSON_FRAGMENT_SCHEMAS` (compose:106), `FRAGMENT_SCHEMAS` (validate_fragment:39), `_FRAGMENT_FILENAMES` (validate_fragment:58), `CONTRACT_SECTION_FRAGMENTS` (qa_checks:1131).
- Doc gap `adding-a-section.md`: `find docs -iname "*adding*"` → no hits.
- `CONTRIBUTING.md` content: 62 lines, sections "Commands", "Repository layout", "Agent definition format", "Reporting security issues" — no code-style expectation.
- `AGENTS.md` Rule 4 covers the abstract workflow (`schema → producer → consumer → validation → tests`), but not the concrete registry paths.

---

**This plan is a proposal. Before implementation: discussion + prioritization in the team. In particular, clarify the still-open Questions 1–3 (Question 4 has been answered since 2026-05-12).**
