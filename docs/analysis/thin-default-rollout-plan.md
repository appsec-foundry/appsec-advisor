# Rollout Plan: Thin/Compact Orchestrator as Default

**Status:** verified against the code (2026-07-03), not yet implemented.
**Goal:** Switch the compact runtime (`SKILL-full-runtime.md`, via `orchestration_controller.py`) from **opt-in** (`APPSEC_THIN_ORCHESTRATOR=1`) to **default with opt-out** (`=0`) — but only if parity is proven.

**Execution:** new branch off `dev` (not `main`/`dev` directly), targeted test suite + `make check`, **stop before push/merge** → summary + diff. Read `AGENTS.md` before non-trivial changes (contract/drift rules). Working directory: `/home/mrohr/appsec-advisor`.

---

## Phase 1 — Verify headless completion *(first)*

Commit `d57d5a3` (2026-07-03) added a deterministic compose backstop `_compose_if_ready()` in `scripts/orchestration_controller.py`: when render fragments are present (`ms-verdict.json` + `security-architecture.md`) but `threat-model.md` is missing, it composes deterministically (pregenerate → `compose_threat_model.py --strict` → `apply_prose_fixes` → `qa_checks autofix`). Invoked via the finalize `next` call (mandatory in `SKILL-full-runtime.md §6` before every completion summary).

**Open verification task:** Does `_compose_if_ready` also fire in the headless **bg-ceiling PROCESS-KILL** case (Claude Code terminates the `-p` process at `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=600s`), or **only** when the orchestrator still gets a finalize turn (turn budget / skipped step)?
- **If not covered:** in `scripts/run-headless.sh` export `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` **or** `APPSEC_PARALLEL_RENDER=0` for headless, and make headless **fail-closed** (exit≠0 if `threat-model.md` is missing — currently it wrongly reports `✓ completed` / exit 0).

## Phase 0 — Prove parity *(hard gate, no merge code)*

Controlled A/B: **thin vs legacy, same model, repo `/home/mrohr/juice-shop`, same depth**, 2–3 runs each (variance baseline). Compare YAML.

Already ~parity (comparison thin `docs/security-thin` vs baseline `docs/security`):
- Threats 53 vs 55, mitigations 53 vs 55, components 11 vs 10, attack surface **107=107**, STRIDE all 6 categories comparable, LLM/AI 5=5, 0 threats without evidence/mitigation link.

**The one open point — severity drift:** thin **C24/H25/M4** vs baseline **C17/H23/M15**. Thin skews more Critical. Probably run/model variance (thin subagents ran `sonnet-4-6`), NOT the orchestrator (it doesn't touch the triage logic). **A/B has to settle this.**

**Gate:** If the A/B shows a real thin-caused severity regression → **do NOT flip**, report findings, stop.

## Phase 2 — Flip the gate *(only if Phase 0 holds; ~10 lines in 4 places)*

1. `scripts/orchestration_controller.py:238` — gate `APPSEC_THIN_ORCHESTRATOR == "1"` → **`!= "0"`** (opt-in → opt-out).
2. `scripts/orchestration_controller.py:260,262` — update the `route()` reason strings.
3. `skills/create-threat-model/SKILL.md:68` — docs "only with `=1`" → "**Default; opt-out via `=0`**".
4. `skills/create-threat-model/SKILL-impl.md:579` — analogous docs adjustment.

**Keep:** all special-mode exclusions (`resume`/`dry-run`/`rerender`/`max_cost`/`max_wall`/`LIVE_PHASE`) still route to legacy. `APPSEC_THIN_ORCHESTRATOR=0` remains a permanent escape hatch.

## Phase 3 — Tests + drift

- `tests/test_orchestration_controller.py`: opt-in → opt-out assertions (default=thin, `=0`→legacy, special modes→legacy). Keep the new `test_compose_if_ready_*` test.
- Changelog entry; `make check` + targeted subset (CONTRIBUTING.md).

## Phase 4 — Safe rollout

Keep the escape hatch; optional canary phase before the opt-out note disappears from the docs.

---

**Context references (as of 2026-07-03):**
- Thin prompt `SKILL-full-runtime.md` = 263 lines vs legacy `SKILL-impl.md` = 4441 lines (~17× smaller → less cache_read/turn = the cost lever).
- Router logic: `orchestration_controller.py:_runtime_for()` (`:236-245`) + `route()` (`:250-269`).
- Only 2 commits have ever touched the thin files (most recent `d57d5a3`) → beta, still hardening.
