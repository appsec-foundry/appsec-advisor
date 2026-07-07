# Plan: Per-Agent Model Routing Controls + Session-Model Transparency

Date: 2026-07-04 · Status: proposed, not started · Origin: Sonnet-5 vs Sonnet-4.6 A/B on juice-shop

## Context

An A/B compared a Sonnet-5 juice-shop scan (`scans2/juice-shop/standard9`) vs a Sonnet-4.6
scan (`standard6`). Findings drove this plan. The pipeline routes models per role; we want to
(a) let the user route each value-agent to a specific model **version**, and (b) make the
effective routing **visible** — especially warn when a scan silently inherits a Sonnet-4.6 session.

## Key facts the executor needs (verified this session)

**Model routing today** (`scripts/resolve_config.py`):
- `MODEL_MATRIX` pins **stride / triage / merger**. Under `sonnet-economy` (default for quick/standard)
  they are pinned to explicit `claude-sonnet-4-6` (a 2026-07-04 uncommitted change — see Prerequisite).
- `EXTENDED_MODEL_MATRIX` routes context_resolver/recon_scanner/config_scanner → `haiku`;
  qa_routine → haiku (sonnet at thorough); **qa_content → `SONNET` (alias → session model)**;
  **orchestrator → `SONNET` (alias)**.
- Per-agent env overrides exist for stride/triage/merger (`APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL`)
  and the extended agents (`APPSEC_QA_CONTENT_MODEL`, `APPSEC_ORCHESTRATOR_MODEL`, etc.).
- The alias `"sonnet"` resolves to the **session model** (proved empirically: standard6 with a 4.6
  session logged ONLY `claude-sonnet-4-6`, no Sonnet-5 anywhere; standard9 logged Sonnet 5).
- **Orchestrator = the CC session/main-loop model.** `orchestrator_model` in the plugin is
  **"informational only"** (SKILL-impl.md:3119) — it does NOT switch the live loop; a running
  process can't change its own model. Pinning the orchestrator = a CC-level setting (`--model` /
  `settings.json "model"`), not a plugin knob.
- **Renderer has NO model knob** — no `renderer_model`, no `APPSEC_RENDERER_MODEL`; it follows the
  frontmatter `model: sonnet` alias → session. Dispatched (default) as TWO parallel
  `appsec-threat-renderer` calls (§7 ‖ MS), SKILL-impl.md ~2726.
- **Abuse-verifier is hardcoded** `MODEL_ID=sonnet` in the Stage-1c dispatch — not config-pinnable.

**Where Sonnet 5 pays off vs 4.6** (from the A/B):
- Merger (dedup: 0 vs 8 file:line collisions), Triage (calibration: 10 vs 15 defensible Crit),
  Renderer/MS (outcome-first CISO framing) → Sonnet 5 measurably better.
- STRIDE discovery → Sonnet 5 WORSE (dropped path-traversal, SSRF sink, prompt injection; folded LLM
  chatbot). 4.6 = better recall AND cheaper → win/win, keep on 4.6.
- qa_content, orchestrator → no observed Sonnet-5 delta.
- Abuse-verifier → 4.6 reintroduces "inconclusive" verdicts (standard6 punted AC-T-002/003).

**Cost reality** (real numbers, `juice-shop/docs/security` Sonnet-5 run):
- Total ≈ **$80**, driven by **~179.5M cache-read** (not the 1.94M active tokens). The dominant
  cost sits in the long-running main analysis session, which follows the **session model**.
- Therefore the BIG saving lever is running the **session on 4.6** (standard6 ≈ half cost). Per-agent
  4.6 pins are second-order trims; per-agent 5-pins are quality **buy-back**, not savings.

**Active-token split (this run):** Threat Analysis & Triage 65% (1.26M) · Report Rendering 17% (331k)
· Abuse Case Verification 15% (294k) · QA Review 3% (60k, ran on haiku).

**Session-model detection (verified feasible):** no model env var is exposed to skill Bash, but the
CC transcript at `~/.claude/projects/*/<CLAUDE_CODE_SESSION_ID>.jsonl` records the exact model id per
assistant message (`.message.model` / `.model`). Reading the LAST assistant message gives the host
session model. Must be fail-safe (internal artifact; silent-skip on miss, never block the scan).

## Plan (grouped, prioritized)

### A — Transparency & session detection (build first; high value, low risk, independent)
1. `scripts/detect_session_model.py` — glob `~/.claude/projects/*/<sid>.jsonl`, return last assistant
   model id; always exit 0; empty on miss.
2. Explicit **warning at skill start** (Configuration Resolution phase) when the detected session model
   is a Sonnet-4.6 id.
3. **Effective per-agent routing table** in the Configuration Summary — real session version + pinned
   agents (replaces the "informational" placeholder).
4. **Drift fix**: qa/orchestrator banners hardcode "sonnet-4-6" (SKILL-impl.md ~3479/3119) while the
   code runs the alias → show the resolved value instead.
5. `data/required-permissions.yaml`: allow read of `~/.claude/projects/**`.

### B — Enabling mechanic (foundation for all knobs)
6. Model knobs must accept **explicit version IDs** (`claude-sonnet-5` / `claude-sonnet-4-6`), not only
   the tier `sonnet|opus`. Without this the version pins are placebos on a mismatched session.

### C — New pin knobs
7. **Renderer knob** `APPSEC_RENDERER_MODEL` (+ matrix entry, dispatch wiring in BOTH parallel-render
   calls + the single-dispatch back-compat path). Manual override, explicit version, **no** auto-conditional
   (resolve_config is blind to the session model).
8. **Abuse-verifier knob** — replace the hardcoded `MODEL_ID=sonnet` with a resolved value. Default
   **tier-following**; 4.6 is **opt-in**, NOT a hard default (protects verdict decisiveness).

### D — Value-agent routing (gated on measurement)
9. **Measure dispatch topology**: are stride/triage/merger dispatched as SEPARATE sessions or bundled
   inside the main analyst? (stage-stats bundles them; agent-run.log shows separate dispatch counts —
   resolve the contradiction.) This decides whether 10 is even mechanically possible.
10. **If separate:** triage/merger → `claude-sonnet-5` expressed as an **override on top of**
    sonnet-economy (do NOT mutate the named sonnet-economy tier definition).

### E — The real cost lever (CC-level, not plugin)
11. 4.6-session default via `settings.json "model": "claude-sonnet-4-6"` (scan-scoped or global) — set
    via the `update-config` skill (settings.json is often write-protected). This is where the saving
    actually comes from.

## Decisions AGAINST (do not implement)
- ❌ qa_content → Haiku: content-QA feeds the Re-Render repair loop; too-weak model → more iterations /
  non-convergence → potentially MORE cost, on the quality gate. Keep the 4.6/sonnet-economy floor.
  (Routine QA is already haiku — correct.)
- ❌ Auto-default "renderer=5 if orchestrator=4.6": resolve_config cannot see the session model.
- ❌ Hard-defaulting abuse to 4.6: reintroduces inconclusive verdicts.
- ❌ Touching STRIDE: stays 4.6 (win/win), already pinned.

## Contract touchpoints (per AGENTS.md — bidirectional)
Each knob: `resolve_config.py` (matrix + arg-parse + env map) + `SKILL-impl.md` (resolution +
dispatch `model:` wiring + config summary) + tests (`test_resolve_config`, `test_agent_definitions`)
+ `data/required-permissions.yaml` + AGENTS.md Editing-Guidance row. Run targeted subset + `make lint`.

## Prerequisite
`scripts/resolve_config.py` currently has UNCOMMITTED changes (the 4.6 pin for stride/triage/merger,
citing this A/B's cost numbers). Build on top of it; confirm with the user before mutating, or have
them commit it first.

## Recommended order
A → 9 (measure) → B → C → D(10 if 9 permits) → E (anytime). A + E are the core (transparency + the one
real saving); C/D are quality buy-back that only pays on a 4.6 session and only if 9 holds.
