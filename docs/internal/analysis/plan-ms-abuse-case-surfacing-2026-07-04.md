# Analysis: Surfacing verified abuse cases in the Management Summary

Date: 2026-07-04 · Status: analysis only, not started · Origin: review of how/where
abuse cases appear in the MS, and whether a concrete worst-case line would clash with
the existing red-box worst-case bullets.

## Question that started this

Are the most-relevant (critical / verified) abuse cases surfaced in the Management
Summary — and prominently enough? Would adding a concrete worst-case abuse-case line
**overlap / contradict / complement** the existing red-box worst-case scenarios?

## Current state (verified in code, 2026-07-04)

Abuse cases are already surfaced in the MS by **two deterministic** lines (not LLM prose):

1. **"Verified attack chains"** — `scripts/compose_threat_model.py:_build_ms_abuse_chain_line`
   (def ~6523; placed in *Security Posture & Top Threats*, right under the top-threats
   table — see assembly at ~7025-7028).
   - Reads `.fragments/abuse-cases.json`.
   - Surfaces ONLY actionable verdicts: `fully_viable` first, then `partially_blocked`.
   - Output = **counts + linked AC-IDs** + generic sentence + link to §9. Example:
     `**Verified attack chains.** 2 fully viable (AC-T-001, AC-T-002); 1 partially blocked (AC-T-003). … see §9.`
   - Returns '' (line omitted) when no viable/partial chain exists.

2. **"Attack-chain analysis"** — `scripts/compose_threat_model.py:_abuse_chain_ms_note`
   (def ~8931; appended **inside the Verdict block**, sid == "verdict", at ~9037-9043 —
   so it renders near the TOP of the MS).
   - Iterates `yaml_data.threats[]`, reads `verified_chain_ids`.
   - Output = **meta stats**: "N findings anchor verified chains, M elevated" + finding
     links (via `linkify_with_label`). Returns '' when no threat anchors a chain.

**Key finding:** both lines are META (counts / IDs / links). **Neither renders the concrete
worst-case scenario** (actor → chained steps → impact). Placement is actually fine
(one in the verdict block = top; one under the top-threats table); the gap is *content*,
not position.

## The red box (the existing worst-case surface)

The MS Verdict is framed by a **red HTML blockquote** (ms-template.md lines 30 / 37 / 96):
`<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">`.
- Contains **2–5 bullets, each = one critical attack path** (bold name + one-sentence
  plain-language explanation + italic **F-NNN** citation).
- These bullets **are** the worst-case scenarios — there is deliberately no separate
  `### ⚠ Worst Case Scenarios` sub-section (ms-template.md:30, 96).
- **LLM-authored** prose (part of the ms-verdict fragment), cited by **F-NNN** (findings).

## Overlap / contradiction / complement verdict

- **Overlap — yes, potential.** Red box (F-NNN, LLM narrative) and abuse chains (AC-NNN,
  deterministically verified) can describe the *same* worst-case, in different ID spaces.
  A separate concrete abuse one-liner would often duplicate a red-box bullet.
- **Contradiction — real risk.** The red box is LLM prose; it can assert a worst-case
  path that the deterministic abuse verifier marked `partially_blocked` / `inconclusive`
  → "red box says X is the worst case; §9 says X is blocked."
- **Complement — yes, but only if wired as the verification layer.** The abuse cases' unique
  value over the red box is *step-by-step code verification*, not the narrative (the red box
  already has that).

## Revised recommendation (supersedes "add a concrete worst-case line")

Do **NOT** add a third standalone concrete abuse-case line (duplication + contradiction risk).
Instead, make abuse cases the **verification layer of the red box**:

- Deterministic link already exists: `threat.verified_chain_ids`. A red-box bullet cites
  F-NNN → if that finding participates in a verified chain, append a badge to the bullet,
  e.g. `— ✓ end-to-end verified (AC-T-001)`.
- Result: the red box stays the single worst-case surface; code-proven paths stand out;
  no duplication; no contradiction (badge appears only for genuinely viable chains).
- The meta "Attack-chain analysis" line can then be dropped or shrunk to a "N of M verified"
  footnote.

## Contract touchpoints (if built — MS is contract-governed, AGENTS.md §1)

- `scripts/compose_threat_model.py` — new post-pass over the rendered verdict blockquote:
  parse F-NNN tokens in each bullet, look up `verified_chain_ids` (map finding → chain),
  append the badge. Reconcile with `_abuse_chain_ms_note` (likely remove/merge it).
- `agents/shared/ms-template.md` — document the badge convention in the Verdict block spec.
- `docs/internal/contracts/schema-invariants.md` — if the linkage becomes a cross-ref rule (§4a).
- Tests: `tests/test_compose_threat_model*.py` (verdict rendering + badge), MS structure tests.
- Fixtures: a fixture with a viable chain + a red-box bullet citing the anchoring finding.

## Feasibility / risks to resolve in the fresh session

- **Bullet parsing is fuzzy.** The red-box bullets are LLM prose; matching a bullet to a
  chain relies on the F-NNN token in the bullet + `verified_chain_ids` on that finding.
  Confirm every viable chain actually anchors a finding that the LLM cites in the red box
  (else the badge silently never appears). Check `verified_chain_ids` population coverage.
- Confirm the fields available per chain in `.fragments/abuse-cases.json` (id, chain_verdict,
  and whether a human-readable title/impact exists) — needed if a concrete line is ever wanted
  as a fallback. Producer: `scripts/render_abuse_cases.py`.
- Decide: badge-in-bullet (preferred) vs a single distinct "Verified end-to-end" line clearly
  labeled as the code-proven subset (lower parsing risk, slightly more duplication).
- Quick depth / `--no-abuse-cases`: abuse verification is skipped → no badges; the red box
  must read fine without them (it does today).

## Related memory / context

- [[project_abuse_cases_feature]] — §9 verifiable scenario chains (schema + library + matcher + verifier).
- [[project_abuse_cases_value_rework]] — chain → effective_severity landed (dormant); activation hook was OPEN.
- [[project_parallel_render_s7_ms]] — MS is rendered by `appsec-threat-renderer`; `ms-critical-attack-tree.json`
  is a *separate* MS element (critical AND/OR tree when ≥2 Critical) — do not confuse with the red-box bullets.
- [[project_threat_register_card_layout]], [[project_anti_patterns_ms_callout]] — other MS-adjacent deterministic passes.
