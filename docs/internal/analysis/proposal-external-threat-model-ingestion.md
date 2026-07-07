# Proposal: Ingesting Existing Threat-Model Descriptions

**Status:** 🟡 Under consideration — **not** committed, not an implementation order.
**Date:** 2026-05-30 · **Deep analysis:** [`analysis-external-threat-model-ingestion.md`](analysis-external-threat-model-ingestion.md)

This document records the *intent* — goal, scope, plan, and **reservations**. It is a basis for a decision, not a roadmap commitment.

---

## Goal

When a target repo already brings its own threat model (e.g., OWASP Juice Shop has an OWASP Threat Dragon `threat-model.json`), the pipeline should **detect** it and optionally use it as **input** — cleanly separated from our own, code-grounded result. Two decoupled channels:

1. **Context channel** — architecture, data flows, trust boundaries, scope decisions, data classification, ownership, terminology. *Actively used* as a non-authoritative seed/prior. **Independently valuable** — even if not a single third-party finding is carried over (it encodes human intent that code scanning does not yield).
2. **Findings channel** — the third-party model's authored threats. **Input-only**, hard-separated from our own, **always verified**, never into the merge. They appear exclusively in an **own report section** that evaluates them *in relation to the current model* (verdict: corroborated / stale / gap / refuted / not verifiable / accepted) + coverage delta.

Additional benefit: **architecture drift detection** (documented intended vs. code-derived actual) falls out of placing the two models side by side.

## Formats (priority)

1. **OWASP Threat Dragon `.json`** — clean JSON, ~1:1 mapping, what Juice Shop has.
2. **OTM (Open Threat Model)** — interchange standard; the object model *is* essentially the internal IR.
3. **Markdown TM** via LLM extraction (the most common, but unstructured form).
Defer: MS-TMT `.tm7`, pytm, Threagile, Threatspec. **Not** a threat model: SARIF, CycloneDX/VEX.

## Hook points (reuse existing machinery)

- **Detection:** deterministic script in recon Step 0 (analogous to `recon_patterns.py`) → `.external-threat-models.json`. Content-sniff, exclude `node_modules`/`$OUTPUT_DIR`, filter out our own output by `meta.analyst` provenance.
- **Context:** via the **existing** `known-threats` channel (`context-resolver` Step 4i) or a Step 4j — no new section apparatus needed.
- **Findings section:** the 5-file section path (`docs/internal/runbooks/adding-a-section.md`), `fragment_type: data`, `condition: render_external_reconciliation`.
- **Verification:** **not** the line-based `evidence-verifier` (external threats are prose without `file:line` — cf. the `source: known-vuln` precedent, which is deliberately left `unchecked`). Verification = **reconciliation** against our own grounded findings.
- **Flags:** `--import-threat-model[=PATH]` · `--no-import-threat-model` · `--import-mode context|known-threats|off`. Interactive → ask; headless/`--yes` → default `context` (non-authoritative), never block.

## Phased plan (if ever implemented)

- **Phase A (small, low-risk):** detection + **context-lite** via the existing 4i channel + a small drift hint. ~80% of the value for ~20% of the effort.
- **Phase B (gated behind real demand):** dedicated reconciliation section + verdict engine + coverage delta. Only for a real, findings-rich model — and then **OTM first**.

---

## Reservations (why "only under consideration")

1. **Demand reality.** People who use the plugin mostly do so *because* no threat model exists. Repos with a committed third-party model are the minority.
2. **Empty showcase.** Juice Shop's TD JSON has **0 threats** — the most expensive component (the reconciliation section) would render an empty section on the flagship test. A sign of over-engineering.
3. **Wrong audience for TD-first.** Findings-rich models come from IriusRisk/OTM shops that already have a mature TM program — they need the plugin the least and expect OTM, not Threat Dragon.
4. **Complexity/fragility.** A mature pipeline (deterministic builders, sidecars, 30+ sections). The findings channel = parser + 5-file section + mapping engine + verdict taxonomy + circular-reasoning guard.
5. **Circular confirmation (the sharpest risk).** If the context channel seeds the architecture and an external finding is then "corroborated" because the seeded component exists → circular. "Corroborated" must be bound to **independent code evidence** (our own T-ID with `file:line`); seed tagged `provenance: imported` + separable. Subtly wrong = falsely confident verdicts (worse than no feature).
6. **Untrusted input.** The third-party model is committed content → treat like Cat-28 AI configs (no instruction-following from descriptions, sanitize prose).
7. **Prioritization.** Against ongoing work (token optimization, substep migrations, render fixes) it's a niche nice-to-have — no priority without a concrete user/customer.

## Preliminary decision

- **Context-lite + detection (Phase A):** sensible, small, low-risk — implementable when needed.
- **Full findings-reconciliation apparatus (Phase B):** conceptually clean (the two-channel separation is right), but for the real demand it is currently **over-engineered**. **Not now, not on Threat Dragon** — gated behind real demand + OTM.
