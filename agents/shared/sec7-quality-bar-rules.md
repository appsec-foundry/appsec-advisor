# §7 Security Architecture v2 — quality-bar rules

Used by `appsec-architect-reviewer` Check 14 (and indirectly by the threat-renderer to avoid producing drift). Validates that the rendered §7 follows the current v2 control-category contract from `agents/shared/prose-style.md → "Control narrative quality bar"` and `data/sections-contract.yaml → schema_v2`. The common drift pattern is a stale fragment that restores legacy §7.3.N flow blocks or omits H4 subcontrol coverage.

**Scope:** the rendered `threat-model.md` §7 body — H3 sections `### 7.1 Security Control Overview` through `### 7.13 Defense-in-Depth Summary`, plus every H4 subcontrol under §7.2-§7.12.

## Per-block checks

| Code | Rule | Severity on violation |
|---|---|---|
| `sec7_v2_heading_set` | H3 heading set and order match the 13 v2 required subsections. | error |
| `sec7_v2_overview_table` | §7.1 contains `Control category \| Verdict \| Main reason` and no finding-ID/control-ID columns. | warning |
| `sec7_v2_control_links` | Every `**Controls covered:**` link text in §7.2-§7.12 has a matching H4 heading in the same section. | error |
| `sec7_v2_h4_labels` | Every H4 subcontrol contains `**Security assessment**` and `**Relevant findings**`. | error |
| `section7_h4_status` | Every H4 subcontrol opens with a `**Status:** <icon> <word> — <clause>` verdict badge (directly under the heading, before the intro). The badge gives the reader the verdict at a glance and, for the two red verdicts, the FIX-vs-ADD signal. | warning |
| `sec7_v2_no_legacy_flows` | No `#### 7.3.N ... Flow` headings and no `**Findings in this flow:**` trailers under v2. | error |
| `qb7_no_floskeln` | §7 prose avoids templated filler such as `leverages`, `robust`, `comprehensive`, `in essence`, `seamless`, `security posture`, and textbook-purpose padding (`with the intention that`, `with the expectation that`, `is expected/intended to`). | warning when repeated; info otherwise |
| `qb7_concrete_openers` | H4 control intros lead with the concrete route/file/library/component — not the formulaic `The application/system/server …` stem. Flagged when ≥3 H4 intros across §7 share that stem. | warning |

**Verdict vocabulary (`🔴 Unsafe` vs `🔴 Missing`).** The §7.1 overview verdict and every H4 `**Status:**` badge draw from `data/sections-contract.yaml → verdict_icons`. The two red verdicts are distinct and must not be conflated: **🔴 Unsafe** = the control exists and is relied upon but is defeated/bypassable (an MD5 hash, a raw-SQL path, a hardcoded key, a parser with unsafe options) → *fix the existing control*; **🔴 Missing** = the control was never built (no CSP, no CSRF middleware, no schema-validation layer) → *add the control*. Flag any §7 block that labels a present-but-broken control "Missing".

**Aggregation:** count of violations per block × per rule. When any block has ≥ 1 `error` violation, write `[W-XX] §7 narrative quality bar` to `.architect-repair-plan.json` so the re-render loop can reshape that block. Lower-severity violations roll up into the existing `report.warnings` / `report.info` pipeline.
