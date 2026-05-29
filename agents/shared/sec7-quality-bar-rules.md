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
| `sec7_v2_no_legacy_flows` | No `#### 7.3.N ... Flow` headings and no `**Findings in this flow:**` trailers under v2. | error |
| `qb7_no_floskeln` | §7 prose avoids templated filler such as `leverages`, `robust`, `comprehensive`, `in essence`, `seamless`, `security posture`, and textbook-purpose padding (`with the intention that`, `with the expectation that`, `is expected/intended to`). | warning when repeated; info otherwise |
| `qb7_concrete_openers` | H4 control intros lead with the concrete route/file/library/component — not the formulaic `The application/system/server …` stem. Flagged when ≥3 H4 intros across §7 share that stem. | warning |

**Aggregation:** count of violations per block × per rule. When any block has ≥ 1 `error` violation, write `[W-XX] §7 narrative quality bar` to `.architect-repair-plan.json` so the re-render loop can reshape that block. Lower-severity violations roll up into the existing `report.warnings` / `report.info` pipeline.
