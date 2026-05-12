# Schema Invariants

Detailed schema and pipeline invariants for `threat-model.md` and `threat-model.yaml`. Summarised in `AGENTS.md` Rule 4 — this file is the authoritative source for the §4a–§4e details.

## §4a. Cross-reference labelling invariant

Every ID class in `threat-model.md` (`T-NNN`, `F-NNN`, `M-NNN`, `TH-NN`, plus `C-NN` / `AF-NNN` covered by `compose`) MUST render as `[ID](#anchor) — <short-title>` when referenced outside its declaration site: the §8 Threat Register ID column, §9 `#### M-NNN — …` headings, and §8 / §7.2 TH-NN anchor cell. Bare `[ID](#anchor)` links make the report unreadable on first pass.

Three things must stay aligned for the invariant to hold:

1. **Schema source of truth.** `schemas/threat-model.output.schema.yaml`
   declares `title` as **required** on `threats[]` (`minLength: 10`, `maxLength: 60`) and on `mitigations[]`. Do NOT make it optional or raise the 60-char ceiling; longer titles wrap in tables. Phase 11 (`agents/phases/phase-group-finalization.md` substep 2) MUST copy `.threats-merged.json[].title` verbatim or the report degrades into `(untitled)` cross-references.

2. **Single linkifier.** `scripts/qa_checks.py:linkify_anchors` is the
   only legal producer of titled cross-references. It runs from `qa_checks.py all` and is idempotent. Its invariants:
   - `_load_label_index` builds T-NNN and F-NNN aliases for the same numeric suffix.
   - `_load_th_label_index` parses TH-NN titles from §8 / §7.2 declarations (`<a id="th-NN"></a>TH-NN — Title`); TH titles do not live in yaml.
   - The bare-ref pass covers `sub_t`, `sub_f`, `sub_m`, `sub_th`; a new ID class needs its own substitution function.
   - The idempotent suffix regex matches `[FTM]-` AND `TH-`, so existing un-suffixed `[F-NNN](#f-nnn)` / `[TH-NN](#th-nn)` links gain `— Title` on rerun.

3. **Tests pin the invariant.**
   `tests/test_qa_checks.py:TestCrossReferenceLabellingInvariant` exercises each ID class; `tests/test_p4_cross_reference_coverage.py:TestCrossReferenceTitleCoverageEndToEnd` verifies that end-to-end `linkify_anchors` produces zero un-suffixed cross-references outside declaration sites. Removing either guard requires an explicit migration justification.

Failure modes to watch for in PR review:
- A schema PR that drops `title` from `threats[].required` → bare links
  ship silently because `_load_label_index` returns empty entries.
- An LLM author hand-formatting `[T-001 — Custom Title](#t-001)` in a
  fragment → bypasses single-source-of-truth and drifts on rerun.
- A new ID class introduced without adding it to the linkifier → that
  class ships as bare links on every rendered MD.

## §4b. Mitigation synthesis invariant

When P1/P2/P3 threats exist in `threat-model.yaml`, `mitigations[]` MUST be non-empty. An empty register means Phase 11 skipped mandatory synthesis (`agents/phases/phase-group-finalization.md` → "Mitigation synthesis (mandatory before YAML write)"). `scripts/validate_intermediate.py:validate_threat_model_output` enforces this; a non-zero post-write self-check MUST block Stage 2.

**Canonical field names** — deviating causes silent data loss:

| Correct field name | WRONG — do not use |
|--------------------|--------------------|
| `mitigations[].id` | ~~`m_id`~~ |
| `mitigations[].title` | ~~`mitigation_title`~~ |
| `mitigations[].threat_ids` | ~~`addresses`~~ |
| `mitigations[].priority` | P1/P2/P3/P4 — NEVER severity words (Critical/High/…) |
| `threats[].mitigation_ids` | ~~`threats[].mitigations`~~ |

The last row is critical: `scripts/compose_threat_model.py` reads `t.get("mitigation_ids")` for §8 Primary Mitigations and §1 Top Findings. `threats[].mitigations` makes those columns render `—`.

## §4c. `components[].threat_ids[]` directionality

After Phase 11, `components[i].threat_ids[]` MUST be the reverse index of `threats[j].component`. If Phase 11 omits it, `scripts/pregenerate_fragments.py:_render_layer_tables` falls back to deriving `threats_by_component`; do NOT remove this fallback or the Linked Threats column can silently render `—`.

## §4d. Flag-conditional QA/contract gates (`skip_attack_walkthroughs`)

`scripts/qa_checks.py` and `scripts/check_inline_shortcut.py` read `.skill-config.json` before applying gates that only matter when attack walkthroughs were authored:

- **`check_ms_structure` Check 4** (Attack Chain Overview required when
  Critical ≥ 2) — skipped when `SKIP_ATTACK_WALKTHROUGHS=true`.
- **`check_chain_compactness`** (flags "no mermaid blocks found") — skipped
  when `SKIP_ATTACK_WALKTHROUGHS=true`.

When `SKIP_ATTACK_WALKTHROUGHS=true`, `attack-walkthroughs.md` contains only a skip notice and no Mermaid blocks. Any QA/contract check that would fire on this stub is a false positive and MUST be conditioned on the flag. `data/sections-contract.yaml` documents this with `required_patterns_condition` and `per_critical_subsection_condition`.

## §4e. §8 Threat Register — source-file links

When a threat carries `evidence.file` (and optionally `evidence.line`), the §8 Component column MUST render a `vscode://file/<path>:<line>` link to the exact source location, not only the component anchor. `scripts/compose_threat_model.py` emits `` [`basename:line`](vscode://file/…) (ComponentName) `` instead of `[C-NN](#c-nn) — ComponentName`. AGENTS.md Rule 10 applies at the table-cell level too.
