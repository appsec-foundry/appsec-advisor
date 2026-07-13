# Schema Invariants

Detailed schema and pipeline invariants for `threat-model.md` and `threat-model.yaml`. Summarised in `AGENTS.md` Rule 4 — this file is the authoritative source for the §4a–§4f details.

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

## §4e. §8 Threat Register — source locations

When a threat carries `evidence.file` (and optionally `evidence.line`), §8 must surface that exact source location in the finding card's `**Location:**` meta field. `scripts/compose_threat_model.py:_build_threat_card` renders it as one backticked token, for example `` `lib/insecurity.ts:58` ``, while the component remains a separate `C-NN` anchor in the same meta line. Do not collapse the location back into the component anchor or split the line number outside the code span.

## §4f. Fragment registry maps — single source of truth

Five maps across three Python files implicitly encode the fragment ↔ schema ↔ contract-section relation. Any change to one MUST be reflected in the others, or the pipeline silently produces broken cross-references or skipped validations. Keep this table in sync whenever a map moves:

| Map | File | Purpose |
|---|---|---|
| `_SECTION_FRAGMENT_MAP` | `scripts/compose_threat_model.py:131` | section_id → ordered list of fragment ids the composer pastes for that section |
| `_KNOWN_JSON_FRAGMENT_SCHEMAS` | `scripts/compose_threat_model.py:148` | fragment filename → (schema name, schema file) for composer-side JSON validation |
| `FRAGMENT_SCHEMAS` | `scripts/validate_fragment.py:39` | fragment id → schema file used by `validate_fragment.py` (the producer-facing validator the LLM is told to run) |
| `_FRAGMENT_FILENAMES` | `scripts/validate_fragment.py:55` | fragment id → on-disk filename under `.fragments/` |
| `CONTRACT_SECTION_FRAGMENTS` | `scripts/qa_checks.py:1163` | section_id → fragment ids that `qa_checks` emits in `fragments_to_rewrite` repair plans |

> Line numbers drift as the files evolve; the canonical match is on the symbol name, not the number. ``scripts/check_fragment_registry.py`` extracts each map by name via AST, so the gate keeps working even when the line numbers go stale.

`data/sections-contract.yaml` is the human-edited declaration that every other map should align with; the maps duplicate fragments of it because each consumer reads only the slice it needs. Adding a new fragment means touching all five maps + the contract + the schema + the fragment's `.j2` template under `templates/fragments/` when it renders via one (the `_render_template` call in `docs/internal/runbooks/adding-a-section.md`). The mechanical sequence is documented in `docs/internal/runbooks/adding-a-section.md`. The automated drift gate lives in `scripts/check_fragment_registry.py` (see Phase A1 of the refactoring plan) — when present it MUST stay green in CI.

## §4g. Systemic weakness evidence invariant

`weaknesses[]` records are first-class assessment conclusions rendered in the
unnumbered **Systemic Weaknesses** chapter. A W-NNN may cite confirmed F-NNN
findings, unsafe-practice locations, or absent-control evidence. Its
`severity_basis` is therefore `confirmed`, `observed-practice`, or
`design-risk`; only the linked findings may carry CVSS. A CWE family is never a
weakness scope: `scripts/merge_threats.py` may group evidence only when it
shares one concrete control scope. Management Summary and §7 links point to W,
while W links to its supporting findings.

Every W-NNN has a required `title` of at most 80 characters. It is the short,
reader-facing heading and must not contain CWE IDs, source paths, routes, or
code snippets; `statement` holds the explanatory detail instead.
