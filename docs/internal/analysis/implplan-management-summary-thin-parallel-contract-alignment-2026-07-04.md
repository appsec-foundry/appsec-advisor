# Handoff: Management Summary and Thin/Parallel contract alignment (2026-07-04)

**Status:** investigation complete; no production fix implemented.

Use this file to resume the work in a fresh session. Repository:
`/home/mrohr/appsec-advisor`, branch `dev`.

At investigation time the only pre-existing worktree entries were:

```text
?? .claude/launch.json
?? .claude/routines
?? .claude/workflows
```

Do not modify or remove them as part of this work.

---

## Objective

Align the report contract, active agent prompts, QA repair planning, CLI routing,
and Thin/Parallel orchestration around one deterministic Management Summary
pipeline.

Thin vs. legacy runtime, parallel vs. serial STRIDE, and split vs. full Stage-2
rendering are execution variants only. They must produce the same fragments and
the same final report structure.

---

## Canonical Management Summary target

The intended current layout is the merged, fragment-driven layout:

```text
## Management Summary
### Verdict
[### Architectural Anti-Patterns]
[### AI / LLM Exposure]
### Security Posture & Top Threats
### Top Mitigations
[### Requirements Compliance]
### Operational Strengths
```

`## Critical Attack Tree` follows the Management Summary as a separate top-level
section. It is not a Management Summary subsection.

Square brackets above mean conditionally rendered.

The current deterministic owner is
`scripts/compose_threat_model.py:_render_management_summary`. The structural
validator agrees on the four mandatory subsections:

```python
(
    "Verdict",
    "Security Posture & Top Threats",
    "Top Mitigations",
    "Operational Strengths",
)
```

Authoritative current surfaces:

- `data/sections-contract.yaml`
- `scripts/compose_threat_model.py:_render_management_summary`
- `scripts/qa_checks.py:_MS_REQUIRED_SUBSECTIONS`
- current golden/example reports

### Retired layout — do not restore

```text
## Management Summary
### Verdict
### Top Findings
### Architecture Assessment
### Mitigations
#### Prioritized Mitigations
#### Follow-up Mitigations
### Operational Strengths
```

The conceptual migration was:

- finding-centric `Top Findings` + separate `Architecture Assessment`
  -> attack-class-centric `Security Posture & Top Threats`;
- two mitigation subtables -> one deterministic `Top Mitigations` leaderboard;
- full Management Summary Markdown authored during Phase 9
  -> judgment-only fragments authored in Stage 2, final Markdown composed by
  deterministic Python.

### Ownership in the target pipeline

Stage-2 `RENDER_ROLE=ms` or the single `RENDER_ROLE=full` agent may author only
judgment-bearing fragments:

- `ms-verdict.json`
- optional `ms-anti-patterns.json`
- optional/richer `ms-ai-exposure.json`
- optional `security-posture-attack-paths.json`
- optional `requirements-compliance.md`
- `ms-critical-attack-tree.json` when applicable, with deterministic fallback

Deterministic code owns:

- the `## Management Summary` heading and subsection order;
- risk-distribution counts;
- Figure 1 and Figure 2 structure;
- the Top Threats table;
- the Top Mitigations leaderboard;
- Operational Strengths;
- final Markdown composition and QA gates.

No agent should author or embed a complete `.management-summary-draft.md`.

---

## One unresolved product decision

`data/sections-contract.yaml` declares optional `triage_notes` gated by
`triage_has_warnings`, but:

- `_render_management_summary` never dispatches it;
- no `_render_triage_notes` implementation exists;
- no current example report renders `### Triage Notes`;
- only legacy finalization prose describes the section.

Recommended decision: retire `triage_notes` from the Management Summary and
surface triage warnings in Findings Register, Run Issues, or QA output. If the
maintainer wants it in the executive summary, implement it deliberately across
contract, producer, renderer, QA, and tests rather than retaining the current
dead declaration.

Resolve this decision before changing the Management Summary contract.

---

## Runtime variants and invariants

### Runtime routing

- `runtime=thin-full`: eligible full/rebuild scans when
  `APPSEC_THIN_ORCHESTRATOR=1`.
- `runtime=legacy`: incremental, rerender, resume, dry-run, deadline/cost,
  live-phase, and rollout fallback paths.

The Thin runtime still dispatches the same `appsec-threat-analyst` agents and
uses the same phase-group prompts. It reads the Stage-1 slice and the post-boundary
tail of `SKILL-impl.md`; it does not define another report contract.

### Stage 1

- Serial path: one analyst with `STAGE1_PHASE_LIMIT=10b`.
- Parallel STRIDE path: Analyst-A -> analyzer fan-out -> Analyst-B with
  `RESUME_FROM_PHASE=9-merge`.

Both paths stop after structured Stage-1 artifacts and deterministic Phase-11
substeps 1-3. Neither should author Management Summary Markdown.

### Stage 2

- `RENDER_ROLE=full`: one agent authors MS + §7 fragments and composes.
- `RENDER_ROLE=ms` plus `RENDER_ROLE=secarch`: two agents author independent
  fragment sets in parallel; the parent composes after both return.

Both variants must produce byte/structure-equivalent deterministic sections for
identical inputs. The only permitted prose differences are inside explicitly
LLM-authored fragment fields.

### Thin finalize backstop

`orchestration_controller.py next` already contains a deterministic compose
backstop for the observed 2026-07-02 Thin/Parallel failure where fragments
existed but `threat-model.md` did not. Preserve this behavior and its ordering:

```text
compose_threat_model.py --strict
apply_prose_fixes.py
qa_checks.py autofix
```

The backstop also regenerates `ms-ai-exposure.json` and
`ms-critical-attack-tree.json` when needed. This is a completeness fallback,
not a separate Management Summary layout.

---

## Confirmed findings

### F1 — Active Phase-9 Management Summary contract is retired

Severity: high.

`agents/phases/phase-group-threats.md` is loaded by serial Stage 1 and Analyst-B.
It still requires:

- loading `agents/shared/ms-template.md`;
- authoring a complete `.management-summary-draft.md`;
- five retired subsections;
- passing that draft through `qa_checks.py ms_structure`.

The current `ms_structure` contract requires `Top Mitigations`, not
`Mitigations`, and renames `Top Findings` to `Security Posture & Top Threats`.
A prompt-conformant legacy draft was reproduced against the real validator and
failed with:

```text
Management Summary missing required sub-section '### Top Mitigations'
```

No Python consumer reads `.management-summary-draft.md`; scripts only list it
for cleanup/baseline exclusion. The draft duplicates Stage-2 work and can block
Stage 1.

Root fix: remove the Phase-9 draft production/hard gate and make Stage 1 end with
structured artifacts only.

### F2 — Management Summary prompts describe the retired layout

Severity: high.

Stale operative/reference surfaces include:

- `agents/phases/phase-group-threats.md`
- `agents/phases/phase-group-finalization.md`
- `agents/shared/ms-template.md`
- `agents/shared/qa-ms-checks.md`
- `agents/appsec-qa-reviewer.md`

They still require `Top Findings`, `Architecture Assessment`, and the old
Mitigations split. Update or retire them together. Do not patch only one prompt.

Nuance: normal Stage 2 uses `agents/appsec-threat-renderer.md`, so the old direct
Markdown write instructions in `phase-group-finalization.md` are not the primary
normal Stage-2 executor. They remain active in compatibility/full-agent paths
and pollute the fully loaded finalization context.

### F3 — §2.4 architecture phase contains mutually exclusive contracts

Severity: high.

The same active `agents/phases/phase-group-architecture.md` first states the
current contract:

```text
2.1 System Context
2.2 Container Architecture
2.3 Components
2.4 Technology Architecture
```

It later mandates `### 2.4 Security Architecture Assessment` and numbered
2.4.1-2.4.9 themes. The contract and pregenerator require Technology
Architecture; Security Architecture Assessment moved to §7.

The deterministic pregenerator masks much of the final-output impact, but the
prompt still drives contradictory agent work. `appsec-qa-reviewer.md` also
retains manual §2.4 Security Architecture Assessment checks.

### F4 — Findings Register prompts retain the old heading/layout

Severity: medium.

Current contract:

- `## 8. Findings Register`
- per-finding card layout
- `## 9. Abuse Cases`
- `## 10. Mitigation Register`
- `## 11. Out of Scope`

Stale prompts still refer to:

- `## 8. Threat Register`;
- the retired 9-column flat table;
- old §9/§10 numbering and anchors.

Affected surfaces include `appsec-threat-analyst.md`,
`phase-group-threats.md`, `phase-group-finalization.md`, and
`appsec-qa-reviewer.md`.

The composer masks most output impact; the residual risk is wrong agent
reasoning, bad cross-references, and QA false positives.

### F5 — QA table-schema repair classification is broken

Severity: high.

Real-function reproduction:

```text
Checker issue:
Top Threats table does not match contract column schema
(expected one of: [...])

Repair action:
type: unclassified
remediation: generic
```

Causes:

- checker emits `expected one of: [...]`;
- repair parser expects `expected: "<single header>"`;
- `_TABLE_LABEL_TO_SECTION` uses retired labels such as `Top Findings` and
  `Prioritized Mitigations`, not `Top Threats` and `Top Mitigations`.

Additional release-gate bug:

```python
blocking action without fragments_to_rewrite
+ cosmetic action with a writable fragment
=> ("cosmetic_advisory", False)
```

The skill treats exit 4 like the clean fast path and may skip QA even though the
plan contains a blocking table-contract defect.

Root fix:

1. classify the exact emitted issue format;
2. map current labels to current contract section IDs;
3. change plan-status precedence so any blocking action wins over cosmetic
   actions, even when the blocking action has no writable fragment target;
4. dispatch QA/manual review for non-writable blocking defects.

### F6 — Fragment registry drift gate is not bidirectional

Severity: medium.

`scripts/check_fragment_registry.py` reports no errors while:

```text
qa_only_section_ids: ['top_findings']
```

`CONTRACT_SECTION_FRAGMENTS` retains the retired `top_findings` ID. The linter
compares values only for shared keys and does not reject extra QA-map section
IDs. Comments also reference a nonexistent `tests/test_qa_fragment_map.py`.

### F7 — Active references name retired/nonexistent fragments

Severity: medium.

`.fragments/ms-architecture-assessment.json` has no current schema or registry
entry, but appears in:

- `agents/shared/architect-repair-classifier.md` as an active repair target;
- `agents/shared/prose-style.md`;
- `agents/shared/prose-samples.md`.

The architect repair loop can therefore request rewriting a file no current
renderer consumes.

`SKILL-impl.md` also shows retired `use-cases.md` and
`ms-architecture-assessment` in its pipeline overview. Those overview entries
are lower-risk documentation drift but should be aligned in the same cleanup.

### F8 — Interactive HELP flags do not match controller/runtime behavior

Severity: high.

Verified behavior:

```text
--clean-cache       -> resolves as mode=full; no cleanup field/action survives
--clean-all         -> resolves as mode=full; no cleanup field/action survives
--trust-mode        -> router aborts: unrecognized argument
--strict-urls       -> router aborts: unrecognized argument
--refresh-discovery -> router aborts: unrecognized argument
--force             -> supported by the router/skill layer
```

`tests/test_help_file.py` explicitly exempts these as
`KNOWN_UNDOCUMENTED_FLAGS`, hiding real behavior drift.

Thin/Parallel relationship: this issue is directly related to the new universal
`orchestration_controller.py route` boundary. Any advertised flag must be
accepted and preserved by the router before either Thin or legacy runtime loads.

Do not solve this only by adding rows to the SKILL table. Decide per flag whether
it belongs to interactive `create-threat-model`:

- if supported: carry it through route -> resolve -> action -> runtime behavior;
- if headless-only: remove it from interactive `HELP.txt` and document it in the
  headless surface instead.

### F9 — AGENTS runtime-model table has a stale default

Severity: low.

`resolve_config.py` currently resolves the standard default to:

```text
reasoning_model = sonnet-economy
merger_model = sonnet
```

`AGENTS.md` still labels `appsec-threat-merger` default runtime model as Opus.
Its frontmatter is also Sonnet. Fix the documentation and add a doc-drift guard
instead of re-deriving routing behavior in prose.

---

## Contract ambiguities to clean while implementing

These are not alternate layouts to preserve:

1. `sections-contract.yaml` still contains legacy `sub_tables` metadata under
   `mitigations`, while its comments, composer, validator, and examples use one
   `Top Mitigations` table.
2. The `security_posture_at_a_glance` comments still mention seven narrative
   bullets in places, while the active output is the Top Threats table.
3. `_render_management_summary` contains a stale comment mentioning
   `top_findings`; the loop no longer dispatches it.
4. `check_ms_structure` docstrings still refer to “five” required subsections
   even though `_MS_REQUIRED_SUBSECTIONS` contains four.

Treat executable fields, current composer behavior, and approved target
decisions as authoritative; remove contradictory comments rather than encoding
multiple accepted layouts.

---

## Implementation plan

### Phase 0 — confirm decisions and baseline

1. Confirm the merged Management Summary target above.
2. Decide whether `triage_notes` is retired or deliberately implemented.
3. Capture baseline tests before edits:

   ```bash
   python3 scripts/validate_config.py
   python3 scripts/check_fragment_registry.py
   pytest tests/test_contract_integrity.py
   pytest tests/test_schema_integrity.py
   pytest tests/test_agent_definitions.py
   pytest tests/test_lazy_phase_group_loading.py
   pytest tests/test_compose_threat_model.py
   pytest tests/test_qa_checks.py
   pytest tests/test_qa_checks_cov_band1.py
   pytest tests/test_help_file.py
   pytest tests/test_orchestration_controller.py
   pytest tests/test_resolve_config.py
   ```

4. Preserve the existing untracked `.claude` entries.

### Phase 1 — add failing drift guards first

Add maintainable tests before prompt cleanup:

1. Contract-to-prompt Management Summary guard:
   - verify active prompts reference the merged headings;
   - reject operative blocks requiring `Top Findings`,
     `Architecture Assessment`, or full `.management-summary-draft.md`;
   - permit those terms only in explicitly marked migration/history prose.
2. §2.4 prompt guard:
   - canonical `2.4 Technology Architecture`;
   - reject operative `2.4 Security Architecture Assessment`.
3. Findings Register prompt guard:
   - canonical heading/card terminology and current numbering.
4. Fragment-reference guard:
   - every operative `.fragments/<name>` reference must resolve to a registered
     fragment or an explicit deterministic/legacy allow-list.
5. Render-variant parity:
   - same fixed fragments/yaml produce the same deterministic MS structure for
     single and split-render finalization paths;
   - Thin `next` backstop produces the same subsection sequence.

Avoid broad regex tests over entire files where historical examples are valid.
Prefer marked operative sections or small declarative expected-heading sets.

### Phase 2 — remove the obsolete Phase-9 MS pipeline

Update together:

- `agents/phases/phase-group-threats.md`
- `agents/shared/ms-template.md`
- `agents/phases/phase-group-finalization.md`
- `agents/appsec-threat-analyst.md`
- `agents/appsec-qa-reviewer.md`
- `agents/shared/qa-ms-checks.md`

Required outcome:

- no Phase-9 `.management-summary-draft.md` production;
- no Phase-9 MS Markdown hard gate;
- Stage 1 ends with structured artifacts/YAML only;
- Stage 2 `ms`/`full` role authors judgment fragments;
- composer alone builds final subsection order/layout;
- remove draft from runtime cleanup/baseline lists only after proving no
  compatibility/resume consumer remains.

Do not hand-edit example reports to hide prompt drift.

### Phase 3 — align contract, composer comments, and examples

1. Resolve/remove `triage_notes`.
2. Remove retired mitigation `sub_tables` metadata if the single table is the
   deliberate final design.
3. Correct stale attack-path bullet comments.
4. Remove stale `top_findings` comments and dead renderer/template code only if
   no compatibility consumer requires them; otherwise mark them explicitly
   legacy and keep them out of registries/repair maps.
5. Regenerate deterministic golden output only through the documented golden
   update path after reviewing the diff.

### Phase 4 — align §2.4 and register prompts

1. Remove the obsolete §2.4 Security Architecture Assessment block from
   `phase-group-architecture.md`.
2. Remove matching manual QA checks.
3. Align Findings Register heading, card layout, anchors, and §9-§11 numbering
   across analyst, threats, finalization, QA, and shared references.
4. Add neutral regression fixtures; do not encode target-application names.

### Phase 5 — fix QA repair classification and registry checks

1. Make table-schema issue emission and parsing share a structured representation
   or one helper rather than coupled prose regexes.
2. Update current table label -> section mappings.
3. Add end-to-end tests:
   - malformed Top Threats header -> `table_schema_drift`;
   - malformed Top Mitigations header -> `table_schema_drift`;
   - current section ID and correct repair target;
   - blocking/no-fragment + cosmetic/writable -> manual review or blocking QA,
     never `cosmetic_advisory`.
4. Make `check_fragment_registry.py` reject extra keys in every registry map
   unless explicitly exempted with rationale.
5. Remove stale `top_findings` QA-map entry.

### Phase 6 — fix interactive CLI/controller parity

For each advertised flag, define the owner and expected action:

- interactive skill;
- headless wrapper only;
- deprecated/removed.

Then add route-level tests exercising:

```text
HELP flag
-> orchestration_controller route
-> resolve_config output/action
-> selected runtime
-> intended cleanup/trust/refresh behavior
```

Ensure cleanup-only flags cannot resolve to a normal `mode=full` assessment.
Security/trust flags must never be silently downgraded.

### Phase 7 — align fragment repair references and model docs

1. Replace/remove `ms-architecture-assessment.json` references.
2. Update prose samples to fields/fragments the active renderer actually authors.
3. Correct the Skill pipeline overview.
4. Correct AGENTS runtime-model defaults.
5. Add a small parser-based doc-drift test sourced from `resolve_config.py`
   rather than duplicating model routing in test constants.

### Phase 8 — verification

Run focused suites after each phase, then:

```bash
make check
pytest -q
```

For renderer/report changes also run:

```bash
pytest tests/test_compose_threat_model.py
pytest tests/test_render_properties.py
pytest tests/test_reference_parity.py
pytest tests/test_sarif_validation.py
pytest tests/test_e2e_pipeline.py
```

Thin/Parallel verification matrix:

| Runtime | STRIDE | Stage 2 | Expected |
|---|---|---|---|
| legacy | serial | full renderer | canonical MS |
| legacy | parallel | split renderer | canonical MS |
| thin-full | parallel | split renderer | canonical MS |
| thin-full | parallel | forced full renderer | canonical MS |
| thin-full | parallel | compose via `next` backstop | canonical MS |

At minimum assert:

- identical required subsection sequence;
- no retired headings;
- no `.management-summary-draft.md` dependency;
- optional sections obey their gates;
- Critical Attack Tree remains outside the MS;
- strict compose -> prose fixes -> QA autofix ordering;
- blocking QA defects cannot be downgraded by cosmetic issues.

If the repository is red before edits, record exact baseline failures and
separate them from regressions.

---

## What not to do

- Do not restore the old five-subsection Management Summary.
- Do not create different report layouts for Thin, legacy, full renderer, or
  split renderer.
- Do not let an LLM write `threat-model.md` directly.
- Do not retain `.management-summary-draft.md` merely for historical comfort
  without a real consumer.
- Do not fix rendered Markdown or example reports by hand.
- Do not relax schemas/QA to accept both old and current layouts.
- Do not solve controller flag drift only in HELP text; behavior and routing
  must agree.
- Do not add broad unmaintainable regex exemptions that turn future drift green.

---

## Resume instructions

1. Read this file and `AGENTS.md`.
2. Confirm branch/worktree:

   ```bash
   git branch --show-current
   git status --short
   ```

3. Reconfirm the `triage_notes` decision with the maintainer.
4. Start with Phase 0 baseline and Phase 1 failing drift guards.
5. Implement producer/root-contract fixes before deleting symptoms.
6. Keep Thin/Parallel as scheduling variants of one deterministic output
   contract.

