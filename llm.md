# Option B — Deterministic yaml-compose for Phase 11 Substep 2

**Status:** design spec (not yet implemented).
**Author:** performance analysis 2026-05-23.
**Goal:** eliminate the 5-6 minute LLM reasoning phase before `threat-model.yaml` is written, and remove the `YAML_INVARIANT_DRIFT` class of bugs at source rather than via post-write repair.

---

## 1. Problem statement (verified from run logs)

Phase 11 Substep 2 ("Composing threat-model.yaml") observed on 2026-05-23 juice-shop run with extended hook logging:

| Metric | Value | Source |
|---|---|---|
| Substep 2 elapsed (STEP_START [2/3] → STEP_START [2/3] validated) | **7 m 57 s** | `.agent-run.log` |
| LLM reasoning phase before yaml `Write` | **~6 min** | gap between STEP_START [2/3] (18:17:52) and FILE_WRITE (18:24:37) with only 2 trivial bash existence-checks |
| Yaml output size | 40,330 chars (~13 k tokens) | hook event `FILE_WRITE` |
| Validation+fix loop after Write | 1 m 12 s (5× validate runs) | hook events 18:24:44–18:25:49 |
| `YAML_INVARIANT_DRIFT` warnings same run | **2** (T-005, T-009) | `.agent-run.log` |
| Stage 1 total | 54 m 36 s, $4.87, 38,970 out tokens | `SESSION_STOP` |

The LLM is paid Anthropic-API tokens to (a) reason about a yaml structure it does not author from scratch, (b) transcribe deterministic fields from `.threats-merged.json` and mis-transcribe them ~5-10 % of the time, and (c) re-run validation against drift it caused itself. Every part of (a) and (b) is mechanically avoidable.

Today's mitigation is `scripts/enforce_yaml_invariants.py` which runs **after** the Write and auto-repairs `stride`/`cwe` drift back to the merged-json values. This works as a safety net but does not address the 6-minute pre-Write reasoning cost.

---

## 2. Design — hybrid skeleton-and-fill

Introduce a new deterministic Python script that authors **everything the LLM has no judgement to add**, leaving only narrative fields as `<placeholder>` markers for the LLM to fill via small `Edit` calls.

```
                ┌────────────────────────────────────────────────────────────┐
                │  Phase 11 Substep 2 (new shape)                            │
                │                                                            │
                │   ┌──────────────────────────┐                             │
                │   │ assemble_yaml_skeleton.py│ ← deterministic, ~3-5 s     │
                │   └─────────────┬────────────┘                             │
                │                 ▼                                          │
                │   ┌──────────────────────────────────┐                     │
                │   │ threat-model.yaml.skeleton       │  every field        │
                │   │  - meta: filled                  │  derivable from     │
                │   │  - components: filled            │  Phase 1-10b        │
                │   │  - attack_surface: filled        │  artifacts is on    │
                │   │  - threats[].stride: copied      │  disk.              │
                │   │  - threats[].title: <PLACEHOLDER>│                     │
                │   │  - threats[].scenario: <PLACEHOLDER>                   │
                │   │  - mitigations[].title: <PLACEHOLDER>                  │
                │   │  - assets: <PLACEHOLDER list>    │                     │
                │   │  - security_controls: <PLACEHOLDER list>               │
                │   └─────────────┬────────────────────┘                     │
                │                 ▼                                          │
                │   ┌──────────────────────────┐                             │
                │   │ LLM: iterate Edit calls  │  small targeted edits       │
                │   │ over <PLACEHOLDER>       │  on narrative fields only   │
                │   └─────────────┬────────────┘                             │
                │                 ▼                                          │
                │   ┌──────────────────────────┐                             │
                │   │ validate_intermediate.py │  schema gate (unchanged)    │
                │   └─────────────┬────────────┘                             │
                │                 ▼                                          │
                │   ┌──────────────────────────┐                             │
                │   │ enforce_yaml_invariants  │  post-write drift gate      │
                │   │  .py (existing)          │  (existing, unchanged)      │
                │   └──────────────────────────┘                             │
                └────────────────────────────────────────────────────────────┘
```

### 2.1 What goes into the skeleton (deterministic)

| YAML section | Source | Confidence |
|---|---|---|
| `meta.schema_version: 1` | constant | 100 % |
| `meta.git.commit_sha`, `branch`, `remote` | `git rev-parse HEAD` etc. | 100 % |
| `meta.project.name`, `version`, `repository` | `package.json` / `pyproject.toml` / git config | 100 % |
| `meta.analysis_version` | `.skill-config.json` | 100 % |
| `meta.run_statistics` | `cost_running_total.py` output | 100 % |
| `components[]` | `.architecture-coverage.json → components[]` | 100 % |
| `attack_surface[]` | `.route-inventory.json` | 100 % |
| `threats[].id` | sequential F-NNN from `.threats-merged.json` ordering | 100 % |
| `threats[].original_id` (T-NNN) | `.threats-merged.json.id` (or `t_id`) | 100 % |
| `threats[].stride` | `.threats-merged.json.stride` (verbatim) | 100 % |
| `threats[].cwe` | `.threats-merged.json.cwe` (verbatim) | 100 % |
| `threats[].component` | `.threats-merged.json.component_id` (verbatim, rename) | 100 % |
| `threats[].evidence` | `.threats-merged.json.evidence` (verbatim) | 100 % |
| `threats[].risk`, `likelihood`, `impact` | `.threats-merged.json` | 100 % |
| `threats[].source` | `.threats-merged.json.source` | 100 % |
| `threats[].violated_requirements` | `.threats-merged.json.requirement_id` (wrap in list) | 100 % |
| `threats[].mitigation_ids` | join via `mitigations[].threat_ids` (computed in pass 2) | 100 % |
| `mitigations[].id` | sequential M-NNN grouping (see 2.3) | 100 % |
| `mitigations[].threat_ids` | from grouping | 100 % |
| `mitigations[].priority` | derived `Critical→P1`, `High→P2`, `Medium→P3`, `Low→P4` | 100 % |
| `mitigations[].severity` | max severity across `threat_ids` | 100 % |
| `mitigations[].effort` | `.stride-*.json.remediation.effort` (majority vote in group) | 100 % |
| `mitigations[].how_code`, `verification`, `steps`, `reference` | `.stride-*.json.remediation.*` | 100 % |
| `triage` | `.triage-flags.json → ranking` | 100 % |

### 2.2 What stays as `<placeholder>` (LLM-bedürftig)

| Field | Why LLM | Placeholder format |
|---|---|---|
| `threats[].title` | needs synthesis from merged `mitigation_title` + scenario | `"<PLACEHOLDER:title:T-NNN>"` |
| `threats[].scenario` | multi-sentence narrative | `"<PLACEHOLDER:scenario:T-NNN>"` |
| `mitigations[].title` | canonicalized fix name | `"<PLACEHOLDER:mitigation_title:M-NNN>"` |
| `assets[]` | top-down from compliance scope + recon | `[]` (LLM appends entries) |
| `trust_boundaries[]` | architectural judgement | `[]` (LLM appends) |
| `security_controls[]` | crosswalk from Phase 8 ratings | `[]` (LLM appends) |
| `critical_findings[]` | derived from `threats` but with synthesis | `[]` (LLM appends) |
| `tier_root_causes` | architectural narrative | `{edge: [], server: [], data: []}` |

### 2.3 Mitigation grouping (the hard part)

The deterministic grouper aggregates `.stride-*.json` mitigations by **canonical fix signature** (library name + version + config key). Today the LLM does this implicitly during yaml composition. Make it explicit:

- Input: list of `(threat_id, mitigation_title, remediation)` tuples across all `.stride-*.json` files
- Group by normalised key:
  - Strip leading verbs (`Upgrade`, `Replace`, `Add`, `Configure`)
  - Extract library@version, file path, or config key as the merge anchor
  - Examples that should group: `"Upgrade jsonwebtoken@9.0.0"` ↔ `"Replace jsonwebtoken with 9.0.0"`
- Output: deduplicated `mitigations[]` entries with `threat_ids[]` listing every T-NNN the group covers

This is the same logic the LLM does today but in Python it is **deterministic, testable, idempotent**. When two mitigation_titles disagree on case, whitespace, or verb tense, the LLM today silently picks one — a non-deterministic source of run-to-run drift.

A first version can be conservative: group only by exact normalised string match. A v2 can add fuzzy matching with a similarity threshold.

---

## 3. Implementation plan

### 3.1 New files

- `scripts/assemble_yaml_skeleton.py` (~250-350 Z. Python)
- `tests/test_assemble_yaml_skeleton.py` (~150-200 Z., unit tests per yaml section)
- Optionally: `data/yaml-placeholder-schema.yaml` (placeholder marker conventions)

### 3.2 Modified files

- `agents/phases/phase-group-finalization.md` Substep 2 — replace "Compose the full yaml body in memory" with the new two-step flow (skeleton → fill placeholders → validate). The existing F-NNN reflow / title-propagation rules survive but become enforcement guidance for the LLM's Edit calls, not authoring rules.
- `skills/create-threat-model/SKILL-impl.md` — add the `assemble_yaml_skeleton.py` invocation between Phase 10b end and the threat-analyst dispatch for Phase 11. Skeleton can be written by the skill itself, before the LLM ever sees the request.
- `agents/appsec-threat-analyst.md` — drop the "Yaml composition is ~45 KB and typically completes in one turn" guidance; replace with "fill `<PLACEHOLDER:*>` markers by reading the skeleton with Read+limit and editing each placeholder block in one Edit per logical section."

### 3.3 Backward compatibility

- The schema (`schemas/threat-model.output.schema.yaml`) is unchanged.
- `validate_intermediate.py` is unchanged.
- `enforce_yaml_invariants.py` continues to run as the post-write drift gate (defence in depth — if a future Edit slip mutates a copied field, it still gets caught).
- The `--no-yaml` flag (`WRITE_YAML=false`) keeps working — skeleton step is skipped.
- Incremental mode (`INCREMENTAL=true`) uses the same skeleton path; the prior yaml is read for the diff, then a fresh skeleton is built and filled.

### 3.4 Out-of-scope (explicit non-goals)

- **No fragment-rendering changes.** Markdown render still uses `compose_threat_model.py`.
- **No deterministic narrative writing.** `threats[].scenario`, asset descriptions, security control assessments stay LLM-authored.
- **No schema migration.** This refactor produces the same yaml shape `schemas/threat-model.output.schema.yaml` already requires.

---

## 4. Test strategy

| Test class | What it asserts |
|---|---|
| `test_skeleton_round_trip` | given fixed `.threats-merged.json` + `.architecture-coverage.json` + `.route-inventory.json` + `.stride-*.json` fixtures, skeleton output is **byte-identical** across runs |
| `test_skeleton_verbatim_fields` | every `threats[].stride` / `cwe` / `component` / `evidence` in skeleton matches `.threats-merged.json` exactly |
| `test_mitigation_grouping_idempotent` | running the grouper twice on the same input produces identical output |
| `test_mitigation_grouping_canonical` | known-equivalent mitigation titles group correctly (table of expected pairs) |
| `test_skeleton_schema_valid` | skeleton (with placeholders intact) passes schema validation when placeholders are nominal strings |
| `test_skeleton_filled_schema_valid` | fixture where placeholders are replaced with example strings still validates |
| `test_no_drift_after_skeleton` | run `enforce_yaml_invariants.py` over filled skeleton → 0 drifts (the whole point) |
| `test_incremental_compatibility` | incremental run reads prior yaml, builds new skeleton, fills only changed threats |

---

## 5. Risk / impact

| Risk | Likelihood | Mitigation |
|---|---|---|
| Mitigation grouping picks different M-NNN ordering than today | Medium | tests pin the ordering; ordering by `min(threat_ids)` then `priority` keeps it deterministic |
| LLM's narrative fields reference M-NNN by string instead of by id, breaks if reordering | Low | the placeholder format includes the M-NNN id (`<PLACEHOLDER:mitigation_title:M-NNN>`), so the LLM never authors the id, only the title |
| Schema evolution requires updating both skeleton author and existing render code | Low | one new file; the rest is unchanged. New required fields would surface as schema validation failures in CI |
| Skeleton + fill takes longer than today's monolithic LLM author | Very low | empirical bound: skeleton ~5 s + ~30 Edit calls × 5 s each = ~3 min vs. today's 7 m 57 s |
| Edge case: a threat in `.threats-merged.json` has no `mitigation_title` | Medium | grouper emits a `<no mitigation>` group with `priority: P4`; LLM fills the actual title via placeholder |

---

## 6. Expected effect (forecast)

| Metric | Today | Forecast | Source |
|---|---|---|---|
| Phase 11 Substep 2 elapsed | 7 m 57 s | ~2-3 min | skeleton script (~5 s) + LLM Edit calls on narrative only (~2-3 min) |
| LLM reasoning before first Write | ~6 min | <30 s | LLM no longer composes structure, just edits placeholders |
| Output tokens for yaml | ~13 k | ~3-4 k | only narrative fields are LLM-generated |
| `YAML_INVARIANT_DRIFT` warnings | observed 2/24 threats | 0 | verbatim fields are mechanically copied, never re-typed |
| Stage 1 total elapsed | 54 m | ~48-50 min | 5-6 min saved in Substep 2 |
| Stage 1 cost | $4.87 | ~$4.20-4.50 | proportional to output token reduction |

---

## 7. Open questions

1. Should the skeleton script also auto-derive `assets[]` from package manifests + database schemas (currently fully LLM)? Worth a separate Stufe 3 pass; out of scope for this design.
2. Should `tier_root_causes` (edge/server/data) be derived from `threats[].component` mapping rather than LLM-authored? Probably yes, but needs a `component → tier` mapping table that doesn't exist yet.
3. Should the LLM's `Edit` calls be enforced (skill-side hook denies a Write/Edit to `threat-model.yaml` if any `<PLACEHOLDER:*>` token remains)? Belt-and-braces option, low cost.

---

## 8. Sequencing

1. Land Hook-Erweiterung (done, 2026-05-23).
2. Land Output-Hygiene-Direktiven für Substep 2 + Renderer Iter 2 (done, 2026-05-23).
3. Measure next 1-2 runs with new logging to confirm Substep 2 is still the bottleneck after the hygiene direktive lands.
4. If confirmed: implement Option B in a separate phase (~1-2 days of focused work for skeleton script + tests + integration).
5. Roll out behind a `USE_DETERMINISTIC_YAML=true` env flag for one juice-shop comparison run before making it default.
