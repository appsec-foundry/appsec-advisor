# V6 - Architecture-Derived Findings (`F-NNN` only)

**Status:** Revised design draft, not implemented.
**Decision:** Do not introduce new public ID classes for architecture
weaknesses. Architecture-derived issues are represented as normal findings
and referenced only as `F-NNN` in the report.

This replaces the earlier `AW-*` / `AF-*` design direction. The goal remains
the same: derive general threats from architectural weaknesses. The mechanism
changes: architecture context becomes metadata and grouping on concrete
findings, not a separate finding namespace.

---

## 1. Core Decision

Use `F-NNN` as the only report-facing finding ID.

Architecture coverage rules may still use stable internal rule IDs such as
`ARCH-CORS-001`, because those identify deterministic checks. They are not
findings. They are provenance.

**No new ID classes appear in the rendered report.** After this change the
report-facing identifier set is reduced by one (`AF-NNN` is removed) and no
new identifier is introduced in its place. `ARCH-*` and `ARCH-HYP-*` stay
strictly internal — they appear in YAML data, SARIF properties, and pentest
task JSON, but never in the Markdown output.

## 1.1 Storage vs Visible Form

YAML storage continues to use `T-NNN` for `threats[].id` (schema pattern
`^T-\d{3,}$` in `schemas/threat-model.output.schema.yaml`). The visible-label
transform `_to_canonical_finding_label` in `scripts/pregenerate_fragments.py`
converts `T-NNN` → `F-NNN` for all report-facing rendering. This design
replaces only the `AF-NNN` class; the `T-NNN` ↔ `F-NNN` dual-form stays
unchanged.

Do not add:

- `AW-*` architectural weakness IDs
- `AF-*` architectural finding IDs
- `architectural_findings[]` as a separate top-level report object
- mitigation references that target `AF-*`

Instead, architecture-derived findings carry ordinary finding IDs plus
architecture metadata:

```yaml
id: F-014
source: architecture-coverage
rule_id: ARCH-CORS-001
architectural_theme: SecureDefaults
title: Cross-origin request abuse through permissive CORS
scenario: >
  The server allows wildcard cross-origin access with credentials, so a
  malicious origin can drive authenticated browser requests against the API.
evidence:
  - file: server.ts
    line: 12
mitigation_ids: [M-006]
```

The report can still group these findings by architecture theme, but every
reference remains a reference to one or more `F-NNN` findings.

## 2. Why This Is Preferable Here

The earlier `AW-*` / `AF-*` model created a separate root-cause layer. That is
useful when architecture weaknesses are first-class objects with independent
lifecycle, cross-repo analytics, and dedicated remediation roadmaps.

For the current goal, that is more machinery than needed.

The user-facing need is:

> Identify general threats that follow from architecture weaknesses.

That can be achieved by creating normal findings whose source is architectural
analysis. The finding itself states the general threat, and its metadata states
which architecture theme and deterministic rule produced it.

Benefits:

- No new public ID schema.
- No extra linkifier / anchor / QA rules for `AW-*` or `AF-*`.
- Existing report semantics stay intact: findings are findings, mitigations
  address findings, Top Findings ranks findings.
- Architecture weaknesses remain visible through grouped views and metadata.
- Incremental ID stability can reuse the existing `F-NNN` baseline logic.

Tradeoff:

- There is no separate anchor like `AF-005 Weak Authentication Architecture`.
  The same concept is represented as a cluster heading plus concrete `F-NNN`
  findings.

That tradeoff is acceptable if the product goal is a simpler, engineer-facing
report rather than a second architecture-finding taxonomy.

## 3. Target Data Model

### 3.1 Architecture-Derived Finding

An architecture-derived issue is a normal finding with additional metadata:

```yaml
id: F-021
source: architecture-coverage
rule_id: ARCH-AUTHZ-001        # internal metadata; never rendered
architectural_theme: Authorization
title: Privilege abuse through inconsistent authorization
```

Recommended fields:

| Field | Purpose | Rendered? |
|---|---|---|
| `id` | Existing finding ID, rendered as `F-NNN`. | yes (as `F-NNN`) |
| `source` | `architecture-coverage`, `threat-hypothesis`, or existing source. | optional column/badge (text) |
| `rule_id` | Stable deterministic rule provenance, e.g. `ARCH-CORS-001`. | **no — internal only** (SARIF + pentest-tasks JSON) |
| `architectural_theme` | One of the existing theme enum values. | optional column (enum text, not an ID) |
| `generic_threat_title` | Optional generic threat wording used before final title authoring. | no (authoring aid only) |
| `evidence` | File/line or inventory evidence. | yes |
| `mitigation_ids` | Existing mitigation references. | yes (as `M-NNN`) |

No separate root-cause ID is required. The architectural origin of a finding
is conveyed by the title prose (e.g. *"Cross-origin request abuse through
permissive CORS"*) — `rule_id` does not need to surface.

### 3.2 Threat Hypotheses (unchanged from current pipeline)

Existing behavior is kept as-is. This subsection documents what already
exists; no code change required.

- Hypotheses live in `.architecture-coverage.json#threat_hypotheses[]` with
  `ARCH-HYP-<TOKEN>-NNN` ids (`data/architecture-coverage-rules.yaml`
  defines the prefixes: `ARCH-HYP-XSS`, `ARCH-HYP-SQLI`, `ARCH-HYP-AUTHZ`,
  `ARCH-HYP-INPUT`).
- Promotion gate (`scripts/arch_coverage_to_threats.py:178-204`) requires
  `proof_state=confirmed` AND `confidence=high` before a hypothesis becomes
  a `threats[]` entry with `source=threat-hypothesis`.
- Promoted threats carry `hypothesis_id` as a trace backlink.
- Hypotheses MUST NOT appear in the report (enforced by
  `schemas/threat-model.output.schema.yaml:646-650`).

`ARCH-HYP-*` is **internal only** — it surfaces in YAML data, SARIF
`properties.threatHypothesisId`, and pentest-tasks JSON. It is never
rendered in the Markdown report.

Example trace (still applies):

```text
ARCH-HYP-SQLI-001 (hypothesis, internal)
  -> proof_state=confirmed, confidence=high
  -> promoted to T-018 in threats[] (storage)
  -> rendered as F-018 in the report (visible form)
```

### 3.3 Architecture Clusters

Architecture clusters are computed views, not findings.

Cluster headings are **deterministic prose strings** derived from a fixed
lookup keyed by `architectural_theme` enum values. The lookup ships in
`scripts/compose_threat_model.py` (new constant `_THEME_HEADING_TEXT`) and
is not driven by per-finding free text. This avoids drift across runs
without introducing a new identifier.

Example lookup entries:

```python
_THEME_HEADING_TEXT = {
    "Authentication": "Custom authentication logic",
    "Authorization": "Inconsistent authorization enforcement",
    "InputValidation": "Missing centralized input validation",
    "SecureDefaults": "Permissive defaults across browser boundary",
    "SessionDesign": "Insecure session boundary",
    # ... one entry per enum value
}
```

Example rendered shape:

```markdown
### Architecture-Derived Finding Clusters

#### Authentication — Custom authentication logic

Findings: [F-001](#f-001), [F-002](#f-002), [F-007](#f-007),
[F-016](#f-016), [F-024](#f-024), [F-028](#f-028)
```

The heading is just a section heading. The actionable references are still
`F-NNN`. No new identifier is introduced.

## 4. Pipeline Shape

Target flow:

```text
architecture coverage rule (`ARCH-*`)
-> control assessment or hypothesis
-> evidence-backed architecture-derived finding (`F-NNN`)
-> optional computed cluster view by `architectural_theme`
```

Detailed behavior:

1. `architecture_coverage_checks.py` evaluates deterministic architecture
   rules and emits rule provenance plus evidence.
2. If evidence is concrete enough, the bridge emits a normal finding candidate.
3. The merge/finalization path assigns the same stable `F-NNN` IDs used for
   all other findings.
4. The renderer may group findings by `architectural_theme`, but does not
   create separate `AF-NNN` entries.
5. Mitigations continue to address `F-NNN` findings.

## 5. Rendering Changes

### 5.1 Management Summary

Top Findings should remain a table of findings only.

Architecture-derived findings can appear naturally in the same ranking:

```markdown
| # | Finding | Component | Type | Criticality | Primary Mitigations |
|---|---|---|---|---|---|
| 1 | [F-001](#f-001) - SQL injection authentication bypass | backend-api | Code | Critical | [M-002](#m-002) |
| 2 | [F-014](#f-014) - Cross-origin request abuse through permissive CORS | backend-api | Architecture-derived | High | [M-006](#m-006) |
```

No `AF-*` row is needed.

### 5.2 Threat Register

The Threat Register remains the single source of truth for concrete findings.

Architecture-derived findings appear as normal `F-NNN` rows. **No `Rule`
column. No `rule_id` badges.** The architectural origin is conveyed by:

- the finding title prose (e.g. *"Cross-origin request abuse through
  permissive CORS"* — the rule is encoded in the wording)
- an optional `Theme` column (enum text, e.g. `SecureDefaults` — not an ID)
- an optional `Source` text tag (e.g. `Architecture coverage` vs `STRIDE`)

| Column | Example | New ID surfaced? |
|---|---|---|
| ID | `F-014` | no (existing) |
| Finding | Cross-origin request abuse through permissive CORS | no |
| Source | Architecture coverage | no (text tag) |
| Theme | SecureDefaults | no (enum text) |
| Component | backend-api | no (existing `C-NN`) |
| Evidence | `server.ts:12` | no |

`rule_id` (e.g. `ARCH-CORS-001`) stays in internal artifacts only:

- `threat-model.yaml` → `threats[].rule_id`
- SARIF export → `properties.architectureCoverageRuleId`
  (`scripts/export_sarif.py:140-142`)
- Pentest-tasks JSON (`scripts/render_pentest_tasks.py:591`)

The Markdown report does not render `ARCH-*` anywhere.

### 5.3 Architecture Cluster Section

Add an optional computed section only when there are enough architecture-tagged
findings to make it useful.

This section must not introduce a new ID class. The `Description` column is
deterministic prose from the `_THEME_HEADING_TEXT` lookup (see §3.3) — not a
free-text per-finding string. Only `F-NNN` and `M-NNN` link out.

```markdown
## Architecture-Derived Finding Clusters

| Theme | Description | Findings | Primary Mitigations |
|---|---|---|---|
| InputValidation | Missing centralized input validation | [F-003](#f-003), [F-008](#f-008), [F-011](#f-011) | [M-002](#m-002) |
| Authorization | Inconsistent authorization enforcement | [F-010](#f-010), [F-018](#f-018), [F-029](#f-029) | [M-009](#m-009) |
```

This gives the root-cause view without turning the root cause into a second
finding. The `Description` text is the same lookup value used for cluster
sub-section headings, so the report tells one consistent story.

### 5.4 Mitigation Register

Mitigations continue to reference findings:

```yaml
mitigations:
  - id: M-006
    title: Restrict CORS to trusted origins
    threat_ids: [F-014]
```

If one mitigation addresses several architecture-derived findings, list every
affected `F-NNN`:

```yaml
threat_ids: [F-010, F-018, F-029]
```

No `addresses_architectural[]`, `architectural_finding_ids[]`, or `AF-*`
reference is needed.

## 6. Schema Implications

Minimal additive schema changes (most fields already exist):

- Allow architecture metadata on existing finding/threat objects:
  - `rule_id` — already present in `schemas/threats-merged.schema.yaml:98`
    and `schemas/threat-model.output.schema.yaml:493,671`
  - `architectural_theme` — already present in same schemas (enum from
    `schemas/architecture-weakness-catalog.schema.yaml:42-58`, kept inline
    after catalog removal)
  - `generic_threat_title` — already present
- Keep `rule_id` restricted to architecture-derived sources (`source` in
  `{architecture-coverage, threat-hypothesis}`).
- Do not add `architectural_findings[]`.
- Do not add `weakness_id`.
- Do not add `architecture_weakness` (any per-finding free-text root-cause
  field would become a de-facto shadow ID for clustering).
- Do not add `AF-*` references to mitigation schemas.

The validator should enforce:

- `source=architecture-coverage` requires `rule_id`.
- `rule_id` must match `^ARCH-[A-Z]+-[0-9]{3}$`.
- `architectural_theme` must be one of the existing theme enum values
  (inline enum survives the catalog removal — copy enum into both
  threat-model and threats-merged schemas).
- Unconfirmed architecture concerns stay in `threat_hypotheses[]`.

**Promotion threshold** (no new logic — mirrors existing
`scripts/arch_coverage_to_threats.py:148-204`):

- `anti_pattern_candidates` → emitted as findings unconditionally
  (`source=architecture-coverage`).
- `threat_hypotheses` → emitted only if `proof_state=confirmed` AND
  `confidence=high` (`source=threat-hypothesis`); otherwise stay in
  `threat_hypotheses[]` and are not rendered.
- Both paths require at least one `evidence` entry with non-empty `file`.

## 7. QA Rules

QA should check architecture-derived findings, not AF coverage.

Recommended checks:

1. Every `source=architecture-coverage` finding has `rule_id`, evidence, and
   `architectural_theme`.
2. No report text references `AW-*` or `AF-*`.
3. Architecture cluster views only link to valid `F-NNN` findings.
4. Mitigations only target valid finding IDs through canonical mitigation
   fields.
5. If three or more findings share an `architectural_theme`, the optional
   cluster section should include that theme, but this is a reporting-quality
   check, not a second finding requirement.

## 8. Migration From The Earlier AW/AF Draft

### 8.1 Files to delete

- `data/architecture-weakness-catalog.yaml`
- `schemas/architecture-weakness-catalog.schema.yaml`
- `schemas/fragments/architectural-findings.schema.json`

### 8.2 Schema fields to remove

- `schemas/threats-merged.schema.yaml:111` — `weakness_id`
- `schemas/threat-model.output.schema.yaml:504,676` — `weakness_id` (both copies)
- `schemas/architecture-coverage.schema.json:76,170,205,241,318` — 5
  `weakness_id` `$ref` sites
- `schemas/fragments/security-posture-attack-paths.schema.json:83` — AF
  reverse reference

### 8.3 Code to remove

- `scripts/arch_coverage_to_threats.py:63,107,131,132` —
  `_WEAKNESS_TRACE_FIELDS`, `weakness_id` parameter and assignment
- `scripts/architecture_coverage_checks.py:59,145,156,157,161,174` —
  catalog loading and weakness propagation
- `scripts/architect_structural_checks.py:603-664` —
  `architectural_findings` aggregation block
- `scripts/compose_threat_model.py:2343,2412,3324,3345,3447` —
  `architectural_findings` rendering
- `scripts/qa_checks.py:5057-5060` — AF-NNN regex check
- `scripts/validate_config.py:8,256,257` — catalog validation

### 8.4 Tests to update

- `tests/test_arch_coverage_bridge.py`
- `tests/test_architecture_coverage_checks.py:85,91`
- `tests/test_validate_config.py:195,203,219`
- `tests/test_architect_structural_checks.py:518-548`
- `tests/test_compose_threat_model.py:1098`
- `tests/test_enforcement_mutations.py:130`
- `tests/test_p1_renderer_correctness.py:184`
- `tests/test_schema_integrity.py:9,139`

### 8.5 Items that ALREADY match this design (keep unchanged)

- `threat_hypotheses[]` with `ARCH-HYP-*` ids — internal-only, never
  rendered (`schemas/threat-model.output.schema.yaml:646-650`)
- `rule_id` (`^ARCH-[A-Z]+-[0-9]{3}$`) propagation in
  `arch_coverage_to_threats.py` — keep
- `T-NNN` → `F-NNN` visible-label transform
  (`scripts/pregenerate_fragments.py:2217-2251`) — keep
- SARIF `properties.architectureCoverageRuleId` and
  `properties.threatHypothesisId` (`scripts/export_sarif.py:140-145`) — keep
- Pentest-tasks JSON `rule_id`/`hypothesis_id`
  (`scripts/render_pentest_tasks.py:590-592`) — keep

### 8.6 Cluster ordering (replaces preferred_id stability)

After removing the AW catalog, the `preferred_id: AF-005 / AF-008 / AF-016`
mappings in `data/architecture-weakness-catalog.yaml` are gone. Cluster
ordering instead relies on:

- Deterministic ordering by `architectural_theme` enum order (defined
  inline in the schema after catalog removal).
- Within a cluster, findings ordered by `F-NNN` ascending (existing
  rendering contract).
- Cluster heading text from `_THEME_HEADING_TEXT` lookup (§3.3) — fixed
  per enum value, not per finding.

**Tradeoff (acknowledged):** No semantic ID slot is reserved for *"Weak
Authentication Architecture"* across runs. This is weaker than the
preferred_id mechanism, and that loss is accepted by construction — the
F-only design rejects stable architectural identity in favor of fewer
report-facing ID classes.

## 9. Example: Juice Shop

Instead of:

```text
AF-005 Weak Authentication Architecture aggregates F-001, F-002, F-007...
```

Use:

```markdown
#### Authentication

Custom authentication weaknesses appear in 6 findings:
[F-001](#f-001), [F-002](#f-002), [F-007](#f-007),
[F-016](#f-016), [F-024](#f-024), [F-028](#f-028).
```

The individual findings remain concrete:

```yaml
id: F-002
title: JWT forgery through hardcoded RSA private key
source: stride
architectural_theme: Authentication
evidence:
  - file: lib/insecurity.ts
    line: 23
```

And:

```yaml
id: F-016
title: Session theft through browser-accessible JWT storage
source: architecture-coverage
rule_id: ARCH-COOKIE-001        # internal metadata; never rendered
architectural_theme: SessionDesign
evidence:
  - file: frontend/src/app/services/auth.ts
    line: 41
```

## 10. Rollout Plan

This is intentionally smaller than the AF/AW plan, but Phase 3 is
cross-cutting — do not underestimate.

| Phase | Increment | Touches | Risk | Notes |
|---|---|---|---|---|
| 1 | Schema field additions; inline `architectural_theme` enum after catalog delete | `schemas/threats-merged.schema.yaml`, `schemas/threat-model.output.schema.yaml` | low | additive only |
| 2 | Bridge emits findings without `weakness_id` | `scripts/arch_coverage_to_threats.py` (~30 LOC delta) | low | gated by tests |
| 3 | Renderer + structural_checks rewrite — **drop AF emission** | `scripts/compose_threat_model.py` (5 sites), `scripts/architect_structural_checks.py` (~60 LOC), `scripts/qa_checks.py` L2 regex, 2 fragment schemas (deleted) | **high** | cross-cutting; rewrites §8.D/§8.G contract, security-posture cross-refs, anchor scheme |
| 4 | Cluster view by `architectural_theme` + `_THEME_HEADING_TEXT` lookup | renderer + heading-lookup table | medium | needs deterministic heading source (§3.3) |
| 5 | Prompt updates — strip `AW-*` / `AF-*`; verify no new ID classes leak | `agents/phases/phase-group-threats.md` (lines 539, 679, 803, 810, 849), `agents/phases/phase-group-finalization.md` (lines 531, 1247), `agents/appsec-qa-reviewer.md` (lines 338, 666, 923) | medium | review LLM output for hallucinated AF-IDs |
| 6 | Test sweep | full test suite — 8 test files modified, schema-integrity tests rewritten | medium | see §8.4 |

## 11. Test Plan

Unit tests:

- Architecture coverage candidate becomes a normal finding candidate.
- `source=architecture-coverage` without `rule_id` fails validation.
- Invalid `architectural_theme` fails validation.
- Renderer produces only `F-NNN` links for architecture-derived issues.
- Cluster view links only to existing `F-NNN` anchors.
- **No `AW-*`, `AF-*`, or `ARCH-*` appears in generated report output.**
  (The `ARCH-*` assertion catches §5.2 regressions where `rule_id` might
  leak into a column or badge.)

Integration tests:

- Synthetic repo with CORS, SQLi, and AuthZ architecture signals produces
  architecture-derived findings with normal `F-NNN` IDs.
- A report with three `InputValidation` findings renders an
  architecture-cluster row headed by `InputValidation` with the
  `_THEME_HEADING_TEXT["InputValidation"]` description, linking to those
  findings.
- Mitigation register references the affected findings directly.

Negative / regression tests:

- **Cluster ordering stability:** two runs with the same architecture
  findings in permuted input order produce byte-identical cluster
  sub-sections (deterministic `architectural_theme` enum order +
  `F-NNN` ascending within cluster).
- **Schema backward compatibility:** an existing `threat-model.yaml` with
  no `weakness_id`/`architectural_findings[]` fields validates against the
  new schema without error.
- **Migration drop:** a fixture with the old AW/AF shape loads, unknown
  fields (`weakness_id`, `architectural_findings`) are ignored (not error),
  `AF-NNN` entries are dropped from rendered output.
- **No ID-class leak:** grep the rendered Markdown for `ARCH-[A-Z]+-[0-9]`
  and `AF-[0-9]` — both must return zero matches.
- **SARIF/pentest-tasks parity:** the internal artifacts continue to carry
  `rule_id` and `hypothesis_id` exactly as before (no regression in
  machine-readable surfaces).

## 12. Acceptance Criteria

The F-only design is complete when:

1. Architecture-derived issues appear as normal `F-NNN` findings.
2. No new public ID class is introduced for architecture weaknesses.
3. `ARCH-*` remains internal provenance only — does not appear in the
   rendered Markdown report (no column, no badge, no link). Surfaces only
   in YAML data, SARIF properties, and pentest-tasks JSON.
4. All architecture cluster summaries link to concrete `F-NNN` findings.
5. Management Summary and Threat Register can rank architecture-derived
   findings without separate `AF-*` rows.
6. QA rejects orphan architecture metadata and invalid `ARCH-*` provenance.
7. Cluster section headings are deterministic across runs (sourced from
   `_THEME_HEADING_TEXT`, no LLM-driven wording variance).
8. SARIF and pentest-tasks JSON outputs continue to carry `rule_id` and
   `hypothesis_id` as before — no regression in machine-readable artifacts.
9. The set of report-facing identifiers is strictly smaller than before:
   `AF-NNN` removed, no replacement introduced.

---

*End of arch2.md - revised F-only design. Do not implement until explicitly
requested.*
