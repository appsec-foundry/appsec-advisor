# Schemas

JSONSchema (Draft 2020-12) contracts for every structured artifact the plugin
produces or consumes. The schemas are the **single source of truth** for the
data contracts; `plugin/scripts/validate_intermediate.py` loads them at runtime
and enforces them via `jsonschema`.

| Schema | Artifact | Written by | Read by |
|--------|----------|------------|---------|
| `dep-scan.schema.yaml` | `$OUTPUT_DIR/.dep-scan.json` | `appsec-dep-scanner` | orchestrator Phase 10, SARIF renderer |
| `stride.schema.yaml` | `$OUTPUT_DIR/.stride-<component-id>.json` | `appsec-stride-analyzer` | orchestrator Phase 9 merge |
| `threats-merged.schema.yaml` | `$OUTPUT_DIR/.threats-merged.json` | orchestrator Phase 9 | diagram annotator, YAML/SARIF exporters, changelog writer, triage validator |

## Design notes

- Schemas capture **structural** invariants (required fields, enum values,
  field types, regex patterns). They are enforced on every write by the
  producing agent (`validate_intermediate.py <type> <path>`).
- Rules that JSONSchema cannot express in Draft 2020-12 remain as Python
  post-checks inside `validate_intermediate.py`:
  - Sequential `T-NNN` numbering in `threats-merged` (`T-001`, `T-002`, …)
  - Uniqueness of `t_id` across the merged list
  - Redaction rule on `hardcoded_secrets[].snippet` (must contain `****`,
    may not expose more than 4 chars of the original secret)
  - `scenario` in stride findings must be ≥ 10 non-whitespace chars
- Error stubs (objects with `parse_error`) bypass the full schema; they are
  a known failure-state contract between a sub-agent and the orchestrator.

## Versioning

Each schema carries a `$id` of the form
`https://appsec-plugin/schemas/<name>.schema.yaml` and the
`https://json-schema.org/draft/2020-12/schema` meta-schema. Breaking changes
require a version bump in the schema `$id` path (e.g. `/v2/<name>.schema.yaml`)
and a coordinated update across the producing agent, the validator, and any
downstream consumer.
