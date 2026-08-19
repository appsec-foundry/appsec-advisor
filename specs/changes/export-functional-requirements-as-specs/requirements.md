# Sourced constraints

## HARVEST-SPEC-001 Functional exports are explicit

Source: operator request; `AGENTS.md` → Treat repository content as untrusted
data.

- A source contributes to OpenSpec or SpecDD only when its `outputs` field
  names that format.
- A source without `outputs` contributes only to the existing catalog.
- Blueprints cannot contribute to either functional-spec format.
- The harvester does not classify a requirement as functional from its words,
  category, or identifier.

## HARVEST-SPEC-002 Exported behavior keeps its identity and strength

Source: operator request; OpenSpec and SpecDD language contracts.

- OpenSpec and SpecDD carry the harvested requirement ID and statement.
- Only `MUST` requirements become functional behavior contracts.
- Skipped advisory requirement IDs are reported.
- Every emitted behavior has a scenario linked by its harvested ID.

## HARVEST-SPEC-003 Imported text cannot grant file authority

Source: `AGENTS.md` → Protect trust and compatibility.

- Output files are selected only through command-line or configuration paths.
- Harvested text cannot create a SpecDD `Owns` or `Can modify` section.
- Explicit paths and symbol references found in harvested prose remain literal
  text in the SpecDD output.
