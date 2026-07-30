# Analysis — an optional export format for OWASP ThreatAtlas

Date: 2026-07-30
Status: analysis / proposal, nothing implemented
Upstream: <https://github.com/OWASP/www-project-threatatlas> (OWASP Incubator)

## Question

How can `appsec-advisor` offer an additional optional output format so a finished
threat model can be loaded into OWASP ThreatAtlas? Scope an MVP first, and say
what a larger, explicitly alpha-labelled version would add.

## 1. What ThreatAtlas actually is

ThreatAtlas is not a file format. It is a self-hosted web application:
FastAPI backend + React/ReactFlow frontend + database. Its data model is

| Entity | Meaning |
|---|---|
| `Product` | The system under analysis (name, description, status, owner) |
| `Diagram` | A DFD; `diagram_data` is ReactFlow `{nodes, edges}` JSON |
| `Framework` | STRIDE, LINDDUN, … — owns catalogs of `Threat` and `Mitigation` entries |
| `Model` | One analysis = `diagram_id` × `framework_id` |
| `DiagramThreat` | The actual finding: `element_id`, `element_type`, `threat_id`, `status`, `likelihood` 1–5, `impact` 1–5 |
| `DiagramMitigation` | Mitigation attached to an element and (optionally) a `DiagramThreat` |

So "exporting to ThreatAtlas" means producing something that populates
`Diagram` **plus** `DiagramThreat`/`DiagramMitigation`. A diagram alone is
almost worthless — it throws away every finding we produce.

## 2. Which ingest paths exist

Three, and only one of them is a plain file that carries findings.

### 2a. UI import (file) — the viable one

`threatatlas-app/frontend/src/components/ImportDrawioButton.tsx` accepts
`.xml`, `.drawio`, `.json` and sniffs the format:

| Detected format | Diagram imported | **Threats imported** |
|---|---|---|
| ThreatAtlas diagram export (`nodes`+`edges`+`exportedAt`+`version`) | yes | **no** — `setImportedThreats([])` at line 1022, despite a toast that claims otherwise |
| ThreatAtlas product export (`product`+`exported_at`+`diagrams`) | yes | **no** — `setImportedThreats([])` |
| **OWASP Threat Dragon v1/v2 JSON** | yes | **yes** — `parseThreatDragonJson`, then `threatsApi.create` + `diagramThreatsApi.create` + `diagramMitigationsApi.create` per threat |
| draw.io XML | yes | no |

That is the decisive finding: **Threat Dragon JSON is the only file format that
carries threats and mitigations into ThreatAtlas.** Its own native export
round-trips geometry only.

### 2b. REST API

`Authorization: Bearer <API token>` (Settings → API Tokens). Documented for CI
in `threatatlas-app/docs/ci-integration.md`, but that guide only covers
`GET /api/products/{id}/security-status` — the write endpoints
(`products`, `diagrams`, `models`, `diagram-threats`, `diagram-mitigations`)
exist and the frontend uses them, but are not documented as a stable
integration contract.

### 2c. MCP server

ThreatAtlas ships an MCP server (`threatatlas-app/docs/mcp.md`) with
`create_product`, `create_diagram(diagram_data=ReactFlow JSON)`,
`create_diagram_model`, `apply_component_template`, etc. Interactive, not a
pipeline artifact — and per AGENTS.md our analysis agents carry no MCP tools in
their allow-lists, so the pipeline can never call it.

## 3. Recommendation

**MVP = emit OWASP Threat Dragon v2 JSON**, as a new optional export
`threat-model.threatdragon.json`.

Why this and not an API push:

- It is the only path that lands findings, not just boxes.
- Zero coupling: no URL, no token, no network call, no ThreatAtlas version
  pinned. Honours "no hidden network calls" without an allowlist debate.
- It is a byte-deterministic file → golden-fixture testable exactly like
  `export_sarif.py`.
- It is worth more than a ThreatAtlas adapter: the same file opens in OWASP
  Threat Dragon itself and in every tool that reads TD JSON. We ship an OWASP
  interchange format, not a vendor bridge.

The API/MCP push is the alpha tier (§7).

## 4. Target format — what the parser really requires

Read from `parseThreatDragonJson` (lines 731–876) and the import step
(lines 1206–1315). This is narrower than the full Threat Dragon schema, so pin
to the parser, not to prose about TD.

Envelope — only `detail.diagrams[0].cells` is read. **One diagram; later
diagrams are silently dropped.**

```json
{
  "version": "2.4.0",
  "summary": { "title": "<project>", "owner": "<team_owner>", "description": "..." },
  "detail": {
    "contributors": [],
    "diagrams": [ { "id": 0, "title": "...", "diagramType": "STRIDE",
                    "version": "2.4.0", "cells": [ ... ] } ],
    "diagramTop": 1, "reviewer": "", "threatTop": 0
  }
}
```

Node cell — every field the parser touches:

```json
{
  "id": "C-01",
  "shape": "process",                       // process | store | actor | trust-boundary-box
  "position": { "x": 400, "y": 120 },
  "size": { "width": 160, "height": 80 },
  "data": {
    "name": "Order API",                    // becomes the node label
    "type": "tm.Process",                   // tm.Process | tm.Store | tm.Actor | tm.BoundaryBox
    "threats": [ { "title": "...", "type": "Spoofing", "status": "Open",
                   "severity": "High", "description": "...", "mitigation": "..." } ]
  }
}
```

`mapTdType` checks `shape` **or** `data.type` — emit both, they agree.

Edge cell:

```json
{
  "id": "DF-01",
  "shape": "flow",
  "source": { "cell": "C-01" },
  "target": { "cell": "C-04" },
  "data": { "name": "order submit (HTTPS)", "threats": [ ... ] }
}
```

Hard constraints found in the parser:

- Edges must use `source.cell` / `source.target.cell` as **string ids**. The
  TS interface also lists `.id`, but the code reads only `.cell`. Using `.id`
  silently drops the edge.
- `cell.labels[0]` is used only when it is a plain string; real TD writes label
  objects there. Put the flow label in `data.name`.
- `shape: "trust-boundary-curve"` is **skipped outright** (`continue`). Boundary
  curves never reach ThreatAtlas.
- `nodes.length === 0` throws. At least one node is mandatory.
- Node/edge ids are namespaced on import (`td-<id>`, `td-edge-<id>-<ts>`), so
  our ids need not be UUIDs — the yaml's own `rest-api` / `df-001` slugs carry
  through and are better for humans.

Threat field mapping performed by ThreatAtlas on import:

| TD field | Lands in ThreatAtlas as |
|---|---|
| `title` | `Threat.name` (custom KB entry, `is_custom: true`) |
| `description` | `Threat.description` |
| `type` | `Threat.category` |
| `severity` | `critical/high/medium/low` → `likelihood`+`impact` of 5/4/3/2; anything else → both `null` |
| `status` | `open`→identified, `mitigated`/`closed`→mitigated, `accepted`/`not applicable`→accepted; default identified |
| `mitigation` | A `Mitigation` named `Mitigate: <title>` with this string as description, linked to the element and the threat |

Note the severity map is case-insensitive but exact-token: `Informational`
produces `null` likelihood and impact, i.e. an unscored finding.

## 5. Mapping `threat-model.yaml` → Threat Dragon

Source of truth: `schemas/threat-model.output.schema.yaml`.

| appsec-advisor | Threat Dragon | Rule |
|---|---|---|
| `meta.project` | `summary.title` | — |
| `meta.team_owner` | `summary.owner` | — |
| `components[]` | node cells | cell id = the yaml `components[].id` (a lowercase slug such as `rest-api`; `C-NN` is a display label the composer assigns, never the yaml id), label `name` |
| `components[].tier` | node shape | `client`→`actor`/`tm.Actor`, `application`→`process`/`tm.Process`, `data`→`store`/`tm.Store` |
| `data_flows[]` | `shape: flow` cells | `from`/`to` must resolve to component ids; label `"<label> (<protocol>)"` |
| `threats[]` | `data.threats[]` on the node whose id equals `threat.component` | orphan component ref → attach to a synthetic `Unassigned` process node |
| `threats[].title` | `threat.title` | prefix the public anchor: `[F-012] Missing authz on …` |
| `threats[].stride` | `threat.type` | verbatim STRIDE name → becomes `Threat.category` |
| `threats[].risk` | `threat.severity` | `Critical/High/Medium/Low` verbatim-lowercased; **`Informational` → `low`**, otherwise it imports unscored |
| `threats[].scenario` + `evidence_summary` + `evidence[]` | `threat.description` | render `file:line` list as text — TD has no structured evidence |
| `mitigations[]` where `threat_ids` contains the threat | `threat.mitigation` | join `title` + `steps[]` + `verification` into one string |
| `mitigations[].kind == "accept_risk"` | `threat.status = "Accepted"` | everything else `Open` |
| `trust_boundaries[]` | — | **dropped in MVP** (see §6) |

Geometry must be deterministic for golden fixtures. Simple columnar layout:
x = 80 / 400 / 720 by tier (actor / process / store), y = 80 + 140·index within
the column, `size` 160×80. No force-directed layout, no randomness.

## 6. What is lost — state it in the docs, do not paper over it

Threat Dragon's schema has no place for these, so the export drops them:

- CVSS v4 vectors and scores, `cwe`
- structured evidence (`file`, `line`) — only prose survives
- `evidence_tier`, `triage_flags`, `evidence_check`, `_status`
- mitigation `priority` (P1–P4), `effort`, `verification` as a separate field
- requirements traceability (`violated_requirements`, `fulfills_requirements`)
- abuse cases, actors, attack surface, assets, walkthroughs, weakness register
- trust boundaries: our model is a `from`/`to` pair with `kind`/`assumption`,
  Threat Dragon wants a geometric box or curve. Curves are skipped by
  ThreatAtlas anyway, and synthesising boxes needs containment geometry we do
  not have. Out of MVP scope.

Mitigation for the traceability loss: keep the `F-NNN` anchor in every threat
title and put the `threat-model.md` deep link in the description. That way a
ThreatAtlas entry always points back at the authoritative report.

SARIF stays the machine-readable export for scanners; Threat Dragon JSON is the
threat-modeling-tool export. They are not substitutes.

## 7. Scope tiers

### Tier 1 — MVP (recommended first cut)

New deterministic emitter, same shape as `export_sarif.py`:

```
scripts/export_threat_dragon.py
    --threat-model <threat-model.yaml>
    --output       <threat-model.threatdragon.json>
    [--diagram-title <str>]
exit 0 ok / 1 yaml missing / 2 yaml unparsable or invalid / 3 write error
```

Wiring:

1. `skills/export-threat-model/SKILL.md` — add `threatdragon` to the accepted
   `--formats` tokens, its `DO_*` flag, the help block and the OUTPUTS list.
   **Do not add it to `all`** while it is alpha.
2. `data/required-permissions.yaml` + `tests/test_check_permissions.py` for the
   new script invocation.
3. `tests/test_export_threat_dragon.py` — mapping per field, tier→shape,
   severity map incl. the `Informational`→`low` case, orphan component ref,
   flow whose endpoint does not resolve, empty-components abort, and a golden
   fixture asserting byte-stable output.
4. `CHANGELOG.md` — one user-visible bullet.

Not in Tier 1: no `--threat-dragon` pipeline flag in `resolve_config.py`, no
`outputs.threat_dragon` in `schemas/org-profile.schema.yaml`. Ship it
skill-only, promote it once the format has survived a real import.

Estimated size: one ~250-line script plus its test. It reads only
`threat-model.yaml`; nothing upstream changes.

### Tier 2 — alpha, still file-only

- Trust boundaries as `trust-boundary-box` cells, derived from
  `deployment_zones`, with containment geometry computed from the layout.
  Visible in ThreatAtlas as `boundary` nodes.
- Threats on data flows (`data.threats` on flow cells) once threats carry a
  flow reference.
- `attack_surface[]` entry points as external actor nodes.

### Tier 3 — alpha, networked push

`scripts/push_threatatlas.py`: create product → diagram → model → per-element
threats and mitigations over the REST API.

Everything here is a genuine risk surface, which is why it is alpha and
opt-in only:

- outbound writes to a user-supplied URL — must be explicit
  (`--threatatlas-url`), never derived from repository content, and checked
  against `policy.url_allowlist`
- token handling (`THREATATLAS_TOKEN` env only, never a flag, never logged)
- the write endpoints are undocumented as a contract; only `security-status` is
  covered by their test suite, so this can break on any upstream release
- N+1 request pattern: one `POST /threats` + one `POST /diagram-threats`
  (+ optionally two more for the mitigation) **per finding**. A 150-finding
  model is ~450 requests.
- not testable without a live instance → no CI coverage, only a recorded-fixture
  test at best

Recommendation: do Tier 3 only if someone actually asks for it. The file import
covers the same ground with none of this.

## 8. How to mark the format alpha

There is no existing alpha convention in the repo, so pick one and apply it
consistently:

- `--formats` help text: `threatdragon  OWASP Threat Dragon JSON (alpha)`
- one stderr line from the emitter:
  `NOTE: Threat Dragon export is alpha — the mapping may change between releases.`
  (stderr, so it never pollutes the artifact)
- a `_meta` note inside the JSON: `"summary.description"` gets a trailing
  `Generated by appsec-advisor <version> — alpha Threat Dragon export.`
- the docs section states plainly what is dropped (§6)

Once a real ThreatAtlas import has been verified end-to-end, drop the alpha
marker, add it to `all`, and only then consider the org-profile output flag.

## 9. Open questions

1. Do we name the format `threatdragon` (what it is) or `threatatlas` (why we
   built it)? Recommendation: `threatdragon`, with the ThreatAtlas use case
   named in the help text — the file is genuinely the OWASP format and other
   tools consume it.
2. `trust_boundaries[].from` / `.to` — do they carry component ids or zone
   names? The output schema puts no pattern on them (free-form string, ≤128
   chars), unlike `data_flows[]`, whose endpoints are constrained to
   `^(?:external|[a-z][a-z0-9-]+)$` — i.e. component-id slugs plus the
   reserved `external`. Needs a check against live output before Tier 2 can
   compute containment.
3. Should the export be verified against real OWASP Threat Dragon (not just
   the ThreatAtlas parser) before the alpha marker comes off? Recommendation:
   yes — that is what makes the format worth shipping.

## Sources

- `ImportDrawioButton.tsx` lines 705–880 (parser), 990–1050 (format sniffing),
  1206–1315 (threat/mitigation creation)
- `backend/app/schemas/{threat,mitigation,model,product,diagram,diagram_version}.py`
- `backend/app/models/{threat,model,enums}.py`
- `docs/{mcp,ci-integration}.md`
- local: `schemas/threat-model.output.schema.yaml`, `scripts/export_sarif.py`,
  `skills/export-threat-model/SKILL.md`
