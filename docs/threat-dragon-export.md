# Threat Dragon export (alpha)

> **Alpha.** The mapping may change between releases. Request this format explicitly; `--formats all` does not include it.

Export architecture and findings from a finished Security Assessment as OWASP Threat Dragon v2 JSON for use in a separate threat-modeling workflow. Open the file in [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) or import it into [OWASP ThreatAtlas](https://owasp.org/www-project-threatatlas/) through **Diagram → Import**.

## Running it

During a scan, so the file is written alongside the report:

```text
/appsec-advisor:appsec-analyzer --threatdragon
```

Or from an existing assessment, without re-scanning:

```text
/appsec-advisor:export-security-assessment --formats threatdragon
```

Or directly from the plugin checkout, replacing the paths with your assessment file and export destination:

```bash
python3 scripts/exporters/export_threat_dragon.py \
  --threat-model /path/to/assessment/security-assessment.yaml \
  --output /path/to/exports/security-assessment.threatdragon.json
```

The export skill reads `security-assessment.yaml` from the application's assessment directory and writes `<exports-dir>/security-assessment.threatdragon.json`. The standalone script uses the input and output paths you pass; its input flag remains `--threat-model`. The same YAML produces the same bytes. The script writes no other files and makes no network calls. See [where assessments are stored](security-assessment.md#where-results-are-stored) for directory selection and legacy imports.

## Why Threat Dragon and not a ThreatAtlas format

ThreatAtlas accepts its own diagram and product exports, draw.io XML, and Threat Dragon JSON. Only the Threat Dragon import creates threats and mitigations; the other formats carry diagram geometry without findings.

## What lands where

| Assessment data | Threat Dragon |
|---|---|
| `meta.project`, `meta.team_owner` | diagram title and owner |
| `components[]` | DFD elements: `tier: client` → actor, `application` → process, `data` → store (legacy `kind` is the fallback, unknown defaults to process) |
| `data_flows[]` | flows between elements; endpoints resolve by component id or name, and the reserved `external` endpoint becomes an actor |
| `threats[]` | threats on their component's element |
| `threats[].stride` | threat type, in Threat Dragon's own spelling (`Information disclosure`); used as the category in ThreatAtlas |
| `threats[].risk` | severity; ThreatAtlas turns Critical/High/Medium/Low into likelihood and impact 5/4/3/2, and an unrated threat exports as Threat Dragon's `TBD` |
| `threats[].cvss_v4.base_score` | the threat's `score` field; the vector goes into the description |
| `threats[].boundary_refs[]` | the crossing and its exposure, in the threat description; a flow across a confirmed internet crossing is also marked `isPublicNetwork` |
| `requirements_compliance`, `threats[].violated_requirements` | bounded requirement status and title lines in the linked threat descriptions, plus document-level counts |
| `abuse_case_analysis` | bounded case verdict, verification state, and matching-step lines in each participating threat description, plus document-level counts |
| `business_context_trace`, `threats[].business_context_basis` | bounded provenance and applied field names in each affected threat description; source prose is never copied |
| `mitigations[]` | the threat's mitigation text, linked from either side |
| `mitigations[].fulfills_requirements`, `mitigations[].blueprint` | bounded requirement and implementation-blueprint text in the mitigation field |
| `mitigations[].kind: accept_risk` | threat status `Accepted`, when no other mitigation is linked |

Threat titles retain their report anchor, for example `[F-012] Missing authorization on …`. Descriptions currently still name `threat-model.md`; for a current assessment, open the same finding anchor in `security-assessment.md`.

## What is lost

Threat Dragon has no native fields for several report dimensions. The export includes the CVSS v4 vector, CWE, evidence summary and location, evidence tier, finding source, mitigation priority and effort, requirements traceability, abuse-case links, and business-context use as bounded text. Requirement and abuse-case rows beyond the stated limits remain only in `security-assessment.yaml` and `security-assessment.md`. Actors, attack surface, assets, walkthroughs, and the weakness register are omitted.

The exporter reports counted warnings for requirements, abuse cases, and business context whose semantics had to be folded into text. It never represents those records as synthetic threats, so finding counts remain stable.

**Trust boundaries are not drawn.** The source model describes crossings with endpoints, a kind, and an assumption. Threat Dragon requires a geometric box or curve, and ThreatAtlas skips boundary curves on import. The exporter reports the omitted count. Referenced crossings remain in threat descriptions, for example `tb-2 external → rest-api (internet-facing)`. Flows across confirmed internet crossings receive `isPublicNetwork`. The complete catalog remains in `security-assessment.yaml` and SARIF.

`security-assessment.md` remains the authoritative report; this export is for threat-modeling tools, SARIF for scanners.

## Known alpha limitations

- **Flow labels are not drawn on the Threat Dragon canvas.** Open a flow to read
  its label; both tools show it in the property panel. Drawing it on the canvas
  would relabel every flow "Data Flow" in ThreatAtlas.
- **One diagram.** ThreatAtlas reads `detail.diagrams[0]` and ignores the rest,
  so the whole model is flattened into a single diagram.
- **Threats are exported as `Open`, apart from accepted risks.** Our
  mitigations are proposed, not verified as implemented, so claiming
  `Mitigated` would be untrue; `accept_risk` is the one kind that records a
  decision already taken.
- **Layout is a fixed three-column grid** (actors, processes, stores). It keeps
  the output byte-stable; rearrange it in the target tool.
- **Large models import slowly into ThreatAtlas.** Its importer issues two to
  four API calls per finding from the browser.

## Best-effort behaviour

The exporter handles these incomplete inputs with warnings on stderr:

- a threat whose component reference does not resolve is attached to a single `Unassigned` element
- a data flow with an unresolved endpoint is dropped; the reserved `external` endpoint is not "unresolved" and materialises an actor element instead
- a YAML document with no `components[]` gets elements from the component references in its threats
- an empty model still produces one placeholder element, because both importers reject a diagram with no elements

Exit codes: `0` success, `1` YAML not found, `2` unparsable YAML, `3` write error.
