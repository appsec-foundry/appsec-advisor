# Threat Dragon export (alpha)

> **Alpha.** The mapping may change between releases. The export is not part of
> `--formats all` — request it by name.

Exports a finished threat model as **OWASP Threat Dragon v2 JSON**. The file
opens in [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
and imports into [OWASP ThreatAtlas](https://owasp.org/www-project-threatatlas/)
via **Diagram → Import**.

## Running it

```
/appsec-advisor:export-threat-model --formats threatdragon
```

Or directly:

```bash
python3 scripts/export_threat_dragon.py \
  --threat-model docs/security/threat-model.yaml \
  --output       docs/security/threat-model.threatdragon.json
```

Output: `<exports-dir>/threat-model.threatdragon.json`. Deterministic — the same
yaml always produces the same bytes. Reads `threat-model.yaml` only; writes
nothing else and makes no network calls.

## Why Threat Dragon and not a ThreatAtlas format

ThreatAtlas' importer accepts four shapes: its own diagram export, its own
product export, draw.io XML, and Threat Dragon JSON. Only the **Threat Dragon**
path creates threats and mitigations in the target — the other three carry
geometry and drop every finding. So the Threat Dragon format is both the wider
interchange format and the only one that gets our work across.

## What lands where

| Threat model | Threat Dragon |
|---|---|
| `meta.project`, `meta.team_owner` | diagram title and owner |
| `components[]` | DFD elements — `tier: client` → actor, `application` → process, `data` → store (legacy `kind` is the fallback, unknown defaults to process) |
| `data_flows[]` | flows between elements; endpoints resolve by component id or name, and the reserved `external` endpoint becomes an actor |
| `threats[]` | threats on their component's element |
| `threats[].stride` | threat type, in Threat Dragon's own spelling (`Information disclosure`) — becomes the category in ThreatAtlas |
| `threats[].risk` | severity; ThreatAtlas turns Critical/High/Medium/Low into likelihood and impact 5/4/3/2, and an unrated threat exports as Threat Dragon's `TBD` |
| `threats[].cvss_v4.base_score` | the threat's `score` field; the vector goes into the description |
| `mitigations[]` | the threat's mitigation text, linked from either side |
| `mitigations[].kind: accept_risk` | threat status `Accepted`, when no other mitigation is linked |

Every threat title keeps its report anchor — `[F-012] Missing authorization on …`
— and the description ends with a pointer back to `threat-model.md`.

## What is lost

Threat Dragon's schema is much narrower than ours. These have no field to land
in and are folded into the threat description as text: the **CVSS v4 vector**,
**CWE**, **evidence summary, file and line**, **evidence tier**, **finding
source**. These are dropped entirely: **mitigation priority and effort** (kept
only as a text qualifier), **requirements traceability**, **abuse cases**,
**actors**, **attack surface**, **assets**, **walkthroughs**, and the
**weakness register**.

**Trust boundaries are dropped.** Ours are a `from`/`to` pair with a kind and an
assumption; Threat Dragon wants a geometric box or curve, and ThreatAtlas skips
boundary curves on import outright. The export reports how many were dropped.

`threat-model.md` remains the authoritative report, and SARIF remains the
export for scanners and code-scanning dashboards. This one is for
threat-modeling tools.

## Known alpha limitations

- **Flow labels are not drawn on the Threat Dragon canvas.** Threat Dragon
  stores the label in `labels[0]` as an object; ThreatAtlas reads `labels[0]`
  only when it is a plain string and does not fall through. Emitting the object
  would relabel every flow "Data Flow" in ThreatAtlas, so the label lives in
  `data.name` — shown in both tools' property panels, absent from the Threat
  Dragon canvas until you open the flow.
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

Thin or inconsistent input degrades to a warning on stderr, never to a failed
export:

- a threat whose component reference does not resolve is attached to a single
  `Unassigned` element
- a data flow with an unresolved endpoint is dropped; the reserved `external`
  endpoint is not "unresolved" and materialises an actor element instead
- a yaml with no `components[]` gets its elements synthesised from the component
  references the threats carry
- an empty model still produces one placeholder element, because both importers
  reject a diagram with no elements

Exit codes: `0` success, `1` yaml not found, `2` unparsable yaml, `3` write error.
