# Multi-Repo Threat Modeling — Offene Punkte

Status: Variante X (Consumer-Pull-Erweiterung der `related-repos.yaml`-Strecke) ist umgesetzt — `expected_auth` und `expected_validation` werden vom Loader extrahiert, der Register-Builder reicht `upstream_properties` (mit `provenance: upstream-asserted`) und `expectation_mismatch` durch zum Slicer und STRIDE-Analyzer. Beide Schemata sind erweitert, Tests grün.

**Diese Doc listet nur noch, was *nicht* umgesetzt ist.**

> **Actor-Layer Non-Goal (actors.md §15.4):** Cross-Repo Actor Resolution ist explizit **nicht** im Scope des Actor-Layer-Konzepts. `related-repos.yaml` triggert keinen Actor-Pull aus Nachbar-Repos. ACT-D-07 (compromised-third-party-service) wird ausschließlich über erkennbare externe API-Calls im Hauptrepo aktiviert, nicht über `related-repos.yaml`. Föderierte Actor-Modelle (Profile B erbt Actor-Definitionen aus Repo A) sind Phase 2.

---

## 1. Offene Schicht-1-Aufgaben (Security Charter)

Charter existiert heute nicht. Org-Profile ist Plugin-Config, kein Threat-Modeling-Charter.

| # | Lücke | Härtegrad | Anmerkung |
|---|---|---|---|
| L1 | Strukturiertes Security Charter (Actors, Compliance, Business-Impact-Klassen, Severity-Maßstäbe) | groß | Neues Schema + Resolver. Actors, Compliance-IDs, Severity-Anker org-weit kuratiert. |
| L2 | Charter-Referenzen im Repo-TM (`applicable_actors`, `compliance_scope`) | klein | Optional-Felder im TM-Schema; Repo-TM verweist statt zu duplizieren. |

---

## 2. Offene Schicht-2-Aufgaben (Repo-TM-Erweiterungen)

Heute fehlen strukturierte Felder, die Composition voraussetzen würde.

| # | Lücke | Härtegrad | Anmerkung |
|---|---|---|---|
| L3 | Stabile Interface-IDs in `components[]` / `attack_surface[]` | mittel | Heute Substring-Match an Strings. Tier-1-Matching wäre der Pflicht-Pfad für präzise Composition. |
| L4 | `consumed_interfaces[]` als strukturiertes Recon-Artefakt | mittel | Recon Section 25 strukturieren: `{url_pattern, method, source_file:line, called_from_component_id, payload_fields, inferred_auth, inferred_validation}`. Pattern-Match auf HTTP-Client-Setup im Consumer-Code (z. B. `Authorization: Bearer`, `clientCert`, `joi.validate(response)`) — ersetzt die manuelle Deklaration von `expected_auth` / `expected_validation`, wenn sie maschinell ableitbar sind, mit Provenance `inferred-from-code`. |
| L11 | **Strukturierte `data_flows[]` im TM-Schema** | groß | Heute nur narrativ im Mermaid + Markdown. Voraussetzung für jede topologische Composition. Schema-Erweiterung + Phase-9/10b-Prompt + Renderer. |
| L12 | Per-Feld-PII-Tagging in Interface-Payloads | mittel | Heute Asset-Klassifikation grob (`Public/Internal/Confidential/Restricted`). Für End-to-End-PII-Tracking nicht ausreichend. |

---

## 3. Offene Schicht-3-Aufgaben (Composition)

Variante X liefert pull-basierte Properties + deterministisches `expectation_mismatch`. Topologie-Composition fehlt.

| # | Lücke | Härtegrad | Anmerkung |
|---|---|---|---|
| L5 | `architecture-export.yaml` per Repo (Producer-Export) | mittel | Aufbauend auf `route-inventory.json` + `architecture-coverage.json` + `pentest-tasks.yaml > endpoints[]`. Ermöglicht bi-direktionale Sicht („wer ruft mich auf"). |
| L6 | Topology-Composer (`compose_cross_repo_architecture.py`) | mittel | Drei-Tier-Matching: explizite ID → URL+Method → OpenAPI-Spec. Output `cross-repo-architecture.json` mit `composed_flows[]`, `unmatched_consumed[]`, `unmatched_exposed[]`. |
| L8 | Invariant-Breakage / Drift-Detection | klein | Snapshot-Hash über `upstream_properties` pro Lauf. Nächster Lauf vergleicht → auto-Hypothesis bei verschwundenem Control / geändertem Auth. Direkt auf Variante X aufsetzbar. |
| L13 | Cross-Repo-Detector als allgemeiner deterministischer Schritt | mittel | `expectation_mismatch` (heute umgesetzt) ist die Minimal-Variante. Erweitern auf weitere Klassen: Schema-/Payload-Field-Mismatch zwischen Consumer-Call und Producer-Schema, Trust-Vererbung über kompromittiertes Upstream, fehlende DiD an Boundary. |
| L14 | Konflikt-Auflösung bei widersprüchlichen Producer-Aussagen | klein | Regel festlegen wenn zwei Upstreams widersprüchliche Properties über dieselbe geteilte Komponente exportieren. |
| L15 | Async-/Event-Flow-Modell (Topics als Interface-IDs) | mittel | Eigener Schema-Block oder Erweiterung der `composed_flows[]` mit `transport: queue|event|sync`. Producer-Subscriber-Relationen statt Caller-Callee. |

---

## 4. Offene Aufgaben Renderer + STRIDE-Härtung

| # | Lücke | Härtegrad | Anmerkung |
|---|---|---|---|
| L7 | STRIDE-Prompt-Härtung mit Eval-Fixtures | hoch | Minimal-Ergänzung in `appsec-stride-analyzer.md` ist eingebaut. Was fehlt: Polyrepo-Fixtures + Eval-Cases, die regression-stable bestätigen dass „upstream-asserted" niemals Severity senkt. |
| L9 | Renderer-Erweiterungen | mittel | Cross-Repo-Mermaid-Subgraphs, neue Report-Sektion `Cross-Repo Data Flows`, Provenance-Spuren in Triage-Tabellen, `pentest-tasks > endpoints[]`-Annotation. Müssen `sections-contract.yaml`-konform sein. |

---

## 5. Offene Fragen vor weiterer Umsetzung

- **Adoption-Realität:** Wieviele Repos haben heute `docs/related-repos.yaml`? Wieviele nutzen die neuen Felder (`expected_auth` / `expected_validation`)? Vor Schritt L5/L6: messen.
- **Match-Rate:** Heutiges Substring-Matching auf realen Daten messen, bevor Tier-1-IDs (L3) priorisiert werden. Unter 60% → L3 wird Pflicht-Vorarbeit.
- **Charter-Owner (L1):** Wer pflegt das in einer Org? Sec-Team einer reicht — aber wer konkret?
- **ID-Strategie (L3):** Konvention pro Repo, oder Org-Konvention? Wer vergibt sie?
- **Sibling-Auto-Discovery:** Heute metadata-only. Anheben auf Properties (analog Variante X für declared entries), oder bewusst out-of-scope?
- **OpenAPI/AsyncAPI als Brücke:** Vorhandene Specs als Tier-3-Match nutzen, statt eigene Interface-IDs erfinden?
- **Granularität von `data_flows[]` (L11):** Pro Komponente, pro Interface, pro Feld?
- **Composed View — eigenes Dokument oder Section im Repo-TM (L6/L9)?**
- **Transitive Composition** (A→B→C): explizit 1-Hop, oder Graph-Walk?

---

## 6. Realistische Reihenfolge für das Restprogramm

Sortiert nach steigendem Wert pro Aufwand, jede Phase einzeln verifizierbar:

1. **L8 (Drift-Detection)** — direkt auf Variante X aufsetzend, ohne neue Verträge. Snapshot-File + Diff. Realitätsprüfung: nach 3 Wochen noch in Gebrauch?
2. **L1 + L2 (Charter)** — Konsistenz Actors/Compliance über alle Repo-TMs derselben Org. Kein Cross-Repo-Compute nötig.
3. **L11 (strukturierte `data_flows[]`)** — Pflicht-Vorarbeit für jede topologische Composition. Eigenständiger Mehrwert: bessere Repo-lokale Threat-Modeling-Qualität.
4. **L3 + L4 + L5 (Interface-IDs + Consumer-Detection + Producer-Export)** — Repo-lokale Artefakte, einzeln messbar.
5. **L12 (Per-Feld-PII-Tagging)** — optional, nur wenn End-to-End-PII-Tracking gewünscht.
6. **L6 + L13 (Composer + erweiterter Cross-Repo-Detector)** — Topologie-Join + deterministische Cross-Repo-Findings.
7. **L7 + L9 (STRIDE-Eval-Fixtures + Renderer)** — die echte Cross-Repo-Sicht im Report.
8. **L14 + L15** — Robustheit (Konfliktregeln) + Async-/Event-Flows.

Nach Schritt 2 hat man bereits hohe Konsistenz über Repos hinweg, ohne neue Composition. Nach Schritt 4 weiß man, ob Schritt 6+7 sinnvoll ist.
