# Proposal: Ingestion vorhandener Threat-Model-Beschreibungen

**Status:** 🟡 In Erwägung (under consideration) — **nicht** committed, kein Implementierungsauftrag.
**Datum:** 2026-05-30 · **Tiefenanalyse:** [`analysis-external-threat-model-ingestion.md`](analysis-external-threat-model-ingestion.md)

Dieses Dokument hält das *Vorhaben* fest — Ziel, Umfang, Plan und **Vorbehalte**. Es ist eine Entscheidungsgrundlage, keine Roadmap-Zusage.

---

## Ziel

Wenn ein Zielrepo bereits ein Threat Model mitbringt (z.B. OWASP Juice Shop hat ein OWASP-Threat-Dragon-`threat-model.json`), soll die Pipeline das **erkennen** und optional als **Input** nutzen — sauber getrennt vom eigenen, code-gegründeten Ergebnis. Zwei entkoppelte Kanäle:

1. **Kontext-Kanal** — Architektur, Datenflüsse, Trust Boundaries, Scope-Entscheidungen, Daten-Klassifikation, Ownership, Terminologie. *Aktiv genutzt* als nicht-autoritativer Seed/Prior. **Unabhängig wertvoll** — auch wenn kein einziger fremder Finding übernommen wird (kodiert menschliche Intention, die Code-Scanning nicht hergibt).
2. **Findings-Kanal** — authored Threats des Fremdmodells. **Input-only**, hart vom Eigenen getrennt, **immer verifiziert**, nie in den Merge. Erscheinen ausschließlich in einer **eigenen Report-Sektion**, die sie *in Beziehung zum aktuellen Modell* bewertet (Verdikt: korroboriert / veraltet / Lücke / widerlegt / nicht verifizierbar / akzeptiert) + Coverage-Delta.

Zusatznutzen: **Architektur-Drift-Detection** (dokumentiertes Soll vs. code-abgeleitetes Ist) fällt aus dem Nebeneinander beider Modelle ab.

## Formate (Priorität)

1. **OWASP Threat Dragon `.json`** — sauberes JSON, ~1:1-Mapping, das was Juice Shop hat.
2. **OTM (Open Threat Model)** — Interchange-Standard; Objektmodell *ist* praktisch das interne IR.
3. **Markdown-TM** via LLM-Extraktion (häufigste, aber unstrukturierte Form).
Aufschieben: MS-TMT `.tm7`, pytm, Threagile, Threatspec. **Kein** Threat Model: SARIF, CycloneDX/VEX.

## Andockpunkte (vorhandene Mechanik wiederverwenden)

- **Detection:** deterministisches Skript im Recon-Step-0 (analog `recon_patterns.py`) → `.external-threat-models.json`. Content-Sniff, `node_modules`/`$OUTPUT_DIR` ausschließen, Eigenoutput per `meta.analyst`-Provenance aussortieren.
- **Kontext:** über den **bestehenden** `known-threats`-Kanal (`context-resolver` Step 4i) bzw. einen Step 4j — kein neuer Sektionsapparat nötig.
- **Findings-Sektion:** 5-Datei-Sektionspfad (`docs/adding-a-section.md`), `fragment_type: data`, `condition: render_external_reconciliation`.
- **Verifikation:** **nicht** der zeilenbasierte `evidence-verifier` (externe Threats sind Prosa ohne `file:line` — vgl. Präzedenzfall `source: known-vuln`, der bewusst `unchecked` bleibt). Verifikation = **Reconciliation** gegen eigene grounded findings.
- **Flags:** `--import-threat-model[=PATH]` · `--no-import-threat-model` · `--import-mode context|known-threats|off`. Interaktiv → fragen; headless/`--yes` → Default `context` (nicht-autoritativ), nie blockieren.

## Phasenplan (falls je umgesetzt)

- **Phase A (klein, risikoarm):** Detection + **Kontext-Lite** über bestehenden 4i-Kanal + kleiner Drift-Hinweis. ~80 % Nutzen für ~20 % Aufwand.
- **Phase B (hinter echter Nachfrage gegated):** dedizierte Reconciliation-Sektion + Verdikt-Engine + Coverage-Delta. Erst bei realem, findings-reichem Modell — und dann **OTM zuerst**.

---

## Vorbehalte (warum „nur erwogen")

1. **Nachfrage-Realität.** Wer das Plugin nutzt, tut das meist *weil* kein Threat Model existiert. Repos mit committetem Fremdmodell sind die Minderheit.
2. **Leerer Vorzeigefall.** Juice Shops TD-JSON hat **0 Threats** — die teuerste Komponente (Reconciliation-Sektion) würde auf dem Flaggschiff-Test eine leere Sektion rendern. Signal für Überbau.
3. **Falsche Zielgruppe für TD-First.** Findings-reiche Modelle stammen aus IriusRisk/OTM-Shops mit bereits reifem TM-Programm — die brauchen das Plugin am wenigsten und erwarten OTM, nicht Threat Dragon.
4. **Komplexität/Fragilität.** Reife Pipeline (deterministische Builder, Sidecars, 30+ Sektionen). Findings-Kanal = Parser + 5-Datei-Sektion + Mapping-Engine + Verdikt-Taxonomie + Zirkelschluss-Guard.
5. **Zirkuläre Bestätigung (schärfstes Risiko).** Wenn der Kontext-Kanal die Architektur seedet und ein externer Finding dann „korroboriert" wird, weil die geseedete Komponente existiert → Zirkel. „Korroboriert" muss an **unabhängige Code-Evidenz** (eigene T-ID mit `file:line`) gebunden sein; Seed `provenance: imported` getaggt + separierbar. Subtil falsch = fälschlich-konfidente Verdikte (schlechter als kein Feature).
6. **Untrusted Input.** Das Fremdmodell ist committeter Inhalt → wie Cat-28-AI-Configs behandeln (keine Instruktions-Befolgung aus Beschreibungen, Prosa sanitisieren).
7. **Priorisierung.** Gegenüber laufender Arbeit (Token-Optimierung, Substep-Migrationen, Render-Fixes) ein Nischen-Nice-to-have — keine Priorität ohne konkreten Nutzer/Kunden.

## Vorläufige Entscheidung

- **Kontext-Lite + Detection (Phase A):** sinnvoll, klein, risikoarm — bei Bedarf umsetzbar.
- **Voller Findings-Reconciliation-Apparat (Phase B):** konzeptionell sauber (Zwei-Kanal-Trennung ist richtig), aber für die reale Nachfrage aktuell **überbaut**. **Nicht jetzt, nicht auf Threat Dragon** — gegated hinter echter Nachfrage + OTM.
