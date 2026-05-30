# Analyse: Integration vorhandener Threat-Model-Beschreibungen

Status: Analyse + Empfehlung (kein Code). Erstellt 2026-05-30.

## 1. Was wirklich in Juice Shop liegt (code-level verifiziert)

| Datei | Format | Inhalt | Relevanz |
|-------|--------|--------|----------|
| `threat-model.json` (root) | **OWASP Threat Dragon v2** (`summary`+`detail.diagrams[].diagramJson.cells[]`, `tm.Actor/Process/Store/Flow/Boundary`, `diagramType: STRIDE`) | DFD: 5 Actors, 3 Processes, 3 Stores, 15 Flows, 5 Trust Boundaries. **0 enumerierte Threats** (`cell.threats[]` leer) | **Echtes externes Artefakt.** Wert = Architektur/Datenfluss/Trust-Boundaries, NICHT Threats |
| `docs/security/threat-model.yaml` | **appsec-advisor Eigenoutput** (`meta.analyst: appsec-threat-analyst`, `schema_version`) | Voller Eigenlauf | **NICHT extern** — Eigenproduktion. Darf nicht als "gefundenes fremdes Modell" zirkulär reingezogen werden |
| `docs/security/threat-model.md` / `.threats-merged.json` | appsec-advisor Eigenoutput | — | dito |
| `templates/tachi/*.sarif/.md` | Fremd-Plugin (tachi) Templates | leere Schablonen | irrelevant |

**Schlüsselbefund:** Das einzige integrierbare Fremdmodell hier ist das Threat-Dragon-JSON — und ausgerechnet das hat **null Threats**, nur ein DFD. Das prägt die ganze Empfehlung: der Gewinn aus Ingestion ist primär das **Architekturmodell** (Komponenten, Flows, Trust Boundaries, Actors), nicht eine fertige Bedrohungsliste.

## 2. Format-Landschaft (Prävalenz × Parsebarkeit)

| Format | Detection | Datenmodell | Parse | Prävalenz | → IR-Mapping |
|--------|-----------|-------------|-------|-----------|--------------|
| **OWASP Threat Dragon** `.json` | `summary`+`detail`, cells `type: tm.*` | DFD + inline `cell.threats[]{title,type,severity,status,description,mitigation}` (denormalisiert) | JSON, sauber | **HOCH** (führendes OSS-GUI-Tool, das tatsächlich committed wird) | **leicht**, ~1:1; Trust-Boundary-Mitgliedschaft ist geometrisch (Bounding-Box) |
| **OTM (Open Threat Model)** `.otm/.yaml/.json` | top-level `otmVersion`+`project` | `project/components/trustZones/dataflows/threats[]/mitigations[]` — normalisiert (Katalog + id-refs) | JSON/YAML, sauber, JSON-Schema publiziert | MITTEL, aber **strategischer Interchange-Standard** (StartLeft konvertiert TMT/TD/Terraform → OTM) | **am leichtesten** — OTM *ist* praktisch das interne IR |
| **Markdown TM** (`threat-model.md`, STRIDE/LINDDUN, Cookbook) | Dateiname + Headings + Pipe-Tabellen + mermaid DFD | unstrukturiert→semi | Markdown, brüchig | **HÖCHSTE Rohzahl** (die meisten Teams machen TM als Doc) | **schwer deterministisch, leicht per LLM-Extraktion** |
| **MS Threat Modeling Tool** `.tm7` | `.tm7` XML, `<ThreatModel>` | DFD + ThreatInstances, .NET-serialisiert | XML, schmerzhaft | HOCH historisch, fallend (Legacy-Enterprise) | **schwer** — besser via StartLeft → OTM |
| **pytm** (Python DSL) | `from pytm import` | code-definiert; Threats werden *generiert*, nicht authored | `.py` (nicht ausführen!) / generiertes `--json` | MITTEL (TM-as-code) | nur generiertes JSON nutzen |
| **Threagile** `threagile.yaml` | `technical_assets:`+`trust_boundaries:` | YAML asset-zentrisch; Risks generiert (`risks.json`) | YAML sauber; Trust-Boundary **referenziell** (schöner als TD) | MITTEL | mittel; braucht generiertes `risks.json` für Threats |
| **Threatspec** | `@threat/@control/@mitigates` Annotationen | verteilt im Code | Grammatik-regulär / aggregiertes JSON | NIEDRIG, Nische | mittel-schwer |
| **SARIF** `.sarif` | `$schema sarif-2.1.0` | Static-Analysis-Findings, **keine** Architektur | — | — | **KEIN Threat Model** — nur Korrelation |
| **CycloneDX/VEX** | `bomFormat: CycloneDX` | SBOM / CVE-Exploitability | — | — | **KEIN Threat Model** — Supply-Chain, orthogonal |

**Zwei strukturelle Achsen, die jedes IR abdecken muss:**
- Threat-Anbindung: **inline-denormalisiert** (Threat Dragon, Markdown) vs. **Katalog + id-refs** (OTM, Threagile, pytm).
- Trust-Boundary-Mitgliedschaft: **geometrisch/Containment** (TD, TMT) vs. **referenziell** (OTM `parent`, Threagile `technical_assets_inside`).
- "TM-as-code"-Tools (pytm/Threagile/Threatspec) **authoren Architektur, generieren Threats per Regeln** → committetes Source-File hat evtl. 0 Threats (wie Juice Shops TD-JSON).

## 3. Wo es im Pipeline-Code andocken würde (es gibt bereits das Muster)

Die Pipeline hat **schon einen Präzedenzfall** für "team-provided prior threats":

- `appsec-context-resolver.md → Step 4i — Known threats`: liest `docs/known-threats.yaml` (eigenes Schema: `threats[]{id,title,stride,severity,status}`) **verbatim** in `.threat-modeling-context.md`. STRIDE-Analyzer + QA lesen das als Kreuzreferenz.
- `config.json → external_context.rest_url`: externer Kontext via REST.
- Deterministische Pre-Pass-Mechanik existiert: `phase-group-recon.md → Step 0` ruft `recon_patterns.py` und schreibt `.recon-patterns.json`. **Genau dort** gehört eine Format-Detection hin.

→ Die saubere Erweiterung ist ein **Step 4j "Existing third-party threat model"** im context-resolver + eine deterministische Detection im Recon-Step-0. Architektonisch konsistent, kein neuer Sonderweg.

## 4. Ehrliche Bewertung deines Vorschlags

Dein Instinkt (auto-detect → per Default fragen → explizite Opt-in/Opt-out-Parameter) ist im Kern richtig, aber an **fünf Stellen würde ich nachschärfen** — sonst entstehen echte Probleme:

### 4.1 Eigenoutput von Fremdmodell trennen (sonst Zirkularität)
`docs/security/threat-model.{yaml,md}` ist appsec-advisors **eigene** Produktion. Bei jedem Re-Run würde eine naive "es existiert ein Threat Model"-Detection das als Fund melden und nach Ingestion fragen → falsche Prompts, potenziell zirkuläre Einspeisung. **Detection muss per Pfad UND Provenance filtern** (`meta.analyst: appsec-threat-analyst` ⇒ self ⇒ ignorieren). Das ist nicht optional, das ist die häufigste Fehlerquelle.

### 4.2 Threat Dragon liefert hier v.a. das DFD — also Architektur-Seed, nicht Threat-Liste
appsec-advisor baut in Phasen 3–7 selbst C4-Komponenten + Trust Boundaries + Actors auf. Ein TD-Modell sollte als **Seed/Prior** in die Architektur-Phase fließen (Komponenten/Flows/Boundaries/Actors nicht neu erraten müssen), **getaggt `provenance: imported`**. Authored Threats (falls vorhanden — bei Juice Shop = keine) gehören in den **known-threats-Kanal (4i)**, nicht direkt in die finale Merge-Liste.

### 4.3 Externe Inhalte sind Evidenz/Kontext, NICHT Ground Truth
Die Pipeline hat einen `evidence-verifier` + QA-Phasen, die annehmen, dass Findings **code-gegründet** sind. Ein importiertes Modell kann veraltet, partiell oder einfach falsch sein (Juice Shops 0-Threats-DFD ist das Paradebeispiel). **Niemals** externe Threats ungeprüft in `.threats-merged.json` mergen — das verseucht Evidence-Verification und Triage. Stattdessen als "Prior model says X — covered? gap?"-Kreuzreferenz behandeln (exakt wie known-threats).

### 4.4 "Per Default fragen" kollidiert mit dem Headless-Design
Die Pipeline ist auf unbeaufsichtigten Lauf gebaut (`--yes/--no-confirm`, `run-headless.sh`, Budget-Watchdogs, CI). Ein interaktiver Default-Prompt **bricht CI-Läufe**. Richtige Auflösung:
- **immer detektieren** (deterministisch, billig),
- **interaktiv**: fragen (AskUserQuestion-Stil),
- **headless/`--yes`**: sicherer Default = **als Kontext importieren, nicht-autoritativ** (oder `ignore-with-note`, siehe 5) — nie blockieren.

### 4.5 Scope-Creep: nicht alle Formate auf einmal
Alle 7+ Formate zu unterstützen ist viel Oberfläche. **Phasiert** vorgehen (siehe Empfehlung).

## 5. Empfehlung

### Parameter-Oberfläche (auf `create-threat-model`)
```
--import-threat-model[=PATH]     Externes Modell importieren (autodetect wenn PATH fehlt)
--no-import-threat-model         Detection-Fund ignorieren (still, mit Notiz im Report)
--import-mode <context|known-threats|off>
                                 context       = Architektur-Seed + nicht-autoritativer Kontext (Default)
                                 known-threats = authored Threats in den 4i-Kreuzreferenz-Kanal
                                 off           = nur erwähnen, nichts einspeisen
```
**Default-Verhalten:** immer detektieren. Interaktiv → per `AskUserQuestion` fragen (Fund anzeigen: Format, #Komponenten/#Flows/#Boundaries/#Threats, Provenance). Headless/`--yes` → `--import-mode context` (nicht-autoritativ), Fund + Entscheidung im Report-Changelog protokollieren.

### Detection (deterministisch, im Recon-Step-0)
Neues Skript analog `recon_patterns.py`, läuft in `phase-group-recon.md → Step 0`, schreibt `.external-threat-models.json`:
```json
[{ "path": "...", "format": "threat-dragon|otm|markdown|...",
   "confidence": "high|medium", "provenance": "self|external",
   "counts": {"components":N,"dataflows":N,"boundaries":N,"actors":N,"threats":N} }]
```
- **Content-Sniff, nicht nur Dateiname** (false positives vermeiden).
- `node_modules`/`vendor`/`$OUTPUT_DIR` ausschließen; `meta.analyst == appsec-threat-analyst` ⇒ `provenance: self` ⇒ aus Ingestion-Kandidaten raus.

### Ingestion (context-resolver Step 4j)
Detektierte **externe** Modelle → in kleines IR normalisieren → Abschnitt "Existing Threat Model (third-party)" in `.threat-modeling-context.md` + strukturiertes Sidecar `.imported-threat-model.json`. Architektur-Phasen lesen die importierten Elemente als **Seed mit `provenance: imported`** — weiterhin der normalen Evidence-Verification unterworfen. Authored Threats → known-threats-Kanal.

### Format-Roadmap (priorisiert)
1. **v1: OWASP Threat Dragon `.json`** — Juice Shop hat's, sauberes JSON, hohe Prävalenz, ~1:1-Mapping. Plus den bestehenden `known-threats.yaml`-Kanal wiederverwenden. **Hier anfangen.**
2. **v2: OTM** — der Interchange-Standard; sein Objektmodell *ist* das IR; öffnet indirekt TMT/Terraform/Lucidchart über StartLeft.
3. **v3: Markdown-TM** via LLM-Extraktion (häufigste Form, aber unstrukturiert) — Best-Effort.
4. **Aufschieben:** `.tm7` (lieber via StartLeft→OTM), pytm/Threagile (nur generiertes JSON), Threatspec (Nische). **SARIF / CycloneDX-VEX sind keine Threat Models** — höchstens Korrelations-Enrichment, nicht Discovery.

### Honest bottom line
- Ja, integrierbar — und es passt sauber in vorhandene Mechanik (4i known-threats, Recon-Step-0-Pre-Pass, external_context). Kein architektonischer Bruch.
- Aber der **größte konkrete Nutzen** für den Juice-Shop-Fall ist das **DFD als Architektur-Seed**, nicht eine Threat-Übernahme (das Modell hat keine Threats).
- Die **zwei nicht-verhandelbaren Leitplanken**: (a) Eigenoutput hart von Fremdmodell trennen (Provenance), (b) Importiertes als nicht-autoritative Evidenz behandeln, nie ungeprüft in den Merge. Alles andere (Prompt-by-default, Flags) ist gut — nur Headless-tauglich machen.
- Start klein: **Threat Dragon → Architektur-Seed + known-threats-Kreuzreferenz**, ein Detection-Skript, ein Step 4j, drei Flags. OTM als nächster Schritt.

---

# Part 2 — Vertiefung: Kontext vs. Findings (zwei entkoppelte Kanäle)

Nachschärfung nach Feedback: Es geht **nicht nur um Findings**, sondern mindestens ebenso um den **Kontext**, der sich aus einem Fremdmodell ziehen lässt. Findings sind reiner **Input** (hart von Eigenen getrennt, immer verifiziert) und bekommen eine **eigene Report-Sektion**, in der sie *in Beziehung zum aktuellen Modell* bewertet werden. Der Kontext dagegen ist **unabhängig davon wichtig** — auch wenn am Ende kein einziger externer Finding übernommen wird.

## 2.1 Reframe: zwei Kanäle, unterschiedliche Vertrauens- und Verifikationsmodelle

| | **Kontext-Kanal** | **Findings-Kanal** |
|---|---|---|
| Inhalt | Architektur, Datenflüsse, Trust Boundaries, Scope, Daten-Klassifikation, Ownership, Terminologie, Intention | Authored Threats des Fremdmodells |
| Rolle | **aktiv genutzt** als Prior/Seed — beeinflusst eigene Analyse | **input-only** — nie in eigene Findings gemerged |
| Vertrauen | nicht-autoritativ, aber lenkend | nicht-autoritativ, immer verifiziert |
| Verifikation | implizit (eigene Analyse bestätigt/verwirft Seed) | **Reconciliation** gegen eigene grounded findings |
| Wert bei 0 Threats | **hoch** (Juice-Shop-Fall!) | null |
| Report | fließt in §2 Architektur / Diagramme ein, getaggt | **eigene Sektion** mit Verdikt-Tabelle |

**Entkopplung ist der Kern:** Man kann `Kontext=on, Findings=reconcile-only` fahren — der sichere Default. Die beiden Kanäle haben *unterschiedliche Mechanik* und dürfen nicht vermischt werden.

## 2.2 Kontext-Kanal — was extrahierbar ist und wo es andockt

| Kontext-Element | Quelle (Format) | Speist Phase | Aus Code rekonstruierbar? |
|---|---|---|---|
| Komponenten / Prozesse / Stores | TD cells · OTM components · Threagile technical_assets | Phase 3–4 (C4) | teilweise |
| Datenflüsse (source→target, Protokoll) | TD tm.Flow · OTM dataflows · Threagile communication_links | Phase 4 | teilweise (Aufruf-Graph ≠ kuratierter Fluss) |
| **Trust Boundaries + Semantik** | TD tm.Boundary · OTM trustZones · Threagile trust_boundaries | Phase 4–7 | **NEIN** — Zonierung ist menschliche Intention |
| **Scope-Entscheidungen** (`outOfScope`) | TD outOfScope · OTM | Severity/Scope-Kalibrierung | **NEIN** — explizite Scoping-Entscheidung |
| Daten-Klassifikation / CIA | OTM assets risk{C,I,A} · pytm Data.classification | Phase 5 (Asset-Klassifikation) | teilweise (Feldnamen heuristisch) |
| Control-Eigenschaften (isEncrypted, isPublicNetwork, implementsAuth) | TD cell-flags · pytm element-attrs | Phase 7 (Controls) | teilweise — nur Hinweis, muss verifiziert werden |
| **Ownership / Team / Geschäftskontext** | TD summary.owner · OTM project.owner+description | context-resolver (business context) | **NEIN** |
| **Terminologie / Benennung** | alle | Diagramm-Labels, Alignment mit Team-Mentalmodell | **NEIN** |
| Prior accepted risks / mitigation status | OTM threat.state · TD threat.status · Threagile risk_tracking | known-threats-Kanal + Reconciliation | **NEIN** |

**Die „NEIN"-Zeilen sind das Gold.** Sie kodieren **menschliche Intention und Urteil, das Code-Scanning strukturell nicht zurückgewinnen kann.** Genau deshalb ist Kontext *unabhängig von Findings* wertvoll — sogar bei einem Modell mit null Threats. Die Pipeline leitet Architektur heute aus Code ab (verlustbehaftet, intentionsblind); das Fremdmodell ist kuratiertes Expertenwissen über *Soll-Zustand, Scope und Sensitivität*.

### Bonus-Wert: Architektur-Drift-Detection (Soll vs. Ist)
Sobald **beide** Modelle vorliegen (extern = dokumentiert/intendiert, eigen = aus Code abgeleitet), wird ihr Vergleich selbst zum Signal:
- Store/Komponente im Modell, aber nicht mehr im Code → **veraltetes Modell**.
- Komponente im Code, aber nicht im Modell → **undokumentierte / Shadow-Komponente** (echtes Risiko).
- Trust Boundary im Modell, im Code aber durchbrochen → **Boundary-Drift**.

Das ist eine **neue Findings-Klasse**, die *nur* aus dem Nebeneinander zweier Modelle entsteht. Eigenständiger Wert, unabhängig davon ob man externe Threats übernimmt.

## 2.3 Findings-Kanal — warum „immer verifizieren" hier anders funktioniert

**Code-verifizierter Knackpunkt:** Der `evidence-verifier` verifiziert, indem er `evidence.file` ±5 Zeilen **erneut liest** (`appsec-evidence-verifier.md:83`). Externe Findings (z.B. Threat-Dragon-Threats) sind **Prosa ohne file:line** (`title/type/severity/status/description/mitigation`). Sie können den zeilenbasierten Verifier **nicht** durchlaufen.

Die Pipeline hat den exakten Präzedenzfall schon: `source: known-vuln`-Findings werden vom Verifier **`unchecked` gelassen**, weil „the evidence is the advisory, not a code line" (`:65`). Externe Modell-Findings haben dieselbe Form.

→ **Verifikation externer Findings ≠ Zeilen-Reread, sondern Reconciliation:** jeden externen Threat auf eigene Komponenten/Datenflüsse mappen, dann prüfen, ob die **eigene, unabhängig code-gegründete** Analyse ihn bestätigt. **Die Reconciliation *ist* die Verifikation.** Das ist ein anderer Mechanismus — er gehört nicht in den evidence-verifier gebolzt, sondern als eigener Schritt (auf dem known-vuln-Muster aufbauend).

**Never-merge + Provenance:** externe Findings tragen `source: external-model:<path>`, zählen **nie** in eigene Finding-Totals / Severity-Statistik / SARIF-„our findings" / Risk-Heatmap. Sie leben in `.imported-threat-model.json` und erscheinen ausschließlich in der Reconciliation-Sektion.

## 2.4 Die dedizierte Reconciliation-Sektion (eigener §-Abschnitt)

Jeder externe Finding bekommt ein **Verdikt relativ zum aktuellen Modell**:

| Verdikt | Bedeutung | Aktion |
|---|---|---|
| **Korroboriert** | eigene code-gegründete Analyse fand denselben Threat unabhängig | eigene T-ID verlinken; erhöht Konfidenz beider |
| **Veraltet / gemildert** | extern „open", eigene Analyse zeigt Control existiert jetzt | externes Modell als stale markieren |
| **Lücke / Net-new** | externer Threat ohne eigenes Pendant | untersuchen: eigene Analyse übersehen ODER nicht code-gegründet |
| **Widerlegt** | eigene Evidenz widerspricht der externen Behauptung | als refuted führen |
| **Nicht verifizierbar** | referenziert Architektur, die im Code fehlt / keine Evidenz | nur als Kontext führen, markiert |
| **Akzeptiert / out-of-scope** | extern als accepted risk markiert | als akzeptiert führen, nicht neu eskalieren |

Plus **Beziehungs-Mapping** (extern → eigene T-IDs: 1:1 / 1:n / keine) und **Coverage-Delta** (welcher %-Anteil externer Threats vom eigenen Modell gedeckt; wie viele eigene Findings das externe Modell *nicht* hat).

**Was die Sektion NICHT tun darf:** eigene Risk-Ratings ändern, Counts beeinflussen, externe Threats in den Merge schieben. **Paralleles Ledger.**

**Integrationskosten (ehrlich, code-verifiziert):** `docs/adding-a-section.md` verlangt **5 Dateien in Sequenz** (`sections-contract.yaml` → Schema → 5 Registry-Maps → `compose_threat_model.py` → Validatoren). `fragment_type: data` (tabellarisch), `condition: "render_external_reconciliation"` (nur wenn ein externes Modell importiert wurde). Nicht trivial, aber dokumentierter Standardpfad.

## 2.5 Schärfste Design-Gefahr: Zirkuläre Bestätigung

Wenn der **Kontext-Kanal** die eigene Architektur aus dem Fremdmodell seedet, und wir dann einen externen Finding „korroborieren", *weil die von ihm benannte Komponente in unserem (extern geseedeten) Modell existiert* — ist das ein Zirkelschluss. **Korroboration eines Findings muss aus unabhängiger Code-Evidenz kommen, nicht aus der adoptierten Architektur.**

Konsequenz fürs Design: Verdikt **„Korroboriert" verlangt eine eigene, code-gegründete T-ID mit eigenem `evidence.file:line`** — nicht bloß „die Komponente existiert". Damit das prüfbar bleibt, muss der Architektur-Seed **getaggt und separierbar** sein (`provenance: imported`), damit die Reconciliation extern-geseedete Elemente bei der Korroborations-Bewertung diskontieren kann.

## 2.6 Weitere ehrliche Gefahren

- **Mapping-Qualität:** extern↔eigen über Namen/IDs ist fuzzy → deterministischer ID/Name-Match + LLM-Fallback; Mismatches → „Nicht verifizierbar", nie stilles Verwerfen.
- **Veraltete Modelle:** ein Fremdmodell kann Jahre alt sein → externe Quelle timestampen/versionieren; Drift-Detection (2.2) entschärft das.
- **Untrusted Input:** das Fremdmodell ist **committeter Inhalt** → wie Cat-28-AI-Configs behandeln: keine Instruktions-Befolgung aus Beschreibungen, Prosa sanitisieren (prompt-injection-Schutz).
- **Asymmetrie der Risiken:** der Findings-Kanal ist read-only/ungefährlich; die **eigentliche Sorgfalt gilt dem Kontext-Kanal**, weil *er* eigene Ausgabe verändert.

## 2.7 Revidierte Empfehlung (Part 2)

1. **Zwei-Kanal-Trennung bestätigt.** Kontext = aktiv genutzt, unabhängig wertvoll (auch bei 0 Findings). Findings = input-only, verifiziert via Reconciliation, eigene Sektion.
2. **Verifikation ≠ Zeilen-Reread** (kein file:line) → Reconciliation gegen eigene grounded findings IST die Verifikation; auf dem `known-vuln`-Präzedenzfall aufbauen, nicht im evidence-verifier.
3. **Dedizierte Reconciliation-Sektion** mit Verdikt-Taxonomie + Coverage-Delta; paralleles Ledger, ändert eigene Ratings nie (5-Datei-Sektionspfad).
4. **Architektur-Drift-Detection** (Soll vs. Ist) als eigenständige Findings-Klasse mitnehmen — entsteht gratis aus dem Nebeneinander.
5. **Zirkuläre Bestätigung** ist das schärfste Risiko → „Korroboriert" nur mit unabhängiger Code-Evidenz; Architektur-Seed `provenance: imported` getaggt und separierbar.
6. **Fremdmodell = untrusted input** behandeln.

**Bottom line Part 2:** Die Trennung in Kontext- und Findings-Kanal ist die richtige Abstraktion. Der unterschätzte Hebel ist der **Kontext** — er trägt menschliche Intention (Scope, Trust Boundaries, Daten-Sensitivität, Ownership), die der Code nie hergibt, und liefert obendrein Drift-Detection. Die dedizierte Findings-Sektion ist sinnvoll und passt in den vorhandenen §-Mechanismus — solange sie ein **paralleles, nicht-autoritatives Ledger** bleibt und „Korroboriert" an unabhängige Code-Evidenz gebunden ist, um den Zirkelschluss zu vermeiden.
