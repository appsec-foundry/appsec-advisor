# Empfehlung - erste Lieferung Architektur-Coverage fuer appsec-advisor

Stand: 2026-05-16
Scope: fokussierte erste Lieferung fuer zentrale, deterministische Pruefung problematischer Security Controls, Architektur-Anti-Patterns und Threat-Hypothesen.

## TL;DR

Ziel der ersten Lieferung ist nicht "mehr Findings um jeden Preis", sondern eine zentrale Always-on-Pruefung: relevante Routes, Security Controls, Architektur-Anti-Patterns und bedrohungsrelevante Control-Hypothesen werden fuer jeden Run deterministisch bewertet und strukturiert an Phase 6/8/9/11 uebergeben.

Der heutige Skill findet bereits viele konkrete Schwachstellen und architekturelle Schwaechen. Was fehlt, ist ein sauberer Zwischenlayer fuer Bedrohungen, die aus schwachen Sicherheitsabstraktionen entstehen, obwohl noch kein einzelner exploitable Source-to-Sink-Pfad voll bewiesen ist. Beispiele: manuelles HTML-Escaping ohne Framework-Autoescaping, Raw-SQL-Konkatenation mit manuellem Escaping, ad-hoc Authorization ohne Policy-/Security-Framework, oder Regex-/Blacklist-Validierung vor sensitiven Sinks. Diese Faelle sollen als **Threat-Hypothesen** sichtbar werden, aber nicht automatisch als harte Schwachstellen behauptet werden.

Die sinnvolle erste Lieferung ist:

- ein neues `scripts/architecture_coverage_checks.py`
- ein neues `scripts/route_inventory.py` als deterministischer Route-Inventory-MVP
- ein kleiner Regelkatalog `data/architecture-coverage-rules.yaml`
- Schemas `schemas/route-inventory.schema.json` und `schemas/architecture-coverage.schema.json`
- ein neues Runtime-Artefakt `$OUTPUT_DIR/.route-inventory.json`
- ein neues Runtime-Artefakt `$OUTPUT_DIR/.architecture-coverage.json`
- fuenf High-Confidence-Regeln fuer harte Kandidaten: Cookie-/Session-Haertung, CORS-Wildcard mit Credentials, JWT-Algorithmus-/Whitelist-Haertung, Cleartext-Transport, Management-Endpoint-Exposure
- vier konservative Threat-Hypothesis-Regeln: XSS-Exposure durch schwaches Output-Encoding, SQLi-Exposure durch ad-hoc SQL-Zugriff, Broken-Access-Control-Exposure durch inkonsistente AuthZ, Broken-Input-Validation-Exposure durch fehlende strukturierte Validierung

Nicht Teil der ersten Lieferung: umfassende Authorization-Coverage, Tenant-/Ownership-Isolation, Step-Up, Audit-Logging, Kubernetes/Terraform-Ausbau, vollstaendige Taint-Analyse und `signal_required`.

Die Kernregel: **immer pruefen, aber nicht immer ein hartes Finding erzeugen.** Jede Regel bekommt einen Status (`not_applicable`, `present`, `partial`, `weak`, `missing`, `anti_pattern`). Control-Gaps werden in `security_controls[]` sichtbar, plausible Bedrohungen werden als `threat_hypotheses[]` sichtbar, und nur evidenzstarke Faelle werden zu harten Threat-Kandidaten.

Umfassende Authorization-Coverage sollte als mode-aware Folgeausbau geplant werden, nicht als Teil der ersten Lieferung. Der Route-Inventory-MVP ist dafuer die notwendige Vorarbeit.

## Verifizierter Ist-Zustand

### Coverage

`scripts/coverage_checks.py` deckt heute zwei deterministische Checks ab:

- Check A: OWASP Top 10 Coverage ueber `data/owasp-top10-cwes.yaml`
- Check D: Cross-Repo Boundary Coverage ueber `.cross-repo-register.json` oder `.threat-modeling-context.md`

Die Phase-9-Spezifikation injiziert daraus `source: coverage-gap` Threats. Die neue Architektur-Coverage sollte **nicht** einfach in `coverage_checks.py` aufgeblasen werden: sie beeinflusst nicht nur Threat-Kandidaten, sondern auch `attack_surface[]` in Phase 6 und `security_controls[]` in Phase 8. `coverage_checks.py` bleibt fuer OWASP-/Cross-Repo-Coverage; die neue Engine erzeugt ein eigenes Artefakt.

### Recon

`scripts/recon_patterns.py` liefert bereits deterministische Kategorien 11, 14, 15, 17, 18, 21, 22, 23, 24, 27 und 28.

Wichtig: **Cat 11 ist kein allgemeines Route-Inventar.** Es scannt exposed/admin/debug/swagger/actuator/metrics/health-artige Pfade. Ein genereller Check "alle anonymen Routen" braucht vorher einen echten Route Extractor.

Cat 28 ist bereits im Recon-Prepass enthalten. Eine Verschiebung nach `config-iac-checks.yaml` kann nur mit Deduplizierung sinnvoll sein, sonst entstehen doppelte Befunde.

### Attack Surface

`threat-model.yaml -> attack_surface[]` existiert bereits und wird in §5 gerendert. Es ist aber heute ein finaler Report-Katalog aus Phase 6, kein deterministisches Route-Inventar.

Phase 6 enthaelt bereits eine kombinierte Grep-Heuristik fuer viele Frameworks. Diese Logik ist prompt-basiert und wird nicht als wiederverwendbares Artefakt gespeichert. Fuer die erste Lieferung sollte sie in einen deterministischen Route-Inventory-Prepass verschoben werden, der Phase 6 und Architektur-Coverage speist.

### Config/IaC

`data/config-iac-checks.yaml` ist datei- und regex-zentriert. Das passt fuer Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate und npm config.

Kubernetes und Terraform sind im Schema als `iac_type` vorhanden, aber der Config-Scanner-Prompt behandelt sie noch als "room for extension". Diese Erweiterung ist also nicht nur YAML-Arbeit; Inventory/Glob-Logik, Agent-Prompt, Tests und ggf. Finding-Type-Zuordnung muessen mitgezogen werden.

### Severity-Vertraege

Mehrere pauschale Severity-Aussagen aus der urspruenglichen Empfehlung muessen korrigiert werden:

- CWE-307 Rate-Limit-Gap ist individuell maximal **Medium**.
- CWE-942 Permissive CORS ist individuell maximal **High**, nicht Critical.
- CWE-347 JWT-Signature/Algorithmus-Fehler ist individuell maximal **High**, ausser als Keystone in einer validierten Critical Chain.
- `coverage-gap`, `requirements-compliance` und `architectural-anti-pattern` duerfen kein CVSS tragen.

## Erste Lieferung

### Ziel

Problematische Security Controls und Anti-Patterns sollen **immer** geprueft werden, ohne dass jeder STRIDE-Subagent diese Luecken neu rekonstruieren muss.

Die erste Lieferung beantwortet fuer eine kleine Regelmenge deterministisch:

- Ist die Regel auf dieses Repository anwendbar?
- Welche Evidenz wurde gefunden?
- Welcher Control-Status ergibt sich daraus?
- Muss daraus ein harter Threat-Kandidat entstehen, oder reicht ein Control-Gap in `security_controls[]`?

Wichtig: "immer pruefen" bedeutet nicht "immer Finding erzeugen". Ein hartes Finding entsteht nur bei hoher Evidenzdichte und klaren Preconditions.

### Zentrale Umsetzungsentscheidung

Die erste Lieferung sollte **nicht** `coverage_checks.py` erweitern. `coverage_checks.py` bleibt fuer OWASP-/Cross-Repo-Coverage in Phase 9. Die Architektur-Coverage braucht eigene Prepasses, weil sie Phase 6 (`attack_surface[]`), Phase 8 (`security_controls[]`), Phase 9 (Threat-Kandidaten) und Phase 11 (finales YAML-/Report-Rendering) bedient.

Neue Dateien:

- `scripts/route_inventory.py` - deterministischer Route-Extractor-MVP
- `schemas/route-inventory.schema.json` - Schema fuer Route-Inventar
- `data/architecture-coverage-rules.yaml` - kleiner Regelkatalog mit Preconditions, Signalen, Severity-Caps und Output-Typen
- `schemas/architecture-coverage.schema.json` - Schema fuer das Runtime-Artefakt
- `scripts/architecture_coverage_checks.py` - deterministische Engine
- `tests/test_route_inventory.py` - Route-Extraction-Tests
- `tests/test_architecture_coverage_checks.py` - Regeltests und Contract-Tests

Neue Runtime-Artefakte:

- `$OUTPUT_DIR/.route-inventory.json`
- `$OUTPUT_DIR/.architecture-coverage.json`

Bestehende Vertraege, die in derselben Lieferung mitgezogen oder explizit bestaetigt werden muessen:

- `schemas/threat-model.output.schema.yaml` - optionales Top-Level-Feld `threat_hypotheses[]` aufnehmen, wenn Hypothesen im finalen Report sichtbar sein sollen.
- `scripts/validate_intermediate.py` - `threat_hypotheses[]` validieren und sicherstellen, dass unbestaetigte Hypothesen kein CVSS, keine Critical-Risk-/Severity-Einstufung und keine T-/F-ID tragen.
- `scripts/pregenerate_fragments.py` - Section 7 aus `security_controls[]` plus `threat_hypotheses[]` rendern; reine Runtime-JSONs werden sonst nicht report-visible.
- `scripts/render_pentest_tasks.py` - Hypothesen als `architecture-driven-probe`-Quelle aufnehmen, nicht als konkrete Exploit-Tasks aus `threats[]`.
- `scripts/export_sarif.py` - bleibt unveraendert, solange unbestaetigte Hypothesen nicht in `threats[]` geschrieben werden. Wenn sie doch in `threats[]` landen, muss SARIF sie explizit filtern.
- `schemas/threats-merged.schema.yaml`, `schemas/threat-model.output.schema.yaml`, `agents/appsec-threat-analyst.md` und CVSS-/Pentest-Tests - nur dann erweitern, wenn bestaetigte Architektur-Hypothesen mit einem neuen `source` wie `architecture-coverage` oder `threat-hypothesis` in den Threat Register promoviert werden.

Wenn Agent-/Skill-Prompts oder Bash-Aufrufe geaendert werden, `data/required-permissions.yaml` im selben Change pruefen und ggf. aktualisieren.

### Output-Vertrag

#### Route Inventory

`.route-inventory.json` ist ein deterministisches Zwischenartefakt. Es ersetzt `attack_surface[]` nicht, sondern liefert Phase 6 und Architektur-Coverage eine belastbare Route-Basis.

MVP-Vertrag:

```json
{
  "version": 1,
  "routes": [
    {
      "route_id": "R-001",
      "method": "GET",
      "path": "/admin/users",
      "framework": "express",
      "handler_file": "src/routes/admin.ts",
      "handler_line": 42,
      "authn_signal": "middleware_present",
      "authz_signal": "unknown",
      "management_surface": true,
      "confidence": "medium"
    }
  ],
  "coverage": {
    "frameworks_detected": ["express"],
    "unsupported_route_files": []
  }
}
```

MVP-Scope:

- Express/Koa/Fastify/Hapi-artige `app.get(...)` / `router.post(...)` Patterns
- Python FastAPI/Flask Decorators
- Spring/JAX-RS Mapping-Annotations
- ASP.NET minimal APIs (`MapGet`, `MapPost`, ...)
- Rails/Laravel/Gin/Echo nur als best-effort Pattern, nicht als vollstaendiger Parser

Nicht-MVP:

- Kontrollflussanalyse
- Router-Komposition ueber mehrere Dateien
- dynamische Pfadkonstruktion
- object-level Authorization
- Tenant-/Owner-Scope-Pruefung

`authn_signal` und `authz_signal` sind bewusst Signale, keine endgueltigen Urteile. Zulaessige Werte sollten mindestens `present`, `absent`, `unknown`, `middleware_present`, `decorator_present` und `inherited_unknown` abdecken.

#### Architecture Coverage

`.architecture-coverage.json` sollte alle Regeln enthalten, nicht nur Treffer. Dadurch ist pruefbar, dass eine Control wirklich bewertet wurde.

Minimaler Vertrag:

```json
{
  "version": 1,
  "rules_evaluated": [
    {
      "rule_id": "ARCH-CORS-001",
      "title": "CORS wildcard with credentials",
      "status": "anti_pattern",
      "applies": true,
      "confidence": "high",
      "control": "CORS Policy",
      "domain": "FrontendSec",
      "evidence": [
        {"file": "src/server.ts", "line": 42, "signal": "origin:* + credentials:true"}
      ],
      "decision": "emit_control_and_threat_candidate"
    }
  ],
  "control_assessments": [],
  "threat_hypotheses": [],
  "anti_pattern_candidates": [],
  "warnings": []
}
```

Zulaessige `status`-Werte:

- `not_applicable` - Preconditions fehlen, z.B. kein JWT-Signal
- `present` - Control vorhanden, keine erkennbare Schwaeche
- `partial` - Control vorhanden, aber unvollstaendig oder unklar
- `weak` - problematischer Control-Zustand, aber nicht stark genug fuer ein hartes Finding
- `missing` - Control erwartet und nicht belegt
- `anti_pattern` - klare Architektur-/Control-Anti-Pattern-Evidenz

#### Threat Hypotheses

`threat_hypotheses[]` ist der neue Zwischenlayer zwischen Control-Gap und hartem Threat. Eine Hypothese beschreibt eine plausible Bedrohung aus Architektur- und Control-Signalen, ohne zu behaupten, dass ein konkreter Exploit bereits voll bewiesen ist.

Minimaler Vertrag:

```json
{
  "hypothesis_id": "ARCH-HYP-SQLI-001",
  "rule_id": "ARCH-SQLI-001",
  "title": "SQL injection exposure from ad-hoc SQL construction",
  "threat_category_id": "TH-01",
  "stride": "Tampering",
  "cwe": "CWE-89",
  "component_id": "data-persistence",
  "surface": "POST /login",
  "proof_state": "control-derived",
  "confidence": "medium",
  "weak_or_missing_controls": ["Parameterized Database Access"],
  "positive_signals": [
    {"file": "routes/login.ts", "line": 34, "signal": "raw SQL concatenation"}
  ],
  "negative_signals": [
    {"scope": "routes/", "signal": "no parameterized-query or ORM call observed near sink"}
  ],
  "exculpatory_signals": [],
  "decision": "emit_hypothesis_only"
}
```

Zulaessige `proof_state`-Werte:

- `control-derived` - plausible Bedrohung aus schwachem/missing Control und passender Attack Surface; kein vollstaendiger Source-to-Sink-Beweis
- `evidence-backed` - konkrete positive Evidence fuer den gefaehrlichen Mechanismus, aber noch kein vollstaendig verifizierter Exploitpfad
- `confirmed` - Source, Sink, Reachability und fehlende/defekte Kontrolle sind belegt; darf zu hartem Threat-Kandidaten eskalieren

Regeln:

- "Kein Framework" allein ist niemals ein Threat.
- Ein harter Kandidat braucht positive Evidence fuer den gefaehrlichen Mechanismus, nicht nur fehlende Evidence fuer ein Framework.
- Hypothesen ohne `proof_state: confirmed` tragen kein CVSS und duerfen nicht Critical sein.
- `unknown`/`inherited_unknown` bleibt ein gueltiger Zustand und darf nicht als `missing` umgedeutet werden.
- Der Report muss Hypothesen sprachlich als plausible Bedrohung formulieren, nicht als bewiesene Schwachstelle.

#### Finaler YAML- und Report-Pfad

`.architecture-coverage.json` ist nur Runtime-Audit-Input. Wenn eine Hypothese im Report erscheinen soll, muss Phase 11 sie in `threat-model.yaml -> threat_hypotheses[]` persistieren. Ein Hinweis in `security_controls[].notes` reicht nicht als Source of Truth, weil Section 7, Pentest-Tasks und QA sonst keine stabile ID, keinen Status und keine Promotion-Beziehung pruefen koennen.

Empfohlener finaler YAML-Shape:

```yaml
threat_hypotheses:
  - id: HYP-001
    source_hypothesis_id: ARCH-HYP-SQLI-001
    rule_id: ARCH-SQLI-001
    title: SQL injection exposure from ad-hoc SQL construction
    threat_category_id: TH-01
    stride: Tampering
    cwe: CWE-89
    component_id: data-persistence
    domain: InputVal
    surface: POST /login
    proof_state: control-derived
    confidence: medium
    linked_control_ids: [SC-007]
    linked_threat_ids: []
    promoted_threat_id: null
    evidence:
      - file: routes/login.ts
        line: 34
        signal: raw SQL concatenation
    validation_objective: Validate whether attacker-controlled parameters reach the raw SQL construction without parameter binding.
```

Report-Regeln:

- Section 7.2 bekommt bei vorhandenen unbestaetigten Hypothesen eine deterministisch gerenderte Tabelle `Threat Hypotheses Requiring Validation` mit den Spalten `ID`, `Hypothesis`, `Control Gap`, `Evidence`, `Validation`.
- Die passenden Domain-Abschnitte 7.4/7.5/7.7 referenzieren `HYP-NNN` in der Notes-Spalte oder in einer eigenen kompakten `Hypotheses`-Spalte. Die Control-Zeile bleibt der Control-Katalog; die Hypothese erklaert die daraus folgende Bedrohung.
- Section 8 bleibt der Threat Register fuer bestaetigte Findings. Unbestaetigte Hypothesen duerfen dort nicht als normale `T-NNN`/`F-NNN`-Zeilen erscheinen.
- Eine Hypothese bekommt erst beim Promoten einen `promoted_threat_id`. Danach darf Section 8 auf die bestaetigte Threat-ID verweisen, Section 7 darf die Herkunft weiter als `HYP-NNN -> T-NNN` anzeigen.
- Management Summary / Top Findings duerfen unbestaetigte Hypothesen nicht mit bewiesenen Findings mischen. Erlaubt ist hoechstens ein kurzer Zaehler wie "3 threat hypotheses require validation" im Architektur-/Control-Kontext.
- SARIF darf unbestaetigte Hypothesen nicht exportieren. Das ist automatisch erfuellt, solange sie nicht in `threats[]` stehen.
- Pentest-Tasks sollen unbestaetigte Hypothesen als `architecture-driven-probe` mit Ziel "validate or refute HYP-NNN" ausgeben, nicht als Exploit-Task aus einem CWE-eligible `threats[]`-Finding.
- Keine neue `### 7.15`-Sektion einfuehren, ausser `data/sections-contract.yaml`, `pregenerate_fragments.py`, `compose_threat_model.py`, QA und Tests werden bewusst mitgezogen. Fuer die erste Lieferung ist Integration in 7.2 plus Domain-Abschnitte konsistenter.

### Regeln der ersten Lieferung

| Regel | Always-on-Pruefung | Harte Kandidaten nur wenn | Primaerer Output |
|---|---|---|---|
| `ARCH-COOKIE-001` Cookie-/Session-Haertung | Session-/Cookie-Signale aus Recon und Code-Evidence bewerten. | Sensitive Session-Cookies werden explizit ohne `HttpOnly`, `Secure` oder `SameSite` gesetzt. | `control_assessment`; Kandidat bei explizit unsicherem Set-Cookie |
| `ARCH-CORS-001` CORS-Wildcard mit Credentials | CORS-Signale aus Recon 7.18 und Code/IaC bewerten. | Wildcard-Origin und Credentials treten gemeinsam auf. | `anti_pattern_candidate` |
| `ARCH-JWT-001` JWT-Algorithmus-/Whitelist-Haertung | JWT-Verifikation und Algorithmus-Konfiguration bewerten. | `alg:none`, dynamische Algorithmuswahl oder `verify()` ohne erlaubte `algorithms`-Whitelist. | `control_assessment`; Kandidat bei High-Confidence |
| `ARCH-TLS-001` Cleartext-Transport / DB-TLS disabled | DSNs, Service-Clients und relevante IaC-Konfiguration bewerten. | Nicht-lokales `http://`, `sslmode=disable`, `ssl=false` oder vergleichbare produktive Transport-Deaktivierung. | `anti_pattern_candidate` oder `control_assessment` |
| `ARCH-MGMT-001` Management-Endpoint-Exposure | `.route-inventory.json` plus Cat 11 und AuthN/AuthZ-/Netzwerkschutz-Signale bewerten. | Management/debug/docs/metrics endpoint wirkt erreichbar und AuthN/AuthZ- oder Netzwerkschutz-Signale sind explizit absent/negativ. `unknown` reicht nicht. | zuerst `weak`/`missing`; harter Kandidat nur bei starker Evidence |

Severity-Policy:

- CORS/CWE-942 individuell maximal High.
- JWT/CWE-347 individuell maximal High, Critical nur spaeter ueber validierte Chain.
- Rate-Limit ist nicht Teil der ersten Lieferung; keine CWE-307-Findings daraus ableiten.
- `architectural-anti-pattern` und `coverage-gap` duerfen kein CVSS tragen.
- Keine pauschalen Criticals.

### Threat-Hypothesis-Regeln

Diese Regeln ergaenzen die fuenf harten High-Confidence-Regeln. Sie sind bewusst konservativ: Sie machen erwartbare Bedrohungen sichtbar, wenn die Architektur keine robuste Standardabstraktion zeigt. Sie ersetzen keine Taint-Analyse und duerfen keine Exploitbarkeit behaupten, solange die Evidence-Kette unvollstaendig ist.

Allgemeines Gate:

```text
Attack surface oder externer Input
+ sensitiver Sink oder sicherheitsrelevante Wirkung
+ schwaches/missing Standard-Control
+ keine entlastende Framework-/Policy-Evidence
= Threat-Hypothese

Konkreter attacker-controlled Source-to-Sink-Pfad
+ Reachability
+ fehlende/defekte Kontrolle am Pfad
= harter Threat-Kandidat
```

| Regel | Hypothese wenn | Harter Kandidat nur wenn | Primaerer Output |
|---|---|---|---|
| `ARCH-XSS-001` XSS-Exposure durch schwaches Output-Encoding | Browser-rendered Input, manuelles HTML-Escaping, direkte DOM-/Template-Sinks oder fehlender Autoescape-/Sanitizer-Nachweis; fehlender CSP verstaerkt die Hypothese, reicht allein aber nicht. | User-kontrollierte Quelle erreicht `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`, deaktiviertes Template-Escaping oder vergleichbaren Sink. | `threat_hypothesis`; `anti_pattern_candidate` nur bei Source-to-Sink |
| `ARCH-SQLI-001` SQLi-Exposure durch ad-hoc SQL-Zugriff | SQL-Datastore vorhanden, Raw Queries oder Query-String-Konkatenation, manuelles Escaping, kein Parameterized-Query-/ORM-/Repository-Layer in der relevanten Schicht belegt. | Request-/Route-Parameter oder andere attacker-kontrollierte Daten erreichen eine SQL-/NoSQL-Query-Konstruktion ohne Parameterbindung oder sichere Query-API. | `threat_hypothesis`; harter Kandidat bei konkretem Sink |
| `ARCH-AUTHZ-001` Broken-Access-Control-Exposure durch inkonsistente AuthZ | Sensitive oder authenticated Routes, ad-hoc Rollenchecks, gemischte Middleware/Decorator-Patterns, client-only Guards oder kein zentraler Policy-/Security-Framework-Nachweis. | Route -> Resource -> Policy/Query-Kette zeigt, dass eine sensitive Aktion oder ein user-/tenant-owned Objekt ohne Role-/Scope-/Ownership-Check erreichbar ist. | `threat_hypothesis`; harte Findings nur bei Evidence-Kette |
| `ARCH-INPUT-001` Broken-Input-Validation-Exposure | Externe Payloads vor Parsern, Queries, Commands, Files, Deserializern oder Business-State-Transitions; Validierung nur per Regex/Blacklist/Trim oder inkonsistent pro Handler. | Payload erreicht sensitiven Sink ohne Schema-/Allowlist-/Typvalidierung; bei Injection-Sinks spezifische CWE verwenden statt generischem CWE-20. | `control_assessment` + `threat_hypothesis`; harter Kandidat bei Sink |

Klarstellungen:

- Fehlender CSP ist zuerst ein `Missing Content Security Policy` Control-Gap. Er wird erst zur XSS-Hypothese, wenn browser-rendered Input oder direkte HTML-/DOM-Sinks vorhanden sind.
- Raw SQL ist nicht automatisch SQL Injection. Raw SQL plus Konkatenation/manuelles Escaping und attacker-kontrollierte Daten ist ein harter Kandidat.
- Keine zentrale AuthZ-Bibliothek ist nicht automatisch Broken Access Control. Inkonsistente serverseitige Checks ueber sensitive Routen hinweg sind eine Hypothese; fehlender Ownership-/Tenant-/Role-Check an einer konkreten Route ist ein Finding.
- Regex-Validierung ist nicht automatisch broken. Blacklisting oder ad-hoc Regex vor einem sicherheitskritischen Sink ist eine Hypothese; ein bypassbarer Pattern am konkreten Sink kann ein Finding werden.
- Hypothesen sind fuer Pentest-Tasks wertvoll: Sie liefern pruefbare "validate or refute"-Aufgaben, ohne den Report mit unbewiesenen Schwachstellen zu ueberladen.

### Pipeline-Integration

1. **Route Inventory nach Recon ausfuehren.**
   `route_inventory.py` laeuft nach `.recon-patterns.json`, nutzt die bestehende kombinierte Phase-6-Route-Heuristik als Script-Logik und schreibt `.route-inventory.json`. Das ist ein einmaliger Prepass, kein Grep pro Regel.

2. **Architecture Coverage nach Route Inventory/Config-Scan ausfuehren.**
   `architecture_coverage_checks.py` laeuft nach `.route-inventory.json`, `.recon-patterns.json` und optional `.config-scan-findings.json`, aber vor Phase 8. Er liest vorhandene Artefakte und macht keine eigenen breiten Repo-Walks.

3. **Phase 6 konsumiert Route Inventory.**
   Phase 6 baut `attack_surface[]` bevorzugt aus `.route-inventory.json`. `attack_surface[]` bleibt das finale YAML-/Report-Format; `.route-inventory.json` ist die vorgelagerte Rohbasis mit Datei/Zeile/Auth-Signalen.

4. **Phase 8 konsumiert `control_assessments` und verlinkt `threat_hypotheses`.**
   Phase 8 muss aus jedem anwendbaren problematischen `control_assessment` (`partial`, `weak`, `missing`, `anti_pattern`) einen passenden `security_controls[]`-Eintrag erzeugen. `present` darf optional als positive Control-Zeile erscheinen; `not_applicable` wird nicht gerendert. Hypothesen bleiben mit diesen Controls verlinkt, z.B. ueber `linked_control_ids` und optional `security_controls[].hypothesis_ids`. Phase 11 persistiert die nicht bestaetigten Hypothesen zusaetzlich in `threat-model.yaml -> threat_hypotheses[]`, damit Section 7 deterministisch zeigen kann, welche Bedrohung aus welchem Control-Gap entsteht.

5. **Phase 9 konsumiert `anti_pattern_candidates` und bestaetigte `threat_hypotheses`.**
   Nicht bestaetigte Hypothesen werden nicht in `.threats-merged.json` uebernommen. Harte Kandidaten werden nur bei `proof_state: confirmed` gemerged, mit passendem CWE, Evidence und ohne CVSS, wenn ihre Quelle design-/coverage-basiert bleibt. Wenn eine bestaetigte Hypothese als code-level STRIDE-Finding mit Source-to-Sink-Evidence reklassifiziert wird, gelten die bestehenden CVSS-Eligibility-Regeln fuer `source: stride`. Fuer Architecture-Coverage sollte ein eigener `source` wie `architecture-coverage` oder `threat-hypothesis` eingefuehrt werden, statt alle Hypothesen unter `architectural-anti-pattern` zu verstecken. Diese Quelle muss dann in `schemas/threats-merged.schema.yaml`, `schemas/threat-model.output.schema.yaml`, `scripts/validate_intermediate.py`, `agents/appsec-threat-analyst.md`, CVSS-Tests, Pentest-Tests und ggf. SARIF-Tests erlaubt und korrekt gefiltert werden. `architectural-anti-pattern` bleibt fuer Requirements-/Blueprint-nahe Architekturverletzungen reserviert. Wenn kein Requirement verletzt wurde, sollte kein synthetisches `requirement_id` erfunden werden; `rule_id`/`hypothesis_id` ist der richtige Trace-Key. Falls aus Kompatibilitaetsgruenden `ARCH-<rule-id>` verwendet wird, muss Schema und Validator das explizit akzeptieren und gegen `.architecture-coverage.json` validieren.

6. **Keine rohen JSONs in STRIDE-Prompts.**
   STRIDE-Dispatches bekommen nicht das gesamte Artefakt. Falls ein Komponenten-Slice spaeter noetig wird, wird nur ein kleiner Pfad in Group C uebergeben, analog zu bestehenden Dispatch-Kontexten.

7. **QA erzwingt Vollstaendigkeit und ehrliche Semantik.**
   `qa_checks.py` oder ein dedizierter Validator muss fehlschlagen, wenn eine problematische Regel (`partial`, `weak`, `missing`, `anti_pattern`) in `.architecture-coverage.json` weder in `threat-model.yaml#security_controls[]`, `threat-model.yaml#threat_hypotheses[]` mit Section-7-Rendering noch in `.threats-merged.json`/Section 8 sichtbar wird. `present` und `not_applicable` sind Audit-Ergebnisse, aber keine Pflichtzeilen im finalen Report. Hypothesen ohne `proof_state: confirmed` duerfen nicht als bewiesene Schwachstellen, nicht mit CVSS, nicht als Critical, nicht im Threat Register und nicht in SARIF gerendert werden.

8. **Unknown-is-not-absent Gate.**
   `unknown`, `inherited_unknown` oder fehlende Route-/AuthZ-Signale duerfen niemals automatisch zu `missing`, `anti_pattern` oder einem harten Threat-Kandidaten eskaliert werden. Jede harte Kandidatur braucht positive Evidence fuer die Schwaeche, nicht nur fehlende Evidence fuer einen Schutz.

### Qualitaetswirkung

Erwarteter Gewinn:

- problematische Controls werden in jedem Run explizit bewertet
- plausible Bedrohungen aus schwachen Sicherheitsabstraktionen werden sichtbar, auch wenn noch kein vollstaendiger Exploitpfad bewiesen ist
- Management-/Admin-Endpunkte werden nicht mehr nur ueber Cat 11-Matches beurteilt, sondern gegen echte Route-Eintraege gespiegelt
- `attack_surface[]` wird stabiler, weil Phase 6 eine deterministische Route-Basis bekommt
- Standard-Mode verpasst weniger Architektur-Gaps
- Section 7 wird weniger von LLM-Erinnerung abhaengig
- Severity und CVSS-Verbote koennen deterministisch geprueft werden
- Anti-Patterns werden deduplizierbar, weil jeder Kandidat eine stabile Rule-ID hat

Wichtigste Risiken:

- False Positives bei negativer Auth-/AuthZ-Erkennung, besonders wenn `authn_signal` aus dem Route-Inventar nur `unknown` ist
- unvollstaendige Route-Extraktion bei Frameworks mit dynamischer Router-Komposition
- Doppelfunde zwischen Recon, Config-Scanner, STRIDE und Architektur-Coverage
- zu generische "missing control"-Prosa ohne konkrete Evidence
- unklare Report-Semantik, wenn Hypothesen wie bestaetigte Findings klingen
- Runtime-only-Hypothesen, die zwar in `.architecture-coverage.json` stehen, aber nicht in `threat-model.yaml` und Section 7 ankommen
- Schema-Drift, wenn `security_controls[]` und Threat-Kandidaten unterschiedliche Feldnamen verwenden

Mitigation:

- Jeder Rule-Eintrag braucht Preconditions, positive Signale, negative Signale und Skip-Gruende.
- Jede Hypothese braucht `proof_state`, `confidence`, `positive_signals`, `weak_or_missing_controls` und optional `exculpatory_signals`.
- Route-Inventar darf `unknown` nicht als `absent` behandeln.
- Harte Kandidaten nur bei `confidence: high`.
- Hypothesen ohne konkreten Source-to-Sink-Pfad bleiben `emit_hypothesis_only`.
- Nicht bestaetigte Hypothesen bekommen einen finalen `HYP-NNN`-Pfad in `threat-model.yaml#threat_hypotheses[]` und Section 7, aber keine `T-NNN`/`F-NNN`-ID.
- Dedupe-Schluessel: `rule_id + cwe + file + line + surface`.
- Control-Gaps duerfen als `weak`/`missing` sichtbar sein, ohne automatisch Threats zu erzeugen.
- Management-Endpoint-Findings brauchen positive Exposure-Evidence: Route/Endpoint-Signal plus fehlender Schutz darf nur dann hart werden, wenn kein AuthN/AuthZ- oder Netzwerkschutz-Signal vorhanden ist und der Endpoint nicht klar test-/local-only ist.
- Token-/JSON-Bloat ist ein Qualitaetsrisiko: Agenten sollen nur kompakte Slices oder Pfade erhalten, sonst steigt Halluzinations- und Drift-Risiko.
- Tests muessen CVSS-Verbot, Severity-Caps, Dedupe und Section-7/Section-8-Abgrenzung abdecken.

### Performancewirkung

Die erste Lieferung sollte neutral bis leicht positiv sein.

Performance-Regeln:

- keine eigenen Repo-weiten Greps pro Regel
- genau ein Route-Inventory-Prepass statt prompt-basierter Phase-6-Greps
- vorhandene `.recon-patterns.json`, `.recon-summary.md` und `.config-scan-findings.json` wiederverwenden; `.threats-merged.json` nur fuer Dedupe/Incremental-Kontext nutzen, wenn es aus einem frueheren Lauf vorhanden ist
- falls zusaetzliche Signale wirklich noetig sind, in einem gebuendelten Scan erheben
- keine LLM-Agenten fuer Join-/Regex-Logik einsetzen
- Route Inventory muss Manifest-/Exclude-Regeln wiederverwenden und `node_modules`, `vendor`, `dist`, `build`, `.git`, `target`, `out` und vergleichbare generierte Verzeichnisse ausschliessen.
- Die Regel-Engine darf Dateien nicht erneut oeffnen, wenn dieselbe Evidence bereits in `.route-inventory.json`, `.recon-patterns.json` oder `.config-scan-findings.json` enthalten ist.
- Fuer grosse Repos sollte der Route-Inventory-Output begrenzt werden: vollstaendige Daten bleiben im Artefakt, Prompts/Logs bekommen nur Counts, Top-Surfaces und Pfade.

Der Script-Overhead ist klein. Der groessere Performance-Hebel ist, dass STRIDE-Agenten weniger wiederholte Control-Rekonstruktion leisten muessen.

### Tokenwirkung

Die erste Lieferung soll Tokens sparen, nicht neue Prompt-Last erzeugen.

Token-Regeln:

- `arch.md` nicht in Runtime-Prompts laden
- `.route-inventory.json` nicht roh in STRIDE-Dispatches inlinen
- `.architecture-coverage.json` nicht roh in STRIDE-Dispatches inlinen
- Phase 8 liest kompakte Control-Assessments einmal
- Phase 9 liest nur harte Kandidaten, bestaetigte Hypothesen oder einen kleinen Slice
- grosse volatile JSON-Kontexte bleiben als Pfade, nicht als Prompt-Inhalt
- Wenn ein Agent Kontext braucht, bekommt er einen kleinen Slice: `route_id`, `method`, `path`, `handler_file`, `handler_line`, `status`, `proof_state`, `confidence`, `rule_id`, `hypothesis_id`, `decision`. Keine kompletten Evidence-Arrays, keine kompletten Route-Listen.
- Dispatch-Kontexte bleiben Group-C-Pfade; volatile JSON wird nicht in Group A/B eingefuegt und nicht in den Prompt-Text kopiert.

Falsch waere: alle Rule-Ergebnisse oder Recon-Rohdaten jedem STRIDE-Subagenten mitzugeben. Richtig ist: deterministische Engine schreibt kompakte Entscheidungen; Agenten nutzen nur die benoetigten Ausschnitte.

### Testumfang der ersten Lieferung

Mindestens:

- Unit-Tests fuer alle fuenf Regeln
- Unit-Tests fuer alle vier Threat-Hypothesis-Regeln
- Unit-Tests fuer Route-Inventory-MVP pro unterstuetztem Framework-Pattern
- Schema-Test fuer `.route-inventory.json`
- Schema-Test fuer `.architecture-coverage.json`
- Schema-Test fuer `threat-model.yaml#threat_hypotheses[]`
- Phase-6-Bridge-Test: `.route-inventory.json` erzeugt erwartete `attack_surface[]`
- Phase-8-Bridge-Test: `control_assessments[]` erzeugen erwartete `security_controls[]`
- Phase-8/11-Bridge-Test: unbestaetigte `threat_hypotheses[]` werden in `threat-model.yaml` persistiert und in Section 7.2 plus passendem Domain-Abschnitt gerendert
- Phase-9-Bridge-Test: `threat_hypotheses[]` werden nur bei `proof_state: confirmed` in `.threats-merged.json` gemerged
- Phase-9-Bridge-Test: `anti_pattern_candidates[]` werden ohne CVSS und mit stabiler Rule-ID gemerged
- Dedupe-Test gegen vorhandene STRIDE/config Findings
- Severity-Cap-Test fuer CWE-942 und CWE-347
- Severity-/Semantik-Test: Hypothesen ohne `confirmed` sind nicht Critical und tragen kein CVSS
- Source-Schema-Test: `architecture-coverage` / `threat-hypothesis` Quelle ist schema- und validatorseitig erlaubt, oder bewusst auf bestehende Quelle gemappt
- QA/validator-Test: anwendbare Regel darf nicht aus dem finalen Output verschwinden
- Renderer-Test: unbestaetigte `HYP-NNN` erscheinen in Section 7, aber nicht in Section 8 Threat Register
- SARIF-Test: unbestaetigte Hypothesen werden nicht als SARIF Rules/Results exportiert
- Pentest-Task-Test: unbestaetigte Hypothesen erzeugen `architecture-driven-probe`-Tasks mit `validate or refute`-Ziel
- Traceability-Test: jede Hypothese verlinkt mindestens ein Control, eine Komponente oder eine Surface; verwaiste Hypothesen failen QA
- Unknown-Gate-Test: `unknown`/`inherited_unknown` erzeugt keinen harten Kandidaten
- Framework-Absence-Test: fehlendes Framework allein erzeugt keinen Threat
- CSP-only-Test: fehlender CSP allein erzeugt keinen XSS-Hard-Candidate
- Raw-SQL-Test: Raw SQL plus Konkatenation/manuelles Escaping erzeugt Hypothese; attacker-kontrollierter Source-to-Sink erzeugt harten Kandidaten
- Regex-Validation-Test: Regex allein ist nicht broken; Blacklist/Regex vor sensitivem Sink erzeugt Hypothese
- Prompt-size/contract test: Phase-9-Dispatch referenziert Coverage-/Route-Kontext nur als Pfad oder kompakten Slice, nicht als rohes JSON
- Exclude-Test: Route Inventory ueberspringt generierte und vendored Verzeichnisse
- Runtime-cleanup-Test: `.architecture-coverage.json` bewusst behandeln
- Runtime-cleanup-Test: `.route-inventory.json` bewusst behandeln

Relevante bestehende Tests nach Umsetzung:

```bash
python3 scripts/validate_config.py
pytest tests/test_contract_integrity.py
pytest tests/test_schema_integrity.py
pytest tests/test_runtime_cleanup.py
pytest tests/test_agent_definitions.py
pytest tests/test_pregenerate_fragments.py
pytest tests/test_compose_threat_model.py
pytest tests/test_pentest_tasks.py
pytest tests/test_export_sarif.py
pytest tests/test_route_inventory.py
pytest tests/test_coverage_checks.py
pytest tests/test_cvss_eligibility.py
pytest tests/test_architecture_coverage_checks.py
```

### Implementierungshinweise und offene Entscheidungen

Diese Punkte sollten vor oder waehrend der Umsetzung explizit entschieden werden. Sie sind keine Zusatzfeatures, sondern Scope- und Contract-Risiken der ersten Lieferung.

1. **Route Inventory MVP hart begrenzen.**
   Der MVP darf nicht zum vollstaendigen Framework-Parser werden. Ziel ist eine belastbare Route-Basis fuer haeufige Patterns und Management-/Attack-Surface-Signale. Dynamische Router-Komposition, komplexe Framework-Metaprogrammierung und vollstaendige AuthZ-Vererbung bleiben ausserhalb.

2. **Phase-6-Bruecke konkretisieren.**
   Vor Implementierung entscheiden: Wird `attack_surface[]` weiterhin vom Orchestrator geschrieben und nur mit `.route-inventory.json` gespeist, oder entsteht ein deterministischer Helper, der aus `.route-inventory.json` ein `attack_surface[]`-Fragment erzeugt? Beides ist moeglich; unklarer Mischbetrieb wuerde Drift erzeugen.

3. **Control-Feldnamen normalisieren.**
   Bestehende Artefakte verwenden teils `control`, teils `architectural_control`. Die neue Bridge muss eine einzige interne Normalform verwenden und erst beim Schreiben in bestehende Schemas adaptieren. Sonst entstehen leere oder doppelte Section-7-Zeilen.

4. **`ARCH-MGMT-001` konservativ halten.**
   Management-Endpoint-Exposure ist der riskanteste First-Delivery-Check. Ein fehlendes AuthZ-Signal reicht nicht. Harte Kandidaten brauchen positive Exposure-Evidence und muessen zentrale/geerbte Schutzmechanismen, Netzwerk-Gates, Testfixtures und local-only Bindings ausschliessen.

5. **Finalen Hypothesen-Pfad vor der Engine klaeren.**
   `threat_hypotheses[]` darf nicht nur ein Feld in `.architecture-coverage.json` bleiben. Vor Implementierung der Regeln muss entschieden sein, wie Phase 11 das Feld nach `threat-model.yaml` uebernimmt, wie `pregenerate_fragments.py` Section 7.2 und die Domain-Abschnitte daraus rendert, und wie QA verhindert, dass `HYP-NNN` versehentlich als `T-NNN`/`F-NNN` im Threat Register erscheint.

6. **Synthetische `requirement_id` klaeren.**
   Wenn `architectural-anti-pattern`-Kandidaten ein synthetisches `requirement_id` wie `ARCH-<rule-id>` tragen, muessen Schema und Validator das explizit akzeptieren und gegen `.architecture-coverage.json` validieren. Besser fuer die neuen Hypothesen: kein `requirement_id` schreiben und stattdessen `rule_id`/`hypothesis_id` als eigene Felder fuehren. Nicht beides ad hoc mischen.

7. **Ein Schritt nach dem anderen.**
   Reihenfolge fuer die Umsetzung: erst `route_inventory.py` + Schema + Phase-6-Bruecke stabilisieren, dann `architecture_coverage_checks.py` mit den fuenf harten Regeln, danach die vier Threat-Hypothesis-Regeln. Alles gleichzeitig breit auszubauen erhoeht Drift- und False-Positive-Risiko.

### Nicht-Ziele dieser Lieferung

Nicht umsetzen:

- True Anonymous Routes
- umfassende Authorization-Coverage
- Tenant-/Ownership-Isolation
- Step-Up fuer sensitive Aktionen
- Security-Event-Audit
- Async-/Queue-/Webhook-Trust
- Cache-Isolation
- Kubernetes-/Terraform-Regelkataloge
- Cat 28-Verschiebung
- `signal_required`
- inhaltsbasiertes Secret-Scanning
- vollstaendige Regex-SAST fuer SQLi/XSS/eval/Taint als Exploit-Behauptung

True Anonymous Routes meint hier: harte Findings fuer alle anonym erreichbaren Routen. Der Route-Inventory-MVP darf unauthentifizierte oder unbekannte Auth-Signale erfassen und als Control-Assessment nutzbar machen; er soll daraus aber noch keine pauschalen Findings erzeugen.

Die uebrigen Themen bleiben wertvoll, brauchen aber bessere Preconditions oder eigene Vorarbeit. Sie wuerden die erste Lieferung zu breit machen und das False-Positive-Risiko erhoehen.

Wichtig: Der Ausschluss von Regex-/Taint-SAST bedeutet nicht, dass XSS-, SQLi-, AuthZ- oder Input-Validation-Bedrohungen ignoriert werden. Er bedeutet nur, dass die erste Lieferung keine exploitable Source-to-Sink-Behauptung allein aus Regex-Treffern ableitet. Konservative `threat_hypotheses[]` aus Attack Surface, sensitiven Sinks und schwachen/missing Controls sind explizit in scope.

## Folgeausbau: Authorization Coverage

### Zielbild

Umfassende Authorization-Coverage ist sinnvoll, aber nur mit mehreren strukturierten Zwischenschichten. Sie darf nicht als "grep fand keine AuthZ-Funktion, also Finding" implementiert werden.

Sinnvolle Artefakte:

- `.route-inventory.json` - Entry Points, Handler-Datei/-Zeile, Method/Path, AuthN/AuthZ-Signale
- `.resource-access-map.json` - Route -> Handler -> Model/Query/Resource-Zugriff
- `.authz-coverage.json` - erwartete vs. gefundene AuthZ-Kontrollen pro Route/Resource

Sinnvolle Scripts:

- `scripts/route_inventory.py`
- `scripts/resource_access_map.py`
- `scripts/authorization_coverage.py`

### Steuerung

AuthZ Coverage sollte mode-aware und explizit uebersteuerbar sein:

```text
--authz-coverage auto|off|basic|deep
```

Default: `auto`.

| Assessment Depth | `auto`-Verhalten | Begruendung |
|---|---|---|
| `quick` | `off` oder nur Route Inventory, wenn ohnehin billig | Quick darf keine teure AuthZ-Analyse starten. |
| `standard` | `basic` | Gute High-Confidence-Signale ohne tiefe Kontrollfluss-/Query-Analyse. |
| `thorough` | `deep` | Vollstaendige Resource-/Tenant-/Policy-/Query-basierte Bewertung. |
| expliziter Schalter | User-Wert gewinnt | `--authz-coverage deep` erzwingt Deep, `off` deaktiviert. |

### Basic Mode (`standard`)

Basic Mode soll Rauschen vermeiden. Er erzeugt primaer `control_assessment`, `warning` oder `missing_candidate`, nicht automatisch harte Findings.

Pruefen:

- Admin-/Management-Routen ohne erkennbare AuthZ-Signale
- Routen mit `:id`/Resource-ID und AuthN, aber ohne offensichtliche Role-/Scope-/Ownership-Signale
- destructive Methoden (`DELETE`, `PUT`, `PATCH`) ohne AuthZ-Signal
- sensitive Aktionen wie role change, API-key creation, export, MFA disable, password reset
- client-only guards ohne Server-side AuthZ-Hinweis

Harte Findings nur bei sehr klarer Evidence, z.B. eine Admin-Route ohne AuthN/AuthZ-Signal und ohne Netzwerkschutz.

### Deep Mode (`thorough`)

Deep Mode darf harte object-level- oder tenant-level Findings erzeugen, aber nur bei belastbarer Kette:

1. Route nimmt attacker-kontrollierte Resource-ID an.
2. Das betroffene Model oder Query-Ziel hat Owner-/Tenant-Felder.
3. Query, Policy oder Guard verwendet diese Felder nicht.

Beispiel fuer starke Evidence:

```text
GET /orders/:id
Order hat user_id
Handler queryt WHERE id = req.params.id
Kein user_id/tenant_id/policy check im Handler, Middleware-Cluster oder Policy-File
```

Deep Mode prueft:

- Route -> Handler -> Model/Query-Verknuepfung
- Owner-Felder wie `user_id`, `owner_id`, `account_id`
- Tenant-Felder wie `tenant_id`, `organization_id`, `workspace_id`
- Policy-/Guard-/Decorator-Abdeckung (`@PreAuthorize`, `requireRole`, `can`, Casbin/OPA/Pundit/CanCanCan/Spring Security)
- list/export endpoints ohne scoped query
- role-only AuthZ bei user-/tenant-owned Resources als `weak`, nicht automatisch als harte Luecke

### Output-Vertrag

`.authz-coverage.json` sollte pro Route mindestens enthalten:

```json
{
  "version": 1,
  "mode": "basic",
  "routes_evaluated": [
    {
      "route_id": "R-014",
      "method": "GET",
      "path": "/orders/:id",
      "resource": "order",
      "action": "read",
      "sensitivity": "user_owned",
      "expected_controls": ["authenticated_user", "ownership_check"],
      "observed_controls": [
        {
          "type": "authenticated_user",
          "file": "src/middleware/auth.ts",
          "line": 18
        }
      ],
      "status": "missing_candidate",
      "confidence": "medium"
    }
  ],
  "finding_candidates": []
}
```

Zulaessige Statuswerte:

- `covered`
- `unknown`
- `weak`
- `missing_candidate`
- `anti_pattern`

`unknown` ist ein gueltiges Ergebnis und darf nicht als Luecke behandelt werden.

### Integration in Pipeline

Empfohlene Reihenfolge nach der ersten Lieferung:

1. Route Inventory aus der ersten Lieferung stabilisieren.
2. `resource_access_map.py` bauen und mit `extract_data_relations.py` abstimmen.
3. `authorization_coverage.py --mode basic|deep` implementieren.
4. Phase 8 nutzt `.authz-coverage.json` fuer AuthZ-Controls.
5. Phase 9 merged nur `confidence: high` Finding-Kandidaten.
6. QA prueft, dass harte AuthZ-Findings die Evidence-Kette Route -> Resource -> Policy/Query tragen.

### Warum nicht Teil der ersten Lieferung

Der Route-Inventory-MVP ist deterministisch und direkt hilfreich. Umfassende AuthZ-Coverage braucht zusaetzlich Resource-Klassifizierung, Datenmodell-/Query-Kontext und Policy-/Guard-Extraktion. Ohne diese Schichten produziert sie zu viele falsche "missing authorization"-Findings.

Deshalb: erste Lieferung baut die Basis; AuthZ Coverage folgt mode-aware als zweiter Ausbau.

## Aktualisierte Reihenfolge

1. **Contracts:** `route-inventory.schema.json`, `architecture-coverage.schema.json`, finales `threat-model.yaml#threat_hypotheses[]`, Regelkatalogformat, Statuswerte, Candidate-Shape.
2. **Route Inventory MVP:** `route_inventory.py` mit Framework-Patterns, AuthN/AuthZ-Signalen und Management-Surface-Klassifizierung.
3. **Architecture Engine:** `architecture_coverage_checks.py` mit den fuenf harten Regeln und vorhandenen Artefakt-Inputs.
4. **Threat-Hypothesis Layer:** XSS/SQLi/AuthZ/InputVal-Regeln als Hypothesen mit `proof_state`, ohne automatische Hard-Finding-Eskalation.
5. **Phase-6-Bruecke:** `attack_surface[]` aus Route Inventory speisen.
6. **Phase-8-/Phase-11-Bruecke:** Control-Assessments in `security_controls[]` und nicht bestaetigte Hypothesen in `threat-model.yaml#threat_hypotheses[]`/Section 7 sichtbar machen.
7. **Phase-9-Bruecke:** nur High-Confidence Anti-Pattern-Kandidaten und bestaetigte Hypothesen mergen.
8. **Renderer/Exporter:** Section 7, Pentest-Tasks und SARIF-Abgrenzung fuer Hypothesen absichern.
9. **Gates:** CVSS-Verbot, Severity-Caps, Dedupe, Vollstaendigkeitspruefung, Hypothesen-Semantik.
10. **Docs/Permissions:** Phase-Anweisungen, `required-permissions.yaml`, Runtime-cleanup bewusst aktualisieren.

## Kostenrahmen

| Block | Realistischer Aufwand | Hebel |
|---|---:|---|
| Route-Inventory Contract + MVP | 1.5-2.5 PT | hoch |
| Architecture-Coverage Contract + Rule-Catalog | 1-1.5 PT | hoch |
| Engine mit 5 Regeln | 2-3 PT | hoch |
| Threat-Hypothesis-Regeln XSS/SQLi/AuthZ/InputVal | 1.5-3 PT | hoch |
| Phase-6-/Phase-8-/Phase-11-/Phase-9-Bruecken | 2-3 PT | hoch |
| QA/Validator/Dedupe/CVSS-/Hypothesen-/Renderer-Tests | 2-2.5 PT | hoch |
| Prompt-/Permission-/Cleanup-Doku | 0.5 PT | mittel |

Realistische erste Lieferung mit Route-Inventory-MVP und sauber integrierter Threat-Hypothesis-Layer: **10.5-15 PT**. Darunter wird wahrscheinlich entweder die Route-Extraktion, die Phase-6-Bruecke, der finale Section-7-Pfad, die Hypothesen-Semantik oder die QA-Absicherung zu schwach.

## Bilanz

Die erste Lieferung sollte zwei deterministische Bausteine und einen klar begrenzten Hypothesen-Layer bauen: ein Route-Inventory-MVP, eine zentrale Architektur-Coverage-Engine und `threat_hypotheses[]` fuer plausible Bedrohungen aus schwachen Sicherheitsabstraktionen. Das Route-Inventar stabilisiert Phase 6 und macht Management-/Anonymous-Surface-Signale belastbarer. Die Coverage-Engine prueft fuenf evidenzstarke Controls/Anti-Patterns immer, schreibt ein schema-validiertes Artefakt und speist Phase 6/8/9/11 mit kompakten Entscheidungen. Der Hypothesen-Layer schliesst die fachliche Luecke zwischen "nur Control fehlt" und "konkrete Schwachstelle bewiesen".

Das erreicht das zentrale Ziel am besten: problematische Controls und daraus folgende Bedrohungen werden reproduzierbar sichtbar, ohne STRIDE-Prompts aufzublasen oder unzuverlaessige umfassende "missing authz"-Findings zu erzeugen. Der Report bleibt ehrlich: bestaetigte Findings, Architektur-Anti-Patterns, Control-Gaps und Threat-Hypothesen sind unterscheidbar. Die wichtige Designentscheidung ist, dass unbestaetigte Hypothesen in Section 7 leben und erst nach Promotion in Section 8, SARIF und CWE-eligible Pentest-Finding-Logik auftauchen.
