# Empfehlung - erste Lieferung Architektur-Coverage fuer appsec-advisor

Stand: 2026-05-14
Scope: fokussierte erste Lieferung fuer zentrale, deterministische Pruefung problematischer Security Controls und Architektur-Anti-Patterns.

## TL;DR

Ziel der ersten Lieferung ist nicht "mehr Findings um jeden Preis", sondern eine zentrale Always-on-Pruefung: relevante Routes, Security Controls und Architektur-Anti-Patterns werden fuer jeden Run deterministisch bewertet und strukturiert an Phase 6/8/9 uebergeben.

Die sinnvolle erste Lieferung ist:

- ein neues `scripts/architecture_coverage_checks.py`
- ein neues `scripts/route_inventory.py` als deterministischer Route-Inventory-MVP
- ein kleiner Regelkatalog `data/architecture-coverage-rules.yaml`
- Schemas `schemas/route-inventory.schema.json` und `schemas/architecture-coverage.schema.json`
- ein neues Runtime-Artefakt `$OUTPUT_DIR/.route-inventory.json`
- ein neues Runtime-Artefakt `$OUTPUT_DIR/.architecture-coverage.json`
- genau fuenf High-Confidence-Regeln: Cookie-/Session-Haertung, CORS-Wildcard mit Credentials, JWT-Algorithmus-/Whitelist-Haertung, Cleartext-Transport, Management-Endpoint-Exposure

Nicht Teil der ersten Lieferung: umfassende Authorization-Coverage, Tenant-/Ownership-Isolation, Step-Up, Audit-Logging, Kubernetes/Terraform-Ausbau und `signal_required`.

Die Kernregel: **immer pruefen, aber nicht immer ein Finding erzeugen.** Jede Regel bekommt einen Status (`not_applicable`, `present`, `partial`, `weak`, `missing`, `anti_pattern`). Nur harte, evidenzstarke Faelle werden zu Threat-Kandidaten.

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

Die erste Lieferung sollte **nicht** `coverage_checks.py` erweitern. `coverage_checks.py` bleibt fuer OWASP-/Cross-Repo-Coverage in Phase 9. Die Architektur-Coverage braucht eigene Prepasses, weil sie Phase 6 (`attack_surface[]`), Phase 8 (`security_controls[]`) und Phase 9 (Threat-Kandidaten) bedient.

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

### Regeln der ersten Lieferung

| Regel | Always-on-Pruefung | Harte Kandidaten nur wenn | Primaerer Output |
|---|---|---|---|
| `ARCH-COOKIE-001` Cookie-/Session-Haertung | Session-/Cookie-Signale aus Recon und Code-Evidence bewerten. | Sensitive Session-Cookies werden explizit ohne `HttpOnly`, `Secure` oder `SameSite` gesetzt. | `control_assessment`; Kandidat bei explizit unsicherem Set-Cookie |
| `ARCH-CORS-001` CORS-Wildcard mit Credentials | CORS-Signale aus Recon 7.18 und Code/IaC bewerten. | Wildcard-Origin und Credentials treten gemeinsam auf. | `anti_pattern_candidate` |
| `ARCH-JWT-001` JWT-Algorithmus-/Whitelist-Haertung | JWT-Verifikation und Algorithmus-Konfiguration bewerten. | `alg:none`, dynamische Algorithmuswahl oder `verify()` ohne erlaubte `algorithms`-Whitelist. | `control_assessment`; Kandidat bei High-Confidence |
| `ARCH-TLS-001` Cleartext-Transport / DB-TLS disabled | DSNs, Service-Clients und relevante IaC-Konfiguration bewerten. | Nicht-lokales `http://`, `sslmode=disable`, `ssl=false` oder vergleichbare produktive Transport-Deaktivierung. | `anti_pattern_candidate` oder `control_assessment` |
| `ARCH-MGMT-001` Management-Endpoint-Exposure | `.route-inventory.json` plus Cat 11 und AuthN/AuthZ-/Netzwerkschutz-Signale bewerten. | Management/debug/docs/metrics endpoint wirkt erreichbar und `authn_signal`/Netzwerkschutz fehlen oder sind klar negativ. | zuerst `weak`/`missing`; harter Kandidat nur bei starker Evidence |

Severity-Policy:

- CORS/CWE-942 individuell maximal High.
- JWT/CWE-347 individuell maximal High, Critical nur spaeter ueber validierte Chain.
- Rate-Limit ist nicht Teil der ersten Lieferung; keine CWE-307-Findings daraus ableiten.
- `architectural-anti-pattern` und `coverage-gap` duerfen kein CVSS tragen.
- Keine pauschalen Criticals.

### Pipeline-Integration

1. **Route Inventory nach Recon ausfuehren.**
   `route_inventory.py` laeuft nach `.recon-patterns.json`, nutzt die bestehende kombinierte Phase-6-Route-Heuristik als Script-Logik und schreibt `.route-inventory.json`. Das ist ein einmaliger Prepass, kein Grep pro Regel.

2. **Architecture Coverage nach Route Inventory/Config-Scan ausfuehren.**
   `architecture_coverage_checks.py` laeuft nach `.route-inventory.json`, `.recon-patterns.json` und optional `.config-scan-findings.json`, aber vor Phase 8. Er liest vorhandene Artefakte und macht keine eigenen breiten Repo-Walks.

3. **Phase 6 konsumiert Route Inventory.**
   Phase 6 baut `attack_surface[]` bevorzugt aus `.route-inventory.json`. `attack_surface[]` bleibt das finale YAML-/Report-Format; `.route-inventory.json` ist die vorgelagerte Rohbasis mit Datei/Zeile/Auth-Signalen.

4. **Phase 8 konsumiert `control_assessments`.**
   Phase 8 muss aus jedem anwendbaren problematischen `control_assessment` (`partial`, `weak`, `missing`, `anti_pattern`) einen passenden `security_controls[]`-Eintrag erzeugen. `present` darf optional als positive Control-Zeile erscheinen; `not_applicable` wird nicht gerendert. Dadurch werden Weak/Missing Controls in Section 7 deterministisch sichtbar.

5. **Phase 9 konsumiert `anti_pattern_candidates`.**
   Harte Kandidaten werden in `.threats-merged.json` uebernommen, mit `source: architectural-anti-pattern`, `architectural_violation: true`, passendem CWE, Evidence und ohne CVSS. Wenn dafuer ein synthetischer `requirement_id` noetig ist, das Format `ARCH-<rule-id>` schema- und validatorseitig erlauben und gegen `.architecture-coverage.json` validieren.

6. **Keine rohen JSONs in STRIDE-Prompts.**
   STRIDE-Dispatches bekommen nicht das gesamte Artefakt. Falls ein Komponenten-Slice spaeter noetig wird, wird nur ein kleiner Pfad in Group C uebergeben, analog zu bestehenden Dispatch-Kontexten.

7. **QA erzwingt Vollstaendigkeit.**
   `qa_checks.py` oder ein dedizierter Validator muss fehlschlagen, wenn eine problematische Regel (`partial`, `weak`, `missing`, `anti_pattern`) in `.architecture-coverage.json` weder in `security_controls[]` noch in `.threats-merged.json` sichtbar wird. `present` und `not_applicable` sind Audit-Ergebnisse, aber keine Pflichtzeilen im finalen Report.

8. **Unknown-is-not-absent Gate.**
   `unknown`, `inherited_unknown` oder fehlende Route-/AuthZ-Signale duerfen niemals automatisch zu `missing`, `anti_pattern` oder einem harten Threat-Kandidaten eskaliert werden. Jede harte Kandidatur braucht positive Evidence fuer die Schwaeche, nicht nur fehlende Evidence fuer einen Schutz.

### Qualitaetswirkung

Erwarteter Gewinn:

- problematische Controls werden in jedem Run explizit bewertet
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
- Schema-Drift, wenn `security_controls[]` und Threat-Kandidaten unterschiedliche Feldnamen verwenden

Mitigation:

- Jeder Rule-Eintrag braucht Preconditions, positive Signale, negative Signale und Skip-Gruende.
- Route-Inventar darf `unknown` nicht als `absent` behandeln.
- Harte Kandidaten nur bei `confidence: high`.
- Dedupe-Schluessel: `rule_id + cwe + file + line + surface`.
- Control-Gaps duerfen als `weak`/`missing` sichtbar sein, ohne automatisch Threats zu erzeugen.
- Management-Endpoint-Findings brauchen positive Exposure-Evidence: Route/Endpoint-Signal plus fehlender Schutz darf nur dann hart werden, wenn kein AuthN/AuthZ- oder Netzwerkschutz-Signal vorhanden ist und der Endpoint nicht klar test-/local-only ist.
- Token-/JSON-Bloat ist ein Qualitaetsrisiko: Agenten sollen nur kompakte Slices oder Pfade erhalten, sonst steigt Halluzinations- und Drift-Risiko.
- Tests muessen CVSS-Verbot, Severity-Caps und Dedupe abdecken.

### Performancewirkung

Die erste Lieferung sollte neutral bis leicht positiv sein.

Performance-Regeln:

- keine eigenen Repo-weiten Greps pro Regel
- genau ein Route-Inventory-Prepass statt prompt-basierter Phase-6-Greps
- vorhandene `.recon-patterns.json`, `.recon-summary.md`, `.config-scan-findings.json` und `.threats-merged.json` wiederverwenden
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
- Phase 9 liest nur harte Kandidaten oder einen kleinen Slice
- grosse volatile JSON-Kontexte bleiben als Pfade, nicht als Prompt-Inhalt
- Wenn ein Agent Kontext braucht, bekommt er einen kleinen Slice: `route_id`, `method`, `path`, `handler_file`, `handler_line`, `status`, `confidence`, `rule_id`, `decision`. Keine kompletten Evidence-Arrays, keine kompletten Route-Listen.
- Dispatch-Kontexte bleiben Group-C-Pfade; volatile JSON wird nicht in Group A/B eingefuegt und nicht in den Prompt-Text kopiert.

Falsch waere: alle Rule-Ergebnisse oder Recon-Rohdaten jedem STRIDE-Subagenten mitzugeben. Richtig ist: deterministische Engine schreibt kompakte Entscheidungen; Agenten nutzen nur die benoetigten Ausschnitte.

### Testumfang der ersten Lieferung

Mindestens:

- Unit-Tests fuer alle fuenf Regeln
- Unit-Tests fuer Route-Inventory-MVP pro unterstuetztem Framework-Pattern
- Schema-Test fuer `.route-inventory.json`
- Schema-Test fuer `.architecture-coverage.json`
- Phase-6-Bridge-Test: `.route-inventory.json` erzeugt erwartete `attack_surface[]`
- Phase-8-Bridge-Test: `control_assessments[]` erzeugen erwartete `security_controls[]`
- Phase-9-Bridge-Test: `anti_pattern_candidates[]` werden ohne CVSS und mit stabiler Rule-ID gemerged
- Dedupe-Test gegen vorhandene STRIDE/config Findings
- Severity-Cap-Test fuer CWE-942 und CWE-347
- QA/validator-Test: anwendbare Regel darf nicht aus dem finalen Output verschwinden
- Unknown-Gate-Test: `unknown`/`inherited_unknown` erzeugt keinen harten Kandidaten
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

5. **Synthetische `requirement_id` klaeren.**
   Wenn `architectural-anti-pattern`-Kandidaten ein synthetisches `requirement_id` wie `ARCH-<rule-id>` tragen, muessen Schema und Validator das explizit akzeptieren und gegen `.architecture-coverage.json` validieren. Alternative: fuer diese Kandidaten kein `requirement_id` schreiben und stattdessen `rule_id` als eigenes Feld fuehren. Nicht beides ad hoc mischen.

6. **Ein Schritt nach dem anderen.**
   Reihenfolge fuer die Umsetzung: erst `route_inventory.py` + Schema + Phase-6-Bruecke stabilisieren, dann `architecture_coverage_checks.py` mit den fuenf Regeln. Beides gleichzeitig breit auszubauen erhoeht Drift- und False-Positive-Risiko.

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
- Regex-SAST fuer SQLi/XSS/eval/Taint

True Anonymous Routes meint hier: harte Findings fuer alle anonym erreichbaren Routen. Der Route-Inventory-MVP darf unauthentifizierte oder unbekannte Auth-Signale erfassen und als Control-Assessment nutzbar machen; er soll daraus aber noch keine pauschalen Findings erzeugen.

Die uebrigen Themen bleiben wertvoll, brauchen aber bessere Preconditions oder eigene Vorarbeit. Sie wuerden die erste Lieferung zu breit machen und das False-Positive-Risiko erhoehen.

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

1. **Contracts:** `route-inventory.schema.json`, `architecture-coverage.schema.json`, Regelkatalogformat, Statuswerte, Candidate-Shape.
2. **Route Inventory MVP:** `route_inventory.py` mit Framework-Patterns, AuthN/AuthZ-Signalen und Management-Surface-Klassifizierung.
3. **Architecture Engine:** `architecture_coverage_checks.py` mit den fuenf Regeln und vorhandenen Artefakt-Inputs.
4. **Phase-6-Bruecke:** `attack_surface[]` aus Route Inventory speisen.
5. **Phase-8-Bruecke:** Control-Assessments in `security_controls[]` sichtbar machen.
6. **Phase-9-Bruecke:** nur High-Confidence Anti-Pattern-Kandidaten mergen.
7. **Gates:** CVSS-Verbot, Severity-Caps, Dedupe, Vollstaendigkeitspruefung.
8. **Docs/Permissions:** Phase-Anweisungen, `required-permissions.yaml`, Runtime-cleanup bewusst aktualisieren.

## Kostenrahmen

| Block | Realistischer Aufwand | Hebel |
|---|---:|---|
| Route-Inventory Contract + MVP | 1.5-2.5 PT | hoch |
| Architecture-Coverage Contract + Rule-Catalog | 1-1.5 PT | hoch |
| Engine mit 5 Regeln | 2-3 PT | hoch |
| Phase-6-/Phase-8-/Phase-9-Bruecken | 1.5-2 PT | hoch |
| QA/Validator/Dedupe/CVSS-Tests | 1-1.5 PT | hoch |
| Prompt-/Permission-/Cleanup-Doku | 0.5 PT | mittel |

Realistische erste Lieferung mit Route-Inventory-MVP: **7-10 PT**. Darunter wird wahrscheinlich entweder die Route-Extraktion, die Phase-6-Bruecke oder die QA-Absicherung zu schwach.

## Bilanz

Die erste Lieferung sollte zwei kleine deterministische Bausteine bauen: ein Route-Inventory-MVP und eine zentrale Architektur-Coverage-Engine. Das Route-Inventar stabilisiert Phase 6 und macht Management-/Anonymous-Surface-Signale belastbarer. Die Coverage-Engine prueft fuenf evidenzstarke Controls/Anti-Patterns immer, schreibt ein schema-validiertes Artefakt und speist Phase 6/8/9 mit kompakten Entscheidungen.

Das erreicht das zentrale Ziel am besten: problematische Controls werden reproduzierbar sichtbar, ohne STRIDE-Prompts aufzublasen oder unzuverlaessige umfassende "missing authz"-Findings zu erzeugen.
