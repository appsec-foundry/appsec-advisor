# Empfehlung - Architektur-Coverage-Checks fuer appsec-advisor

Stand: 2026-05-14
Scope: verifizierte Empfehlung zu zusaetzlichen Checks fuer Architektur-Schwaechen, fehlende Authentifizierung, Haertung und weitere relevante Security-Architekturaspekte.

## TL;DR

Die Grundrichtung bleibt richtig: Das Plugin sollte mehr Architektur-Coverage deterministisch aus bestehenden Artefakten ableiten, statt diese Luecken in jedem STRIDE-Subagenten neu vom LLM rekonstruieren zu lassen.

Die urspruengliche Empfehlung war aber an mehreren Stellen zu optimistisch. Nicht alle Checks sind gleich reif:

- **Sofort sinnvoll:** Cookie-/Session-Haertung, CORS-Wildcard mit Credentials, JWT-Algorithmus-/Whitelist-Haertung, Cleartext-Transport, Internal-/Management-Endpoint-Exposure.
- **Sinnvoll, aber nur mit Preconditions:** CSRF, Auth-Rate-Limit, Service-to-Service-Auth, Tenant-/Ownership-Isolation, Step-Up fuer sensitive Aktionen, Audit-Logging fuer Security Events.
- **Erst nach Vorarbeit sinnvoll:** allgemeines Anonymous-Routes-Inventory und umfassende Authorization-Coverage. Cat 11 ist heute kein vollstaendiges Route-Inventar.
- **Nicht als Quick Win behandeln:** `signal_required`. Das Feld existiert, ist aber dokumentations-only und nicht an den aktuellen OWASP-Coverage-Check gekoppelt.

Die beste Umsetzung ist eine kleine, schema-validierte Architektur-Coverage-Schicht, die kompakte Kandidaten erzeugt. Sie darf die STRIDE-Prompts nicht mit rohem JSON aufblasen.

## Verifizierter Ist-Zustand

### Coverage

`scripts/coverage_checks.py` deckt heute zwei deterministische Checks ab:

- Check A: OWASP Top 10 Coverage ueber `data/owasp-top10-cwes.yaml`
- Check D: Cross-Repo Boundary Coverage ueber `.cross-repo-register.json` oder `.threat-modeling-context.md`

Die Phase-9-Spezifikation injiziert daraus `source: coverage-gap` Threats. Neue Architektur-Coverage passt strukturell hierher, aber der Output sollte dann explizit schema-validiert werden. Aktuell gibt es kein eigenes Schema fuer `.coverage-gaps.json`.

### Recon

`scripts/recon_patterns.py` liefert bereits deterministische Kategorien 11, 14, 15, 17, 18, 21, 22, 23, 24, 27 und 28.

Wichtig: **Cat 11 ist kein allgemeines Route-Inventar.** Es scannt exposed/admin/debug/swagger/actuator/metrics/health-artige Pfade. Ein genereller Check "alle anonymen Routen" braucht vorher einen echten Route Extractor.

Cat 28 ist bereits im Recon-Prepass enthalten. Eine Verschiebung nach `config-iac-checks.yaml` kann nur mit Deduplizierung sinnvoll sein, sonst entstehen doppelte Befunde.

### Config/IaC

`data/config-iac-checks.yaml` ist datei- und regex-zentriert. Das passt fuer Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate und npm config.

Kubernetes und Terraform sind im Schema als `iac_type` vorhanden, aber der Config-Scanner-Prompt behandelt sie noch als "room for extension". Diese Erweiterung ist also nicht nur YAML-Arbeit; Inventory/Glob-Logik, Agent-Prompt, Tests und ggf. Finding-Type-Zuordnung muessen mitgezogen werden.

### Severity-Vertraege

Mehrere pauschale Severity-Aussagen aus der urspruenglichen Empfehlung muessen korrigiert werden:

- CWE-307 Rate-Limit-Gap ist individuell maximal **Medium**.
- CWE-942 Permissive CORS ist individuell maximal **High**, nicht Critical.
- CWE-347 JWT-Signature/Algorithmus-Fehler ist individuell maximal **High**, ausser als Keystone in einer validierten Critical Chain.
- `coverage-gap`, `requirements-compliance` und `architectural-anti-pattern` duerfen kein CVSS tragen.

## Priorisierte Architektur-Coverage

### Tier 1 - sofort sinnvoll, hohe Evidenzdichte

Diese Checks koennen mit vorhandener Recon-Ausgabe plus eng begrenzten Folge-Greps implementiert werden.

| # | Check | Eingang | Empfohlene Logik | Severity-Policy | FP-Risiko |
|---|---|---|---|---|---|
| 1 | **Cookie-/Session-Haertung** | Recon §7.1, Cookie-/Session-Setups | Fehlende `httpOnly`, `secure`, `sameSite` auf sensitiven Session-Cookies als Kandidat emitten. Session-/CSRF-Kontext miterfassen. | CWE-1004/CWE-614, severity aus Evidence + Context; kein pauschales Critical. | niedrig |
| 2 | **CORS-Wildcard mit Credentials** | Recon §7.18 + Code-Pattern | Nur flaggen, wenn Wildcard-Origin und Credentials gemeinsam auftreten (`origin: '*'` + `credentials: true` oder entsprechende Header). | CWE-942, max High individuell. | sehr niedrig |
| 3 | **JWT-Algorithmus-/Whitelist-Haertung** | Recon §7.1, JWT-Verifikation | `alg:none`, dynamische Algorithmuswahl oder `verify()` ohne erlaubte `algorithms`-Whitelist als Kandidat. | CWE-347, max High individuell; Critical nur via validierte Chain. | niedrig bis mittel |
| 4 | **Cleartext-Transport / DB-TLS-disabled** | DSNs, service clients, IaC | `sslmode=disable`, `ssl=false`, `http://` fuer Inter-Service/DB-Verbindungen flaggen. Localhost, Testfixtures und docs ausschliessen. | CWE-319, evidenzbasiert. | niedrig |
| 5 | **Internal-/Management-Endpoint-Exposure** | Cat 11 + AuthZ/IAM-Signale | `/admin`, `/metrics`, `/actuator`, `/swagger`, `/api-docs`, debug endpoints nur dann flaggen, wenn keine AuthN/AuthZ- oder Netzwerkschutz-Evidence vorliegt. | CWE-306/CWE-862/CWE-548 je nach Fall; nicht CWE-419 pauschal. | niedrig bis mittel |

Diese fuenf Checks haben den besten Wert/Aufwand-Mix. Sie verbessern Standard-Mode-Qualitaet ohne eine breite neue Analysephase.

### Tier 1b - sinnvoll, aber nur mit Gatekeeping

Diese Checks sind wertvoll, erzeugen aber ohne Preconditions schnell Rauschen.

| Check | Warum sinnvoll | Preconditions | Empfohlene Ausgabe |
|---|---|---|---|
| **CSRF-Coverage** | Klassische Architektur-/Browser-Grenze, von Code-Scannern oft nur teilweise erkannt. | Cookie-basierte Auth + state-changing route + keine Bearer-only/SPAs ohne Cookies. | Finding-Kandidat oder Coverage-Warnung, CWE-352. |
| **Auth-Rate-Limit auf Auth-Endpunkten** | Relevantes Abuse-Control fuer Login, Reset, Token-Issue. | Auth-Endpunkt sicher erkannt; kein vorhandenes Rate-Limit/Lockout/IdP-Delegation-Signal. | Max Medium als Einzelfinding; ggf. als primitive control gap. |
| **Service-to-Service-Auth-Luecke** | Erfasst implizites Service-Trust-Modell. | Cross-repo/SaaS/interface signal + §7.31 ohne Mechanismus reicht allein nicht fuer ein High-Finding; Kontext zu interner/externer Erreichbarkeit noetig. | Zunaechst STRIDE-Hint oder coverage warning; Finding erst mit starker Evidence. |
| **True Anonymous Routes** | Sehr wertvoll fuer AuthN/AuthZ-Coverage. | Braucht echtes Route-Inventar mit Middleware-/Decorator-Zuordnung. Cat 11 reicht nicht. | Nach Route-Extractor als eigener Check. |
| **Authorization Coverage** | Prueft Default-Deny, RBAC/ABAC, object-level checks. | Route-Inventar + Resource-/Tenant-Signale + authz middleware/decorator signals. | Coverage-Kandidaten, keine pauschale Severity. |

## Weitere wichtige Security-Architekturaspekte

`arch.md` war urspruenglich zu eng auf Auth, Hardening, Transport und IaC fokussiert. Die folgenden Aspekte sind fuer den Plugin-USP besonders relevant.

### Tenant- und Ownership-Isolation

Sehr hoher Wert. `TH-20 Cross-Tenant Isolation Bypass` existiert bereits, `signal_required` ist aber noch nicht produktiv gekoppelt.

Sinnvolle Signale:

- `tenant_id`, `organization_id`, `workspace_id`, `account_id`
- ORM models mit Tenant-/Owner-Feldern
- Routen mit `:id`/resource IDs
- Queries, Cache Keys, background jobs und queue consumers ohne Tenant-/Owner-Scope

Empfehlung: erst als gezielter STRIDE-Hint oder Coverage-Warnung einbauen, nicht als pauschaler harter Finding-Generator. Ein harter Check braucht Datenmodell- und Route-Kontext.

### Authorization-Architektur

Nicht nur "Auth vorhanden?", sondern:

- Default-Deny vs allow-by-default
- zentrale Policy Decision Points
- Rollen-/Scope-Pruefung
- object-level checks
- Admin-/Owner-/Tenant-Grenzen

Empfehlung: nach Route-Inventar priorisieren. Dieser Bereich hat hohen Nutzen, aber ohne gute Route-/Resource-Zuordnung hohes FP-Risiko.

### Step-Up fuer sensitive Aktionen

Relevante Aktionen:

- Passwort aendern
- MFA enrolment/deactivation
- API key/token erzeugen
- Rollen/Rechte aendern
- Datenexport
- Payment/Refund/admin destructive actions

Empfehlung: guter Tier-1b-Check. Er sollte nur feuern, wenn sensitive Aktionen erkannt werden. Abwesenheit solcher Aktionen darf keinen Befund erzeugen.

### Security-Event-Audit

Architektonisch wichtig und scanner-untypisch. Pruefbare Events:

- Login/logout/failure
- Password reset/change
- MFA changes
- role/admin changes
- token/API-key creation
- destructive mutations
- data export

Empfehlung: zunaechst Coverage-Warnung statt hartes Finding. Harte Findings nur bei klarer Evidence fuer sensitive Aktion ohne Logging.

### Admin-/Management-Plane-Trennung

Mehr als "endpoint exposed":

- getrennte Admin-Plane
- Gateway-/Ingress-Policy
- IP allowlist/private subnet
- separate AuthZ fuer admin functions
- kein Swagger/metrics/debug im Public Plane

Empfehlung: mit Internal-Endpoint-Exposure kombinieren, aber als eigenstaendiges Architekturthema in §7/STRIDE sichtbar machen.

### Async-, Queue- und Webhook-Trust

Typische Luecken:

- queue messages ohne Signatur oder producer identity
- replaybare webhook payloads
- fehlende idempotency keys
- verlorener tenant/user context in background jobs
- DLQ/logs mit PII

Empfehlung: conditional aktivieren, wenn queue/webhook/worker-Signale existieren. Eher STRIDE-Hints als reine Regex-Findings.

### Cache-Isolation

Besonders bei Multi-Tenant-Systemen relevant:

- Cache keys ohne tenant/user scope
- shared CDN fuer private Daten
- session/cache namespace reuse

Empfehlung: nicht pauschal. Nur in Verbindung mit Tenant-Signalen und Cache-Nutzung als gezielter STRIDE-Hint.

### Network Segmentation und Egress Control

Relevante Signale:

- private/public subnet separation
- Kubernetes NetworkPolicy
- service mesh policy
- outbound allowlists
- metadata-service protection
- direct DB from public-facing tier

Empfehlung: gut fuer IaC-/architecture coverage, aber nur wenn IaC vorhanden ist. Kubernetes/Terraform-Erweiterungen sollten diesen Bereich abdecken.

### Abuse Controls jenseits Login

Nicht nur `/login`:

- search/export/report generation
- upload/import
- expensive LLM/tool endpoints
- password reset/token issue
- admin bulk actions

Empfehlung: nach Route-Klassifizierung angehen. Ohne Semantik ist es zu verrauscht.

### Privacy und Data Lifecycle

Wichtig, aber nur teilweise aus Code ableitbar:

- PII in logs
- retention/delete/export
- backup encryption
- support/admin data access

Empfehlung: primaer requirements-/policy-getrieben, mit evidenzbasierten Greps als Unterstuetzung. Nicht als generischer Coverage-Gap.

### AI-/LLM-App-Integration

Cat 28 deckt Developer-Workstation-/Assistant-Config ab. Separat relevant sind Anwendungen, die selbst LLM/RAG/Tools nutzen:

- prompt-injection containment
- tool-call authorization
- retrieval ACLs
- cross-tenant data leakage in RAG
- model output reaching code/HTML/shell sinks

Empfehlung: nur conditional bei LLM-Signalen. Nicht mit Cat 28 vermischen.

## Wo die Checks hingehoeren

### Option A - klein starten in `coverage_checks.py`

Empfohlen fuer die ersten 5 Tier-1-Checks.

Erweiterung:

- `check_hardening_coverage()` - Cookie, CORS, JWT
- `check_transport_coverage()` - cleartext/DB TLS
- `check_management_endpoint_coverage()` - internal/admin/ops endpoints

Wichtig: Wenn `.coverage-gaps.json` erweitert wird, ein Schema und Validation-Tests ergaenzen. Die bestehende Core-Regel "jedes strukturierte Artefakt hat ein Schema" sollte hier nicht weiter aufgeweicht werden.

### Option B - eigenes Modul `architecture_coverage_checks.py`

Empfohlen, sobald mehr als 5-6 Architekturchecks produktiv werden oder wenn Route-/Tenant-/Audit-Logik dazukommt.

Vorteile:

- separates Schema, z.B. `schemas/architecture-coverage.schema.yaml`
- klarer Unterschied zwischen `finding_candidate`, `coverage_warning` und `stride_hint`
- weniger Vermischung mit OWASP-Coverage-Check A
- besser testbare Preconditions

Pragmatische Entscheidung: Option A fuer die ersten High-Confidence-Checks, Option B fuer Route-/Tenant-/Audit-Ausbau.

## Tier 2 - IaC-Erweiterungen

Sinnvoll, aber sekundaer und nicht in jedem Fall reine YAML-Arbeit.

| Thema | Bewertung | Hinweis |
|---|---|---|
| **Kubernetes hardening** | sinnvoll | Nicht nur YAML. Config-Scanner-Inventar, Pattern-Logik und Tests muessen erweitert werden. |
| **Terraform harte Checks** | sinnvoll begrenzt | Nur wenige High-Signal-Regeln: public ingress sensitive ports, public S3 ACL, IAM wildcard. Keine breite checkov/tfsec-Kopie. |
| **Dockerfile gaps** | sinnvoll | `curl | bash`, `ADD https://`, secret-like `ARG`. Niedriges bis mittleres FP-Risiko. |
| **docker-compose gaps** | sinnvoll | `pid: host`, `ipc: host`, default credentials. |
| **Filename-basierte Credentials** | vorsichtig sinnvoll | Als Repo-Read/secret-management signal, nicht als inhaltsbasiertes Secret-Scanning. |
| **Cat 28 nach config-iac-checks.yaml** | nur mit Dedupe | Cat 28 existiert bereits in Recon. Verschieben/duplizieren ohne Merge-Strategie verschlechtert Qualitaet. |

## Tier 3 - weiterhin bewusst nicht

- Inhaltsbasiertes Secret-Scanning mit Entropie/Provider-Prefixes. Besser Gitleaks/trufflehog importieren.
- Regex-SAST fuer SQLi/XSS/eval/Taint. Besser Semgrep/CodeQL konsumieren.
- Breite Cloud-Rule-Bibliotheken fuer Terraform/CloudFormation/ARM/Bicep/Helm.
- Eigene Threat-Bibliothek parallel zu `known-threats.yaml`.
- Generische "missing input validation"-Heuristik.
- Branchen-Compliance-Kataloge als eigene Rule-Library. Requirements-URL-Modell reicht.

## `signal_required`

`signal_required` ist sinnvoll, aber kein 0.5-PT-Quick-Win.

Der aktuelle OWASP-Coverage-Check arbeitet auf `data/owasp-top10-cwes.yaml` und Threat-CWEs. `signal_required` lebt in `data/threat-category-taxonomy.yaml` auf TH-NN-Ebene. Eine Aktivierung braucht daher eine echte Designentscheidung:

1. Check A bleibt OWASP-CWE-basiert und bekommt nur einfache Recon-Gates pro OWASP-Kategorie.
2. Oder es entsteht ein separater TH-NN-Coverage-Check, der `signal_required` und `signal_patterns` auswertet.

Empfehlung: nicht vor den Tier-1-Checks. Erst klaeren, ob das Ziel OWASP-Rauschreduktion oder TH-NN-Architektur-Coverage ist.

## Auswirkungen und Risiken

### Tokenverbrauch

Positive Wirkung:

- Deterministische Coverage reduziert wiederholte LLM-Rekonstruktion in STRIDE.
- Standard-Mode wird konsistenter, ohne Thorough/Architect-Reviewer zu erzwingen.

Risiken:

- Rohes `.recon-patterns.json` oder grosse Check-Ausgaben in STRIDE-Prompts wuerden Token sparen wieder zunichtemachen.
- Architektur-Coverage sollte nur kompakte Kandidaten, Counts und Dateipfade weitergeben.
- Volatile Kontextpfade duerfen nicht in Prompts inlined werden; bestehende Group-A/B/C-Dispatch-Ordnung respektieren.

Gemessener Anhaltspunkt im aktuellen Repo:

- `recon_patterns.py all` auf `/root/appsec-advisor`: ca. 7.5 s, Output ca. 14.8 KB.
- `coverage_checks.py all` auf leerem Output: ca. 0.2 s, Output ca. 9.2 KB.

Der Script-Overhead ist also klein. Der eigentliche Token-Risikohebel ist, wie viel davon in Agent-Prompts landet.

### Performance

Gute Performance-Regeln:

- Keine 8 separaten Repo-Walks.
- Pattern-Scans buendeln.
- Bestehende `.recon-patterns.json`, `.recon-summary.md`, `.cross-repo-register.json` und `.threats-merged.json` wiederverwenden.
- Route-Inventar, falls eingefuehrt, als einmaliger Prepass mit strukturierter Ausgabe bauen.

Schlechte Performance-Regeln:

- Pro Check eigene Grep-Runden ueber das ganze Repo.
- LLM-Agent fuer reine Regex-/Join-Logik.
- Config-Scanner-Regelkatalog stark vergroessern, ohne quick-mode cap oder file-surface precheck.

### Qualitaet

Erwarteter Gewinn:

- weniger vergessene Architektur-Gaps im Standard-Mode
- konsistentere Severity-Vorbewertung
- bessere Evidence-Verlinkung
- weniger Abhaengigkeit vom Architect-Reviewer

Qualitaetsrisiken:

- False Positives bei negativer Auth-/AuthZ-Erkennung.
- Doppelbefunde zwischen Recon, Config-Scanner, STRIDE und Coverage.
- Severity-Inflation, wenn CWE-Caps ignoriert werden.
- Coverage-Gaps mit zu generischer Prosa, die Engineer-Zeit verschwendet.
- CVSS-Verletzungen, wenn coverage/policy/design gaps Scores bekommen.

Mitigation:

- Jeder Check braucht klare Preconditions.
- Output muss zwischen `finding_candidate`, `coverage_warning` und `stride_hint` unterscheiden.
- Dedupe ueber CWE + file + line/route + title/surface.
- Tests fuer Severity-Caps, CVSS-Verbot und Skip-Faelle.

## Aktualisierte Reihenfolge

1. **Contract vorbereiten:** Schema/Validation fuer erweiterte Coverage-Ausgabe, Tests fuer Merge/Dedupe/Severity/CVSS-Verbot.
2. **Tier-1 High-Confidence:** Cookie, CORS, JWT, cleartext transport, management endpoint exposure.
3. **Quality gates:** keine pauschalen Criticals, keine CVSS fuer coverage gaps, Dedupe gegen STRIDE/config-scan.
4. **Tier-1b gated:** CSRF, Auth-Rate-Limit, Service-to-Service-Auth als Kandidaten/Warnungen mit Preconditions.
5. **Route-Inventar:** erst danach True Anonymous Routes und Authorization-Coverage.
6. **Breitere Architekturthemen:** Tenant/Ownership, Step-Up, Security Audit, Admin Plane, Async/Webhook/Queue, Cache Isolation.
7. **IaC-Erweiterungen:** Kubernetes/Terraform/Docker/Compose mit Config-Scanner-Wireup und Dedupe.
8. **`signal_required`:** separat entscheiden: OWASP-Gating oder TH-NN-Coverage.

## Kostenrahmen

| Block | Realistischer Aufwand | Hebel |
|---|---:|---|
| Contract + Schema + Merge-/Dedupe-Tests | 1-2 PT | hoch, verhindert Output-Drift |
| Tier-1 High-Confidence Checks | 3-5 PT | hoch |
| Tier-1b gated Checks | 3-5 PT | mittel bis hoch |
| Route-Inventar + AuthZ Coverage | 5-8 PT | hoch, aber groesserer Eingriff |
| Tenant/Step-Up/Audit/Admin/Async/Cache | 4-8 PT | hoch, je nach Scope |
| Tier-2 IaC-Erweiterungen | 3-5 PT | mittel |
| `signal_required` sauber aktivieren | 1.5-3 PT | mittel bis hoch |

Eine kleine sinnvolle erste Lieferung liegt bei etwa **4-7 PT**. Die komplette erweiterte Architektur-Coverage liegt eher bei **12-22 PT**, nicht bei 6-8 PT.

## Bilanz

Die Empfehlung bleibt: Architektur-Coverage deterministisch ausbauen. Aber nicht als breiter Regex-Katalog und nicht mit pauschalen High/Critical-Bewertungen.

Der beste erste Schritt ist ein kleiner Satz evidenzstarker Checks mit sauberer Schema-/Merge-/Severity-Absicherung. Danach lohnen Route-Inventar, Tenant-/Ownership-Isolation, Step-Up, Security-Audit und Admin-Plane-Trennung am meisten. Diese Themen treffen den Plugin-USP am besten: Architektur-Risiken sichtbar machen, die klassische Scanner uebersehen.
