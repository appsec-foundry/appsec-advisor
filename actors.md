# Actor Modeling — Konzept

**Status:** Design (noch nicht umgesetzt)
**Scope:** Actor-Layer als Input für STRIDE-Analyse, Architect-Reviewer-Integration, Quick/Incremental-Verhalten, Cross-Reference zu Attack-Tree-Konzept.

---

## 0. Ziel

### Outcome

Das Tool generiert nach Umsetzung dieses Konzepts Findings für Threat-Klassen, die heute strukturell nicht entstehen — Insider, Supply-Chain (als Actor, nicht nur Config), Privilege-Escalation-Pfade, B2B-Partner-Organisationen, Multi-Tenancy-Adjacent-Tenants, und domain-spezifische Actor-Klassen via Discovery. Jedes Finding trägt explizite Actor-Attribution (`actor_ids`, `primary_actor`) und actor-modulierte Likelihood. Reviewer kann pro Run lückenlos nachvollziehen, welcher Actor zu welchem Threat geführt hat, welche Actors aktiviert wurden warum, und welche Actors deaktiviert sind mit Rationale.

Actor-Layer-Drift erzeugt kein Findings-Chaos: F-NNN-IDs sind stabil, deaktivierte Actors führen zu `[obsolete-actor]`- oder `dormant`-Markern statt zu verschwindenden Findings, und Re-Runs ohne Code-/Input-Änderung sind deterministisch.

### Done-Kriterien (messbar)

Konzept gilt als umgesetzt wenn — verifiziert in dedizierten Test-Repos:

1. **Default-Library-Aktivierung sichtbar:** In einem Standard-Run wird jede der 9 Default-Actor-Klassen entweder aktiviert (mit Rationale aus Recon-Signalen) oder explizit ausgelassen (mit Rationale). Kein Actor verschwindet stillschweigend.
2. **Test-Repo Multi-Tenancy** (Tenant-Spalte + Tenant-Middleware): mindestens 1 Finding mit `actor_ids: [ACT-D-09]`.
3. **Test-Repo CI-Pipeline + `.env`**: mindestens 1 Finding mit `actor_ids` enthält `ACT-D-04` oder `ACT-D-06`.
4. **Test-Repo B2B-API:** Discovery schlägt B2B-Partner-Org als `proposed_additional` vor; nach Reviewer-Promotion ist Actor stabil im Repo-Layer mit gleichbleibender ID und Findings bleiben unter dieser ID stabil getagged.
5. **Stable-ID-Test:** Re-Run ohne Code- und Input-Drift produziert byte-identische Findings-Liste (Snapshot-Replay + Stable-ID).
6. **Actor-Disable-Test:** Re-Run nach Disable eines Actors mit zugeordneten Findings — betroffene Findings tragen `[obsolete-actor]`- oder `dormant`-Marker, verschwinden nicht. Severity wird neutral re-moduliert.
7. **Slice-Diff-Re-Run-Test:** Re-Run mit Actor-Input-Drift ohne Code-Drift triggert Forward-STRIDE nur für Komponenten mit Slice-Änderung, nicht repo-weit.
8. **Quick-Mode-Test:** Findings tragen Actor-Tags aus Default-Library; Discovery-Skip ist im Bericht explizit dokumentiert; keine LLM-Calls für Actor-Discovery.
9. **Architect-Reviewer Check #15** läuft in Standard/Thorough-Modus und produziert strukturierte Findings für die 5 Sub-Checks.
10. **Documentation & Sample Surface gelandet:** README.md, `docs/org-profiles.md`, `docs/internal-plugin-packaging.md`, `docs/multi-repo-analysis.md`, `CHANGELOG.md`, `skills/create-threat-model/HELP.txt`, sowie Fixture-Trio in `tests/fixtures/e2e/` (Multi-Tenancy/CI/B2B) sind im selben Release-Cut aktualisiert. Vollständige Pfad-Liste in §14 "Documentation & Sample Surface".

### Non-Goals

Aus dem Scope dieses Konzepts explizit ausgeschlossen:

- **Keine Auto-Promotion** von Discovery-Vorschlägen in den Repo-Layer. Persistierung ist Reviewer-Pflicht.
- **Keine Cross-Repo-Actor-Resolution.** ACT-D-07 wird nur über repo-interne externe API-Calls aktiviert. `related-repos.yaml` triggert keine Actor-Pulls aus anderen Repos. Föderierte Actor-Modelle sind Phase 2.
- **Keine Profile-Inheritance zwischen Org-Profiles für Actors.** Enterprise-Setup bleibt single-profile.
- **Keine LLM-basierte Re-Tagging-Heuristik** bei Actor-Input-Drift. Stattdessen Forward-STRIDE-Re-Run pro betroffener Komponente (siehe §13).
- **Kein Hard-Fail** bei Schema-v1-Org-Profiles oder fehlender Default-Coverage in `inherit_defaults: false`. Warnings statt blockierender Validierungs-Fehler.
- **Keine Tree-/Attack-Path-Konstruktion** in diesem Doc. Separates `trees.md` baut auf Actors auf (siehe §16).
- **Keine Severity-Re-Mixing in CVSS Base.** Actor-Modulation passiert nur über Likelihood-Multiplier, CVSS-Compliance bleibt intakt.
- **Keine Migration aus narrativen Business-Context-Dokumenten** in diesem Scope. Ein optionales Extract-Actors-Skill ist Phase 2 (§15.3).

---

## 1. Problem und Motivation

Das aktuelle Tool hat keinen expliziten Actor-Parameter im Analyzer. STRIDE-Analyzer-Prompt enthält implizite Annahmen ("anonymous internet attacker", "authenticated user"), aber keine strukturierte Actor-Dimension. Folge: ganze Threat-Klassen werden strukturell nicht gesucht.

**Konkrete Lücken heute:**

- **Insider-Threats**: kein Actor → keine Suche nach CI-Secret-Exfiltration durch Dev, Staging-zu-Prod-Pivot, Audit-Log-Bypass durch privilegierten Operator.
- **Supply-Chain-Attacker**: teilweise als `SUPPLY_CHAIN_FINDINGS` aus Recon, aber nicht als Actor-Klasse → Dependency-Confusion, Maintainer-Account-Takeover, Build-Artifact-Tampering werden als isolierte Config-Findings analysiert, nicht als Actor-getriebene Angriffsklassen.
- **Authenticated Power-User**: Privilege-Escalation-Pfade von Standard-User zu Admin werden meist lokal gefunden, nicht systematisch verfolgt.
- **B2B-Partner / Multi-Tenancy-Customer / IoT-Device-Owner**: domain-spezifische Actors, die strukturell zum System gehören, aber von generic-Attacker-Modellen nicht abgedeckt sind.

**Was diese Lücke nicht ist:** Ein UX-Problem oder Reporting-Problem. Es ist ein Finding-Discovery-Problem — Threats, die ohne Actor-Modell schlicht nicht generiert werden.

---

## 2. Design-Prinzipien

Drei Prinzipien, die das Design durchziehen und Risiken aus früheren Analysen strukturell ausschließen:

1. **Anti-Anchoring durch verpflichtende LLM-Extension.** Eine explizite Actor-Liste birgt das Risiko, dass das LLM seine Suche darauf verengt. Lösung: nach jeder Input-Resolution läuft eine Discovery-Phase, die Actors *zusätzlich* identifizieren darf und muss. Default-Library ist exhaustiv genug, dass auch ohne Discovery nichts strukturell verloren geht.

2. **Stable IDs entkoppelt von Layer-Drift.** Findings tragen Actor-Tags als Annotation, nicht als Existenz-Bedingung. Wenn ein Actor deaktiviert wird, verschwindet das Tag — das Finding bleibt persistent. Damit ist F-NNN-Stabilität über Reruns gewährleistet.

3. **Hybrid-Inputs statt monolithischer Library.** Vier Layer (Plugin-Default → Enterprise → Repo → LLM-Discovery) ergänzen einander additiv. Spätere Layer können ergänzen oder anpassen, nicht stillschweigend ersetzen. Jeder Eintrag trägt `_provenance` für Audit.

---

## 3. Layer-Architektur

```
Plugin-Default-Library          (data/actors/default-library.yaml)
        ↓ additiv-merge
Enterprise-Layer                (org-profile/<profile>/actors/*.yaml)
        ↓ additiv-merge
Repo-Layer                      (<target-repo>/.appsec/actors.yaml)
        ↓ additiv-merge
LLM-Discovery                   (appsec-actor-discoverer Agent)
        ↓
Resolved Actor Set              (.actors-resolved.json)
```

### Merge-Semantik

- **Additiv per ID.** Neuer Layer fügt Actors hinzu oder modifiziert existierende per ID-Match.
- **Field-Level-Deep-Merge** bei ID-Kollision. Spätere Layer überschreiben einzelne Felder, mergen Listen (`access`, `tooling`) zu Union.
- **Explizites Disable** über `disable: [ACT-XX]`-Sektion in jedem Layer. Deaktivierung wird in `_provenance.disabled_by` geloggt; jeder deaktivierte Default-Actor erscheint im Run-Issues-Bericht (Audit-Sichtbarkeit).
- **LLM-Discovery darf nicht disablen.** Discovery schlägt nur vor (`proposed_additional`). Persistierung erfordert Reviewer-Promotion in nächsten Repo-Layer.

### Provenance

Jeder Actor im resolved-Set trägt:

```yaml
_provenance:
  layer: plugin | enterprise | repo | discovery
  source_file: <relativer Pfad>
  introduced_at: <git-sha oder layer-version>
  modified_by: [<layer>, <layer>, ...]   # Liste wenn mehrere Layer das Feld berührt haben
  disabled_by: <layer>                    # nur wenn disabled
  promoted_from_discovery: true|false     # true wenn Actor ursprünglich von LLM-Discovery vorgeschlagen
  promoted_at: <git-sha>                  # nur wenn promoted_from_discovery=true
```

**Promotion-ID-Stabilität:** Beim Promoten eines Discovery-Actors (`ACT-X-N`) in den Repo-Layer behält der Actor seine ursprüngliche ID. Provenance trägt die Promotion-Information. Damit bleiben Findings, die unter `ACT-X-N` im Discovery-Run getagged wurden, beim nächsten Run stabil mit dem nun persistierten Actor verbunden. Optionales Renaming auf `ACT-R-M` ist erlaubt, dann **muss** ein `renamed_from: ACT-X-N` Alias im Repo-Layer geführt werden.

---

## 4. Actor-Datenmodell

### Pflichtfelder

| Feld | Zweck |
|---|---|
| `id` | Stabile Referenz `ACT-NN`. Findings taggen damit. Niemals neu vergeben. |
| `label` | Lesbares Kürzel (`malicious-insider-dev`) |
| `access` | Zonen/Systeme mit Reach. Strukturierte Enum-Liste (siehe unten). |
| `capabilities` | Strukturierter Block: sophistication, tooling, dwell_time, surface_reach |
| `motivation` | Enum: `financial`, `disruption`, `espionage`, `curiosity`, `accidental` |

### Optionale Felder

| Feld | Zweck |
|---|---|
| `activation_conditions` | Heuristik wann Actor relevant ist. Bei Default-Library: hardcoded Signal-Set. Bei custom-actors: optional — Default ohne Conditions ist `always-active im Repo-Scope` mit sichtbarer Annotation im Bericht. |
| `description` | Freitext für menschliche Reviewer, kein LLM-Inhalt |
| `severity_modulation` | Multiplier-Lookup pro Threat-Category für Likelihood-Adjustment. Plugin-Library liefert Per-Actor-Defaults; Layer überschreiben additiv. Konkrete Mechanik in §10. |

### Capabilities-Block

```yaml
capabilities:
  sophistication: high | medium | low
  tooling: [debugger, network-sniffer, off-the-shelf, custom-malware, social-eng]
  dwell_time: short | weeks | months
  surface_reach: [local, lateral, persistent]
```

Strukturiert (nicht Freitext), weil:
- Per-Component-Slicing braucht Heuristik auf `surface_reach`/`access`.
- Severity-Modulation rechnet mit `sophistication`-Multipliers.
- Architect-Reviewer Check #15 prüft Konsistenz `capabilities` vs. tatsächlich getaggte Findings.

### Access-Enum

Vordefinierte Zonen, ergänzt durch Repo-Layer wenn nötig:

```
internet, dmz, internal-network,
authenticated-user-session, authenticated-admin-session,
local-fs, ci-cd-secrets, ci-cd-runtime,
staging-env, prod-env, prod-readonly-db, prod-write-db,
build-pipeline, deployment-pipeline,
client-device, mobile-device,
adjacent-tenant, peer-service
```

Repo-Layer darf Custom-Zonen ergänzen (`access: [internet, custom-vpn-zone]`); Plugin lässt sie durch ohne Validierungs-Fehler, aber logged "unbekannte Zone — Slicing-Heuristik fällt zurück auf liberal-include".

---

## 5. Plugin-Default-Library

Pfad: `data/actors/default-library.yaml`. Im Plugin gepflegt, exhaustiv genug, dass auch ohne Override nichts strukturell verloren geht.

### Default-Actors

| ID | Label | Standard-aktiv wenn |
|---|---|---|
| `ACT-D-01` | `anonymous-internet-attacker` | öffentliche Komponente in Recon |
| `ACT-D-02` | `authenticated-low-priv-user` | Auth-Surface in Recon |
| `ACT-D-03` | `authenticated-high-priv-user` | Role/Admin-Konzept im Code |
| `ACT-D-04` | `malicious-insider-dev` | `.env`/`secrets/`/Dev-Tooling im Repo |
| `ACT-D-05` | `malicious-insider-ops` | Deploy-/Infra-Code im Repo |
| `ACT-D-06` | `supply-chain-attacker` | Dependencies/CI/Build-Pipeline existieren |
| `ACT-D-07` | `compromised-third-party-service` | externe API-Calls erkennbar im Repo (HTTP-Clients, SDK-Imports). `related-repos.yaml` ist Recon-Input für Threat-Surface, **kein** Aktivierungs-Trigger — Cross-Repo-Actor-Pull ist Phase 2 (§15.6). |
| `ACT-D-08` | `physical-device-holder` | Client-Side-Storage / Mobile-Patterns |
| `ACT-D-09` | `tenant-from-adjacent-tenancy` | **Mindestens 2 Multi-Tenancy-Signale gleichzeitig**: (a) Tenant-Spalte/-Feld im Schema (`tenant_id`, `tenantId`, `organization_id`, `orgId`, `account_id`, `workspace_id`, `customer_id`, `realm_id` und Snake-/Camel-Varianten) PLUS (b) Tenant-Scoping-Pattern (Middleware/Context wie `tenantContext`/`current_tenant`, RLS-Policy-Spalten, Foreign-Key auf Tenants-Table). Einzelnes `account_id` ohne Scoping-Pattern reicht **nicht**, sonst False-Positives auf single-tenant Apps. |

**Disambiguation ACT-D-07 vs. ACT-D-09:** ACT-D-07 = externer Service, dessen Auth/API der Angreifer kontrolliert (Reach: peer-service, externe API-Antwort). ACT-D-09 = legitimer Co-Tenant innerhalb derselben Multi-Tenant-Instanz (Reach: shared-database, shared-cache, lateral). Wo beide passen, werden beide getagged — `primary_actor`-Algorithmus (§10) entscheidet deterministisch.

`ACT-D-*` Prefix kennzeichnet Default-Library. Enterprise/Repo verwenden `ACT-E-*` und `ACT-R-*`. Discovery vergibt `ACT-X-*` (X für "extension/proposed"). Promotion durch Reviewer behält die ursprüngliche ID per default (`ACT-X-3` bleibt `ACT-X-3` auch im Repo-Layer); optionales Renaming auf `ACT-R-N` erfordert Alias-Pflege `renamed_from: ACT-X-3` (siehe §3 Promotion-ID-Stabilität).

### Activation-Conditions

Hardcoded im Plugin. Recon-Phase setzt Signal-Flags (`has_public_routes`, `has_auth_surface`, `has_role_concept`, `has_secrets_in_repo`, `has_ci_pipeline`, `has_external_apis`, `has_client_storage`, `has_multi_tenancy_signal`). Resolver aktiviert Default-Actor genau dann, wenn alle benötigten Signale gesetzt sind.

**Recon-Erweiterung erforderlich.** Diese Signal-Flags werden heute von der Recon-Phase **nicht** emittiert. Implementierung dieses Konzepts setzt voraus, dass `appsec-recon-scanner` einen `signals`-Block pro Repo in das Recon-Output schreibt; die Flag-Namen sind bewusst stable, damit Activation-Conditions im Plugin gegen ein definiertes Vokabular prüfen. Bis dahin laufen alle Default-Actors mit Fallback `signal_missing → activate-with-warning` (sichtbar im Bericht), um Findings-Verlust durch unimplementierte Signale zu vermeiden.

**Recon-Anforderung:** Damit Per-Component-Slicing (§9) deterministisch ist, **muss** die Recon-Phase pro identifizierter Komponente einen strukturierten Block liefern mit:
- `component_type` (enum: `auth-service`, `admin-interface`, `payment-handler`, `ci-cd-pipeline`, `developer-workstation`, `data-store`, `api-endpoint`, `web-frontend`, `worker`, `gateway`, ...)
- `deployment_zones` (enum-Liste aus dem Access-Enum oben)

Detection erfolgt primär deterministisch (File-Path-Pattern, Dockerfile, package.json-Hints, Framework-Detection). Bei ambiguer Komponente fällt Recon auf LLM-Klassifikation zurück und markiert `_provenance.classification: llm-fallback` — Slicing-Determinismus ist dann für diese Komponente bewusst broken und sichtbar.

**Activation ≠ Relevance pro Komponente.** Activation = "ist überhaupt im Scope dieses Repos". Per-Component-Slicing entscheidet später, welche aktivierten Actors zu welcher Komponente passen (Sektion 9).

---

## 6. Enterprise-Layer (Org-Profile-Integration)

### Schema-Erweiterung

Bestehendes Org-Profile-Schema (`schemas/org-profile.schema.yaml`, kanonische Fixture-Referenz: `tests/fixtures/org-profiles/acme/org-profile.yaml`) bekommt eine neue Top-Level-Sektion `actors:`. Versions-Bump erfolgt über das existierende `api_version`-Feld:

```yaml
# org-profile/<profile-name>/org-profile.yaml
api_version: appsec-advisor.org-profile/v2   # bump von /v1

organization:
  id: acme
  name: Acme Corp
  profile_version: 1.0

compatibility:
  core: ">=0.0 <999.0"

default_preset: ci-standard

# ... existierende Blocks (requirements, llm_context, security_coach,
#     skill_toggles, presets) bleiben unverändert ...

actors:
  inherit_defaults: true              # Plugin-Defaults aktiv lassen (Standardwert)
  disable: []                          # explizite ID-Deaktivierungen mit Audit
  add: actors/*.yaml                  # Glob für zusätzliche Actor-Dateien
```

Actor-Definitionen liegen in `org-profile/<profile-name>/actors/*.yaml`, parallel zum existierenden `context/`-Verzeichnis (das die `llm_context`-Dokumente trägt). Ein File pro Actor oder gruppiert nach Klasse (`insiders.yaml`, `external.yaml`) — frei wählbar. Jede Datei enthält ein Top-Level-Array `actors:` mit Actor-Objekten gemäß Datenmodell (§4).

### Validierung

`validate_org_profile.py` wird um Actor-Sektion erweitert:
- ID-Eindeutigkeit innerhalb des Profils
- Schema-Validität pro Actor (jsonschema)
- `disable`-Referenzen müssen auf existierende Actor-IDs zeigen (Plugin-Defaults oder gleichprofilig hinzugefügte)
- Aktivierungs-Konditionen, falls custom, gegen bekannte Signal-Flags prüfen

### Fingerprint-Impact

`resolve_org_profile.py` berechnet heute `profile_fingerprint` als sha256 über profile YAML bytes. Erweiterung: Fingerprint wird über *alle* gemergten Actor-Dateien des Profils gehasht.

**Wichtig für Incremental:** Eine reine Actor-Input-Änderung (Fingerprint geändert, Code unverändert) triggert keinen Recon-Re-Run und keinen repo-weiten Forward-STRIDE-Re-Run; sie triggert nur einen Per-Component-Slice-Diff-getriebenen Forward-STRIDE-Re-Run für Komponenten, deren `.actors-for-<component-id>.json` tatsächlich gedriftet ist. Granularität wird in §13 beschrieben. (Es existiert kein separater "Tagging-Cache" als Artefakt — die Slice-Datei pro Komponente ist die einzige Cache-Einheit auf Actor-Ebene.)

### Layered-Merge mit Plugin-Defaults

Bei `inherit_defaults: true` (Standard) merged der Resolver Plugin-Defaults zuerst, dann Enterprise-Actors. Disable-Liste wirkt nach dem Merge — Enterprise kann Plugin-Default-Actor explizit deaktivieren, muss aber `disabled_by: enterprise` setzen und einen `disable_reason` mitliefern (Pflicht für Audit-Trail).

**Enterprise-Disable ist terminal für Repo-Layer.** Repo darf ein Enterprise-Disable nicht zurücknehmen (kein `enable:`-Reverse). Wenn Repo den Actor braucht: er redefiniert ihn unter eigener `ACT-R-*` ID. Klare Trennung, sichtbarer Akt im Repo-Layer-File. Begründung: Compliance-Setups brauchen verlässliche Enterprise-terminale Decisions; eine Reverse-Operation würde Org-Profile zur Empfehlung statt zur Policy degradieren.

`inherit_defaults: false` ist ein Notausstieg für regulierte Umgebungen, die einen vollständig kontrollierten Actor-Stack wollen. Tool warnt nicht-blockierend (Run-Issue, kein Fail): es listet alle 9 Default-Actor-Klassen mit Status `covered | partial | missing`. Enterprise darf pro selbst-definiertem Actor `replaces: ACT-D-NN` deklarieren — dann gilt die Klasse als `covered`. Keine Pflicht-Liste; Entscheidung liegt beim Reviewer.

### Schema-Version-Migration

Org-Profile mit `api_version: appsec-advisor.org-profile/v1` werden beim Laden transparent als v2 behandelt mit Default-Werten:

```yaml
actors:
  inherit_defaults: true
  disable: []
  add: []
```

Tool emittiert dann pro Run ein `info`-Issue: `Org profile is api_version v1 — auto-upgraded for this run. Persist as v2 to silence this notice.` Optionaler CLI-Befehl `appsec-advisor:migrate-org-profile <path>` führt die Migration physisch durch. Hard-Fail bewusst vermieden: Schema-Bump darf existierende Setups nicht brechen. `compatibility.core`-Bereich bleibt unverändert — actor-Erweiterung ist additiv, nicht versionsbrechend.

---

## 7. Repo-Layer (`.appsec/actors.yaml`)

### Datei-Struktur

```yaml
# <target-repo>/.appsec/actors.yaml
schema_version: 1
inherit_org: true             # Org-Profile-Actors aktiv lassen (Standard)
disable: []                    # explizite Deaktivierung mit Rationale-Pflicht
actors:
  - id: ACT-R-1
    label: b2b-partner-org
    access: [authenticated-user-session, partner-api-zone]
    capabilities:
      sophistication: medium
      tooling: [off-the-shelf]
      dwell_time: weeks
      surface_reach: [lateral]
    motivation: financial
    description: "Eingebundener B2B-Kunde mit eigenem API-Key, kann eigene Tenants nicht aber fremde sehen."
```

### Override-Semantik

- **Repo darf Org-Actor-Felder anpassen** (ID-Match): z.B. Org definiert `supply-chain-attacker` generisch, Repo schärft `capabilities.tooling` auf konkrete Ecosystem-Spezifika.
- **Repo darf Org-Actor disablen** mit `disable: [ACT-E-7]` + Pflicht-Feld `disable_reason`. Tool zeigt im Run-Issues-Bericht: "Repo deaktiviert ACT-E-7 weil: <reason>".
- **Repo-Actors haben Prefix `ACT-R-*`**. IDs sind stabil innerhalb des Repos.

### Discovery-Toggle

Optional am Layer-Top-Level:

```yaml
discovery:
  enabled: true               # default true; quick-mode setzt extern auf false
  max_proposed: 10            # Limit für vorgeschlagene Actors pro Run
```

### Stale-Detection für Repo-Layer

Repo-Actors können einen optionalen `evidence`-Block tragen, der den Resolver-Pass `verify_anchors` triggert:

```yaml
- id: ACT-R-1
  label: b2b-partner-org
  ...
  evidence:
    files: ["routes/partner-api/*.ts"]
    pattern: "PartnerAuth|partnerApiKey"
```

Wenn Pattern nicht mehr matcht → Actor wird mit `_provenance.stale: true` markiert, aber **nicht entfernt**. Stride-Analyzer kriegt den Hinweis "may be outdated"; Run-Issues meldet zur Pflege.

**Performance-Hinweis:** Evidence-Matching läuft nur, wenn `actors_inputs_fingerprint` oder Code-Fingerprint sich geändert hat. Ergebnis wird in `.evidence-match-cache.json` mit File-Mtime-Check persistiert. Pattern-Engine: ripgrep (bereits Standard-Dependency). Bei Repo-Layern mit >20 Actors: parallele Matches.

---

## 8. LLM-Discovery-Phase

### Agent-Spezifikation

**Name:** `appsec-actor-discoverer`

**Pipeline-Position:** Nach Recon (Phase 2), nach Config-IaC-Scan (Phase 2.5), VOR Architecture-Modeling (Phase 3) und VOR STRIDE-Fan-out. Eigene Phase (Phase 2.7), kein Sub-Step.

**Modell:** Sonnet. Discovery ist breadth-first-Identifikation, kein Deep-Reasoning. **Erwartetes Budget: 15–25k Tokens** — Recon-Summary kann alleine 5k umfassen, plus Config-Scan, plus Cross-Repo-Register als Input. Frühere Schätzung 5–10k war zu knapp.

**Skipped wenn:** Quick-Mode aktiv (siehe Sektion 12) oder `discovery.enabled: false` im Repo-Layer.

### Inputs

| Input | Quelle |
|---|---|
| Gemergte Actor-Liste (Layer 1-3) | `.actors-merged-static.json` (vom Resolver vorab erzeugt) |
| Recon-Summary | `.recon-summary.md` |
| Config-Scan | `.config-scan.json` |
| Threat-Modeling-Context | `.threat-modeling-context.md` |
| Cross-Repo-Register | `.cross-repo-register.json` (falls vorhanden) |

### Anti-Anchoring-Prompt-Kern (zweistufig)

Der Prompt ist bewusst in zwei Sektionen geteilt, damit die Heuristik-Liste nicht selbst zum Anker wird:

**Sektion A — Signal-konditionierte Checklist.** Heuristik wird nur gefordert, wenn das Recon-Signal vorhanden ist:

> "Du bekommst eine Actor-Liste. Diese Liste ist nicht abschließend.
>
> Für jede der folgenden Bedingungen, **die im Recon-Output zutrifft**, prüfe die genannte Actor-Frage und antworte:
> - Wenn `has_external_apis` → Webhook-Sender? B2B-Partner-Org?
> - Wenn `has_multi_tenancy_signal` → Shared-Tenant-Customer? Cross-Tenant-Information-Leak-Actor?
> - Wenn ML/AI-Komponente erkannt → Training-Data-Poisoner? Prompt-Injector?
> - Wenn IoT/Device-Pattern erkannt → Device-Owner?
> - Wenn Plugin-/Extension-System erkannt → Plugin-Author?
> - Wenn Marketplace-Pattern erkannt → Buyer/Seller mit eigener Auth?
> - Wenn Embedded-Customer-Code erkannt → Customer-as-Code-Author?
>
> Bedingung nicht erfüllt → keine Pflicht-Antwort dazu, kein 'n/a'-Eintrag."

**Sektion B — Free-Form-Slot.** Bewusst ohne vorgegebene Heuristik-Liste:

> "Welche Actor-Klassen siehst du noch im Repo, die strukturell zum System gehören, aber weder in der Liste noch in Sektion A abgedeckt sind? Begründe jeden Vorschlag mit konkretem Recon-Signal (file:line oder section-name). Bevorzuge False-Positives über False-Negatives — Reviewer kann ablehnen, Auslassung fällt strukturell durch."

Vorschläge aus Sektion B tragen im Output `discovery_method: heuristic-bypass`, damit Reviewer sieht welche Vorschläge aus offener Exploration kamen (typischerweise höhere Confidence-Anforderung an die Rationale).

### Output: `.actors-discovered.json`

```json
{
  "schema_version": 1,
  "confirmed_relevant": [
    {
      "id": "ACT-D-04",
      "relevance_evidence": "recon-summary §3.2 zeigt .env-Datei in Repo",
      "confidence": "high"
    }
  ],
  "proposed_additional": [
    {
      "id": "ACT-X-1",
      "label": "b2b-partner-org",
      "access": ["partner-api-zone"],
      "capabilities": { ... },
      "motivation": "financial",
      "rationale": "recon-summary §3.7 zeigt routes/partner-api/* mit eigenem API-Key-Auth",
      "confidence": "high"
    }
  ],
  "inputs_questioned": [
    {
      "id": "ACT-E-3",
      "reason": "Recon zeigt keine Mobile-App-Patterns; ACT-E-3 (physical-device-holder) hat keinen plausiblen Reach für dieses Repo",
      "recommendation": "review_for_disable"
    }
  ],
  "coverage_rationale": "Final-Set covers anonymous internet, authenticated low/high priv, supply chain via npm, B2B partner integration. Kein Multi-Tenancy-Signal, kein IoT, kein ML."
}
```

### Reviewer-Promotion

`proposed_additional`-Actors sind **im laufenden Run aktiv** und werden an STRIDE-Analyzer mitgegeben. Sie tragen `_provenance.layer: discovery` und `_provenance.proposed: true`.

Im Endbericht erscheinen sie in einer eigenen Sub-Section ("Newly identified actors — please confirm") mit Rationale und Findings, die sie ausgelöst haben.

**Persistierung erfordert manuellen Reviewer-Commit.** Reviewer kopiert `ACT-X-1` aus `.actors-discovered.json` in `.appsec/actors.yaml`, vergibt eine `ACT-R-N` ID, committed. Beim nächsten Run wird der Actor stabil im Repo-Layer geführt.

Kein Auto-Promotion. Sonst würde Discovery-Output über Reruns selbständig in den Repo-Layer wandern und ein Gefühl falscher Stabilität erzeugen.

`inputs_questioned`-Markierungen erscheinen **sowohl** in `.run-issues.json` **als auch** im Bericht (eigene Sub-Section §1.5.3 "Actors flagged for review"). Begründung: Reviewer arbeitet primär aus dem Bericht; Run-Issues-JSON wird in der Praxis ignoriert.

**Eskalation:** Wenn derselbe Actor in N≥3 aufeinanderfolgenden Runs `inputs_questioned` bleibt, eskaliert das Tool die Markierung von `advisory` auf `defect` im Bericht-Header (Severity-Vokabular konsistent mit §11 und §14: `info | advisory | defect`, lowercase). Verhindert Endlosschleife "Discovery fragt → Reviewer ignoriert → Discovery fragt erneut".

### Discovery-Cache-Key

Discovery läuft nicht bei jedem Run neu. `.actors-discovered.json` wird Teil des persistierten State und wiederverwendet, solange folgender Hash unverändert bleibt:

```
discovery_inputs_fingerprint = sha256(
  recon-summary-content ||
  config-scan-content ||
  actors_inputs_fingerprint ||      # Plugin + Enterprise + Repo Actor-Files
  plugin_version ||                  # Plugin-Updates triggern Discovery-Refresh
  discovery_prompt_version           # Semver des Discovery-Prompts; Bump bei Prompt-Edit
)
```

Snapshot-Replay ist Default, nicht Re-Run. Begründung: LLM-Determinismus ist nicht garantierbar; pro-Run-Re-Discovery erzeugt false-positive Diffs in `actor_ids` zwischen Runs. Reviewer kann mit `--refresh-discovery` einen Re-Run explizit erzwingen.

Persistiert in `.skill-config.json` neben den existierenden Fingerprints.

---

## 9. Per-Component-Slicing

### Relevance-Heuristik

Orchestrator (Python, nicht LLM) berechnet pro Komponente die relevanten Actors. Heuristik:

```
actor_relevant_to_component(actor, component) :=
    actor.access ∩ component.deployment_zones ≠ ∅
    OR actor.id ∈ COMPONENT_ALWAYS_RELEVANT[component.type]
```

Heuristik bewusst auf zwei Bedingungen reduziert. Eine frühere Variante referenzierte `component.interfaces.exposed_to`; das Feld ist im Recon-Datenmodell (§5) nicht spezifiziert und wurde entfernt, um die Slicing-Formel an `deployment_zones` als einzige Reach-Quelle zu binden. Domain-Spezifika (z.B. ein Service mit Partner-API-Zone) werden über `COMPONENT_ALWAYS_RELEVANT` ergänzt, nicht über zusätzliche Interface-Felder.

### COMPONENT_ALWAYS_RELEVANT

Lookup-Tabelle, layered analog zum Actor-Layer (additive Merge): Plugin liefert Defaults, Org-Profile und Repo-Layer ergänzen pro Custom-Component-Type.

Plugin-Defaults:

| Komponenten-Typ | Immer-Relevante Actor-Klassen |
|---|---|
| `ci-cd-pipeline` | supply-chain-attacker, malicious-insider-ops |
| `auth-service` | anonymous-internet-attacker, authenticated-low-priv-user |
| `admin-interface` | authenticated-high-priv-user, malicious-insider-dev |
| `payment-handler` | anonymous-internet-attacker, authenticated-low-priv-user, malicious-insider-dev |
| `developer-workstation` | malicious-insider-dev, supply-chain-attacker |

Org- und Repo-Layer dürfen ergänzen, z.B.:

```yaml
# org-profile/<profile>/component-relevance.yaml
component_always_relevant:
  tax-calculation-microservice:
    - ACT-D-04   # malicious-insider-dev
    - ACT-E-3    # finance-auditor (org-spezifisch)
```

Defensive Default: lieber zu viele relevant als zu wenige.

**Component-Type-Quelle:** `component.type` und `component.deployment_zones` stammen aus dem Recon-Output (siehe §5 Recon-Anforderung). Slicing rechnet deterministisch, solange Recon deterministisch klassifiziert; LLM-Fallback-Klassifikationen werden im Bericht markiert.

### Slice-File

Pro Komponente wird `.actors-for-<component-id>.json` erzeugt:

```json
{
  "component_id": "auth-service",
  "relevant_actors": [
    {"id": "ACT-D-01", "label": "anonymous-internet-attacker", ...},
    {"id": "ACT-D-02", "label": "authenticated-low-priv-user", ...},
    {"id": "ACT-X-1", "label": "b2b-partner-org", "proposed": true, ...}
  ],
  "relevance_rationale": {
    "ACT-D-01": "component.interfaces[0] exposed_to=internet",
    "ACT-X-1": "actor.access=[partner-api-zone] ∩ component.deployment_zones=[partner-api-zone]"
  }
}
```

Pfad geht als Prompt-Param `RELEVANT_ACTORS_INDEX_PATH` an STRIDE-Analyzer (analog zu existierenden Index-Paths).

---

## 10. STRIDE-Analyzer-Integration

### Neuer Prompt-Parameter

`RELEVANT_ACTORS_INDEX_PATH` — Pfad zur Slice-Datei. Analyzer liest die Datei **einmal** zu Beginn von Step 1, behält die Actor-Liste im Working-Memory.

### Pflicht-Verhaltensänderung in Step 3

Pro STRIDE-Kategorie (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation):

> Iteriere über alle relevanten Actors. Pro Actor: kann *dieser* Actor mit *diesen* Capabilities *diesen* Threat hier realisieren? Wenn ja → Finding mit `actor_ids: [...]` und `primary_actor: <id>`. Wenn nein → keine Eintragspflicht (kein Coverage-Theater).

Damit ist die Iteration im Prompt verankert, aber kein "n/a"-Trail erzwungen. Findings entstehen wenn Actor × Threat × Code-Evidence zusammenkommen.

### Severity-Mechanik

Eine Mechanik, durchgängig: **Multiplier-Lookup pro Actor × Threat-Category, applied als Likelihood-Modifier auf eine numerische `base_likelihood` (CVSS Base bleibt unangetastet).**

```
actor_adjusted_likelihood = base_likelihood × actor.severity_modulation[threat_category_id]
```

- **Verhältnis zum existierenden `likelihood`-Feld.** `threat-model.output.schema.yaml` führt heute `likelihood` als String-Enum (`Critical | High | Medium | Low | Informational`). Das Feld bleibt für Bericht-Konsistenz erhalten. `base_likelihood` ist eine **neue numerische Größe** im Bereich `[0.0, 1.0]`, abgeleitet aus dem existierenden Enum via deterministischem Lookup (`Critical=1.0`, `High=0.8`, `Medium=0.6`, `Low=0.4`, `Informational=0.2`). `actor_adjusted_likelihood` wird zurück auf das Enum gemappt (selber Lookup, Banding) und überschreibt **nicht** das ursprüngliche `likelihood`-Feld; es erscheint als zusätzliches Feld neben `likelihood`. Findings ohne aktiven Actor (`actor_ids: []`) behalten `actor_adjusted_likelihood = likelihood` (neutral).
- Plugin-Library liefert Per-Actor-Default-Multipliers pro Threat-Category (TH-NN aus existing taxonomy). Layer überschreiben additiv. Multiplier-Range bewusst `[0.5, 1.5]`, damit Modulation nicht das volle Severity-Banding überspringt.
- `actor_adjusted_likelihood` erscheint als sichtbare Spalte im Bericht **neben** `raw_cvss` und `likelihood`. Kein Re-Mix in CVSS-Base, damit CVSS-Compliance intakt bleibt.

### Finding-Schema-Erweiterung

```yaml
- id: F-007
  title: "JWT role claim forgery enables admin access"
  stride: [Spoofing, Elevation]
  threat_category_id: TH-02
  actor_ids: [ACT-D-01, ACT-D-04]     # NEU — wer das ausnutzen kann
  primary_actor: ACT-D-04              # NEU — schärfster Ausnutzer, treibt Likelihood
  severity:
    raw_cvss: 8.1
    base_likelihood: 1.0
    actor_adjusted_likelihood: 0.85   # NEU — base_likelihood × primary_actor.severity_modulation[TH-02]
  _provenance:
    created_by_actor: ACT-D-04        # NEU — wenn Finding strukturell von einem Actor abhängt, der nicht in der Default-Library ist
  ...
```

### `primary_actor`-Auswahl-Algorithmus

Deterministisch, hardcoded:

```
primary_actor = argmax over actor_ids by:
  1. actor_adjusted_likelihood (höchster gewinnt)
  2. Tiebreak: id-lexikografisch (stabil und reproduzierbar)
```

`sophistication` wurde bewusst **nicht** als Tiebreak gewählt: low-sophistication-Threats kommen schon über höhere `severity_modulation`-Multipliers für Mass-Threat-Categories rein. Eine zusätzliche Sophistication-Achse als Tiebreak würde Targeted-Threats fälschlich downranken.

Wenn primary-Actor zwischen Runs wechselt (z.B. neuer Actor mit höherer Modulation kommt rein): Severity ändert sich, Diff-Renderer markiert `[input-change]`. Das ist nachvollziehbar — Audit-Trail über `actor.severity_modulation`-History.

### Stable-ID-Garantie (präzise)

Findings, die einmal generiert wurden, bleiben über Reruns persistent. Drei Fälle:

1. **Actor-Tag-Verlust:** Ein in `actor_ids[]` getaggter Actor wird disabled → Tag wird entfernt, `primary_actor` neu berechnet (deterministisch, siehe oben). Finding selbst bleibt.
2. **Alle Actor-Tags weg:** Finding bleibt mit `actor_ids: []` und Marker `[obsolete-actor]` im Bericht. Severity wird auf `actor_adjusted_likelihood = base_likelihood × 1.0` (neutral) gesetzt. Run-Issues meldet zur Reviewer-Entscheidung.
3. **Discovery-Actor-Abhängigkeit:** Findings, die **strukturell** nur unter einem Discovery-Actor entstehen würden (`_provenance.created_by_actor: ACT-X-N`), kriegen im Folgerun bei dessen Disable den Status `_status: dormant` statt zu verschwinden — sichtbar im Bericht mit dem Hinweis "actor disabled, finding preserved for review".

**Was Stable-ID nicht garantiert:** Findings, die unter einem in Run N noch nicht aktivierten Actor in Run N+1 *neu entstehen*. Diese sind echt neu und werden über Pro-Komponenten-Slice-Diff-Forward-STRIDE-Re-Run erfasst (siehe §13).

---

## 11. Architect-Reviewer Check #15 — Actor Coverage

### Position im Reviewer

Bestehender `appsec-architect-reviewer` hat Checks 1-12 (strukturell + systemisch) + Conditional Check 13 (Config/IaC) + Conditional Check 14 (§7 Security Architecture narrative quality bar, Post-Render-Gate). Check #15 wird neu angehängt und ist konditional aktiv: nur wenn `.actors-resolved.json` existiert (also nicht in Quick-Mode).

### Inputs

- `.actors-resolved.json` (alle aktiven Actors mit Provenance)
- `.actors-discovered.json` (Discovery-Output)
- `threat-model.yaml` (Findings mit `actor_ids`-Annotation)
- Pro Komponente: `.actors-for-<component-id>.json`

### Prüfungen

**Check 15.1 — Aktivierte-aber-ungenutzte Actors**

Für jeden Actor in `.actors-resolved.json` mit `_provenance.layer != discovery`: existiert mindestens ein Finding mit diesem Actor in `actor_ids[]`?

- Wenn nein und Actor war für mindestens eine Komponente als relevant getaggt → `actor_activated_no_findings` Issue mit Severity gemäß §14 Tabelle (`info` Single-Run, eskaliert auf `advisory` wenn N≥2 Runs leer). Rationale: entweder ist der Actor übervalidiert (Activation-Condition zu breit), oder die STRIDE-Analyse hat Threats unter diesem Actor übersehen.
- Mitigation-Empfehlung: Reviewer prüft pro betroffener Komponente ob unter diesem Actor Threats existieren sollten.

**Check 15.2 — Disabled-ohne-Rationale**

Für jeden Eintrag im resolved-Set mit `_provenance.disabled_by != null`: existiert `disable_reason`?

- Wenn nein → `actor_disabled_without_rationale` Issue mit Severity `defect` (siehe §14 Tabelle). Wird als Validierungsfehler im Schema gefangen, aber als Backstop hier nochmal geprüft.
- Wenn ja → `info`-Eintrag mit Auflistung aller deaktivierten Actors und Rationales (für Audit-Trail im Bericht).

**Check 15.3 — Komponenten ohne Actor-Attribution**

Für jede analysierte Komponente: hat mindestens ein Finding mit `actor_ids != []`?

- Wenn nein → `component_findings_no_actor_attribution` Issue mit Severity `advisory` (siehe §14 Tabelle). Rationale: STRIDE-Analyzer hat Findings emittiert ohne Actor-Tagging — entweder Bug in Analyzer-Prompt-Adherence oder strukturelles Problem mit der relevant-Actor-Liste für diese Komponente.

**Check 15.4 — Discovery-Vorschläge ohne Reaktion**

Für jeden `proposed_additional`-Actor in `.actors-discovered.json`: existiert mindestens ein Finding mit diesem Actor in `actor_ids[]`?

- Wenn nein → `proposed_actor_no_findings` Issue mit Severity `info` (siehe §14 Tabelle, keine Eskalation — Discovery-Vorschläge sind erwartbar leer). Discovery hat Actor vorgeschlagen, aber keine Findings darunter gefunden. Möglicherweise Over-Discovery; Reviewer kann diesen Actor als `inputs_questioned` markieren beim nächsten Run-Promotion-Pass.

**Check 15.5 — Inputs-Questioned ohne Review-Aktion**

Für jeden Actor in `inputs_questioned` aus vorherigem Run: erscheint er noch im resolved-Set?

- Wenn ja und Run ist nicht der erste → `questioned_actor_not_reviewed` Issue mit Severity `advisory` (eskaliert auf `defect` nach 3 Runs ohne Reaktion, siehe §14 Tabelle und §8 Eskalation). Discovery hat empfohlen ihn zu prüfen; Reviewer hat nicht reagiert. Pflegehinweis.

### Output

Architect-Reviewer schreibt Findings dieser Klasse als Kommentare in `threat-model.md` (analog bestehende Checks). Sie sind **advisory**, nicht **normative** — sie blockieren keine Rendering.

Zusätzlich werden alle Check-15-Ergebnisse strukturiert in `.architect-review.json` persistiert für Telemetrie und Trend-Analyse über Reruns.

---

## 12. Quick-Mode-Verhalten

### Was läuft

- **Plugin-Default-Library**: aktiv. Activation-Conditions ausgewertet. Default-Actors stehen im resolved-Set, getagged in Findings, severity-moduliert. Kein LLM-Aufwand, alles deterministisch.
- **Enterprise-Layer**: aktiv falls Profile aktiv. Org-Profile-Actors sind kein zusätzlicher LLM-Call, also auch im Quick verfügbar.
- **Repo-Layer**: aktiv. `.appsec/actors.yaml` wird gelesen, deterministisch gemerged.
- **Per-Component-Slicing**: aktiv (Python, kein LLM).
- **STRIDE-Analyzer Actor-Tagging**: aktiv. Findings tragen `actor_ids`. Modell-Aufwand ist marginal (existing STRIDE-Call kriegt einen zusätzlichen Prompt-Param).

### Was übersprungen wird

- **LLM-Discovery-Phase** (`appsec-actor-discoverer`): skipped. Statische Liste reicht.
- **Architect-Reviewer Check #15**: nicht ausgeführt (Quick-Mode hat eh keinen Architect-Reviewer).
- **`.actors-discovered.json`** wird **nicht** erzeugt. Stattdessen schreibt der Resolver einen leeren Marker `.discovery-skipped.json` mit `{ "reason": "quick-mode" }` für Audit.

### Sichtbarkeit für den Nutzer

Im finalen Threat-Modell.md erscheint im "Run Configuration"-Block:

> `Actor discovery: disabled (quick mode) — using static library only`

Zusätzlich in der "Identified Actors"-Sub-Section (Sektion 14):

> `Note: This run used the static actor library only. Re-run with --standard or --thorough to enable LLM-based actor discovery for repo-specific actor identification.`

Damit hat der Reviewer transparent Sicht auf den Trade-Off.

### Trade-Off

Quick-Mode liefert weiterhin Actor-getagged Findings — das ist ein klarer Lift gegenüber heute. Was fehlt: B2B-Partner-Actors, Multi-Tenancy-Actors, ML-spezifische Actors und andere domain-spezifische Klassen, die nur via LLM-Discovery aus Recon-Signalen ableitbar sind. Das ist akzeptabel: Quick ist für Pre-Commit-Checks und schnelles Feedback gedacht, nicht für Release-Reviews.

---

## 13. Incremental-Scan-Verhalten

### Inputs-Fingerprint

Neuer Hash `actors_inputs_fingerprint`:

```
sha256(
  default-library.yaml ||
  org-profile/actors/*.yaml ||
  .appsec/actors.yaml ||
  .appsec/actors-config (discovery toggle etc.)
)
```

Persistiert in `.skill-config.json` neben dem existierenden `profile_fingerprint` und Code-Fingerprint.

### Cache-Invalidierung — pro Komponente

| Was hat sich geändert? | Recon-Cache | Forward-STRIDE-Cache (pro Komponente) | Trees |
|---|---|---|---|
| Nur Code | invalidieren | invalidieren (alle Komponenten mit Code-Diff) | rebuild für betroffene Komponenten |
| Nur `actors_inputs_fingerprint` | behalten | **invalidieren nur für Komponenten mit Slice-Änderung** | rebuild für betroffene Komponenten |
| Beides | invalidieren | invalidieren (Union der Komponenten-Sets) | rebuild |

**Re-Tagging-Phase wurde bewusst verworfen.** Heuristisches Re-Tagging ohne LLM-Reasoning hat geringere Qualität als der initiale STRIDE-Pass (Heuristik kann Threat-Mechanik nicht beurteilen). Stattdessen läuft bei Actor-Input-Drift ein gezielter **Slice-Diff-getriebener Forward-STRIDE-Re-Run** — nur für Komponenten, deren `.actors-for-<component-id>.json` sich gegenüber dem letzten Run unterscheidet. Komponenten mit identischer Slice behalten ihre Findings unverändert.

### Slice-Diff-getriebener Forward-STRIDE-Re-Run

Aktiv wenn `actors_inputs_fingerprint` geändert UND Code-Fingerprint unverändert:

1. Resolver baut neue resolved-Set
2. Discovery läuft nur dann neu, wenn `discovery_inputs_fingerprint` (siehe §8) sich geändert hat — sonst gecachtes `.actors-discovered.json` aus vorherigem Run wiederverwendet
3. Per-Component-Slicing rechnet neu
4. Für jede Komponente: Wenn `.actors-for-<component-id>.json` sich gegenüber Vor-Run unterscheidet → Forward-STRIDE-Re-Run für diese Komponente (LLM, mit aktualisierter Actor-Liste). Komponenten mit identischer Slice: Findings unverändert.
5. Severity-Modulation wird neu angewandt **nur wenn** die `severity_modulation`-Multipliers selbst Teil des Input-Drifts sind (z.B. Plugin-Library-Update mit neuen Multiplier-Werten oder Org/Repo-Layer-Override). Bei reiner Slice-Drift ohne Multiplier-Drift bleiben `actor_adjusted_likelihood`-Werte für unveränderte Findings byte-identisch. Re-Apply ist deterministisch und LLM-frei.
6. Diff-Renderer markiert betroffene Findings als `[input-change]`.

**Trade-off bewusst:** Forward-STRIDE-Re-Run pro betroffener Komponente ist teurer als rein heuristisches Re-Tagging, aber konsistent in der Reasoning-Qualität. Wenn die Slice-Stabilität gut ist (kleine Actor-Listen-Änderung trifft wenige Komponenten), bleibt der Overhead überschaubar.

### Diff-Klassifikation im Bericht

Neuer Diff-Kategorie im Changelog:

- `[code-change]` — Finding entstanden durch Code-Modifikation
- `[input-change]` — Actor/Asset-Input geändert, Finding re-getagged oder severity-moduliert
- `[promotion]` — Discovery-Vorschlag wurde zum Repo-Layer promotet

Damit ist für jeden Diff-Eintrag im Threat-Modell sofort klar, ob er aus Code-Drift oder Input-Drift kommt — zentral für Reviewer-Vertrauen in den Diff.

### Edge-Case: Profile-Fingerprint-Churn

Wenn das Enterprise-Profile häufig aktualisiert wird (z.B. wöchentliche Threat-Intel-Updates an `org-profile/actors/`), invalidiert das jeden Repo-Cache. Mitigation:

- Profile-Fingerprint wird zerlegt in `profile_core_fingerprint` (Presets, Defaults) und `profile_actors_fingerprint` (Actor-Definitions). Nur letzterer triggert die Actor-Re-Tagging-Phase; ersterer triggert die volle Re-Evaluation. Saubere Granularität.

---

## 14. Bericht-Output-Änderungen

### Reconciliation mit bestehender Heatmap-Actor-Liste

Der bestehende Bericht hat in §0/§1 (Security Posture at a Glance) bereits ein Actor-Konzept: 6 Display-Slugs (`internet-anon`, `internet-user`, `internet-priv-user`, `build-time`, `repo-read`, `victim-required`) aus `data/posture-actor-labels.yaml`, schema-validiert in `schemas/fragments/security-posture-attack-paths.schema.json` als Enum. Diese sind **Display-Labels** für die Heatmap-Diagramm-Karten, nicht ID-tragende Threat-Actor-Records.

Beide Modelle koexistieren ohne Ersetzung:

- **`ACT-*` IDs (dieses Konzept)** sind die kanonische Quelle für Finding-Attribution (`actor_ids`, `primary_actor`), Severity-Modulation und §1.5-Tabelle. Sie tragen Capabilities, Provenance, Stable-IDs.
- **6 Heatmap-Slugs** bleiben für die §0/§1-Visualisierung. Der Compose-Step mappt jeden `primary_actor` aus dem Threat-Register deterministisch auf einen der 6 Slugs (Lookup-Tabelle `data/actor-id-to-heatmap-slug.yaml`, neu): `ACT-D-01 → internet-anon`, `ACT-D-02 → internet-user`, `ACT-D-03 → internet-priv-user`, `ACT-D-04`/`ACT-D-05` → `repo-read`, `ACT-D-06` → `build-time`, etc. Custom-Actors (`ACT-E-*`, `ACT-R-*`, `ACT-X-*`) tragen optional ein `heatmap_slug:`-Feld im Datenmodell (§4 Optionale Felder); fehlt es, fällt der Mapper deterministisch auf `internet-user` zurück und meldet im Run-Issues-Bericht `actor_missing_heatmap_slug` (Severity `info`).

Damit bleibt die Heatmap-Stabilität (max 6 Slugs in der Enum) erhalten, während das §1.5-Modell beliebig viele `ACT-*` IDs trägt. Schema der Posture-Attack-Paths wird nicht gebumpt.

### Neue Sub-Section §1.5 — Identified Actors

Nach §1.System Overview, vor §2.Architecture Diagrams. Tabelle aller im Run aktiven Actors:

| ID | Label | Layer | Status | Findings | Relevant for |
|---|---|---|---|---|---|
| ACT-D-01 | anonymous-internet-attacker | plugin-default | active | 8 | auth-service, payment-handler, web-frontend |
| ACT-D-04 | malicious-insider-dev | plugin-default | active | 3 | ci-cd-pipeline, developer-workstation |
| ACT-R-1 | b2b-partner-org | repo | active | 2 | partner-api |
| ACT-X-1 | ml-prompt-injector | discovery (proposed) | proposed | 1 | ai-assistant-handler |

Plus Sub-Section "Newly identified actors — please confirm" wenn proposed-Actors existieren.

Plus Sub-Section §1.5.3 "Actors flagged for review" wenn Discovery `inputs_questioned`-Markierungen erzeugt hat. Eskaliert nach 3 Runs auf WARNING im Bericht-Header (siehe §8).

Plus Sub-Section "Disabled actors" wenn deaktivierte mit Rationale existieren.

Plus Sub-Section "Dormant findings" wenn Findings im Status `_status: dormant` vorliegen (siehe §10 Stable-ID-Garantie, Fall 3).

### Threat-Register-Erweiterung (§8)

Findings-Tabelle bekommt eine zusätzliche Spalte "Primary Actor" oder "Actors" je nach Verbosity-Mode.

Pro Finding-Detail-Block (`### F-NNN`) erscheint ein neues Sub-Feld:

```markdown
**Actors:** ACT-D-01 (primary), ACT-D-04
```

### Verdict-Math (§Management Summary)

Verdict-Generator nutzt `actor_adjusted_likelihood`, nicht nur raw_cvss. Verdict-Text kann jetzt aussagen "9 Critical findings exploitable by anonymous attacker, 3 additional Critical findings requiring insider access".

### Mitigation-Register (§9)

Mitigation-Karten zeigen pro Mitigation die abgedeckten Actor-Klassen ("Blocks: ACT-D-01, ACT-D-04 attack paths"). Reviewer sieht direkt welche Threat-Klassen geschlossen werden.

### Run-Issues — Severity-Stratifizierung

Neue Issue-Klassen in `.run-issues.json` mit expliziter Severity, um Alert-Fatigue zu vermeiden:

| Klasse | Default-Severity | Eskalation |
|---|---|---|
| `actor_activated_no_findings` | `info` (Single-Run) | `advisory` wenn N≥2 Runs leer |
| `proposed_actor_no_findings` | `info` | keine (Discovery-Vorschläge sind erwartbar leer) |
| `questioned_actor_not_reviewed` | `advisory` | `defect` nach 3 Runs ohne Reaktion (siehe §8) |
| `disabled_actor_no_rationale` | `defect` | — (sollte Validierungs-Fehler sein, Backstop) |
| `component_findings_no_actor_attribution` | `advisory` | — |
| `stale_actor_evidence` | `advisory` | — |

**Bericht-Header zeigt nur `defect`-Count.** `advisory` und `info` collapsed in expandierbarem Block. Pro Issue-Klasse wird aggregiert: statt 12× "actor X activated, no findings" → 1× "12 actors activated without findings — see list".

Begründung: 6 Issue-Klassen × 5 Sub-Checks aus §11 erzeugen unstratifiziert Dauerlärm; Reviewer-Aufmerksamkeit ist die knappe Ressource.

### Documentation & Sample Surface

Implementierung dieses Konzepts erfordert Updates an mehreren bestehenden Doku- und Sample-Artefakten. Vollständige Liste der zu touchenden Pfade, gegen den Repo-Stand verifiziert:

**README.md** — vier Sections brauchen Actor-Mention:
- `## What it checks` — Actor-getriebene Threat-Klassen ergänzen (Insider, Supply-Chain als Actor-Klasse, B2B-Partner, Multi-Tenancy-Adjacent-Tenant).
- `## Quick start` — kurzer Hinweis, dass Default-Library ohne Config aktiv ist; Verweis auf `docs/org-profiles.md` für Enterprise-Erweiterung und auf `.appsec/actors.yaml` für Repo-Layer.
- `## Cross-repo context` — Klarstellung: Actor-Pull aus `docs/related-repos.yaml` wird **nicht** unterstützt (§15.4); ACT-D-07 wird ausschließlich über repo-interne externe API-Signale aktiviert.
- `## Architecture` — Stages-Bullet ergänzen um Discovery-Phase (Phase 2.7) und Architect-Reviewer Check #15.

**`docs/` — drei dedizierte Doku-Seiten:**
- `docs/org-profiles.md` — neue Section "Actors" mit dem `actors:`-Block-Schema aus §6, Verweis auf `actors/*.yaml`-Layout, Override- und Disable-Semantik gegenüber Plugin-Defaults.
- `docs/internal-plugin-packaging.md` — Klarstellung der zwei Distribution-Wege: (a) Plugin-Default-Library um eigene Actors erweitern (`data/actors/default-library.yaml`, generisch); (b) Org-Profile mit gebündelten Actors ausliefern (`org-profile/<name>/actors/*.yaml`, firmen-/domain-spezifisch).
- `docs/multi-repo-analysis.md` — Hinweis auf das §15.4-Non-Goal (keine föderierte Actor-Auflösung über `related-repos.yaml`).

**Fixtures (`tests/fixtures/`):**
- `tests/fixtures/org-profiles/acme/org-profile.yaml` — `actors:`-Block ergänzen (mindestens `inherit_defaults: true` + ein `ACT-E-*` Beispiel-Actor unter `actors/insiders.yaml`).
- `tests/fixtures/e2e/` — drei neue Synthetic-Repos für die Done-Kriterien aus §0:
  - Multi-Tenancy-Repo (Tenant-Spalte + Scoping-Pattern → ACT-D-09)
  - CI-Pipeline-Repo (`.env` + GitHub-Actions → ACT-D-04/ACT-D-06)
  - B2B-API-Repo (Partner-Auth-Route → Discovery `proposed_additional`)

**Skill-internal:**
- `skills/create-threat-model/HELP.txt` — neuer Flag `--refresh-discovery` (siehe §8) in CLI-Flag-Reference. Quick-Mode-Behavior-Section um Actor-Discovery-Skip ergänzen.
- `skills/create-threat-model/SKILL-impl.md` — Pipeline-Doku um Phase 2.7 (Actor-Discovery) erweitern, inkl. Cache-Key-Doku aus §8.
- `agents/appsec-stride-analyzer.md` Inputs-Liste — neuer Prompt-Param `RELEVANT_ACTORS_INDEX_PATH` (§10) ergänzen, parallel zu `PRIOR_FINDINGS_INDEX_PATH`/`KNOWN_THREATS_INDEX_PATH`.
- `agents/appsec-architect-reviewer.md` — Check #15 (Actor Coverage) als neue konditionale Check-Sektion anhängen, analog zur existierenden Check-#14-Sektion.

**Release-Doku:**
- `CHANGELOG.md` Unreleased-Section — Eintrag für `api_version: appsec-advisor.org-profile/v2` (additive Erweiterung, v1-Profile laden auto-upgraded mit `info`-Notice); plus User-facing Liste der neuen `ACT-*` Tagging-Spalte im Bericht und §1.5-Sub-Section.

**Nicht betroffen:** `AGENTS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `release.md` (historisches Dokument), `skills/create-threat-model/SKILL.md` (reines Routing-File).

---

## 15. Offene Design-Entscheidungen

Items, die vor Implementierung explizit entschieden werden müssen. Die früheren Punkte "Severity-Modulation" und "`primary_actor`-Algorithmus" wurden im aktuellen Konzept geklärt und sind aus dieser Liste entfernt — siehe §10 Severity-Mechanik bzw. `primary_actor`-Auswahl-Algorithmus. Die folgenden 5 Punkte sind weiterhin offen:

1. **Activation-Conditions strukturiert oder Freitext?** Default-Library: strukturiert (Signal-Liste). Custom-Actors: Reviewer-Erfahrung zeigt, ob strukturierte Conditions reichen oder ob Freitext-Heuristiken nötig sind. **Empfehlung:** start strukturiert; bei Bedarf erweitern.

2. **Capabilities-Schema-Strenge.** Sollen `tooling`-Werte aus fester Enum-Liste sein, oder freier String? **Empfehlung:** Enum für Default-Library, freier String für Repo/Discovery-Actors mit Validator-Warning bei unbekannten Werten (kein Hard-Fail).

3. **Migration aus narrative Business-Context-Dokumenten.** Soll ein optionales Skill (`/appsec-advisor:extract-actors`) angeboten werden, das aus einer narrativen Business-Context-Quelle (z.B. einer hypothetischen `docs/business-context.md` im Target-Repo — heute kein Repo-Standard) LLM-Vorschläge für `.appsec/actors.yaml` generiert? **Empfehlung:** Phase 2, nicht im initialen Scope. Quellenformat (Markdown, JSON, andere) wird mit dem Skill-Design festgelegt.

4. **Cross-Repo Actor-Resolution.** Bei `--related-repo`-Setup: liest das Tool `.appsec/actors.yaml` aus jedem related Repo? **Empfehlung:** vorerst nein, Cross-Repo-Actors nur im Hauptrepo definieren. ACT-D-07 (compromised-third-party-service) wird ausschließlich über erkennbare externe API-Calls im Hauptrepo aktiviert (§5), nicht über `related-repos.yaml`. Konzept für föderierte Actor-Modelle später.

5. **Profile-Inheritance bei mehreren Org-Profiles.** Kann Profile B von Profile A erben? Heutiges System unterstützt das nicht. **Empfehlung:** nicht für Actors einführen; Enterprise-Setup ist single-profile.

---

## 16. Beziehung zu Attack-Tree-Konzept

Das Attack-Tree-Konzept (`trees.md`, separates Dokument noch zu schreiben) baut **auf** dem Actor-Konzept auf. Konkrete Kopplungspunkte:

- **Actors aktivieren Goals.** Goal `G-EXFIL-DATA` aktiviert sich nur, wenn mindestens ein Actor mit `motivation: financial OR espionage` aktiv ist.
- **Tree-Leaves tragen `actor_ids`.** Pro Leaf wird annotiert, welche Actors den Pfad ausnutzen können. Steuert Tree-Severity.
- **Goal-Deaktivierung → dormant, nicht removed.** Analog zur Stable-ID-Garantie für Findings (§10): wenn alle motivations-treibenden Actors disabled werden, kriegt der Goal-Knoten `_status: dormant`. Tree-Leaves bleiben sichtbar mit Marker "goal currently inactive". Konsistente Semantik über Findings und Trees hinweg.
- **Discovery-Coupling.** Wenn LLM-Discovery einen neuen Actor vorschlägt (z.B. B2B-Partner-Org), aktiviert das in der Tree-Phase neue Goal-Kandidaten (z.B. "Defraud counterparty via order manipulation").
- **Architect-Reviewer-Check #16** (Tree-Path-Plausibility) prüft: passen die `actor_ids` der Tree-Leaves zu den `capabilities` der Actors? Insider-only Leaf mit anonymous-attacker-Actor wäre ein Defect.

Reihenfolge der Realisierung: Actors zuerst, dann Trees. Trees ohne Actor-Modell wären strukturell luftig, weil Goals ohne Actor-Motivation nicht aktiviert werden können.

---

## 17. Zusammenfassung der Garantien

Was dieses Design strukturell garantiert:

1. **Anti-Anchoring:** LLM-Discovery läuft pflicht-mäßig (außer Quick-Mode) und darf jederzeit Actors hinzufügen. Default-Library ist exhaustiv. Repo/Org können nicht stillschweigend Default-Actors verbergen.

2. **Stable IDs (präzise):** F-NNN-Findings, die einmal generiert wurden, bleiben über Reruns persistent. Bei Actor-Disable verlieren sie Tags und kriegen `[obsolete-actor]`- bzw. `dormant`-Marker, verschwinden aber nicht. Findings, die strukturell neu unter Actor-Drift entstehen können, werden über den pro-Komponenten Slice-Diff-Forward-STRIDE-Re-Run erfasst (siehe §13). Was Stable-ID **nicht** garantiert: die rückwirkende Persistierung von Findings, die ohne den aktivierten Actor strukturell nie generiert worden wären — diese werden mit `_status: dormant` weitergeführt, nicht für immer aktiv gehalten.

3. **Audit-Trail:** Jeder Actor trägt `_provenance` mit Layer, Source, Modifikationen. Architect-Reviewer-Check #15 prüft Inkonsistenzen. Run-Issues meldet Pflegebedarf.

4. **Layer-Hygiene:** Plugin/Enterprise/Repo/Discovery-Layer haben klare Override-Regeln. Disable mit Pflicht-Rationale. Validierung im existing org-profile-Resolver erweitert.

5. **Quick-Mode-Konsistenz:** Default-Library bleibt aktiv, sodass auch in Quick die wichtigsten Actor-Klassen Findings antreiben. Nur Discovery wird gespart.

6. **Incremental-Effizienz:** Actor-Input-Änderungen invalidieren Forward-STRIDE **pro Komponente** — nur Komponenten mit veränderter relevant-Actor-Slice werden neu analysiert. Komponenten ohne Slice-Änderung behalten ihre Findings unverändert. Diff im Bericht unterscheidet input-driven vs. code-driven Changes. Re-Tagging ohne LLM wurde bewusst verworfen — siehe §13.

7. **Architect-Sign-Off:** Check #15 stellt sicher, dass Actor-Layer-Konfiguration und tatsächliche Finding-Verteilung konsistent sind. Stillschweigende Inkonsistenzen werden geflagged.

Damit ist das Konzept für den Actor-Layer vollständig genug, um als Basis für Plan-Phase und Implementierung zu dienen. Nächster Schritt: ein paralleles `trees.md` mit demselben Detail-Grad für den Attack-Tree-Builder, sobald Actor-Konzept abgenommen ist.
