# Analyse: Incremental Mode für das AppSec Plugin

**Datum:** 2026-04-11
**Scope:** Effiziente Nutzung des Plugins im inkrementellen Modus (Pipeline / Merge Request), Baseline-Strategie, technisches Analysemodell, Auswirkung auf alle 11 Report-Sektionen.

---

## 1. Ausgangslage — was das Plugin heute schon kann

| Baustein | Status | Ort |
|---|---|---|
| CLI-Flags `--incremental`, `--full`, `--dry-run`, `--resume` | vorhanden | `scripts/run-headless.sh:17-20` |
| Auto-Incremental wenn `threat-model.md` existiert | vorhanden | `plugin/skills/create-threat-model/SKILL.md:123-136` |
| Delta-Detection via `git diff --name-only HEAD~1..HEAD` | vorhanden | `plugin/agents/appsec-threat-analyst.md:62-89` |
| Selective STRIDE: nur geänderte Komponenten re-analysieren | dokumentiert | Phase 9, `appsec-threat-analyst.md:77` |
| Checkpoint/Resume | vorhanden | `.appsec-checkpoint` |
| Dep-Scanner Manifest-Hash-Caching | vorhanden | `appsec-dep-scanner.md:39-59` |
| ISO-Timestamps in Intermediate-Files | vorhanden | `.stride-*.json`, `.recon-summary.md` |

Die Rahmenstruktur ist also da — Flags, Auto-Detect, git-diff, Checkpoint. Was fehlt, ist die Substanz darunter.

---

## 2. Lücken gegenüber dem Pipeline-/MR-Einsatz

| # | Lücke | Auswirkung |
|---|---|---|
| L1 | Baseline ist `HEAD~1..HEAD`, nicht „letzter TM-Run" | Bei mehreren Commits zwischen zwei TM-Updates wird der echte Delta verfehlt |
| L2 | `--incremental` ohne Baseline fällt still auf Full zurück (`SKILL.md:196`) | Kein harter Error wie gefordert |
| L3 | `--dry-run` erzwingt Full-Mode (`SKILL.md:127`) | Gewünschte „Delta-Dry-Scan"-Semantik fehlt komplett |
| L4 | Stale-Cleanup löscht `.stride-*.json` am Start jedes Runs (`plugin/CLAUDE.md`, Abschnitt „Stale file cleanup") | Carry-Forward kann gar nicht funktionieren — killt L5+L6 an der Wurzel |
| L5 | Kein strukturiertes Technisches Modell persistiert — nur MD (Pflicht) + YAML (optional) | MD-Parsing fragil, Template im Umbau, keine stabile Baseline |
| L6 | Nur Threats wären carry-forward-fähig — die anderen 10 Sektionen nicht | Architektur, Assets, Attack Surface, Controls etc. müssen jedesmal neu gebaut werden |
| L7 | Kein File→Sektion-Index | Kein Weg zu entscheiden, welche Sektion ein Diff invalidiert → Dominoeffekte nicht sauber propagiert |
| L8 | Blinder Fleck: semantische Änderungen ohne File-Korrelation | Neue Data-Flow-Edge ohne editierte Datei wird nicht erkannt |
| L9 | Kein Git-SHA-Tracking im Report | Nicht nachvollziehbar, gegen welchen Stand der Delta lief |
| L10 | Incremental-Metadata-Zeilen im Report fehlen (dokumentiert in `threat-analyst.md:82-88`, aber Template schreibt sie nicht) | CI kann nicht verifizieren, was wirklich gescannt wurde |
| L11 | Lock-Handling in Pipelines (1 h gültig, kein Cleanup) | Deadlock-Risiko bei parallelen MR-Runs |

---

## 3. Warum `threat-model.md` als Baseline nicht reicht

### 3.1 Die bestehenden Intermediate-Files werden gelöscht
In `plugin/CLAUDE.md` steht unter „Stale file cleanup":
> Intermediate files from previous runs (`.stride-*.json`, `.dep-scan.json`) in `$OUTPUT_DIR` are automatically deleted before each new assessment starts.

Damit sind genau die Dateien, die für Carry-Forward gebraucht würden, beim nächsten Run weg. Die dokumentierte „Wiederverwendung" in `appsec-threat-analyst.md:77` funktioniert heute also gar nicht — das ist eine echte Lücke, kein kosmetisches Problem.

### 3.2 Markdown-Parsing ist fragil
- Das Template ist laut `render_threat_model_schema.py:35-38` mitten im Umbau (aktuell nur `99-full-body.md` als Pass-Through required).
- Component-ID → Datei-Mapping existiert in der MD **nicht strukturiert** — es steckt verteilt in Section 2 (C4-Diagramme) und VS-Code-Deep-Links.
- Threat-ID, Severity, CWE, Status müssten über Regex aus Tabellenzeilen extrahiert werden — bricht bei jeder Template-Änderung.

### 3.3 `threat-model.yaml` ist optional
Nur mit `--yaml` geschrieben. Als Pflicht-Baseline unbrauchbar, solange es ein Opt-in ist.

**Fazit:** Ein dediziertes technisches Analysemodell als Pflicht-Artefakt ist zwingend.

---

## 4. Alle 11 Sektionen — Invalidierungs-Matrix

Fast jede Sektion kann durch einen Code-Diff invalidiert werden, nicht nur Threats. Ein reines Carry-Forward von `.stride-*.json` deckt nur Phase 9 ab. Alle anderen Phasen (2–8, 10) brauchen ebenfalls strukturierte Baseline-Daten.

| Sektion | Strukturierter Kern | Invalidiert wenn… | Carry-Forward-Granularität |
|---|---|---|---|
| **1. System Overview** | Tech-Stack-Liste, externe Integrationen, Business-Context | neues Package-Manifest, neue ENV-Vars, Änderung an `docs/business-context.md`, `.threat-modeling-context.md`, Context-Resolver-Response | ganze Sektion |
| **2. Architecture (C4)** | Nodes + Edges (Context/Container/Component), File→Component-Map, Tech-Stack-Diagramm | neues/gelöschtes Verzeichnis, neue Service-Deployment-Einheit, neues Dockerfile / compose-Service / k8s-Manifest, neue Dependency-Richtung zwischen Komponenten | knotenweise |
| **3. Use Cases** (Sequenzdiagramme) | Use-Case-ID, Akteure, beteiligte Komponenten, Entry-Point-File | Änderungen an Auth-Middleware, Route-Handlern, Session-Code, OAuth/OIDC-Config | pro Use-Case |
| **4. Assets** | Asset-ID, Typ (Data/Code/Infra/Availability), Location (File+Komponente), Sensitivity | neue/gelöschte DB-Migrationen, Schema-Dateien (Prisma/SQL/GraphQL), neue `.env.example`-Einträge, neue Secrets-Indikatoren | pro Asset |
| **5. Attack Surface** | Entry-Point-ID, Typ (HTTP/Queue/File/IPC/CLI), Auth-Status, Owner-Komponente, Source-File+Line | neue Routen, neue Queue-Consumer, neue File-Handler, gelöschte Endpoints, Änderung am Router-File | pro Entry-Point |
| **6. Trust Boundaries** | Boundary-ID, Komponenten links/rechts, Data-Flows die sie kreuzen | neue Services, neue externe Integrationen, Netzwerk-Config-Änderung, neue AuthN/AuthZ-Hop | pro Boundary |
| **7. Security Controls** (24 Kategorien) | Control-ID, Category, Evidence (file:line), Rating, Linked-Threats | Änderung an Validation-/Crypto-/Auth-Code, neue Middleware, Config-Änderung, neue gefährliche Sinks | pro Control |
| **7b. Requirements Compliance** | Req-ID, Status, Evidence-Files, Linked-Threats | Änderung an Files, die eine Requirement abdecken; neue Requirements-YAML-Version | pro Requirement |
| **8. Threat Register** | Threat-ID, Component, STRIDE, CWE, Severity, Evidence-Files, Mitigations | Änderung an Component-Files ODER upstream Sektionen 5/6/7 invalidiert | pro Threat |
| **9. Critical Findings** | Derivativ aus Sektion 8 (Severity ≥ High) | wenn Sektion 8 sich ändert | immer regenerierbar |
| **10. Mitigation Register** | Mitigation-ID, Linked-Threats, Fulfilled-Requirements | wenn Threats/Requirements sich ändern | derivativ |
| **11. Out of Scope** | Accepted-Risks aus `known-threats.yaml` + `.threat-modeling-context.md` | wenn diese Quellen sich ändern | ganze Sektion |

### 4.1 Zwei Kernprobleme, die der Diff auslöst

**a) Propagations-Kaskade.** Eine geänderte Datei berührt selten nur eine Sektion. Beispiel: neue Route in `src/api/payments.ts` invalidiert:
```
Section 2 (Component „API" bekommt neuen Edge)
  → Section 5 (neuer Entry-Point)
    → Section 6 (ggf. neue Trust-Boundary-Querung)
      → Section 7 (AuthZ/Input-Validation-Rating neu für diesen Endpoint)
        → Section 8 (neue STRIDE-Analyse für Komponente „API")
          → Section 9/10 (derivativ)
```
Ohne expliziten Invalidierungs-Graph fehlt die Logik, wo der Dominoeffekt stoppt. Aktuell macht der Orchestrator das ad-hoc — für Pipelines zu vage.

**b) Data-Flow-Änderungen ohne File-Änderung.** Eine neue Edge im C4-Container-Diagramm kann entstehen, obwohl keine neue Datei existiert — z.B. wenn ein bestehender Service eine neue Queue publiziert. Die aktuelle `git diff --name-only`-Logik sieht das nur, wenn die publishende Datei mit editiert wurde. Blinder Fleck. Braucht zusätzlich einen semantischen Diff über das Component-Graph-Modell selbst.

---

## 5. Empfehlungen

### E1 — Neues technisches Analysemodell als Pflicht-Artefakt

**Datei:** `docs/security/.baseline/threat-model-state.json`

- Immer geschrieben (auch ohne `--yaml`), **nur** wenn Phase 11 sauber durchläuft
- Ist die **einzige** Prüfgröße für „gibt es eine Baseline?" — nicht `threat-model.md`
- Enthält strukturierte Einträge **aller 11 Sektionen**, nicht nur Threats

**Struktur-Vorschlag:**

```json
{
  "schema_version": 1,
  "baseline": {
    "git_sha": "ce52a08",
    "git_ref": "main",
    "generated_at": "2026-04-11T10:22:00Z",
    "plugin_version": "0.9.0-beta",
    "mode": "full",
    "assessment_depth": "standard"
  },

  "components": [
    {
      "id": "auth-svc",
      "name": "Auth Service",
      "kind": "service",
      "files": ["src/auth/**", "src/jwt/*.ts"],
      "file_hashes": {"src/auth/login.ts": "sha256:..."},
      "tech": ["node", "express"],
      "last_analyzed_sha": "ce52a08"
    }
  ],

  "architecture": {
    "c4_context":   { "nodes": [...], "edges": [...], "hash": "sha256:..." },
    "c4_container": { "nodes": [...], "edges": [...], "hash": "..." },
    "c4_component": { "per_container": {...}, "hash": "..." },
    "tech_stack_diagram": { "nodes": [...], "hash": "..." }
  },

  "use_cases": [
    { "id": "UC-01", "title": "Login flow", "actors": [...],
      "components": ["auth-svc", "api-gw"], "evidence_files": [...],
      "hash": "..." }
  ],

  "assets": [
    { "id": "A-01", "type": "data", "name": "user_credentials",
      "location": { "component": "auth-svc", "files": [...] },
      "sensitivity": "critical", "hash": "..." }
  ],

  "attack_surface": [
    { "id": "E-01", "type": "http", "route": "POST /login",
      "component": "api-gw", "auth_required": false,
      "source": "src/api/login.ts:14", "hash": "..." }
  ],

  "trust_boundaries": [
    { "id": "TB-01", "name": "internet-edge",
      "between": ["internet", "api-gw"],
      "crossed_by": ["E-01", "E-02"], "hash": "..." }
  ],

  "security_controls": [
    { "id": "SC-07.3", "category": "Input Validation",
      "rating": "partial", "evidence": ["src/mw/validate.ts:22"],
      "linked_threats": ["T-014"], "hash": "..." }
  ],

  "requirements": [
    { "id": "SEC-AUTH-001", "status": "pass",
      "evidence": [...], "linked_threats": [...], "hash": "..." }
  ],

  "threats": [
    { "id": "T-001", "component_id": "auth-svc", "stride": "S",
      "severity": "High", "cwe": "CWE-287",
      "evidence_files": [...], "mitigations": ["M-003"],
      "source_run_sha": "...", "hash": "..." }
  ],

  "mitigations": [
    { "id": "M-003", "threats": ["T-001"],
      "fulfills": ["SEC-AUTH-001"], "hash": "..." }
  ],

  "out_of_scope": { "accepted": [...], "hash": "..." },

  "file_index": {
    "src/auth/login.ts": {
      "sha256": "...",
      "touches": {
        "components": ["auth-svc"],
        "use_cases": ["UC-01"],
        "assets": ["A-01"],
        "attack_surface": ["E-01"],
        "controls": ["SC-01.1", "SC-07.3"],
        "threats": ["T-001", "T-014"]
      }
    }
  },

  "intermediate_refs": {
    "recon_summary": ".baseline/recon-summary.md",
    "recon_hash": "sha256:...",
    "stride_files": { "auth-svc": ".baseline/stride-auth-svc.json" },
    "dep_scan": ".baseline/dep-scan.json",
    "context": ".baseline/threat-modeling-context.md"
  }
}
```

**Pflicht-Regeln:**

1. **Jeder strukturierte Eintrag bekommt einen `hash`** — stabiler Fingerprint aus seinen Input-Files + semantischem Inhalt. Ändern sich die Files aber der Hash bleibt gleich → kein Re-Rendering nötig (Whitespace-Change, Comment-only).
2. **`file_index.<path>.touches`** ist der rückwärts gerichtete Dependency-Graph: zentral für die Invalidierungs-Logik.
3. **Recon-Diff als zweite Quelle** — semantische Änderungen ohne File-Korrelation (Problem 4b).

### E2 — Baseline-Unterverzeichnis `.baseline/`

```
docs/security/
├── threat-model.md              (Report)
├── threat-model.yaml            (optional, --yaml)
├── threat-model.sarif.json      (optional, --sarif)
└── .baseline/
    ├── threat-model-state.json  (kanonische Baseline)
    ├── stride-<component-id>.json
    ├── dep-scan.json
    ├── recon-summary.md
    └── threat-modeling-context.md
```

**Stale-Cleanup muss `.baseline/` ausnehmen** — sonst fällt der gesamte Inkremental-Modus um.

### E3 — Harte Mode-Matrix

| Flags | Baseline vorhanden? | Verhalten |
|---|---|---|
| `--incremental` | **nein** | `exit 2` — „no baseline found, run --full first" |
| `--incremental` | ja | Delta gegen Baseline → State + TM + Baseline updaten |
| `--incremental --dry-run` | **nein** | `exit 2` |
| `--incremental --dry-run` | ja | Delta-Analyse → **nur** `threat-model.delta.md` + `.delta.json` schreiben, State/TM/Baseline unverändert |
| `--full` | egal | Full-Scan → TM + State + Baseline (re-)schreiben |
| (ohne Flag) | ja | Auto-Incremental (heutiges Verhalten) |
| (ohne Flag) | nein | Full (first run) |

### E4 — Git-SHA-basierter Diff statt `HEAD~1`

`plugin/agents/appsec-threat-analyst.md:70` ändern auf:
```bash
git diff --name-only <baseline.git_sha>..HEAD
```
`<baseline.git_sha>` stammt aus `threat-model-state.json`. Damit sind beliebig lange Commit-Ketten zwischen zwei TM-Runs abgedeckt.

### E5 — Invalidierungs-Algorithmus (Kaskade)

Bei jeder geänderten Datei `f`:

1. Lookup `file_index[f].touches` → Set betroffener Entry-IDs
2. Markiere diese Einträge als *dirty*
3. Propagiere über die Sektions-Dependency-Kette:
   `components → use_cases → attack_surface → trust_boundaries → security_controls → threats → critical_findings → mitigations`
4. Re-build nur die *dirty* Einträge; Rest wird aus State verbatim übernommen
5. Falls Recon-Diff strukturell etwas Neues findet (z.B. neuer Entry-Point, neue Edge ohne editiertes File → blinder Fleck), werden die entsprechenden Sektionen zusätzlich als dirty markiert

### E6 — Recon-Scanner liefert strukturierten Diff

Im Inkremental-Modus muss der Recon-Scanner nicht nur `.recon-summary.md` schreiben, sondern zusätzlich einen semantischen Diff gegen `.baseline/recon-summary.md`:

```
Kategorie 3.1 Input Validation: +1 neuer Sink
Kategorie 5.2 Crypto: unverändert
Kategorie 7.16 Dependency Confusion: 1 Indikator verschwunden
```

Das schließt Lücke L8.

### E7 — Delta-Report-Format für Dry-Scan

Strukturiertes Delta-Rendering, ideal für MR-Kommentare:

```
=== THREAT MODEL DELTA (dry run) ===
Baseline: ce52a08 · 2026-04-11
Current:  a3f91b2 · 2026-04-11

Architecture
  + Container added: payment-svc
  ~ Edge added: api-gw → payment-svc

Attack Surface (+2 / -0 / ~1)
  + E-14: POST /api/payments/charge [unauthenticated ⚠]
  + E-15: GET  /api/payments/status
  ~ E-03: auth_required changed false → true

Trust Boundaries
  ~ TB-01: new crossing via E-14

Security Controls
  ❌ SC-07.3 Input Validation: auth-svc partial → missing (evidence removed)

Threats (+2 / -0 / ~1)
  + T-014 [High, CWE-306] Missing AuthN on /payments/charge
  + T-015 [Medium, CWE-20] Unvalidated amount field
  ~ T-007 severity: Medium → High (new call-path exposes to internet)
```

Erzeugt aus State-Diff (`baseline.state` vs. `current.state`).

### E8 — Metadata-Tabelle im Report

`plugin/scripts/render_threat_model.py` erweitern um Incremental-Zeilen:

```
| Mode                   | incremental |
| Baseline SHA           | ce52a08 |
| Current SHA            | a3f91b2 |
| Changed Files          | 7 |
| Re-analyzed Components | 2 |
| Carried forward        | 5 |
```

### E9 — Pipeline-taugliches Lock-Handling

- Lock-Cleanup-Hook bei `exit`/`trap` in `run-headless.sh`
- Lock-Datei enthält PID + Start-Timestamp; stale wenn PID tot **oder** > 1 h
- `--force-unlock` Flag für echte Deadlocks in CI

### E10 — Validierung

- Neues Script `validate_state.py` analog zu `validate_intermediate.py` für das State-Schema
- Neue Pytests: `test_state_schema.py`, `test_incremental_invalidation.py`
- Smoke-Test: Full-Run → Commit → Incremental-Dry-Run muss konsistente Deltas liefern

---

## 6. Priorisierung (empfohlene Umsetzungsreihenfolge)

| # | Schritt | Aufwand | Entblockt |
|---|---|---|---|
| 1 | Stale-Cleanup auf `.baseline/` ausnehmen + Verzeichnis einführen | S | Alles andere — ohne das funktioniert kein Carry-Forward |
| 2 | Baseline-Error-Path: `--incremental` ohne State → `exit 2` | S | L2, produktionsreifer Pipeline-Einsatz |
| 3 | Minimal-State-File: nur `baseline` + `components` + `threats` + `file_index` für Komponenten-Ebene | M | Deckt den heute dokumentierten Incremental-Modus korrekt ab |
| 4 | Git-SHA-Diff statt `HEAD~1` | S | L1, L9 |
| 5 | Metadata-Tabelle um Incremental-Zeilen erweitern | S | L10, CI-Verifizierbarkeit |
| 6 | Dry-Scan-Semantik umdrehen: `threat-model.delta.md` als eigener Output-Pfad, TM/State/Baseline read-only | M | Haupt-Use-Case |
| 7 | State-Schema auf alle 11 Sektionen ausweiten | L | Volle Carry-Forward-Effizienz, 80–90 % Token-Einsparung pro Run |
| 8 | File→Sektion-Index + Invalidierungs-Kaskade | L | Deterministische Dominoeffekt-Propagation |
| 9 | Recon-Scanner strukturierter Diff | M | Schließt blinden Fleck L8 |
| 10 | Lock-Cleanup + `--force-unlock` | S | L11, parallele MR-Runs |
| 11 | Schema-Validator + Tests | M | Regression-Safety |

Legende: S = klein (< 2h), M = mittel (halber Tag), L = groß (1+ Tag)

---

## 7. Kurzfazit

Das Plugin hat die Rahmenstruktur für Inkremental-Modus (Flags, Auto-Detect, git-diff, Checkpoint) — aber drei harte Probleme:

1. **Die Baseline-Persistenz fehlt**: Stale-Cleanup löscht genau die Dateien, die Carry-Forward bräuchte.
2. **Nur Threats sind strukturiert denkbar** — Architektur, Use Cases, Assets, Attack Surface, Controls haben kein maschinenlesbares Äquivalent, obwohl ein Diff sie genauso invalidieren kann.
3. **Fehlerpfade und Dry-Scan-Semantik** entsprechen nicht dem Pipeline-Use-Case (stille Fallbacks statt `exit 2`, `--dry-run` erzwingt Full).

Die Lösung ist **ein zentrales `threat-model-state.json`** in `.baseline/` mit strukturierten Einträgen aller 11 Sektionen, File-Index für Rück-Propagation, und einer harten Mode-Matrix im Skill. Damit werden 80–90 % jedes Runs carry-forward-fähig, und der Dry-Scan kann einen strukturierten Delta-Report für MR-Kommentare produzieren.

**Minimal-invasiver Einstieg:** Schritte 1–2 der Priorisierung (`.baseline/`-Verzeichnis + harter Error-Path) ermöglichen sofort eine produktionsreife, wenn auch reduzierte, Pipeline-Nutzung. Schritte 3–6 folgen als nächster Meilenstein, 7–8 als Ausbau-Phase.
