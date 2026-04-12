# Incremental Mode — Analyse & Designempfehlung

**Datum:** 2026-04-11
**Autor:** Senior Claude Plugin Developer + Senior Security Specialist (Analyse)
**Scope:** `appsec-plugin` — Umsetzung eines effizienten Incremental-Mode für Pipeline-/MR-Einsatz
**Status:** Design-Vorschlag, noch nicht implementiert

---

## 1. Zielsetzung

Der `create-threat-model`-Skill soll effizient im Incremental-Modus einsetzbar werden, sodass in einer CI-Pipeline oder für einen Merge Request **nur die Änderung (Diff)** seit dem letzten erstellten oder aktualisierten Threat Model berücksichtigt wird.

**Konkrete Anforderungen:**

1. Ein technisches Modell mit Referenz auf den letzten Scan-Stand muss persistiert werden — der Incremental-Scan bezieht sich darauf.
2. Startet der User einen Incremental-Scan ohne existierendes Bedrohungsmodell, muss der Lauf mit einer klaren Fehlermeldung abbrechen.
3. Im Dry-Scan-Modus wird der Diff im Kontext des existierenden Threat Models gescannt, aber dieses **nicht** aktualisiert — es wird nur das Delta ausgegeben.

---

## 2. Ist-Zustand

### 2.1 Was bereits existiert

| Komponente | Datei | Zustand |
|---|---|---|
| Skill-Flag-Parsing | `plugin/skills/create-threat-model/SKILL.md` | `--incremental`, `--full`, `--dry-run` vorhanden |
| Auto-Incremental-Detection | `SKILL.md:121-136` | Aktiv wenn `threat-model.md` existiert |
| Orchestrator-Incremental-Abschnitt | `plugin/agents/appsec-threat-analyst.md:62-88` | Grob skizziert, nutzt `git diff HEAD~1..HEAD` |
| Intermediate Files | `$OUTPUT_DIR/.stride-*.json`, `.recon-summary.md` | Werden geschrieben, **vor jedem Run gelöscht** |
| `threat-model.yaml` Export | via `--yaml`-Flag | Opt-in, wird nicht immer geschrieben |

### 2.2 Identifizierte Probleme

| # | Problem | Schweregrad | Fundort |
|---|---|---|---|
| A1 | `--incremental` ohne Baseline fällt still auf Full zurück | 🔴 Kritisch | `appsec-threat-analyst.md:66` |
| A2 | `--dry-run` erzwingt `INCREMENTAL=false` | 🔴 Kritisch | `SKILL.md:128` |
| A3 | `git diff HEAD~1..HEAD` als einzige Delta-Quelle | 🟠 Hoch | `appsec-threat-analyst.md:70` |
| A4 | Kein persistenter Baseline-Marker (Commit-SHA, Zeitstempel) | 🟠 Hoch | Fehlt komplett |
| A5 | `.stride-*.json` wird vor jedem Run gelöscht | 🟠 Hoch | `appsec-threat-analyst.md:~594` |
| A6 | Phase 2 Recon läuft auch im Incremental voll | 🟡 Mittel | `phase-group-recon.md` |
| A7 | Report enthält nicht die Daten, die ein Delta-Engine braucht | 🟡 Mittel | Struktur-Lücke |
| A8 | Widerspruch: `appsec-threat-analyst.md:548` sagt „always runs a full assessment" | 🟢 Niedrig | Toter Text |
| A9 | `--yaml` als Opt-in | 🟢 Niedrig | Skill-Flag |

**Bewertung:** A1 und A2 sind Blocker für den beschriebenen Use-Case. A3–A5 sind strukturelle Defizite, die Incremental heute nur scheinbar funktional machen. A6 ist der wirtschaftliche Hauptgewinn. A7–A9 sind Hygiene-Themen.

---

## 3. Das technische Analysemodell

Das technische Analysemodell besteht aus **genau drei Artefakten** — jedes mit klarer Verantwortung und Lebensdauer.

### 3.1 `threat-model.yaml` — das fachliche Modell

**Verantwortung:** Der strukturierte, maschinenlesbare Stand des Bedrohungsmodells. Enthält **was gefunden wurde** und **gegen welchen Stand gescannt wurde**.

**Neu gegenüber heute (always-on + Erweiterung):**

```yaml
meta:
  generated: 2026-04-11T09:12:04Z
  schema_version: 1
  mode: full | incremental
  git:
    commit_sha: ab12cd34...        # Anker für git diff
    branch: main
    remote_url: git@...
  baseline_ref: ef98gh76...         # nur bei incremental: SHA des Vorgänger-TMs

components:                         # NEU: Komponente ↔ Pfade ↔ Threats
  - id: auth-service
    name: Auth Service
    kind: service
    paths: ["services/auth/**", "libs/jwt/**"]
    threat_ids: [T-003, T-004, T-011]

assets: [...]                       # bestehend
attack_surface: [...]               # bestehend
threats: [...]                      # bestehend, mit stabilen T-IDs
mitigations: [...]                  # bestehend
```

- **Lebensdauer:** Dauerhaft, versioniert, committed
- **Zielgruppe:** User, CI-Tools, Dashboards, DefectDojo, GHAS
- **Wer schreibt:** Orchestrator in Phase 11
- **Wer liest beim Delta-Lauf:** Orchestrator (für `meta.git.commit_sha` → Delta-Anker, für `components[].paths` → file-to-component routing, für `threats[]` → carry-forward)

### 3.2 `.stride-<component-id>.json` — Rohbefunde pro Komponente

**Verantwortung:** Die unverarbeiteten STRIDE-Ergebnisse pro Komponente. Existiert bereits heute, wird aber vor jedem Run gelöscht.

**Änderung:** Cleanup-Logik muss modusabhängig werden. Bei `INCREMENTAL=true` bleiben die Files erhalten und dienen als carry-forward-Quelle für unveränderte Komponenten.

- **Lebensdauer:** Zwischen Runs erhalten, gitignored, pro Komponente überschrieben wenn re-analysiert
- **Zielgruppe:** Plugin-intern
- **Wer schreibt:** Jeder `appsec-stride-analyzer`-Aufruf
- **Wer liest beim Delta-Lauf:** Orchestrator in Phase 9, wenn die Komponente nicht in `changed_paths` auftaucht

### 3.3 `.appsec-cache/baseline.json` — Runtime-State

**Verantwortung:** Reine Cache-Invalidierung und Zähler. Hat keinen fachlichen Wert, enthält nur Daten, die der nächste Lauf braucht um schnell zu sein.

```json
{
  "schema_version": 1,
  "recon_fingerprint": {
    "manifests": {
      "package.json": "sha256:...",
      "go.mod": "sha256:..."
    },
    "dockerfiles": {
      "Dockerfile": "sha256:...",
      "services/auth/Dockerfile": "sha256:..."
    },
    "iac": {
      "k8s/deployment.yaml": "sha256:...",
      "terraform/main.tf": "sha256:..."
    }
  },
  "id_counters": {
    "next_threat_id": 48,
    "next_mitigation_id": 23
  },
  "stride_files": {
    "auth-service": {
      "path": ".stride-auth-service.json",
      "sha256": "..."
    }
  }
}
```

- **Lebensdauer:** Volatil, auto-gitignored, kann jederzeit gelöscht werden → erzwingt Full-Run
- **Zielgruppe:** Ausschließlich das Plugin selbst
- **Wer schreibt:** Orchestrator in Phase 11 (nur wenn `DRY_RUN=false`)
- **Wer liest beim Delta-Lauf:** Orchestrator vor Phase 2 (Recon-Skip via `recon_fingerprint`) und Phase 9 (Integritätscheck der `.stride-*.json`)

### 3.4 Welche Frage löst welches Artefakt?

| Frage beim Delta-Lauf | Gelöst durch |
|---|---|
| Gegen welchen Commit vergleiche ich? | `threat-model.yaml` → `meta.git.commit_sha` |
| Welche Datei gehört zu welcher Komponente? | `threat-model.yaml` → `components[].paths` |
| Welche Threats kann ich unverändert übernehmen? | `threat-model.yaml` → `threats[]` + stabile T-IDs |
| Wie heißt die nächste freie T-ID? | `.appsec-cache/baseline.json` → `id_counters.next_threat_id` |
| Kann ich Phase 2 Recon überspringen? | `.appsec-cache/baseline.json` → `recon_fingerprint` |
| Sind die Rohbefunde noch integer? | `.appsec-cache/baseline.json` → `stride_files[].sha256` + `.stride-*.json` |
| Was ist mein Arbeitsstand pro Komponente? | `.stride-<id>.json` |

### 3.5 Warum nicht einfach den Report (md) verwenden?

`threat-model.md` enthält Dateireferenzen nur als Prosa (`services/auth/login.ts:42`). Ein zuverlässiger Delta-Engine kann keine Prosa parsen — er braucht strukturierte Komponente→Pfade-Maps. Die md bleibt das User-Artefakt, die yaml wird das technische Modell.

### 3.6 Warum nicht alles in die yaml packen?

Vier Felder gehören NICHT in die yaml:

1. **Recon-Fingerprint** (Hashes) — reine Cache-Invalidierung, für User wertlos
2. **`next_threat_id`-Counter** — Implementierungsdetail
3. **`.stride-*.json`-Integritätshashes** — Intermediate-Integrity-Check
4. **Cache-TTL-Zeitstempel** — Dep-Scanner-Cache-Mechanik

Gründe: Git-Rauschen bei jedem Dependency-Bump, Korruptionsgefahr durch Hand-Edits, Abstraktionsbruch (yaml soll an DefectDojo/GHAS verteilbar sein, ohne interne Hashes).

---

## 4. Kern-Designentscheidungen

### 4.1 Flag-Semantik: orthogonale Booleans statt neuer Mode

`INCREMENTAL` und `DRY_RUN` werden unabhängig voneinander behandelt. Keine neuen Variablen, kein neuer Mode-Enum.

| `INCREMENTAL` | `DRY_RUN` | Verhalten |
|---|---|---|
| false | false | Full scan, schreibt TM + yaml + Baseline |
| true  | false | Delta-Scan, updatet TM + yaml + Baseline |
| false | true  | Full, Phasen 0–1 only, keine Writes (aktuelles Verhalten) |
| true  | true  | **Delta-Scan im Kontext des TM, keine Writes, nur Delta-Report** ← neu |

- `INCREMENTAL` steuert **was** analysiert wird (Delta vs. Full, Carry-forward, Baseline-Pflicht)
- `DRY_RUN` steuert **ob am Ende geschrieben** wird (`threat-model.md/yaml`, `.appsec-cache/baseline.json`)

**Abort-Matrix:**

| Konstellation | Verhalten |
|---|---|
| `--incremental` + kein `threat-model.md` / `threat-model.yaml` | Hartes Abort mit Fehlermeldung |
| `--incremental --full` | Abort (Konflikt) |
| `--incremental --dry-run` + kein TM | Abort |

### 4.2 yaml als Always-On

`threat-model.yaml` wird bei jedem Run geschrieben. Das `--yaml`-Flag entfällt, optional `--no-yaml` für Nischenfälle.

**Gewinne:**
- Ein Flag weniger
- SARIF kann aus yaml abgeleitet werden (weniger Drift-Risiko)
- QA-Reviewer und Delta-Engine teilen sich die gleiche Strukturquelle
- Einheitlicher Audit-Trail

**Caveat:** yaml-Schema wird Teil der öffentlichen Plugin-Schnittstelle und braucht `schema_version` + Versionierungsdisziplin.

### 4.3 Pipeline-taugliche Delta-Erkennung

Baseline-Quellen in Reihenfolge:

1. `$APPSEC_BASELINE_REF` Env-Variable (CI-Override, z. B. `$CI_MERGE_REQUEST_DIFF_BASE_SHA` in GitLab, `$GITHUB_BASE_REF` in GitHub Actions)
2. `meta.git.commit_sha` aus `threat-model.yaml`
3. Fallback `origin/<branch>` mit Warnung

```bash
BASELINE_SHA="${APPSEC_BASELINE_REF:-$(yq '.meta.git.commit_sha' threat-model.yaml)}"
CHANGED=$(git -C "$REPO_ROOT" diff --name-only "$BASELINE_SHA"..HEAD)
CHANGED_UNCOMMITTED=$(git -C "$REPO_ROOT" diff --name-only HEAD)
```

### 4.4 Phase 2 Recon-Skip via Fingerprint

```
if manifest/Dockerfile/IaC-Hashes unverändert
   AND .recon-summary.md existiert:
  → Recon skippen, Datei wiederverwenden
  → Log: "[Phase 2/11] ⟳ Recon cached — fingerprint unchanged since <baseline_sha>"
else:
  → Recon-Scanner normal dispatchen, Fingerprint aktualisieren
```

**Dies ist der größte Token-Einsparposten.** Ohne diesen Schritt bleibt Incremental nur marginal günstiger als Full, da Phase 2 heute 25 Turns + 24 Grep-Kategorien kostet.

### 4.5 Phase 9 STRIDE Carry-Forward mit T-ID-Stabilität

Pro Komponente aus `threat-model.yaml` → `components[]`:

- `changed_paths ∩ component.paths != ∅` → STRIDE re-dispatchen, `.stride-<id>.json` überschreiben
- sonst → `.stride-<id>.json` direkt wiederverwenden, T-IDs stabil halten
- Neue Komponenten (neue Dockerfiles/Services im diff) → fresh STRIDE, neue T-IDs aus `next_threat_id`
- Entfernte Komponenten → Threats als „resolved — component removed" in Delta-Report

**Voraussetzung:** `.stride-*.json` darf nicht mehr unbedingt gelöscht werden (siehe Punkt A5). Cleanup muss modusabhängig werden.

### 4.6 Delta-Report `threat-model.delta.md`

Neue Datei, die bei allen Incremental-Läufen (auch Dry) geschrieben wird:

- **Header**: Baseline-SHA, aktueller SHA, geänderte Dateien, betroffene Komponenten
- **Neue Threats** (seit Baseline)
- **Geänderte Threats** (Risk-Rerating, neuer Evidence-Pfad)
- **Resolved Threats** (Komponente/Datei gelöscht oder Control hinzugekommen)
- **Unverändert** (nur Count, nicht aufgelistet)
- **Link auf Full Report**

**Schreibregel:**

| Modus | Delta-Report | TM-md | TM-yaml | Baseline-Sidecar |
|---|---|---|---|---|
| `INCREMENTAL=true, DRY_RUN=false` | ✅ | ✅ update | ✅ update | ✅ update |
| `INCREMENTAL=true, DRY_RUN=true` | ✅ | ❌ | ❌ | ❌ |

---

## 5. Konkrete Datei-Änderungen

| Datei | Änderung | Aufwand |
|---|---|---|
| `plugin/skills/create-threat-model/SKILL.md` | Zeile 128 löschen, Abort-Logik für `--incremental` ohne Baseline, Flag-Matrix (§4.1), `--yaml`/`--no-yaml` umdrehen | S |
| `plugin/agents/appsec-threat-analyst.md` | Incremental-Abschnitt (Z. 62–88) umschreiben, Z. 548 aufräumen, Cleanup (~594) modusabhängig, DRY_RUN-Write-Gate, yaml-Schema erweitern | M |
| `plugin/agents/phases/phase-group-recon.md` | Recon-Skip auf Fingerprint-Basis, Fingerprint-Berechnung am Phase-Ende | M |
| `plugin/agents/phases/phase-group-threats.md` | STRIDE Carry-Forward-Regeln, T-ID-Stabilität, Resolved-Tracking | M |
| `plugin/agents/phases/phase-group-finalization.md` | Delta-Report-Template, `.appsec-cache/baseline.json`-Write, Summary um added/changed/resolved/unchanged-Counts erweitern | M |
| `plugin/scripts/baseline_state.py` (neu) | Read/Write/Validate des Sidecar-Schemas | S |
| `tests/` | Flag-Matrix, Abort-ohne-Baseline, Dry-Incremental-Write-Gate, Fingerprint-Skip, T-ID-Stabilität | M |

**Gesamt-Aufwand:** ~2–3 Entwicklungstage für einen erfahrenen Plugin-Dev bei sequenzieller Umsetzung.

---

## 6. Empfohlene Umsetzungsreihenfolge

| Schritt | Inhalt | Value | Risiko | Blockt bestehende Funktionalität? |
|---|---|---|---|---|
| **1** | Skill-Flag-Matrix + Abort bei `--incremental` ohne Baseline + A2-Fix (Z. 128) | Pipeline-Safety | Minimal | Nein |
| **2** | yaml-always-on + `components[]`-Block + `meta.git`-Erweiterung | Strukturquelle für Delta | Niedrig (neue Datei für alte User) | Nein |
| **3** | Sidecar `.appsec-cache/baseline.json` + `baseline_state.py` | Cache-Foundation | Niedrig | Nein |
| **4** | Delta-Report + Dry-Incremental-Write-Gate | Haupt-User-Value | Niedrig | Nein |
| **5** | Phase 2 Recon-Skip via Fingerprint | **Größte Token-Einsparung** | Mittel (Fingerprint-Abdeckung) | Nein |
| **6** | Phase 9 Carry-Forward + T-ID-Stabilität | Qualitative Konsistenz | Mittel (Edge Cases) | Nein |
| **7** | CI-Env-Override `$APPSEC_BASELINE_REF` | Pipeline-Integration | Minimal | Nein |

Jeder Schritt ist für sich mergebar und liefert inkrementellen Wert. Die Reihenfolge minimiert Risiko durch Fundament-first: Safety → Struktur → Optimierung → Qualität.

---

## 7. Bewertung & Risiken

### 7.1 Stärken

- **Klare Trennung** User-facing Reports ↔ Plugin-interner State
- **Orthogonale Flag-Semantik** ohne neuen Mode-Enum
- **Jeder Schritt inkrementell** und einzeln wertvoll
- **Token-Einsparung nicht nur theoretisch** — Phase 2 Recon-Skip ist der konkrete Hebel
- **Pipeline-Tauglichkeit explizit adressiert** (CI-Baseline-Override, harte Aborts)
- **Drei-Artefakt-Struktur** ist die minimale saubere Lösung — nicht weniger, nicht mehr

### 7.2 Offene Risiken

| Risiko | Mitigation |
|---|---|
| **Recon-Fingerprint übersieht security-relevantes File** → veralteter Cache wird verwendet | Conservative Fingerprinting; bei Unsicherheit Recon neu laufen (fail-safe default) |
| **T-ID-Kollisionen bei Branch-Parallelität** (zwei MRs vergeben gleichzeitig Threats) | Entweder zentrale Counter im Main-Branch-TM, oder UUID-basierte IDs statt fortlaufend, oder Branch-Prefix (`T-feat-auth-001`) |
| **Schema-Versionierung** — yaml wird öffentliche API | `schema_version`-Feld + Migration-Skript + semver-Disziplin |
| **Hand-Edits an der yaml** durch Teams (FP-Suppression, Severity-Anpassung) | Dokumentation; optional `user_overrides`-Block der bei re-scan respektiert wird |
| **Baseline-Drift**: Wenn der Baseline-Commit force-pushed wird, zeigt `commit_sha` ins Leere | Fallback auf `origin/<branch>` mit Warnung im Delta-Report |

### 7.3 Gesamtnote

🟢 **Architektur ist solide und pragmatisch.**

Keine Over-Engineering-Fallen (wie ein initialer „4-Mode"-Vorschlag, der verworfen wurde), klare Trennlinien, jeder Baustein begründet. Die Umsetzung ist überschaubar und in sich konsistent.

**Empfehlung:** Mit Schritt 1 starten. Das ist der billigste, sicherste und effektivste erste Zug — er fixt die kritischen Safety-Probleme A1 und A2, ohne bestehende Funktionalität anzutasten.

---

## 8. Antworten auf die Ursprungsfragen

> **Frage:** „Dafür muss vermutlich ein technisches Modell mit Timestamp vom letzten Diff des Bedrohungsmodells gespeichert werden, auf das sich dann der Scan bezieht."

**Antwort:** Ja. Der Timestamp und der git-Commit-SHA wandern in `threat-model.yaml` unter `meta.generated` und `meta.git.commit_sha`. Die yaml IST das technische Modell, auf das sich der nächste Scan bezieht. Kein separater Timestamp-File nötig.

> **Frage:** „Wenn der User einen Incremental-Scan startet, es aber noch gar kein Bedrohungsmodell gibt, muss mit einer Fehlermeldung abgebrochen werden."

**Antwort:** Abort-Matrix in §4.1 — `--incremental` ohne existierendes `threat-model.md`/`threat-model.yaml` führt zu hartem Abort. Kein silent fallback.

> **Frage:** „Wenn der User mit Dry-Scan startet, wird der Diff zwar im Kontext des existierenden Threat Models gescannt, aber dieses dann im Anschluss nicht aktualisiert, sondern nur das Delta."

**Antwort:** Realisiert durch orthogonale Flags `INCREMENTAL=true, DRY_RUN=true` (§4.1). Die Delta-Analyse läuft vollständig, aber am Ende werden nur `threat-model.delta.md` geschrieben — `threat-model.md`, `threat-model.yaml` und `.appsec-cache/baseline.json` bleiben unberührt.

> **Frage:** „Reicht hierzu einfach der Report `threat-model.md` aus, oder muss zusätzlich noch eine technische Darstellung des Bedrohungsmodells mit sämtlichen Meta-Dateien gespeichert werden?"

**Antwort:** Die md reicht nicht — sie enthält Dateireferenzen nur als Prosa, was für einen Delta-Engine nicht maschinell parsbar ist. Benötigt wird die Drei-Artefakt-Struktur aus §3: `threat-model.yaml` (always-on, fachliches Modell), `.stride-<id>.json` (Rohbefunde), `.appsec-cache/baseline.json` (Runtime-State).

> **Frage:** „Braucht man hierfür wirklich einen neuen Mode?"

**Antwort:** Nein. Die zwei existierenden Booleans `INCREMENTAL` und `DRY_RUN` kodieren bereits alles, wenn man sie orthogonal statt verdrahtet behandelt. Der initiale Vorschlag mit vier Modes (`full`/`full-dry`/`incremental`/`incremental-dry`) war Overengineering.
