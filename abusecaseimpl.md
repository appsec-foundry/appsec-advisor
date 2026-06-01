# Implementierungsplan: Finding Register + Abuse Cases

## Ziele

1. **Finding Register** — `§8 Threat Register` wird zu `§8 Finding Register`. Die bisherige
   künstliche T-NNN/F-NNN-Doppeligkeit (T-NNN im YAML, F-NNN im Report, Übersetzung im
   Composer) wird aufgelöst: F-NNN wird die einzige kanonische ID, überall konsistent.

2. **Abuse Cases** — Neues dreistufiges Modell: atomare Findings (F-NNN) → strukturelle Chains
   (CC-NNN) → narrative Szenarien mit Verdict (AC-NNN). Abuse Cases sind aktiv durch den Plugin
   verifikationsgetrieben, nicht nur dokumentarisch.

3. **Org-Profil-Integration** — Mandatory und custom Abuse Cases über das Org-Profil definierbar,
   mit scope-qualifier, `grants`/`requires`-Logik und optionalem CI-Release-Gate.

---

## Risiken

| Risiko | Schwere | Gegenmaßnahme |
|---|---|---|
| T-NNN ist in externen SARIF-Consumern (GitHub Advanced Security, DefectDojo) als Regel-ID referenziert | Hoch | Migration Script `migrate_finding_ids.py`; SARIF-Export behält Rückwärtskompatibilität via `aliases[]` für eine Hauptversion |
| Incremental-Mode liest `meta.git.commit_sha` + T-IDs aus bestehendem `threat-model.yaml` — nach Rename ist das Baseline-YAML inkonsistent | Hoch | `baseline_state.py` bekommt einen Migrationspfad: erkennt `threats[]` in Legacy-YAML und übersetzt on-the-fly beim ersten incremental Read |
| `qa_checks.py` hat ~15 Stellen mit hardcoded `T-NNN`-Pattern, `TABLE_ID_RE` (Zeile 90), `_collect_threat_register_t_ids()` (Zeile 5154), `check_xrefs()` (Zeile 403), `_inject_row_anchors()` (Zeile 435–455) — nach Rename produziert die QA-Gate falsche `orphaned-threat-ref`-Fehler auf jeden F-NNN-Report | Hoch | Alle `T_ID_RE`/`TABLE_ID_RE`-Checks in Phase 2 migrieren; `_collect_threat_register_t_ids()` auf `"## 8. Finding Register"` heading umstellen; T-NNN als accepted-legacy bis Phase 3 |
| `compose_threat_model.py` hat 8 hardcoded `#8-threat-register`- und `#9-mitigation-register`-Anker in generierten Texten (Zeilen 6243, 6266, 6594, 6768, 7480, 9889, 10963, 11623) — nach §9-Nummernshift zeigen alle Mitigation-Register-Links ins Leere | Hoch | Alle hardcoded Anker in Phase 2/5 auf `#8-finding-register` und `#10-mitigation-register` updaten; `data/sections-contract.yaml` als einzige Wahrheitsquelle für Anker-Slugs einführen |
| `phase-group-threats.md` enthält `## 8. Threat Register`-Heading-Beispiele (Zeilen 750, 886) und T-NNN-Referenzen im Critical-Attack-Tree-Beispiel (Zeile 1040) sowie `§9 Mitigation Register`-Links (Zeile 1056) — LLM-Agenten generieren nach Rename inkorrekte Headings | Mittel | Alle betroffenen Agenten-Prompts in Phase 2 synchron aktualisieren; besonders `phase-group-threats.md` und `appsec-qa-reviewer.md` (Zeile 279: `## 8. Threat Register` als Expected-Heading) |
| `appsec-qa-reviewer.md` Check 3 (Zeile 172) sucht `T-NNN` in §9 Addresses und Check 3c (Zeile 175) sucht `T-NNN` in Attack Tree — nach Rename werden F-NNN-only-Reports als fehlerhaft gemeldet | Mittel | Phase 2: QA-Check-Pattern auf F-NNN als primary umstellen; `§9`-Referenzen auf neue Nummern anpassen |
| §9-Nummernshift betrifft alle `§9`-Anchors im generierten Report — MS enthält `[§9 Mitigation Register](#9-mitigation-register)` an 6 Stellen in `compose_threat_model.py`; nach Shift zeigen diese Links auf die neue §9 Abuse Cases statt §10 | Hoch | Gleichzeitig mit §9-Einführung alle `#9-mitigation-register`-Anchors auf `#10-mitigation-register` setzen; nie schrittweise (Report wäre kurzzeitig inkonsistent) |
| Bestehende `threat-model.md`-Ausgaben in Repos enthalten `T-NNN`-Anker — externe Deep-Links brechen | Mittel | Dual-Anchor-Strategie: Composer emittiert `<a id="t-NNN"></a>` legacy-Anker neben `<a id="f-NNN"></a>` für zwei Hauptversionen |
| Abuse-Case-Verifier erhöht Laufzeit bei `standard`/`thorough` | Niedrig | Ein Agent pro Candidate parallel (wie STRIDE Phase 9); Wall-Clock = langsamster Einzelfall (~2–3 min), nicht N × ~2 min; max. 15 Turns pro Agent |
| Org-Profil-Abuse-Cases mit zu spezifischen `probe.sink_patterns` schlagen auf falschen Repos an | Niedrig | `scope_qualifier.required_signals` filtert Repos ohne relevante Recon-Signale; `not_applicable` Verdict statt false positive |

---

## Übersicht der betroffenen Artefakte

### Datenmodell (Schemas)
- `schemas/threat-model.output.schema.yaml` — `threats[]` → `findings[]`, `threat_ids` → `finding_ids`
- `schemas/threats-merged.schema.yaml` — `t_id` → `f_id` als primäres Feld; `threats[]` → `findings[]`
- `schemas/stride.schema.yaml` — `threats[]` → `findings[]`
- `schemas/triage-flags.schema.yaml` — `threat_ids` → `finding_ids`; `top_threats` → `top_findings`
- `schemas/fragments/compound-chains.schema.json` — `threat_ids` → `finding_ids`
- `schemas/fragments/mitigation-overrides.schema.json` — `threat_ids` → `finding_ids`
- `schemas/fragments/assets.schema.json` — `linked_threats` → `linked_findings`
- **NEU** `schemas/abuse-cases.schema.yaml` — vollständiges Schema für AC-NNN
- **NEU** `schemas/fragments/abuse-cases.schema.json` — Fragment-Schema für Composer

### Scripts
- `scripts/build_threat_model_yaml.py` — `build_threats()` → `build_findings()`; `t_id→id`-Translation entfällt
- `scripts/merge_threats.py` — Umbenennung intern; Output-Key `threats` → `findings`
- `scripts/compose_threat_model.py` — T-NNN/F-NNN Alias-Logik entfällt; Dual-Anchor-Emission; §8-Heading
- `scripts/export_sarif.py` — F-NNN als primäre Rule-ID; `aliases[]` für T-NNN Backwards-Compat
- `scripts/render_pentest_tasks.py` — `_yaml_threat_to_merged()` → `_yaml_finding_to_merged()`
- `scripts/qa_checks.py` — ID-Pattern-Erkennung auf F-NNN erweitern; T-NNN als deprecated-warning
- `scripts/aggregate_threat_summary.py` — `_extract_threats()` → `_extract_findings()`
- `scripts/validate_finding_refs.py` — bereits auf F-NNN ausgerichtet, minimale Anpassung
- `scripts/reserve_ids.py` — neuer ID-Typ `abuse_case` für AC-NNN Reservierung
- **NEU** `scripts/match_abuse_cases.py` — deterministischer Matcher: Chain-Template gegen findings[]
- **NEU** `scripts/verify_abuse_cases.py` — ruft `appsec-abuse-case-verifier` auf; schreibt `.abuse-case-verdicts.json`
- **NEU** `scripts/render_abuse_cases.py` — Composer-Helfer für §9 Rendering aus `.abuse-case-verdicts.json`

### Agents
- `agents/appsec-stride-analyzer.md` — `component_id`/`threats[]` intern; Output-Contract auf `findings[]`
- `agents/appsec-triage-validator.md` — `threat_ids` → `finding_ids`; Phase-10b-Erweiterung um Abuse-Case-Synthesis
- `agents/appsec-threat-merger.md` — interne Terminologie; Output bleibt kompatibel via Schema
- `agents/appsec-threat-analyst.md` — §8-Heading-Referenz; T-NNN→F-NNN canonical Hinweise
- `agents/appsec-threat-renderer.md` — §8/§9-Fragment-Authoring; Dual-Anchor-Regel
- `agents/appsec-qa-reviewer.md` — Check 3: `Threat Register` → `Finding Register`; ID-Patterns
- `agents/shared/qa-crossref-rules.md` — F-NNN als primäres Pattern
- `agents/phases/phase-group-finalization.md` — §8/§9-Struktur; Fragments-Tabelle; CC-NNN Promotion
- `agents/phases/phase-group-threats.md` — Merge-Output-Referenzen; Abuse-Case-Synthesis-Schritt
- **NEU** `agents/appsec-abuse-case-verifier.md` — neuer Agent, ~40 Turns, Haiku

### Org-Profil
- `schemas/org-profile.schema.yaml` — neues `abuse_cases`-Toplevel-Objekt
- `scripts/resolve_org_profile.py` — Abuse-Case-Glob auflösen
- `scripts/validate_org_profile.py` — Abuse-Case-YAML validieren
- **NEU** `data/abuse-cases/default-library.yaml` — Plugin-Standard-Templates (Account Takeover, Bulk Exfiltration, Privilege Escalation)

### Report-Struktur
- §8 Finding Register (war: Threat Register) — Heading, Anker, alle Querverweise
- §9 Abuse Cases — neue Sektion, ersetzt bisherige §9-Nummerierung
- §10 Mitigation Register (war: §9)
- §11 Out of Scope (war: §10)
- `data/sections-contract.yaml` — neue Sektionsdefinitionen; Nummernshift

---

## Phasen

---

### Phase 1 — Datenmodell-Fundament (kein Rendering, kein Report-Impact)

**Ziel:** F-NNN als einzige kanonische ID in allen Intermediates und Schemas verankern.
Die Übersetzungsschicht `t_id → id` in `build_threat_model_yaml.py` entfällt.

**Arbeiten:**

1. `schemas/threats-merged.schema.yaml`
   - `t_id` → `f_id` als Required-Feld (Primär-ID)
   - `threats[]` → `findings[]`
   - Backwards-Compat: `t_id` als deprecated-optional für Migration behalten (mit `deprecated: true`-Annotation)

2. `schemas/stride.schema.yaml`
   - `threats[]` → `findings[]`
   - `local_id`-Feld bleibt (component-scoped Sequenz, unveränderlich)

3. `schemas/triage-flags.schema.yaml`
   - `flags[].threat_ids` → `finding_ids` (Zeile 45 — individuelles Flag-Objekt)
   - `ranking.views.top_threats` → umbenennen (Zeile 89); `top_findings` existiert bereits
     parallel in der Schema (Zeile 99) — Legacy-Key entfernen, sobald alle Leser migriert

4. `schemas/fragments/compound-chains.schema.json`
   - Kein `threat_ids`-Feld vorhanden — `keystones[]` und `contributors[]` verwenden ein
     `ref`-Feld mit Pattern `^[FT]-\d{3,4}$` das bereits beide Formate akzeptiert
   - Nach Phase 1: Pattern auf `^F-\d{3,4}$` einschränken (T-NNN nicht mehr gültig)

5. `scripts/merge_threats.py`
   - Output-Key `threats` → `findings`
   - `_assign_t_ids()` → `_assign_f_ids()` (Zeile 935 — Funktion und interne T-NNN-Logik)
   - T-NNN-Sequenz wird zu F-NNN-Sequenz (gleiche Logik, anderer Prefix)
   - Achtung: `scripts/triage_compute_ranking.py` liest `yaml_data.get("threats")` (Zeile 488)
     und enthält bereits eine `_finding_id()`-Hilfsfunktion (Zeile 101) die `t_id`/`id`/`finding_id`
     als Fallback-Kette nutzt — diese Funktion vereinfacht sich nach Phase 1 auf rein `f_id`

6. `scripts/build_threat_model_yaml.py`
   - `build_threats()` → `build_findings()`
   - `threat["id"] = threat.pop("t_id", ...)` entfällt — F-NNN direkt übernehmen
   - `mitigations[].threat_ids` → `finding_ids`
   - `critical_findings[].threat_id` → `finding_id`

7. `scripts/reserve_ids.py`
   - `_ID_TYPES` (Zeile 61): `"threat": ("next_threat_id", "T", 3)` → `"finding": ("next_finding_id", "F", 3)`
   - `"threat"` als deprecated Alias behalten (wirft Warning, mappt auf `finding`)
   - Neuer Eintrag: `"abuse_case": ("next_abuse_case_id", "AC", 3)` für AC-NNN Reservierung
   - `baseline.json` Counter-Key `next_threat_id` → `next_finding_id` (Migration in `baseline_state.py`)

**Migrationspfad für bestehende YAMLs:**

```python
# scripts/migrate_finding_ids.py (NEU)
# Liest threat-model.yaml mit threats[], schreibt findings[] mit F-NNN stabil.
# Mappt T-001 → F-001 1:1 (Sequenzstabilität).
# Wird von baseline_state.py on-the-fly aufgerufen wenn Legacy-YAML erkannt wird.
```

**Validation:**
- Alle bestehenden Tests in `tests/` müssen nach Umbenennung grün sein
- `validate_intermediate.py` erkennt Legacy-Schema und migriert on-the-fly

**Risiko dieser Phase:** Hoch — zentrale Datenstruktur ändert sich. Isoliert halten: kein
Report-Rendering bis Phase 2 abgeschlossen.

---

### Phase 2 — Report-Rendering und Contracts

**Ziel:** `§8 Finding Register` im Report; T-NNN-Anker als Legacy-Compat erhalten;
Composer-Logik vereinfachen.

**Arbeiten:**

1. `scripts/compose_threat_model.py`
   - `T-NNN/F-NNN Alias-Logik` entfällt (Zeilen 235–378 — bidirektionale Alias-Registrierung
     Zeilen 260–265, T-NNN→F-NNN Visible-Label-Normalisierung Zeilen 373–377) — F-NNN überall
   - Dual-Anchor: Composer emittiert `<a id="t-NNN"></a>` zusätzlich zu `<a id="f-NNN"></a>`
     für jede Findings-Zeile in §8 (externe Deep-Links bleiben valid)
   - §8-Heading: `## 8. Threat Register` → `## 8. Finding Register`
   - Alle internen `get("threats")` → `get("findings")`

2. `agents/appsec-threat-renderer.md`
   - Alle `T-NNN`-Referenzen in Prompts → F-NNN
   - Dual-Anchor-Regel explizit dokumentieren
   - `ms-critical-attack-tree.json` Leaf-Label-Regel: F-NNN statt T-NNN

3. `agents/shared/qa-crossref-rules.md`
   - F-NNN als primäres ID-Pattern
   - T-NNN als accepted-legacy (kein Hard-Fail bis Phase 3)

4. `agents/appsec-qa-reviewer.md`
   - Check 3: `Threat Register` → `Finding Register`
   - ID-Muster-Erkennung auf F-NNN als kanonisch

5. `data/sections-contract.yaml`
   - §8-Heading anpassen
   - §9 Abuse Cases als neue Sektion registrieren (noch leer, Scaffold)
   - §10 Mitigation Register (Nummernshift)
   - §11 Out of Scope (Nummernshift)

6. `scripts/export_sarif.py`
   - F-NNN als primäre `ruleId`
   - `aliases: ["T-NNN"]` im SARIF-Rule-Objekt für eine Hauptversion

7. `scripts/qa_checks.py`
   - `check_heading_hygiene`: §8-Heading auf neue Bezeichnung
   - T-NNN-Pattern als `deprecated_id_pattern`-Warning (nicht Error)

**Validation:**
- `tests/test_export_sarif.py` prüft F-NNN als primäre Rule-ID + T-NNN in aliases
- E2E-Test gegen Juice-Shop-Fixture: §8-Heading korrekt, alle F-NNN-Anker gesetzt,
  T-NNN-Dual-Anker vorhanden

---

### Phase 3 — Abuse Case Datenmodell

**Ziel:** Schema, Org-Profil-Integration und Standard-Library für Abuse Cases.

**Arbeiten:**

1. **`schemas/abuse-cases.schema.yaml` (NEU)**

```yaml
# Vollständiges Schema — Auszug der kritischen Felder

abuse_case:
  required: [id, title, source, attacker, goal, chain]
  properties:
    id:
      pattern: "^(AC|ORG-AC)-[0-9]{3,}$"
    source:
      enum: [mandatory, discovered]
    detail_level:
      enum: [minimal, standard, full]
      default: standard
    attacker:
      required: [actor_id, initial_access]
      properties:
        initial_access:
          enum: [unauthenticated, authenticated_low_priv, authenticated_high_priv, physical]
        prerequisite:
          type: string   # Freitext, geht direkt in Report-Prosa
    scope_qualifier:
      properties:
        required_signals: { type: array }    # Recon-Signale
        path_patterns:    { type: array }    # Glob gegen Repo
    chain:
      items:
        required: [step, label, grants, probe]
        properties:
          step:       { type: integer }
          label:      { type: string }
          grants:     { type: string }   # Attacker-State nach diesem Step
          requires:   { type: string }   # Attacker-State der vorausgesetzt wird (optional Step 1)
          description: { type: string }  # Narrative für Report
          required:   { type: boolean, default: true }
          probe:
            required: [sink_patterns]
            properties:
              entry_points:
                properties:
                  endpoint_patterns: { type: array }
                  file_hints:        { type: array }
              sink_patterns:    { type: array }   # Regex/Literal-Liste
              control_patterns: { type: array }   # Wenn gefunden → Step blocked
              control_sufficiency:
                enum: [any, all]
                default: any
              anchors:          # Nach erstem Run befüllbar
                items:
                  required: [file, pattern]
                  properties:
                    file:      { type: string }
                    line_hint: { type: integer }
                    pattern:   { type: string }
    combined_risk_rationale: { type: string }
    release_gate:
      properties:
        fail_on:
          items:
            enum: [fully_viable, partially_blocked]
        applies_to_presets: { type: array }
```

2. **`schemas/org-profile.schema.yaml`** — neues Toplevel-Objekt:

```yaml
abuse_cases:
  type: object
  additionalProperties: false
  properties:
    inherit_defaults:
      type: boolean
      default: true
    disable:
      type: array
      items: { type: string, pattern: "^AC-[0-9]{3,}$" }
    add:
      type: string
      default: "abuse-cases/*.yaml"
```

3. **`data/abuse-cases/default-library.yaml` (NEU)**

Drei Plugin-Standard-Templates, die mit `inherit_defaults: true` aktiviert werden:

- `AC-T-001` — Account Takeover via Script Injection + Token Theft
  - `scope_qualifier.required_signals: [has_user_generated_content, has_auth_surface]`
  - Chain: XSS-Sink → localStorage/sessionStorage → Token-Replay
- `AC-T-002` — Bulk Data Exfiltration via Broken Object Authorization
  - `scope_qualifier.required_signals: [has_auth_surface, has_role_concept]`
  - Chain: IDOR/missing-ownership-check → Mass-Enumeration → Data-Access
- `AC-T-003` — Privilege Escalation via Mass Assignment / JWT Confusion
  - `scope_qualifier.required_signals: [has_auth_surface]`
  - Chain: Unfiltered-Field-Write → Role-Elevation → Admin-Access

4. `scripts/resolve_org_profile.py`
   - `abuse_cases.add`-Glob auflösen und Dateien laden
   - Standard-Library einlesen wenn `inherit_defaults: true`
   - Deaktivierte IDs aus `disable[]` herausfiltern

5. `scripts/validate_org_profile.py`
   - Abuse-Case-YAMLs gegen `schemas/abuse-cases.schema.yaml` validieren
   - `grants`/`requires`-Konsistenz prüfen (jedes `requires` muss in einem vorherigen `grants` definiert sein)

---

### Phase 4 — Abuse Case Matching und Verifikation

**Ziel:** Deterministisches Matching (Chain-Template gegen findings[]) und aktive
Code-Verifikation (neuer Agent `appsec-abuse-case-verifier`).

**Arbeiten:**

1. **`scripts/match_abuse_cases.py` (NEU)**

   Deterministischer Matcher, kein LLM. Wird in Phase 10b aufgerufen, bevor der
   Triage-Validator seine LLM-Synthesephase startet.

   Algorithmus pro Abuse Case:
   - Scope-Qualifier prüfen (Recon-Signale + Path-Patterns)
   - Pro Step: `sink_patterns` gegen alle F-NNN aus `.findings-merged.json` matchen
     (nach Phase 1 umbenannt; bis dahin: `.threats-merged.json` mit `t_id`-Feld lesen)
     (CWE-Primär, Component, Evidence-File)
   - `grants`/`requires`-Graphvalidierung: Steps müssen lückenlos verkettbar sein
   - Verdict vorläufig berechnen (ohne Code-Verifikation):
     - Alle Required-Steps gematcht → `candidate`
     - Kein Required-Step gematcht → `not_applicable`
     - Partial → `partial_candidate`
   - Output: `.abuse-case-matches.json`

2. **`agents/appsec-abuse-case-verifier.md` (NEU)**

   Ein Agent pro Abuse Case — **nicht** ein Agent für alle Candidates. Exakt das
   STRIDE-Dispatch-Muster aus Phase 9: N Agents parallel, Wall-Clock = langsamster
   Einzelfall statt Summe.

   - **Modell:** Haiku
   - **Budget:** max. 15 Turns (ein Case, wenige Steps — kein 40-Turn-Budget nötig)
   - **Scope:** genau ein Abuse Case; gibt genau ein Verdict-Objekt zurück
   - **Input (als Env-Vars):**
     - `ABUSE_CASE_ID` — z.B. `AC-T-001`
     - `ABUSE_CASE_PATH` — Pfad zur Case-Definition (aus Org-Profil oder Standard-Library)
     - `MATCH_RESULT_PATH` — Pfad zum Case-Eintrag in `.abuse-case-matches.json`
     - `REPO_ROOT`, `OUTPUT_DIR`
   - **Aufgabe:** Pro Step des zugewiesenen Cases:
     - Entry-Point aus `probe.entry_points` suchen (Grep)
     - Sink-Pattern im Datenfluss vom Entry-Point nachverfolgen (Read + Grep)
     - Control-Pattern prüfen (`control_sufficiency: any|all` beachten)
     - Step-Verdict: `confirmed` / `blocked` / `inconclusive`
   - Wenn `probe.anchors[]` vorhanden: direkt File:Line prüfen statt suchen
     (Incremental-Optimierung nach erstem Run)
   - **Output:** `$OUTPUT_DIR/.abuse-case-verdict-<AC-ID>.json` (ein File pro Agent)

   Output-Schema pro Agent:
   ```json
   {
     "abuse_case_id": "AC-T-001",
     "step_verdicts": [
       {
         "step": 1,
         "verdict": "confirmed",
         "matched_finding_id": "F-048",
         "evidence": { "file": "...", "line": 119, "excerpt": "..." },
         "controls_found": []
       },
       {
         "step": 2,
         "verdict": "confirmed",
         "matched_finding_id": "F-046",
         "evidence": { "file": "...", "line": 13, "excerpt": "..." },
         "controls_found": []
       }
     ]
   }
   ```

   `verify_abuse_cases.py` merged die einzelnen `.abuse-case-verdict-*.json`-Files
   nach Abschluss aller Agents zu `.abuse-case-verdicts.json`.

3. **`scripts/verify_abuse_cases.py` (NEU)**

   Dispatcht einen `appsec-abuse-case-verifier`-Agent **pro Candidate parallel**,
   analog zum STRIDE-Dispatch in `phase-group-threats.md`. Wartet auf alle, merged
   Einzelergebnisse.

   ```bash
   # Pseudocode — Parallelisierung wie Phase-9-Dispatch
   candidates=$(python3 match_abuse_cases.py list-candidates --output-dir "$OUTPUT_DIR")
   for ac_id in $candidates; do
     Agent(appsec-abuse-case-verifier, env: ABUSE_CASE_ID=$ac_id, ...)  # parallel
   done
   wait_all
   python3 merge_abuse_case_verdicts.py --output-dir "$OUTPUT_DIR"
   ```

   **Budget-Guard:** wenn `.budget-critical` gesetzt vor dem ersten Dispatch →
   alle Candidates als `inconclusive` markieren, kein Agent dispatcht.
   Wenn `.budget-critical` während der parallelen Ausführung gesetzt wird:
   laufende Agents beenden sich selbst (analog zu STRIDE Budget-Critical-Handling),
   bereits abgeschlossene Verdicts bleiben erhalten.

4. **`agents/appsec-triage-validator.md`** — Phase-10b-Erweiterung:

   Nach Step 6 (Ranking — letzter bestehender Step, Zeile 99 in `appsec-triage-validator.md`)
   drei neue Schritte. Step 6 läuft deterministisch via `triage_compute_ranking.py`
   (`APPSEC_TRIAGE_DETERMINISTIC=1`, Zeile 77); die neuen Steps hängen an den Fast-Path an:

   **Step 7: Abuse Case Matching (deterministisch)**
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/match_abuse_cases.py" \
     --output-dir "$OUTPUT_DIR" \
     --org-profile "$ORG_PROFILE_PATH"
   # → .abuse-case-matches.json
   ```

   **Step 8: Abuse Case Verification (parallel Haiku-Agents)**
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/verify_abuse_cases.py" \
     --output-dir "$OUTPUT_DIR" \
     --repo-root "$REPO_ROOT"
   # Dispatcht N Agents parallel (ein Agent pro Candidate)
   # Wall-Clock ≈ langsamster Einzelfall (~2–3 min), nicht N × ~2 min
   # → .abuse-case-verdict-AC-T-001.json, .abuse-case-verdict-AC-T-002.json, ...
   # → .abuse-case-verdicts.json (merged)
   ```
   Nur ausführen wenn `.abuse-case-matches.json` mindestens einen `candidate` enthält.

   **Step 9: Verdict Finalisierung (deterministisch)**
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/match_abuse_cases.py" finalize \
     --verdicts "$OUTPUT_DIR/.abuse-case-verdicts.json"
   ```
   Berechnet finales Chain-Verdict aus Step-Verdicts:
   - Alle Required-Steps `confirmed`, keine Controls → `fully_viable`
   - Mind. ein Required-Step `confirmed` + mind. ein Control in anderem Step → `partially_blocked`
   - Alle Required-Steps haben Control → `mitigated`
   - Mind. ein Required-Step `inconclusive` → `inconclusive` (kein CI-Fail)

   **Step 10: CC-NNN Promotion**
   - Welche CC-NNN haben einen AC-NNN-Match? → `promoted_to: AC-NNN` markieren
   - Ihr `§8.C`-Block wird zum Stub reduziert (Link auf §9)

---

### Phase 5 — Report-Integration: §9 Abuse Cases

**Ziel:** Neue §9-Sektion im Report; CC-NNN Stub-Rendering; Critical Attack Tree Integration;
Nummernshift §9/§10/§11.

**Arbeiten:**

1. **`schemas/fragments/abuse-cases.schema.json` (NEU)**

   Fragment-Schema für den Composer. Der LLM (Renderer) authored dieses Fragment nicht —
   es wird deterministisch aus `.abuse-case-verdicts.json` erzeugt:

   ```json
   {
     "schema_version": 1,
     "abuse_cases": [
       {
         "id": "AC-T-001",
         "title": "...",
         "source": "mandatory",
         "verdict": "fully_viable",
         "combined_risk": "Critical",
         "actor_label": "...",
         "goal": "...",
         "prerequisite": "...",
         "chain_verdict_steps": [...],
         "matched_finding_ids": ["F-048", "F-046"],
         "promoted_from_chain": "CC-01",
         "blocking_mitigations": [...]
       }
     ]
   }
   ```

2. **`scripts/render_abuse_cases.py` (NEU)**

   Deterministisch. Liest `.abuse-case-verdicts.json` + `threat-model.yaml`,
   schreibt `.fragments/abuse-cases.md` und `.fragments/abuse-cases.json`.

   Report-Rendering pro AC-NNN:
   ```markdown
   ### <a id="ac-NNN"></a>AC-NNN — <Title>

   > **Source:** <mandatory: org-profile AC-T-001 | discovered>
   > **Actor:** <actor_label>
   > **Combined Risk:** <emoji> <level>
   > **Verdict:** <icon> <verdict_label>

   **Goal:** <goal>

   **Prerequisite:** <prerequisite>

   **Attack chain**

   | Step | Finding | Evidence | Outcome | Status |
   |------|---------|----------|---------|--------|
   | 1 | [F-048](#f-048) — <title> | `file:line` | <grants> | ✓/⚠/? |

   **Why combined risk exceeds individual ratings**
   <combined_risk_rationale>

   **Blocking mitigations**
   | Mitigation | Breaks chain at |
   |---|---|
   | [M-007](#m-007) — <title> | Step 1 |
   ```

3. **`scripts/compose_threat_model.py`**
   - `§9 Abuse Cases`-Sektion aus `.fragments/abuse-cases.md` einbinden
   - §9/§10/§11-Nummernshift
   - CC-NNN Stub-Rendering: wenn `promoted_to` gesetzt → nur eine Zeile +
     Link auf §9 statt vollem Block
   - Critical Attack Tree: wenn Leaf-Finding Teil eines AC ist →
     `[F-NNN · AC-NNN ①]`-Label

4. **`agents/appsec-threat-renderer.md`**
   - `§9 Abuse Cases`-Fragment nicht selbst authoren — deterministisch
   - Wissen um Nummernshift (§9→§10 Mitigation Register)
   - Keine Änderung an `ms-top-mitigations.json` oder Attack-Tree-Fragments nötig

5. **`agents/phases/phase-group-finalization.md`**
   - Fragment-Tabelle: neuer Eintrag `abuse-cases.json` + `abuse-cases.md`
   - §8.C Stub-Rendering-Regel dokumentieren
   - §9-Referenzen updaten

6. **`data/sections-contract.yaml`**
   - `threat_register.heading` (Zeile 1564): `"## 8. Threat Register"` → `"## 8. Finding Register"`
   - Neue Sektion `abuse_cases` zwischen `threat_register` und `mitigation_register` einfügen
   - `mitigation_register.heading` (Zeile 1594): `"## 9."` → `"## 10."` — Nummernshift
   - `out_of_scope.heading` (Zeile 1609): `"## 10."` → `"## 11."` — Nummernshift
   - Alle `§9`-Referenzen auf Mitigation Register in Agenten-Prompts anpassen

7. **`scripts/qa_release_gate.py`**
   - Release-Gate-Prüfung: wenn `abuse_case.verdict in release_gate.fail_on`
     und aktives Preset in `release_gate.applies_to_presets` → Exit 1

---

### Phase 6 — Incremental Mode + Stabilität

**Ziel:** Abuse Cases korrekt im Incremental-Zyklus; Anchor-Stabilität zwischen Runs.

**Arbeiten:**

1. **`scripts/baseline_state.py`**
   - `abuse_case_verdicts[]` in `baseline.json` speichern
   - Carry-Forward-Logik: wenn alle `matched_finding_ids` eines AC carried forward
     sind → Verdict carried forward (kein Re-Verify)
   - Wenn mindestens ein matched Finding re-analyzed → AC neu matchen und
     `verify_needed: true`

2. **`agents/appsec-threat-analyst.md`** — Incremental-Erweiterung:
   - Nach STRIDE-Carry-Forward-Entscheidung: Abuse-Case-Match-Status aus
     `baseline.json.abuse_case_verdicts[]` lesen
   - Wenn `verify_needed: true` → Phase 10b dispatcht Verifier für diesen AC

3. **Anchor-Persistenz AC-NNN:**
   - `reserve_ids.py abuse_case --count N` weist stabile AC-NNN zu
   - Matching-Fingerprint: `source + chain[].grants-Sequenz` — nicht Finding-IDs,
     da die sich bei Renames ändern könnten
   - Org-Profil-Cases behalten ihren definierten `id`; Discovered-Cases bekommen
     reservierte AC-NNN die stabil bleiben wenn Chain-Template unverändert

4. **`--check-abuse-case` CLI-Flag (NEU)**
   - Ruft deterministisch `match_abuse_cases.py` + `verify_abuse_cases.py` auf
   - Ohne vollständigen STRIDE-Run — setzt bestehendes `threat-model.yaml` voraus
   - Nützlich nach einem Fix: "Hat M-007 den Chain AC-T-001 tatsächlich unterbrochen?"

---

### Phase 7 — Tests, Migration, Dokumentation

**Arbeiten:**

1. **`scripts/migrate_finding_ids.py` (NEU)**
   - Liest Legacy `threat-model.yaml` mit `threats[]` und T-NNN
   - Schreibt `findings[]` mit F-NNN (1:1-Mapping T-001→F-001)
   - Wird als einmaliger Upgrade-Schritt bei erstem Run nach Plugin-Update aufgerufen

2. **Tests — Finding-Register-Rename (bestehende Tests anpassen)**

   Direkt betroffene Test-Dateien mit konkreten Änderungen:

   | Test-Datei | Änderung |
   |---|---|
   | `test_merge_threats.py` | `_write_stride(..., threats=[...])` → `findings=[...]`; `_threat()` → `_finding()`; alle `t_id`-Felder in Fixtures auf `f_id` |
   | `test_threats_merged_schema.py` | Fixtures in `valid_threats_merged.json`: `threats[]` → `findings[]`, `t_id` → `f_id`; alle parametrisierten Fehlerfälle (Zeilen 97–113) anpassen |
   | `test_qa_checks.py` | Zeile 75/100: `## 8. Threat Register` → `## 8. Finding Register` in Inline-Fixtures; Zeile 135 `test_t_id_re_matches` und Zeile 689 `test_t_id_re_no_false_positive` auf F-NNN-primär umstellen; Zeile 924 `## Threat Register` Fixture; Zeile 2107 Inline-MD-Fixture |
   | `test_compose_threat_model.py` | Zeile 299/331: `§8 Threat Register`-Heading-Fixtures auf `§8 Finding Register`; Zeile 394/395/411/423: `T-001`→`F-001` in Anchor/Chain-Map-Tests; alle `t_id`-Felder in Fixture-Dicts |
   | `test_export_sarif.py` | Zeile 131–134: `test_threat_id_canonical_and_legacy` → primär F-NNN, T-NNN als legacy-compat; Zeile 66: `threat_ids` → `finding_ids` in Mitigation-Fixture; Zeile 473–474: Rule-IDs auf F-NNN |
   | `test_reserve_ids.py` | Zeile 65/78/86: `next_threat_id` → `next_finding_id`; neuer Test für `abuse_case` ID-Typ |
   | `test_triage_compute_ranking.py` | Zeile 71/82/109/122/135: `t_id`-Felder in Minimal-YAML-Fixtures auf `f_id`; `threats[]` → `findings[]` in `_minimal_yaml()` |
   | `test_contract_integrity.py` | Erwartet §8 "Finding Register", §9 "Abuse Cases", §10 "Mitigation Register", §11 "Out of Scope" nach Nummernshift |
   | `test_agent_definitions.py` | Neuer Agent `appsec-abuse-case-verifier` in `AGENT_BUDGETS` (max. 15 Turns) und `PIPELINE_AGENTS` eintragen; `model: sonnet` im Frontmatter (Contract-Gate) aber `haiku`-Dispatch-Override |
   | `test_aggregate_threat_summary.py` | Zeile 237: `## Consolidated Finding Register` — schon korrekt; prüfen ob andere Stellen `Threat Register` hardcoded haben |

3. **Tests — Neue Abuse-Case-Funktionalität (neue Test-Dateien)**

   | Test-Datei | Was getestet wird |
   |---|---|
   | `tests/test_match_abuse_cases.py` (NEU) | Unit-Tests für deterministischen Matcher: scope_qualifier-Filterung, CWE/sink-Pattern-Matching, `grants`/`requires`-Graphvalidierung, Candidate/not_applicable-Verdict-Ausgabe |
   | `tests/test_abuse_case_verdicts.py` (NEU) | Verdict-Finalisierung: alle Required-Steps confirmed → `fully_viable`; partial Controls → `partially_blocked`; inconclusive propagation; `mitigated` wenn alle Steps blocked |
   | `tests/test_abuse_cases_schema.py` (NEU) | Schema-Validierung für `schemas/abuse-cases.schema.yaml`: valide Cases durch, Pflichtfelder fehlen, ungültige `grants`/`requires`-Referenzen, release_gate-Werte |
   | `tests/test_org_profile_schema.py` | Bestehende Datei — neue Test-Cases für `abuse_cases.inherit_defaults`, `abuse_cases.disable[]`, `abuse_cases.add`-Glob |
   | `tests/test_resolve_org_profile.py` | Bestehende Datei — neue Test-Cases: Standard-Library geladen wenn `inherit_defaults: true`; disable-Liste filtert korrekt |
   | `tests/test_e2e_pipeline.py` oder `test_full_run_e2e.py` | Neuer E2E-Test-Case: Juice-Shop-Fixture → `§9 Abuse Cases`-Sektion vorhanden, AC-T-001 Verdict korrekt, CC-01 als Stub promoted |

4. **`docs/org-profiles.md`**
   - Neue Sektion "Abuse Cases" mit vollständigem YAML-Beispiel für eigenen Case
   - Erklärung `grants`/`requires`-Logik und `scope_qualifier`
   - `release_gate`-Konfiguration und CI-Exit-Code-Verhalten
   - `probe.anchors[]` — Incremental-Optimierung nach erstem Run

5. **`README.md`**
   - Zeile 173: "STRIDE findings, evidence links, mitigation register" →
     "STRIDE findings, evidence links, abuse case scenarios, mitigation register"
   - Neue Zeile im "What it checks"-Abschnitt:
     `| **Abuse Cases** | Scenario-level attack chains verified against the codebase — end-to-end paths from entry point through exploitation to impact, with per-step verdicts and CI release gates. |`
   - Zeile 30: "Findings keep stable IDs" — bereits korrekt, keine Änderung nötig

6. **`AGENTS.md`**
   - `§4b` (Zeile 86): `canonical fields are id/title/threat_ids/priority` →
     `threat_ids` → `finding_ids`
   - `§4c` (Zeile 87): `components[].threat_ids[]` → `finding_ids[]`
   - `§4e` (Zeile 89): `threats with evidence.file` → `findings with evidence.file`
   - Zeile 94: "Threat IDs such as `T-NNN`" → "Finding IDs such as `F-NNN`"
   - Zeile 122: "T-ID stability" → "F-ID stability"
   - Zeile 291: "T-ID stability" → "F-ID stability"
   - Neue Zeile im "Read First"-Block (nach Zeile 19):
     "Abuse Case definitions in the org profile (`abuse-cases/*.yaml`) feed
     `match_abuse_cases.py` and the `appsec-abuse-case-verifier` agent — treat
     them with the same contract discipline as schemas."
   - Neue Zeile in der Pipeline-Agenten-Tabelle (Zeile 315):
     `| appsec-abuse-case-verifier | schema/output contract, probe patterns, budget ceiling |`

7. **`CHANGELOG.md`** — Breaking Changes:
   - `threats[]` → `findings[]` in allen Intermediates und Output-YAML
   - `t_id` → `f_id` als primäres ID-Feld in `.findings-merged.json`
   - §9 Abuse Cases neu; §9/§10 Mitigation Register und §10/§11 Out of Scope verschieben sich
   - Migration: `scripts/migrate_finding_ids.py` für bestehende `threat-model.yaml`-Dateien

---

## Contract Gates und Report-Verlinkung — vollständige Bestandsaufnahme

### Betroffene Gates in `qa_checks.py`

Diese Stellen hard-failen oder produzieren falsche Fehler wenn Phase 2 nicht vollständig umgesetzt ist:

| Gate / Funktion | Zeile | Problem | Phase-2-Fix |
|---|---|---|---|
| `T_ID_RE = re.compile(r"\bT-(\d{3,4})\b")` | 86 | Erkennt T-NNN als gültige IDs; nach Rename kein T-NNN mehr im Report | Als `_LEGACY_T_ID_RE` behalten, nur noch für Dual-Anchor-Check |
| `TABLE_ID_RE` Pattern `[TM]-\d+` | 90 | Erkennt T-NNN als Threat-Register-Zeilen | Pattern auf `[FM]-\d+` erweitern |
| `check_xrefs()` — `defined_t` aus `TABLE_ID_RE` | 403–418 | `orphaned-threat-ref` auf T-NNN; nach Rename würde jeder F-NNN-Report als broken gelten | `defined_t` → `defined_f`; Fehlermeldung auf "Finding Register row" |
| `_inject_row_anchors()` Zeile 446: `"# Threat Register rows: inject <a id=\"t-nnn\">"` | 435–455 | Injiziert `<a id="t-nnn">` in §8-Rows; muss zusätzlich `<a id="f-nnn">` emittieren (Dual-Anchor) | Inject beide Anchors gleichzeitig |
| `_collect_threat_register_t_ids()` — regex `r"^##\s+8\.\s+Threat\s+Register\b"` | 5154–5170 | Findet §8-Body nur über "Threat Register"-Heading | Heading-Pattern auf "Finding Register" (primary) + "Threat Register" (legacy-compat) |
| `_extract_h2_section_body()` calls mit Literal `"## 8. Threat Register"` | 605, 615, 628 | Abschnittserkennung bricht | Beide Heading-Varianten akzeptieren |
| `check_chain_tid_consistency()` — prüft T-NNN in Attack-Tree-Nodes gegen §8 | 5081–5106 | Nach Rename sind Leaves F-NNN, nicht T-NNN | Auf F-NNN als primary umstellen |
| STRIDE-Coverage-Check (Zeile 977): `"Threat Register Total"` im Fehlertext | 977 | Nur Text, kein Hard-Fail — aber irreführend | Text auf "Finding Register" updaten |

### Betroffene Anchor-Links in `compose_threat_model.py`

Alle folgenden Stellen generieren Links die nach dem §9-Nummernshift ins Leere zeigen. **Müssen atomar in Phase 5 geändert werden** (nie schrittweise — sonst ist der Report kurzzeitig inkonsistent):

| Zeile | Aktueller Anchor | Nach Phase 5 |
|---|---|---|
| 6243 | `#9-mitigation-register` | `#10-mitigation-register` |
| 6266 | `#9-mitigation-register` | `#10-mitigation-register` |
| 6594 | `#9-mitigation-register` | `#10-mitigation-register` |
| 6768 | `#8-threat-register` + `#9-mitigation-register` | `#8-finding-register` + `#10-mitigation-register` |
| 7480 | `#8-threat-register` | `#8-finding-register` |
| 9889 | `#8-threat-register` | `#8-finding-register` |
| 10963 | `#9-mitigation-register` (short-form `#9`) | `#10-mitigation-register` |
| 11623 | `#8-threat-register` | `#8-finding-register` |

Zusätzlich: `_render_threat_register` (Zeile 1164 ff.) erzeugt intern den §8-Block — Funktionsname bleibt, aber alle generierten Heading-Texte und Anchors updaten.

### Betroffene Agenten-Prompts (Verlinkungslogik)

Diese Stellen beeinflussen was der LLM in generierten Report-Abschnitten schreibt:

| Datei | Zeile(n) | Problem |
|---|---|---|
| `phase-group-threats.md` | 750, 886 | `## 8. Threat Register` als Heading-Beispiel für generierten Report |
| `phase-group-threats.md` | 1040 | `[§8 Threat Register](#8-threat-register)` im Critical-Attack-Tree-Beispiel |
| `phase-group-threats.md` | 1051, 1056 | `#8-threat-register` Anchor + `§9 Mitigation Register` |
| `phase-group-threats.md` | 1354 | "Threat Register" als Referenz-Abschnitt für Label-Konsistenz-Regel |
| `phase-group-finalization.md` | 452–453 | Fragment-Tabelle nennt `§8 Threat Register`, `§9 Mitigation Register`, `§10 Out of Scope` |
| `phase-group-finalization.md` | 697 | Critical-Attack-Tree: "linking each leaf to its §8 Threat Register row" + "mitigations live in §9" |
| `phase-group-finalization.md` | 718 | Kanonische Nummernliste: `8 Threat Register, 9 Mitigation Register, 10 Out of Scope` |
| `phase-group-finalization.md` | 916 | `§8 Threat Register, §9 Mitigation Register, §10 Out of Scope` |
| `appsec-qa-reviewer.md` | 172 | `§9 Addresses line` — zeigt auf altes §9 |
| `appsec-qa-reviewer.md` | 175 | `T-NNN in Findings pointer` + `§8 row` → beide Patterns anpassen |
| `appsec-qa-reviewer.md` | 197 | `T-xxx exists in YAML but not in Threat Register` |
| `appsec-qa-reviewer.md` | 275 | `## 8. Threat Register` als erwartetes Heading in Contract-Table |
| `appsec-qa-reviewer.md` | 279 | `## 8. Threat Register` als Present-Check |
| `appsec-qa-reviewer.md` | 288 | `§8 Threat Register and §9 Mitigation Register` in MS-Generation-Fallback |
| `appsec-qa-reviewer.md` | 357 | `T-NNN in §8 rows + M-NNN above §9 headings` — linkify_anchors-Beschreibung |
| `appsec-qa-reviewer.md` | 395, 411 | `§9` als Mitigation-Register-Referenz |
| `appsec-threat-renderer.md` | 182, 234 | `§8 Threat Register` + `§9` in Prose-Regeln |

### Atomare Änderungspakete

Die obigen Stellen können nicht unabhängig geändert werden — sie müssen in zwei atomaren Paketen deployed werden:

**Paket A (Phase 2) — F-NNN als kanonische ID, §8 Finding Register:**
Alle `qa_checks.py`-Gates + alle `compose_threat_model.py`-Stellen mit `#8-threat-register` + alle Agenten-Prompts mit "Threat Register"-Heading-Referenz. Ein Report der F-NNN enthält muss nach diesem Paket ohne QA-Fehler durchlaufen.

**Paket B (Phase 5) — §9 Abuse Cases + Nummernshift:**
Alle `#9-mitigation-register` → `#10-mitigation-register` in `compose_threat_model.py` + alle `§9`-Referenzen in Agenten-Prompts + `sections-contract.yaml` Nummernshift. Darf erst deployed werden wenn `render_abuse_cases.py` die neue §9 befüllt — sonst hat der Report eine leere §9.

---

## Inhaltliches Zusammenspiel (Querschnitt)

### Drei-Ebenen-Modell im Report

```
F-NNN Finding        atomare, evidenz-belegte Beobachtung (§8 Finding Register)
   ↑ referenced by
CC-NNN Chain         strukturelle Verkettung, Keystone/Contributor (§8.C)
   ↑ promoted to
AC-NNN Abuse Case    narratives Szenario mit Verdict + Verifikation (§9)
```

Jede Ebene hat eine einzige kanonische Darstellung. Ein Chain der zu einem Abuse Case
promoted wird, hat keinen eigenen Prose-Block mehr in §8.C — nur einen Stub.

### Verlinkung zwischen Sektionen

| Von | Nach | Form |
|---|---|---|
| MS Worst Case Scenarios | §9 AC-NNN | `[AC-NNN](#ac-NNN)` Bullet |
| Critical Attack Tree Leaf | §8 F-NNN + §9 AC-NNN | `[F-NNN · AC-NNN ①]` Label |
| §3 Walkthrough | §8 F-NNN | `**Source:** [F-NNN](#f-nnn)` |
| §8.C CC-NNN (promoted) | §9 AC-NNN | `→ Promoted to [AC-NNN](#ac-nnn)` |
| §9 AC-NNN Step | §8 F-NNN | `[F-NNN](#f-nnn) — <title>` in Chain-Tabelle |
| §9 AC-NNN Blocking Mitigation | §10 M-NNN | `[M-NNN](#m-nnn) — <title>` |
| §3 Walkthrough | §9 AC-NNN (optional) | `**Part of:** [AC-NNN](#ac-nnn)` wenn Step dieses Walkthroughs |

### Verifier-Ergebnis und Report-Narrative

Das `step_verdict` aus dem Verifier bestimmt direkt die Report-Darstellung:

| Step-Verdict | Tabellen-Icon | Bedeutung |
|---|---|---|
| `confirmed` + keine Controls | ⚠ | Schritt ausführbar, kein Schutz |
| `confirmed` + Controls gefunden | ◐ | Schritt teilweise geblockt |
| `blocked` | ✓ | Schritt durch Control unterbrochen |
| `inconclusive` | ? | Nicht eindeutig verifizierbar |

Das Chain-Verdict ist deterministisch aus Step-Verdicts abgeleitet und nie vom LLM
"bewertet" — das macht es auditierbar und diff-bar zwischen Runs.

### SARIF und Pentest Tasks

- SARIF: Abuse Cases werden **nicht** als SARIF-Rules exportiert — sie sind
  Szenarien, keine atomaren Findings. Der SARIF-Export bleibt finding-granular (F-NNN).
  `export_sarif.py` ergänzt optional `tags: ["ac-NNN"]` auf betroffenen Rules,
  damit SARIF-Consumer die Chain-Zugehörigkeit sehen.

- Pentest Tasks: `render_pentest_tasks.py` erhält neuen `--include-abuse-cases`-Flag.
  Wenn gesetzt, werden AC-NNN mit `detail_level: full` und `pentest_guidance`-Block
  als separate Task-Sektion "Scenario Verification" vorangestellt — vor den atomaren
  Finding-Tasks.

---

## Umsetzungsreihenfolge und Abhängigkeiten

```
Phase 1 (Datenmodell)
  └──→ Phase 2 (Report/Contracts)       ← kann parallel mit Phase 3 starten
         └──→ Phase 5 (§9 Report)
Phase 3 (Abuse Case Schema)
  └──→ Phase 4 (Matching + Verifikation)
         └──→ Phase 5 (§9 Report)
                └──→ Phase 6 (Incremental)
                       └──→ Phase 7 (Tests/Migration/Docs)
```

Phase 1 und 3 sind unabhängig voneinander startbar. Phase 5 hängt von beiden ab.
Phase 2 kann früh parallel laufen und liefert den sichtbaren Zwischenstand
(§8 Finding Register ohne §9 Abuse Cases) als eigenständig nutzbares Artefakt.
