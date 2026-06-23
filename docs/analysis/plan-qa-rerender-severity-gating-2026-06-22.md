# QA Re-Render: Severity-Gating (blocking vs cosmetic)

**Datum:** 2026-06-22
**Status:** UMGESETZT 2026-06-22 (qa_checks.py + SKILL-impl.md + Tests + CHANGELOG; uncommitted)
**Ziel:** Re-Render-Loop nur bei echten Defekten auslösen, nicht bei kosmetischen
Befunden. Kosmetik wird weiterhin sichtbar gemacht (Warnings), aber verbrennt
keine Loop-Iterationen (Fragment-Fixer-Dispatch + Recompose, LLM, ~Minuten).

---

## 1. Ist-Zustand (verifiziert im Code)

Vor jedem Agent-Dispatch läuft deterministisch:

```bash
python3 scripts/qa_checks.py repair_plan threat-model.md $OUTPUT_DIR
GATE_EXIT=$?
```

`cmd_repair_plan` (qa_checks.py:2413) → Exit-Code steuert den Skill-Flow
(SKILL-impl.md ~3280–3550):

| Exit | `status`        | Skill-Aktion |
|------|-----------------|--------------|
| 0    | `pass`          | kein Re-Render |
| 1    | `fail`          | **Re-Render-Loop** (apply_repair_plan → fragment-fixer → recompose), max 3 Iter. |
| 2    | (Tool-Fehler)   | QA-Agent als Fallback |
| 3    | `manual_review` | Loop übersprungen, einmal QA-Agent (kein Fragment kann's fixen) |

**Die einzige Schwelle** (`_classify_plan_status`, qa_checks.py:2405):

```python
actionable = any(a.get("fragments_to_rewrite") for a in actions)
if not issues:            return "pass", actionable          # exit 0
if actions and not actionable: return "manual_review", actionable  # exit 3
return "fail", actionable                                    # exit 1 → Re-Render
```

**→ Es gibt keinerlei Severity-Unterscheidung.** Sobald *irgendeine* Aktion ein
nicht-leeres `fragments_to_rewrite` trägt, ist es Exit 1 → Re-Render. `thorough`
verschärft das, weil `QA_DEPTH=extended` *mehr* dieser Checks scharfschaltet und
zusätzlich Stage 4 (Architect-Review, eigener Loop) aktiviert.

---

## 2. Alle Re-Render-treibenden Action-Typen + Vorschlag

Nur Typen mit nicht-leerem `fragments_to_rewrite` treiben heute den Loop (Exit 1).
Typen mit leerem `fragments_to_rewrite` (infobox, posture_*, placeholders,
yaml_md_consistency) gehen schon heute auf `manual_review`/Exit 3 — **nicht
Gegenstand dieser Änderung.**

| # | `type` | Check / Befund | Heute | **Vorschlag** | Begründung |
|---|--------|----------------|-------|---------------|------------|
| 1 | `mermaid_syntax` | ungültiger Mermaid-Block | Loop | **blocking** | bricht Diagramm-Render |
| 2 | `toc_nested_link` | Link in §3-Heading | Loop | **blocking** | bricht §3-TOC |
| 3 | `auth_method_decomposition` | §7.2 IAM nicht nach Mechanismus zerlegt | Loop | **blocking** | §7-Contract-Struktur |
| 4 | `validation_approach_first` | §7.6 öffnet nicht mit Approach-Block | Loop | **blocking** | §7-Contract-Struktur |
| 5 | `control_subsection_coverage` | §7.x H4-Control-Shape fehlt | Loop | **blocking** | §7 v2 Contract |
| 6 | `missing_required_subsection` | Pflicht-Subsection fehlt | Loop | **blocking** | Contract |
| 7 | `missing_section` | ganze Sektion fehlt | Loop | **blocking** | Contract |
| 8 | `forbidden_ms_heading` | unerlaubtes MS-`###` | Loop | **blocking** | MS-Struktur |
| 9 | `table_schema_drift` | Tabellen-Spalten ≠ Contract | Loop | **blocking** | Datendarstellung falsch |
| 10 | `walkthrough_coverage` | Critical-Walkthrough fehlt ganz | Loop | **blocking** | echte Inhalts-Lücke |
| 11 | `unclassified` | unbekannter Befund | Loop | **blocking** | sicherer Default |
| 12 | `section_order_drift` | Sektion in falscher Reihenfolge | Loop | **blocking** | i.d.R. reiner Recompose, billig |
| 13 | `required_subsection_order_drift` | Subsection-Reihenfolge | Loop | **blocking** | Contract-Order |
| 14 | `relevant_findings_bullet_list` | inline statt Bullet-Liste `**Relevant findings**` | Loop | **cosmetic** | rein darstellerisch (Entscheidung User) |
| 15 | `chain_tid_consistency` | Chain-Node zitiert „falsches" T-NNN (Keyword-Heuristik) | Loop | **blocking** | falsche T-ID-Referenz = Korrektheit (Entscheidung User) |
| 16 | `walkthrough_depth` | §3.x-Body kürzer als Schwelle / fehlendes alt/else / 3-Node-Stub | Loop | **cosmetic** | Inhalts-Dünne, keine Korrektheit |
| 17 | `chain_compactness` | §3.1-Chain >6 Nodes / Layout-Keyword | Loop | **cosmetic** | reine Lesbarkeit |
| 18 | `diagram_compactness` | §2.3/§2.4-Diagramm >7 Nodes | Loop | **cosmetic** | reine Lesbarkeit |
| 19 | `recon_iam_bridge` | Recon-MFA-Evidenz fehlt in §7 | Loop | **cosmetic** | Inhalts-Hinweis (Entscheidung User) |

**Borderline-Entscheidungen (2026-06-22 final):**
- **#14 `relevant_findings_bullet_list` → cosmetic** (User: „inline vs Bullet" trivial).
- **#15 `chain_tid_consistency` → blocking** (User: falsche T-ID-Referenz ist kritisch).
- **#19 `recon_iam_bridge` → cosmetic** (User).

**`COSMETIC_ACTION_TYPES` (Code, qa_checks.py):** `diagram_compactness`,
`chain_compactness`, `walkthrough_depth`, `relevant_findings_bullet_list`,
`recon_iam_bridge`. Alles andere = blocking.

---

## 3. Umsetzung (Severity-Feld + Loop-Gate — gewählter Ansatz)

### 3a. Producer: `qa_checks.py`

1. **Zentrale Map** statt verstreuter Strings:
   ```python
   COSMETIC_ACTION_TYPES = frozenset({
       "diagram_compactness", "chain_compactness",
       "walkthrough_depth", "chain_tid_consistency", "recon_iam_bridge",
   })  # exakte Menge nach deiner Freigabe von #14/#15/#19
   ```
2. Jede `actions.append({...})` bekommt:
   ```python
   "severity": "cosmetic" if a_type in COSMETIC_ACTION_TYPES else "blocking",
   ```
   (Eine Hilfsfunktion `_severity_for(type)` statt 19× Hand-Edit; setzt das Feld
   nachträglich in der Dedup-Schleife bei 2351 für alle Aktionen.)
3. **Gate umschreiben** (`_classify_plan_status`, 2384):
   ```python
   blocking = any(a.get("fragments_to_rewrite")
                  and a.get("severity") != "cosmetic" for a in actions)
   cosmetic = any(a.get("fragments_to_rewrite")
                  and a.get("severity") == "cosmetic" for a in actions)
   if not issues:                       return "pass", blocking
   if blocking:                         return "fail", blocking          # exit 1
   if cosmetic:                         return "cosmetic_advisory", blocking  # NEU → exit 4
   return "manual_review", blocking                                      # exit 3
   ```
4. **`cmd_repair_plan`** (2413): neuer Branch
   ```python
   if plan["status"] == "cosmetic_advisory":
       plan_path.write_text(...)   # Plan ERHALTEN für Surfacing
       return 4
   ```
   Plan-Datei bleibt liegen (anders als `pass`, das sie löscht) → Completion-
   Summary kann die Kosmetik-Advisories anzeigen.

### 3b. Consumer: `SKILL-impl.md` Re-Render-Loop (~3280–3330)

Neuer Exit-Branch neben 0/1/2/3:
```
GATE_EXIT == 4 → cosmetic_advisory:
   - KEIN Re-Render, KEIN Fragment-Fixer.
   - .qa-status.json: status="pass" + cosmetic_advisories[] aus .qa-repair-plan.json.
   - Banner: "N kosmetische QA-Hinweise (kein Re-Render)" + Liste.
   - Loop-Exit wie bei pass.
```

### 3c. Opt-out (Repo-Muster, optional)

`APPSEC_QA_COSMETIC_BLOCKING=1` → `COSMETIC_ACTION_TYPES = frozenset()` zur
Laufzeit, d.h. altes Verhalten (alles blocking). Default = neues Verhalten.

### 3d. Contract-Pflichten (AGENTS.md §4 — bidirektional)

- [ ] `qa_checks.py` — severity-Feld + Gate + Exit 4 (Producer)
- [ ] `SKILL-impl.md` — Exit-4-Branch (Consumer)
- [ ] `data/required-permissions.yaml` — prüfen, ob neuer Pfad/Befehl nötig (vmtl. nein)
- [ ] Repair-plan-Schema (falls vorhanden) — `severity` + `status: cosmetic_advisory` zulassen
- [ ] Tests: `_classify_plan_status` (blocking-only→fail, cosmetic-only→cosmetic_advisory,
      mixed→fail, empty-fragments→manual_review), `cmd_repair_plan` Exit-4,
      Opt-out-Env. Drift-Guard für SKILL-impl Exit-Branch.

---

## 4. Wirkung & Risiko

- **Thorough profitiert am meisten:** genau die `extended`-Checks (#15–#19) sind
  die kosmetischen — Re-Render fällt künftig nur bei Render-/Contract-/Inhalts-
  Defekten an.
- **Kein stilles Verschlucken:** Kosmetik bleibt im Plan + Completion-Summary
  sichtbar (Exit 4, Plan-Datei erhalten).
- **„Fix the producer" bleibt intakt:** wir relaxen kein Schema, wir patchen
  nichts downstream — wir stufen nur die Loop-Auslösung ab.
- **Risiko niedrig:** rein in der Gate-Klassifizierung; Default-Verhalten per
  Env umkehrbar; Borderline-Fälle explizit dir zur Freigabe vorgelegt.
- **Nicht abgedeckt:** Stage-4 Architect-Repair-Loop (`.architect-repair-plan.json`)
  ist ein separater Mechanismus. Falls dort dasselbe Severity-Gating gewünscht
  ist → eigener Folge-Schritt.

---

## 5. Entscheidungen (2026-06-22, final & umgesetzt)

1. Borderline: #14 cosmetic, #15 blocking, #19 cosmetic.
2. **Exit-Code 4** (`cosmetic_advisory`) — Plan-Datei bleibt fürs Surfacing.
3. **Opt-out-Env `APPSEC_QA_COSMETIC_BLOCKING=1`** umgesetzt.

## 6. Verifikation

- `tests/test_qa_checks_cov_band1.py`: `_action_severity` (cosmetic/blocking/env-
  override), `_classify_plan_status` (cosmetic-only→`cosmetic_advisory`+
  actionable False, mixed→fail, no-severity→blocking-default), `cmd_repair_plan`
  cosmetic-only→Exit 4 + Plan-Erhalt.
- Subset grün: `test_qa_checks_cov_band1` / `test_qa_checks` / `test_apply_repair_plan`
  (314 passed, 1 skipped) + Regression `test_skill_auto_retry` /
  `test_compose_threat_model_cov2` / `test_check_inline_shortcut` (211 passed).
- ruff clean. Bestehende `_classify_plan_status`-Tests unverändert grün
  (Rückwärtskompatibilität: Aktion ohne `severity` = blocking).
