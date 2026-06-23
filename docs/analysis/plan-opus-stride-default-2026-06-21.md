# Umsetzungsplan: Opus als Default für STRIDE-Reasoning (außer `quick`)

Status: **PLAN — NICHT umgesetzt. Code-Claims verifiziert 2026-06-21** (file:line +
Konsumenten gegen `scripts/resolve_config.py` geprüft; Korrekturen eingearbeitet). Folgt
der Empfehlung aus
[`analysis-model-placement-orchestrator-vs-stride-2026-06-21.md`](analysis-model-placement-orchestrator-vs-stride-2026-06-21.md).

Ziel: **Vereinheitlichte Verwendung von Opus für die Reasoning-Phase** (STRIDE/Triage/
Merge) bei `standard`/`thorough`. `quick` bleibt auf Sonnet (bewusst flacher Modus). Der
größen-getriggerte Auto-Downgrade auf alles-Sonnet entfällt.

---

## 0. Entscheidung / Scope

- **„Opus für STRIDE" = der volle `opus`-Tier** (stride **+ triage + merger** auf Opus).
  Begründung: Kalibrierungsgewinn kommt aus `triage=opus`, Kostenersparnis aus
  `stride=opus` — nur zusammen ergeben sie das gemessene V3-Ergebnis (besser **und** auf
  großen Repos billiger). Ein „nur-stride"-Tier würde die Kalibrierung halb liegen lassen
  und einen neuen, unnötigen Tier einführen.
- **`quick` unangetastet:** bleibt `sonnet-economy` (reduzierte STRIDE-Tiefe, Sonnet
  passt). Sonnet-STRIDE ist nur dort + bei explizitem Opt-out legitim.
- **Vereinheitlichung = flach, nicht size-adaptiv:** Default flach `opus` für
  standard/thorough, **kein** automatischer Größen-Switch mehr. Kleine Repos kosten etwas
  mehr — bewusster Trade-off zugunsten Einheitlichkeit + Qualität; Opt-out via
  `--reasoning-model sonnet-economy` / `--max-cost`. (Die size-adaptive *Inversion* —
  klein→economy, groß→opus — ist als optionale Phase 4 vermerkt, nicht Teil des
  Kern-Plans.)

---

## 1. Verifikations-Gate (Phase 0 — empfohlen, nicht zwingend)

Die Kosten-Inversion ist **N=1** (nur Juice-Shop, großes Repo). Vor dem flachen Flip
empfohlen: **Stufe-0-Matrix** auf 1 kleinem + 1 mittleren Repo, je
`sonnet-economy` / `opus-cheap` / `opus`. Liefert:
- den fehlenden `opus-cheap`-Datenpunkt (isoliert, ob STRIDE-auf-Sonnet der Kostentreiber
  ist oder triage/merger),
- ob die Kosten-Inversion auf kleinen Repos kippt (erwartet: ja → bestätigt den
  Opt-out-Bedarf, nicht die Richtung),
- echte Opus-Standard-**Wall-Zeit** (V3 war idle-kontaminiert) → Eingang für die
  Duration-Rekalibrierung in Phase 3.

Entscheidungsregel: Die **Richtung** (Opus-Reasoning als Default) hängt **nicht** vom
Ergebnis ab — sie ist durch Qualität (Kalibrierung/Evidenz/Fläche) getragen. Stufe 0
kalibriert nur Magnitude + Duration. Wer das Gate überspringen will, kann direkt zu
Phase 2; dann Phase 3 mit konservativer Schätzung statt Messung.

---

## 2. Kern-Änderung (Producer: `scripts/resolve_config.py`)

### 2a. Default-Tier umstellen
`resolve_reasoning_model` (~Z. 498-501): `standard`/`thorough`-Default
`"opus-cheap"` → `"opus"`. `quick` bleibt `"sonnet-economy"`.

```
elif depth == "quick":
    mode = "sonnet-economy"
else:
    mode = "opus"          # war: "opus-cheap"
```

### 2b. Größen-Downgrade entfernen  *(verifiziert 2026-06-21)*
`resolve_default_tier_for_capped_repos` (B2d, Z. 415) + Aufrufstelle **Z. 1508**
(`cfg.update(resolve_default_tier_for_capped_repos(cfg, ns))`) **entfernen**. Mit neuem
Default `opus` würde B2d ohnehin no-op'en (Guard `!= "opus-cheap"`), aber als toter Pfad
mit falscher Philosophie raus.

- `resolve_repo_size_cap` (Z. 373) **behalten**, aber nur noch **label-informativ**
  (`repo_size_capped`, `repo_size_source_files`, `depth_label`-Marker). Es reduziert
  ohnehin keine Komponenten (Kommentar Z. 383-385). **Hinweis:** der B2d-Docstring Z. 433
  („the large-repo cap reduces MAX_STRIDE_COMPONENTS to 3") ist **stale** — kein Code
  reduziert das; `max_stride_components` = `STRIDE_COMPONENT_CEILING = 10` (Z. 209/298),
  depth-unabhängig. Entfällt mit B2d.
- **Verifiziert: `repo_size_capped` hat 3 Konsumenten, ALLE reine Anzeige** (kein
  Verhalten) → Entfernen von B2d ist verhaltens-sicher. ABER beide Anzeige-Notes sagen
  „→ economy reasoning tier" und werden nach der Umstellung **falsch** → Text mitändern:
  - `scripts/resolve_config.py:2196` (Config-Summary-Note)
  - `scripts/resolve_config.py:2536` (Post-Summary-Note) ← *im ersten Plan übersehen*
  - `skills/create-threat-model/SKILL-impl.md:1171` (Label-String)
  Neue Aussage z.B.: „Large repo (<N> source files) → längerer Lauf erwartet; Reasoning
  bleibt auf dem Default-Opus-Tier (alle kriterien-selektierten Komponenten analysiert)."
- `reasoning_auto_switched`: wird nicht mehr gesetzt (nur in B2d, Z. 471). Einziger Leser
  ist **`scripts/resolve_config.py:2359`** (display-only, `_format_reasoning_summary`) →
  wird toter Branch → mit entfernen.
- **Bestehender „alles→Sonnet"-Opt-out bleibt erhalten:** `--no-opus` / `opus_disabled`
  (Resolver ~Z. 609 „Opus→Sonnet ceiling", Anzeige Z. 2358). Nach der Umstellung ist das
  der saubere Weg, den neuen Opus-Default komplett auf Sonnet zu zwingen — neben
  `--reasoning-model sonnet-economy`.

### 2c. `opus-cheap` von Default zu reinem Opt-in
`opus-cheap` in `MODEL_MATRIX` **behalten** (explizites `--reasoning-model opus-cheap`
bleibt gültig für Nutzer, die den Mittelweg wollen), aber es ist **kein Default** mehr.
Kommentar an `MODEL_MATRIX["opus-cheap"]` ergänzen: „explicit opt-in only; not any
depth's default since 2026-06 — see analysis-model-placement". Kein hartes Deprecation,
keine Entfernung (vermeidet Breaking Change für bestehende Skripte/`--reasoning-model`).

---

## 3. Mitlaufende Contracts (bidirektional, AGENTS.md §4)

### 3a. Tests (Pflicht — pinnt heutige Defaults/Labels)
Betroffene Dateien mit **verifizierten** Treffer-Zahlen (2026-06-21, Regex
`opus-cheap|sonnet-economy|repo_size_capped|reasoning_auto_switched|"opus"|reasoning_model`):
- `tests/test_resolve_config.py` — **56 Treffer** (nicht ~33) — Default- und
  Label-Assertions umstellen; B2d-Tests entfernen/anpassen. **Größter Aufwandsposten.**
- `tests/test_reasoning_model_resolution.py` — **31** — Default-Resolution
  standard/thorough (`opus-cheap` → `opus`).
- `tests/test_haiku_routing_per_depth.py` — **24** — extended-routing bleibt unverändert
  (Haiku-Scanner sind tier-unabhängig), aber Default-Tier-Annahmen prüfen.
- `tests/test_estimate_duration.py` — **4** — Anker/Model-Factor (Phase 3b).
- `tests/test_render_completion_summary.py` — **5** — Reasoning-Label-Anzeige
  (inkl. des toten `reasoning_auto_switched`-Branches, falls dort getestet).

Richtung pro Cluster bewusst wählen (Test-vs-Code): Default-Flip = Code führt, Tests
nachziehen; aber prüfen, ob ein Test eine *Invariante* schützt (dann Test führt).

### 3b. Duration-/Cost-Schätzung (`scripts/estimate_duration.py`)
- Anker-Kommentare Z. 63-64 auf neuen Default (`opus` statt `sonnet-economy`/`opus-cheap`).
- `_MODEL_FACTOR`: `opus: 1.40` für **Dauer** vorerst belassen (Opus-Latenz real;
  exakt nach Stufe-0-Wall-Messung rekalibrieren). Hinweis: die *Kosten*annahme hinter
  1.40 ist widerlegt — falls estimate_duration eine Kostenkomponente daraus ableitet,
  diese entkoppeln (Dauer ≠ Kosten).
- Banner-Schätzung: Standard-Kosten steigen (Opus-Reasoning). Werte aktualisieren, sobald
  Stufe-0/echter Lauf vorliegt; bis dahin konservativ + als Schätzung kennzeichnen.

### 3c. Nutzerseitige Oberflächen
- `skills/create-threat-model/SKILL.md` + `SKILL-impl.md`: Config-Summary / Depth-Labels /
  ggf. Advisory-Hinweise auf neuen Default; Default-Erwähnungen suchen (`opus-cheap`,
  „economy tier").
- `docs/threat-modeler.md`: Kostentabelle (Standard ~$17.37 etc. steigt), Default-Modell-
  Beschreibung; der bereits ergänzte Opus-Reasoning-TIP wird damit konsistent.
- `scripts/run-headless.sh` + `HELP.txt`: `--reasoning-model`-Default-/Hilfetext.
- `scripts/render_completion_summary.py`: Reasoning-Label-Choices/Anzeige.

### 3d. Permissions
`data/required-permissions.yaml`: **keine Änderung** — Modell-Routing fügt keinen neuen
Bash-Befehl / Write-Target / Sub-Agent-Dispatch hinzu. (In der Umsetzung kurz
gegenprüfen.)

---

## 4. Optional / später — size-adaptive Inversion (NICHT im Kern-Scope)

Falls Small-Repo-Kosten zum Problem werden: B2d-Logik **invertieren** statt entfernen —
kleine/einfache Repos → `sonnet-economy` (kein Thrash zu sparen), große/komplexe → `opus`.
Das ist mehr Logik + mehr Tests und widerspricht dem „vereinheitlicht"-Ziel; daher
bewusst aus dem Kern-Plan herausgehalten. Voraussetzung wäre belastbare Stufe-0-Evidenz
zum Crossover-Punkt.

---

## 5. Rollout / Verifikation der Umsetzung

1. (Phase 0) Stufe-0-Matrix laufen lassen → Magnitude + Wall bestätigen.
2. Code-Änderungen 2a–2c, dann Tests 3a grün ziehen.
3. `make lint` / `make test` (Subset nach CONTRIBUTING „Targeted tests"; Baseline-Fails
   von neuen trennen).
4. Ein echter `standard --full` Lauf gegen Juice-Shop **aus einer Sonnet-Session** →
   bestätigt: STRIDE läuft auf Opus (`.agent-run.log` zeigt Opus-Dispatches,
   `.skill-config.json` `stride_model=opus`, `reasoning_label` neu), Kosten/Dauer im
   erwarteten Rahmen, Report-Qualität (Severity-Verteilung) wie V3.
5. Doku-Schätzwerte (3b/3c) mit echtem Lauf finalisieren.

## 6. Rollback

Reiner Config-/Default-Change, keine Schema-/Datenmigration. Rollback = Default in
`resolve_reasoning_model` zurück auf `"opus-cheap"` + B2d wiederherstellen + Tests
zurück. Nutzer-Opt-out (`--reasoning-model …`) funktioniert während der gesamten Zeit in
beide Richtungen, daher geringes Risiko.

## 7. Risiken / offene Punkte

- **Small-Repo-Mehrkosten** (bewusster Trade-off; Opt-out vorhanden). N=1 für die
  Inversion → Phase 0 mindert das.
- **Duration-Schätzung** ohne saubere Opus-Wall-Messung vorerst konservativ.
- **Test-Pin-Umfang** (**56** in `test_resolve_config.py` + 31 + 24 in den anderen,
  verifiziert 2026-06-21) ist der größte Aufwandsposten.
- **Config-Summary/Label-Strings** ggf. an mehreren Stellen dupliziert → vor Edit
  enumerieren (Grep auf `opus-cheap`, `sonnet-economy (auto`, `reasoning_auto_switched`).
