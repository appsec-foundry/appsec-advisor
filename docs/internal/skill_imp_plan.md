# Umsetzungsplan — SKILL-impl.md für Sonnet-Orchestrierung aufräumen

**Datei:** `appsec-advisor/skills/create-threat-model/SKILL-impl.md`
**Branch:** `feature/skill-impl-sonnet-cleanup` · **Stand:** 2026-06-20

## Ziel

Der Skill soll **zuverlässig von Sonnet** (statt nur Opus) als Orchestrierer laufen.
Primärziel = **Followability für ein schwächeres Modell**; Token-/Kostenersparnis ist
willkommener Nebeneffekt, nicht der Treiber. Der dominante Kostenhebel (~5× durch
Sonnet-Session) ist **bereits eingefahren und live validiert** — was offen ist, jagt nur
noch einen Rest (~$1/Lauf Prompt-Kürzung) bzw. Innen-Sauberkeit.

Kernhypothese: Sonnet scheitert nicht an der Größe, sondern an **verstreuten/vergrabenen
Verträgen** und **Prosa-statt-Tabellen-Verzweigungen**.

## Status — was umgesetzt + validiert ist

Primärziel **erreicht und live belegt**: `/model sonnet`-Standardlauf (juice-shop
`455206c32`, ~66 min) sauber durch — alle drei Fan-outs parallel (STRIDE 7/64 s, **Abuse 6/7 s**,
Render 2/4 s), QA-Gate `pass` (`gate_exit 0`), Secret-Scan clean, **0 errors**, keine
übersprungenen Schritte. Volle Suite grün (8384), je Workstream eigener Commit.

| Workstream | Status |
|---|---|
| **P1** Abuse-Verifier-MUST-Block | **DONE** `cf7c13a` — vergrabener „ONE message"-Vertrag in lokalen HARD-CONSTRAINT-Block; STRIDE-Block war schon ideal (kein Churn) |
| **P5** Mode-Routing-Tabelle | **DONE** `6bcf2bd` — additive Navigations-Tabelle, per-Sektion-Bedingungen bleiben autoritativ |
| **format_line-Bug** (vom Live-Lauf aufgedeckt) | **DONE** `007f4be` — Step-Logging auf `log_event.py` mandatet, inline-`format_line` verboten; Guard-Test |
| **P8** Lazy-Load (Pattern) | **TEILWEISE** `d3a1d4f` — Re-Render-Branch → `modes/rerender.md`, JIT-Load; Guard-Test |
| **P3** Shell→`.sh` (größter Block) | **TEILWEISE** `df36584` — Auto-Emitter (139 Z.) → `scripts/auto_emitter_pass.sh`, Charakterisierungstests |

## Offene Arbeit (aktueller Strang: Variante b — erst Review-Scan, dann gebündelt)

Voraussetzung: **ein `--verbose --quick --keep-runtime-files`-Sonnet-Lauf** (`/tmp/tm-verbose-quick`)
liefert die Evidenz für Phase B.

**Phase B — mit Lauf-Evidenz:**
- **P4-Marker:** Sektionen „Verbose Mode" **und** „Tracing Mode — Marker File Lifecycle" existieren
  je 2× (früh `$VERBOSE_REPORT` ⟷ autoritativ `RESOLVED_JSON` + EXIT-Trap). Frühes Paar entfernen,
  autoritatives als einzige Quelle → behebt zugleich die **`VERBOSE_REPORT`-Fragilität** (2× gelesen,
  0× zugewiesen). Gate = `--verbose`-Lauf bestätigt Marker-Verhalten unverändert.
- **Recon-Inline-Fallback:** Diagnose aus dem Lauf — `.route-inventory.json` vorhanden? Turn-Exhaustion
  vs. API-Latenz? **Fix nur falls Turn-Budget**; bei API-Latenz kein sauberer Struktur-Fix.

**Phase C — De-Akkretierung (runtime-byte-identisch, test-verifiziert, konservativ):**
- **P6:** ~132 Incident-/Versions-Marker aus dem Anweisungsfluss → knappe Rand-/Changelog-Notiz.
  Chesterton: schützende Rationale ko-lokalisieren, nicht löschen.
- **Meta-Narration:** 28× verstreut → 1 starke Aussage oben + lokale Verstärkung an 2–3 heißen
  Stellen. R2-Risiko (Redundanzabbau schwächt Adhärenz) → genau dafür ist Phase D Pflicht.

**Phase D — finaler Sonnet-Re-Validierungslauf.** Beweist, dass das Entrümpeln die Followability
nicht geschwächt hat (Tests beweisen nur „Pipeline unverändert", **nicht** „Sonnet folgt noch").

### Gated / niedrig priorisiert (eigener Live-Run nötig oder geringer Wert)

- **P8-Rest** (Incremental-Cluster 298+119 Z., Resume 79 Z., Dry-Run 12 Z.): größter Rest-Token-Gewinn,
  aber **entangled** — Resume enthält das Always-Run **Requirements-fail-closed-Gate** (blind extrahieren
  = Bug), Incremental ist kontrollfluss-+test-verflochten, Dry-Run rein deskriptiv. Braucht
  per-Modus-Golden-Run (`--incremental`). Endzustand = SKILL-impl.md als dünnes Rückgrat + JIT-Lade-Tabelle;
  die Datei verschwindet **nicht** (Always-Run-Kern: Config-Resolution, Stages, Gates).
- **P3-Rest** (Deadline-Watchdog/Wipes/Completion-Persistenz …): voll verifizierbar (Charakterisierungstests),
  niedriges Risiko, aber sinkender Grenznutzen je Block. Nur wenn Dateigröße eigenständiges Ziel ist.
- **P2** (Verzweigungen → Tabellen): der Live-Lauf hat **alle** Branches korrekt navigiert — adressiert
  ein nicht-manifestierendes Problem. Niedrigste Priorität.

### Bewusst NICHT umgesetzt (mit Begründung)

- **P7** (Verbatim-Subjects-Copy-Block): Subjects stehen schon in gebacktickter „source of truth"-Tabelle;
  ein Copy-Block schüfe konkurrierende Zweitquelle (verletzt Leitplanke 3).
- **P4-pregenerate-Dedup**: keine echte Duplikation — 3 Ausführungs-Sites, 2. Aufruf divergent
  (`+_chain-skeleton.md`); Dedup zu kanonischer Referenz verletzt R3.

## Leitplanken (gelten für jede offene Änderung)

1. **Byte-identisches Laufzeitverhalten.** Diff zeigt nur Umformung, keinen geänderten Befehl/Exit-Code.
2. **Deterministisches Substrat ist das Pro-Phase-Gate.** Die `SKILL-impl`-pinnenden Tests
   (`test_skill_composition_split`, `test_incremental_mode`, `test_skill_auto_retry`, …) + die Gates
   (`check_stride_dispatch`, `validate_dispatch_manifest`, `check_inline_shortcut`, `requirements_gate`)
   im Gleichschritt aktualisieren. Golden-Run nur als finaler Smoke, nicht pro Phase.
3. **Lokale statt globale Verstärkung.** Verträge EINMAL am Ausführungspunkt als „MUST"-Block.
4. **Chesterton's Fence.** Schützende Rationale ko-lokalisieren (Skript-Docstring) oder knapp inline,
   nie pauschal löschen.
5. **Inkrementell, kein Big-Bang.** Pro Workstream ein reviewbarer Commit + Test.
6. **Cache-stable prefix respektieren.** Einfügungen nahe Dateianfang invalidieren den Prefix
   (AGENTS.md:186). Statische Edits re-stabilisieren nach einmaligem Re-Cache.

## Risiken & Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| **R2** Redundanzabbau (P6/Meta-Narration) schwächt LLM-Adhärenz | Lokale Verstärkung statt globaler Wiederholung; **Phase-D-Re-Run als Beweis** |
| **R3** Cross-File-Refs unter Kontextdruck nicht geladen | Nur für **Dispatch-Punkt-Verträge** (INLINE). Mode-Bodies/Rationale auslagerbar (phase-group beweist es) |
| **R4** Chesterton — verlorene Schutz-Rationale | Pointer am Ort; Rationale in Skript-Docstring |
| **R5** Extraktions-Drift (Exit-Codes/Quoting) | Verbatim Bash→`.sh`, kein Python-Rewrite; Charakterisierungstest alt==neu |
| **R7** Divergente Duplikate falsch gemerged | Vor Dedup Autorität per Lauf-Evidenz klären (P4-Marker) |

## Nicht-Ziele

- Keine funktionale Änderung an Pipeline, Gates oder Output-Schema.
- Kein Entfernen von Sicherheits-Gates oder Recovery-Pfaden.
- Kein Big-Bang-Rewrite; keine Aufteilung **operativer Dispatch-Punkt-Verträge** über Dateigrenzen
  (P8 lagert nur mode-conditional Bodies aus — siehe R3).
- Keine Modell-Routing-Änderung der Analyse-Sub-Agenten (bereits auto-geroutet).
