# Full-M1 Design — Stage-1 STRIDE-Fan-out auf Level-0 (Skill-Orchestrator)

**Ziel:** Die Phase-9-STRIDE-Analyse (heute seriell-inline im Level-1-Analyst, der Hauptkostentreiber: ~5 Komponenten seriell ≈ 25–31 min) **parallel** machen, indem der **Skill (Level-0, kann nachweislich parallel fan-outen)** die `appsec-stride-analyzer` selbst dispatcht. Erwartung: Stage 1 31 → ~12–15 min (Wall-Clock ≈ langsamster Analyzer statt Summe).

**Variante:** A (minimal-chirurgisch) — Analyst-Split an der Phase-8/9-Grenze; Skill macht den STRIDE-Fan-out dazwischen. Begründung: wiederverwendet vorhandene Agenten (`appsec-stride-analyzer` existiert) + die meiste Dispatch-Infrastruktur ist schon da.

---

## 1. Verifizierter Ist-Zustand (Daten-Handoffs)

Auf Platte nach Phase 8 vorhanden (geprüft an juice-shop-Output):
- `.components.json` — `{id, name, description, paths, complexity, tier, framework}` pro Komponente. ✅ Komponenten-Identität.
- `.trust-boundaries.json` — Liste mit `from/to/components` → pro Komponente ableitbar.
- `.security-controls.json` — Liste, **nach DOMAIN organisiert, NICHT nach Komponente**. ⚠️
- `.recon-summary.md` / `.recon-patterns.json` — KNOWN_SECRETS/VULNS.
- `.dispatch-context/<id>/{prior-findings,known-threats}.json` — pro Komponente. ✅
- `.actors-for-<id>.json`, `.taxonomy-slices/<id>/` — pro Komponente. ✅

Was der stride-analyzer pro Dispatch braucht (aus `appsec-stride-analyzer.md` Inputs + `phase-group-threats.md:212–252`):
`COMPONENT_ID/NAME/DESCRIPTION/PATHS/COMPLEXITY`, `MAX_TURNS`, `ESTIMATED_THREAT_COUNT`, **`INTERFACES`**, **`TRUST_BOUNDARIES`**, **`CONTROLS`**, `KNOWN_SECRETS/VULNS/LLM_PATTERNS`, `STRIDE_PROFILE`, `TAXONOMY_SLICE_DIR`, + die Index-Pfade (`PRIOR_FINDINGS_INDEX_PATH`, `KNOWN_THREATS_INDEX_PATH`, `CROSS_REPO_CONTEXT_PATH`, `PHASE_8B_VIOLATIONS_INDEX_PATH`, `RELEVANT_ACTORS_INDEX_PATH`).

## 2. Der Kern (und das Risiko): der Dispatch-Manifest-Handoff

**Problem:** `INTERFACES`, die **pro-Komponente-Teilmenge** der `CONTROLS` (domain→component-Mapping) und `ESTIMATED_THREAT_COUNT` liegen heute **nicht** strukturiert auf Platte — der Analyst leitet sie in Phasen 6–8 **kontextuell** ab und schreibt sie direkt in die Dispatch-Prompts. Ein rein-deterministischer Builder kann sie **nicht** vollständig rekonstruieren.

**Konsequenz:** Analyst-A muss am Phase-8/9-Übergang ein **vollständiges Per-Komponente-Dispatch-Manifest** serialisieren (`.stride-dispatch-manifest.json`), das ALLE skalaren Params + Pfad-Referenzen enthält. Das ist ein **LLM-authored Handoff** → braucht ein **Schema + deterministischen Validator** (Hard-Gate vor dem Fan-out), sonst dispatcht der Skill mit unvollständigen Params.

→ Dies ist das lasttragende, risikobehaftete Stück von Full-M1.

## 3. Komponenten der Umsetzung

| # | Änderung | Art | Verifizierbar |
|---|---|---|---|
| 1 | **Schema** `schemas/stride-dispatch-manifest.schema.{yaml,json}` (pro Komponente: alle Dispatch-Params + Pfade) | neu | ✅ deterministisch (schema-test) |
| 2 | **Validator** `scripts/validate_dispatch_manifest.py` (Hard-Gate: jede Komponente vollständig, Pfade existieren) | neu | ✅ deterministisch (unit-test mit Fixtures) |
| 3 | **Analyst-A**: neues `STAGE1_PHASE_LIMIT=8` — Phasen 1–8 + Dispatch-Prep (slices, `.dispatch-context/`) + **Manifest schreiben**, dann STOP vor Phase 9 | Prompt (analyst + phase-group-threats) | ❌ nur Full-Run |
| 4 | **Skill STRIDE-Fan-out**: Manifest lesen → validieren (Gate #2) → **N `appsec-stride-analyzer` parallel dispatchen** (eine Message) → auf alle `.stride-*.json` warten | SKILL-impl (Logik aus phase-group-threats:203–252 hochziehen) | ❌ nur Full-Run |
| 5 | **Analyst-B**: `STAGE1_PHASE_LIMIT=10b` ab Phase 10 (Merge/Evidence/Triage/yaml) — konsumiert `.stride-*.json` (existiert großteils schon als Logik) | Prompt | ❌ nur Full-Run |
| 6 | `check_stride_dispatch.py`-Gate: bei Level-0-Dispatch **besteht es natürlich** (echte `.progress` von echten Agenten); M1-lite-Inline bleibt Fallback wenn Fan-out ausfällt | (klein) | ✅ |
| 7 | Tests: Schema + Validator + Manifest-Builder-Fixtures | neu | ✅ |

## 4. Verifikation — der ehrliche Teil

- **Deterministisch (CI, jetzt machbar):** Schema-Validität, Validator-Logik (vollständiges vs. lückenhaftes Manifest → pass/fail), die Slice/dispatch-context-Contracts.
- **Behavioral (NUR teurer Full-Run):**
  1. *Läuft E2E* — `make e2e-full-standard` (mit `--max-duration`-Fix), ~45–60 min, sandbox-disabled.
  2. *Parallelisiert wirklich* — neues e2e-Assert: `.agent-run.log`/`.hook-events.log` `AGENT_SPAWN`-Timestamps der stride-analyzer müssen sich **überlappen** (Wall-Clock ≈ langsamster, nicht Summe).
  3. *Qualität erhalten* — Threat-Set (Count/T-IDs/Severities) vorher (seriell-inline, Baseline) vs. nachher (parallel) auf demselben Repo diffen → kein Coverage-Regress.
- **Nicht billig iterierbar:** jede Verhaltens-Iteration ist ein 45–60-min-Lauf. Genau hier liegt das Projektrisiko.

## 5. Ehrliche Einordnung + empfohlener Pfad

Full-M1 ist **machbar, aber eine echte Re-Architektur** (5 Dateien + neues Script + Schema + Tests), deren lasttragendes Stück (LLM-authored Dispatch-Manifest) **Korrektheitsrisiko** trägt und **nur per teurem Full-Run** verhaltens-verifizierbar ist. Es ist **kein Single-Session-Task** und ein halbfertiger Stand würde die funktionierende Pipeline brechen.

**Empfohlener gestaffelter Pfad (risiko-minimal):**
1. **Jetzt (deterministisch, null Pipeline-Risiko):** Schema (#1) + Validator (#2) + Tests (#7) bauen — das lasttragende Contract-Stück, vollständig unit-testbar. De-riskt den Rest.
2. **Dann (Prompt, ein Full-Run-Gate):** Analyst-Split (#3, #5) + Skill-Fan-out (#4) + Gate (#6). Verifikation per einem `e2e-full-standard` mit den neuen Parallel-/Qualitäts-Asserts (#4 der Verifikation).
3. **Cutover** erst, wenn der Vorher/Nachher-Threat-Diff Qualitätserhalt zeigt; sonst M1-lite-Inline bleibt aktiv (kein Regress).

**Fallback by design:** Wenn der Fan-out/Manifest in Prod ausfällt, greift die M1-lite-Inline-Escape-Klausel (bereits umgesetzt) — der Analyst inlinet STRIDE wie heute. Full-M1 ist also additiv/abschaltbar, kein Hard-Cutover.

---

## 6. Umsetzungs- + Verifikations-Status (2026-06-04)

- **Foundation: FERTIG + verifiziert.** `schemas/stride-dispatch-manifest.schema.yaml`, `scripts/validate_dispatch_manifest.py`, `scripts/build_stride_dispatch_manifest.py`, `tests/test_dispatch_manifest.py` (15 Tests grün) + realer Round-Trip gegen juice-shop-Artefakte (valides 5-Komp-Manifest).
- **Orchestrierung: VERDRAHTET, opt-in (`APPSEC_PARALLEL_STRIDE=1`).** Analyst `STAGE1_PHASE_LIMIT=8` (Analyst-A) + `RESUME_FROM_PHASE=9-merge` (Analyst-B); SKILL-impl Step-3-Branch: Analyst-A → builder → validate (Gate) → parallele stride-analyzer-Fan-out → Analyst-B, mit graceful Fallback auf Default-Inline. Default-Pfad byte-unverändert; deterministische Suite 0 neue Fehler.
- **Behavioral: NACHGEWIESEN (PASS) — juice-shop, 5 Komponenten (2026-06-04 m1verify).** Nach zwei Vorarbeiten (Env-Forward in `run-headless.sh` + prominenter Routing-Block am Stage-1-Kopf) feuerte der Branch: Analyst-A (`=8`) → `.stride-analyst-context.json` → Builder → Manifest → **5 stride-analyzer parallel dispatcht** (Starts 10:21:46–51, alle ~5 s) → Analyst-B → Renderer. **STRIDE-Wall ~5:45 vs ~22 min seriell-äquivalent ≈ ~16 min Ersparnis**; überlappende Fenster = echte Nebenläufigkeit. Exit 0, valides Model, Hard-Gates clean. **Netto-Stage-1 moderater** (~27 vs ~31 min) wegen Analyst-A/B-Split-Overhead + nicht-parallelisierter Umgebungsphasen; **skaliert mit Komponentenzahl**.
  - **Follow-up A (GEFIXT):** Builder wies LLM-`controls`-Dict ab → dict→String-Flatten in `build_stride_dispatch_manifest.py`.
  - **Follow-up B (GEFIXT):** parallele Analyzer schrieben `.progress/` nicht (`agent_progress.sh` no-op't ohne `OUTPUT_DIR`-ENV) → `check_stride_dispatch.py` false-positivte. Fix: Gate erkennt jetzt `.stride-dispatch-manifest.json` / `AGENT_SPAWN`-Hook-Evidenz als Dispatch-Beweis (2 neue Tests grün) **+** Step 3c instruiert `export OUTPUT_DIR` im Dispatch (damit `.progress` legitim geschrieben wird).

  ~~Verifikationslauf (synthetic, 2073s): **Branch feuerte NICHT**~~ (frühere 2-Komp-Synthetic-Fixture, vor den Vorarbeiten — historisch): — kein `.stride-analyst-context.json`/`.stride-dispatch-manifest.json`, STRIDE lief inline (Default). Ursachen:
  1. Headless-Orchestrator nahm den opt-in-Conditional (in Step-3-Prosa vergraben) nicht — gleiche „neuer opt-in-Zweig wird nicht zuverlässig befolgt"-Hürde wie M2b-Live-Loop; ggf. zusätzlich Env-Propagation der `APPSEC_PARALLEL_STRIDE` bis in die Skill-Bash.
  2. **Synthetic-Fixture hat nur 2 Komponenten** (`express-api`, `data-layer`) → strukturell ungeeignet, Multi-Komp-Parallelität zu zeigen.
- **Was echte Verifikation braucht:** (a) Branch zuverlässig zünden — Env-Propagation in `run-headless.sh` explizit forwarden **+** den `PARALLEL_STRIDE`-Branch prominenter/früher platzieren (eigener Stage-1-Abschnitt statt Step-3-Prosa); (b) ein **juice-shop-Standard-Lauf (5 Komp)** mit neuem `AGENT_SPAWN`-Overlap-Assert + Vorher/Nachher-Threat-Diff. Mehrere ~35–60-min-Läufe; nicht billig iterierbar.
- **Kein Regress:** Default-Pfad erzeugte ein valides Model; die 13 e2e-Assertion-Fehler sind prä-existent (Standard/Working-Tree), nicht von den (nicht-gefeuerten) Full-M1-Änderungen.
