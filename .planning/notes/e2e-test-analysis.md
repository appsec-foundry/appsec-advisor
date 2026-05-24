# End-to-End Test Analyse — appsec-advisor

**Datum:** 2026-05-24
**Status:** Analyse — keine Umsetzung
**Frage:** Kann man echte E2E-Tests bauen, die Rendering, alle Outputs, Skills, Business-Kontext und Requirements als Input abdecken?

---

## TL;DR

**Ja, machbar — aber als 3-Tier-Pyramide, nicht als einzelner "real run". Ein
einziger naiver E2E-Lauf pro PR ist weder bezahlbar noch deterministisch
genug.** Heute fehlt ein Mittel-Layer zwischen den 50+ Python-Unit-Tests und
einem echten LLM-Lauf. Den größten Gewinn liefert ein neuer **Tier 2
(Hybrid-Replay)** der Skill-Orchestrierung + Agent-Dispatch + Hooks + Hard-Gate
ohne echten LLM. Tier 3 (echter LLM-Lauf) ist machbar, aber nur als
nightly/manuelles Job, nicht pro PR.

---

## 1. Was heute existiert (Bestandsaufnahme)

### 1.1 Test-Suite (~50 Dateien in `tests/`)

| Kategorie                         | Beispiele                                                                                                           | Was sie abdecken                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Renderer-Determinismus            | `test_compose_threat_model.py`, `test_render_threat_model.py`, `test_render_properties.py`                          | `compose.render()` byte-identisch; Anchor-Round-trip; Heading-Hierarchie          |
| Contract / Schema                 | `test_contract_integrity.py`, `test_schema_drift.py`, `test_schemas.py`, `test_fragment_registry.py`                | sections-contract.yaml, JSON-Schemas, Fragment-Registry-Konsistenz                 |
| Enforcement (Mutations-Matrix)    | `test_enforcement_mutations.py`                                                                                     | Schema-Reject, Contract-Order-Reject — jeder Gate hat mind. eine Mutation         |
| Intermediate-Validierung           | `test_validate_intermediate.py`, `test_p1_renderer_correctness.py`, …`p2`/`p3`/`p4`                                  | `.threats-merged.json`, `.triage-flags.json`, `.stride-*.json` Shape              |
| Pipeline-Wiring (deterministisch) | `test_e2e_pipeline.py`                                                                                              | **compose → annotate → qa_checks → pentest_tasks** auf gefrorenem Run-Verzeichnis |
| Skill-Logik (statisch)            | `test_skill_auto_retry.py`, `test_skill_composition_split.py`, `test_phase_group_prompts.py`                        | SKILL-impl-Markdown lesen, Routing prüfen — keine Ausführung                       |
| Hooks / Lock / Status             | `test_acquire_lock_heartbeat.py`, `test_appsec_status_live.py`, `test_agent_logger.py`                              | Concurrency, Heartbeat, Logger                                                     |

### 1.2 E2E-Fixture (`tests/fixtures/e2e/frozen-run/`)

Ein vollständiges **gefrorenes Run-Verzeichnis** (synthetic Juice-Shop):
`threat-model.yaml`, `.threats-merged.json`, `.dep-scan.json`,
`.stride-C-0X.json`, `.triage-flags.json`, `.recon-summary.md`,
`.appsec-cache/baseline.json`, `.fragments/*` (11 Fragmente: ms-verdict,
ms-architecture-assessment, critical-attack-chain, attack-walkthroughs,
operational-strengths-overrides, system-overview, assets, attack-surface,
architecture-diagrams, security-architecture, out-of-scope).

→ `test_e2e_pipeline.py` replayed dieses Verzeichnis durch jeden Post-LLM-Script.
**Aber: kein einziger LLM-Call, keine Skill-Routing, kein Orchestrator, keine
Hooks, kein Hard-Gate.**

### 1.3 Headless-Runner

`scripts/run-headless.sh` existiert bereits — wrappt `claude -p` für
non-interaktive Läufe; unterstützt alle Flags inkl. `--repo`, `--output`,
`--assessment-depth`, `--with-sca`, `--sarif`, `--restore-from`, `--max-duration`,
`--max-budget`, `--fail-on`, `--audit-requirements`. CI-Mode-Auto-Detect ist
eingebaut.

→ **Infrastruktur für echte E2E ist schon da, wird aber von keinem Test
genutzt.** README sagt "future work".

### 1.4 CI heute

`.github/workflows/tests.yml`: `pytest tests/ -v --tb=short` auf Python
3.10/3.11/3.12 + Ruff + `validate_config.py`. **Kein LLM, kein
run-headless.sh, kein Cost-Tracking.**

---

## 2. Was "echtes E2E" abdecken müsste

| Dimension                  | Heute             | Lücke                                                                                       |
|----------------------------|--------------------|----------------------------------------------------------------------------------------------|
| Rendering (final MD)        | ✅ frozen → compose | ✅ ausreichend für Deterministik; ❌ keine Aussage über LLM-erzeugte Prosa-Qualität           |
| Alle Outputs (.md/.yaml/.sarif/.pdf/pentest-tasks) | Teilweise         | `.sarif.json` `test_export_sarif.py`; `.pdf` `test_export_pdf.py`; **PDF/SARIF nie als Output eines kompletten Skill-Runs verifiziert**, nur als Einzelscripte |
| Skill-Routing (`SKILL.md` → `SKILL-impl.md`) | ❌                  | Routing-Case-Matrix wird statisch geprüft (`test_skill_composition_split.py`), aber niemals ausgeführt |
| Orchestrator (`appsec-threat-analyst` 250 turns) | ❌                  | Keine Tests; nur Prompt-Linting in `test_phase_group_prompts.py`                              |
| Sub-Agent Dispatch (`Agent` tool)                | ❌                  | Frontmatter-Validierung (`test_agent_definitions.py`); kein Mocking-Layer für Dispatch       |
| Hooks (`agent_logger.py` PreTool/PostTool/Stop)  | Unit               | `test_agent_logger*.py`; keinen E2E-Lauf, der echte Hook-Sequenz durch ein Skill validiert    |
| Stage-Übergänge + Hard-Gate (`check_inline_shortcut.py`) | Unit               | `test_check_inline_shortcut.py`; keine Integration mit Retry-Loop                            |
| Auto-Retry (M2.13)                              | Unit              | `test_skill_auto_retry.py` (Prompt-Inspection); kein realer 2-Iteration-Lauf                  |
| Business-Kontext (`--requirements <url>`, `org-profile`) | Teilweise        | `test_requirements_source_resolution.py`, `test_resolve_org_profile.py`; **kein End-zu-End mit echter URL-Crawl** |
| 9 Skills jenseits `create-threat-model`         | Teilweise         | Statisch verifiziert; nur `audit-security-requirements` hat Logik-Tests; `publish-threat-model`, `export-threat-model`, `threat-model-health`, `clean-run-state`, `fix-run-issues`, `status`, `check-permissions` haben **keinen End-zu-End-Walkthrough** |
| Cost / Turn-Budget Drift                        | ❌                  | `phase-budgets.yaml` referenziert in `aggregate_run_issues.py`; kein Regressions-Test, dass ein Lauf im Budget bleibt |

---

## 3. Vorgeschlagene 3-Tier-Pyramide

### Tier 1 — Behalten: Deterministisches Post-LLM-E2E (`test_e2e_pipeline.py`)
- Schnell (<10s gesamte Suite), kein API-Key, läuft pro PR.
- **Aktion:** keine — bereits gut.

### Tier 2 — NEU: Hybrid-Replay des Skill-Flows (größter Gewinn, machbar)

**Idee:** Den Orchestrator-Loop tatsächlich ausführen, aber jeden `Agent(...)`-
Call durch einen Replay-Stub ersetzen, der das passende `.fragments/*` aus dem
gefrorenen Fixture auf Disk schreibt (so wie es ein echter LLM-Agent tun würde).
SKILL.md → SKILL-impl.md Routing, Stage 0–3 Bash, Phase-Group-Lazy-Load,
`Agent` Dispatch, Hooks, Hard-Gate, Retry-Loop laufen **echt**.

**Mechanik:**
- Pytest-Harness baut ein `tmp_output_dir`, gibt es `scripts/run-headless.sh`
  mit einem alternativen `CLAUDE_BINARY=./tests/stubs/claude_replay.py`.
- `claude_replay.py` ist ein Drop-in für `claude -p`, das den SKILL-impl.md-
  Flow gegen eine `replay-transcript.jsonl` abspielt (jeder Eintrag: erwarteter
  Bash/Agent-Call → Mock-Response, ggf. mit File-Write-Side-Effects).
- Transcript wird einmal aus einem echten Lauf aufgezeichnet
  (`scripts/run-headless.sh --record-transcript`) und gehärtet (PII-strip,
  Pfad-Normalisierung).

**Abdeckung:**
- ✅ SKILL Routing
- ✅ Stage 0 Preamble (Lock, Auto-Clean, `resolve_config.py`)
- ✅ Stage 1 Phase-Group-Sequenz (Recon → Architecture → Threats)
- ✅ Stage 2 Renderer + `compose_threat_model.py --strict`
- ✅ Hard-Gate `check_inline_shortcut.py`
- ✅ Stage 3 QA-Reviewer + Re-Render-Loop
- ✅ Auto-Retry M2.13 (Transcript mit absichtlich fehlender 1. Iteration)
- ✅ Hooks (`agent_logger.py` schreibt `.hook-events.log` → assertion)
- ✅ Exit-Codes pro Stage
- ✅ Stage 4 `--architect-review` (separater Transcript)
- ❌ LLM-Prosa-Qualität (per Definition)

**Kosten:** $0, Laufzeit <30s pro Test, läuft pro PR.

**Aufwand-Schätzung:** 1 Phase à 5–8 Tasks
(`tests/stubs/claude_replay.py`, Recording-Mode, Transcript-Schema,
~5 kanonische Transcripts (happy, retry, gate-violation, qa-rerender,
architect-review), Pytest-Harness, CI-Wiring).

### Tier 3 — NEU: Echter LLM-Lauf, gated (Realismus, aber teuer)

**Trigger:**
- `workflow_dispatch` (manuell)
- nightly cron
- Label `e2e-real` auf PRs

**Setup:**
- `tests/fixtures/e2e/synthetic-repo/` (heute ~2 Files) **erweitern** auf ein
  20–30-File-Mini-Stack (Express + Sequelize + Dockerfile + 1–2 Routes mit
  bewussten SQLi/SSRF/XSS-Pfaden → STRIDE findet vorhersagbare Threats).
- Alternativ `examples/threat-modeler/` aufs synthetische Repo zeigen.

**Matrix:**

| Variante                                          | Modell-Tier      | erwartete Kosten | Dauer  |
|---------------------------------------------------|-------------------|-------------------|--------|
| `quick` + synthetic-repo                          | `haiku`           | ~$0.30            | 3–5 min |
| `standard` + synthetic-repo                       | `opus-cheap` (Sonnet) | ~$1.50            | 6–10 min |
| `thorough` + Juice Shop                           | `opus-cheap`      | ~$8                | 20–30 min |
| `quick` + `--audit-requirements` + lokale URL    | `haiku`           | ~$0.20            | 2–3 min |
| `quick` + `--with-sca`                             | `haiku`           | ~$0.40            | 4–6 min |

**Assertions (fuzzy, nicht byte-Vergleich):**
- Exit-Code 0
- Files existieren: `threat-model.{md,yaml}`; konditional `.sarif.json`, `.pdf`, `pentest-tasks.yaml`
- Schemas valide (re-use `validate_intermediate.py`, `test_schemas.py`)
- `compose.render()` auf erzeugtem yaml liefert kanonische MS-Struktur
- **Erwartungs-Bänder:** 4 ≤ #threats ≤ 12; mind. 1 STRIDE-Category-Coverage je T/I/D/E/E/S; #components ≥ 3
- Keyword-Floor: `["SQL", "Injection"]` im Markdown bei synthetic-repo mit SQLi-Pfad
- Cost-Budget: `verify_run_costs.py` exit 0; gesamt < $X für Tier
- Phase-Budgets: kein Phasen-Heartbeat-Stall
- Kein `inline-shortcut`-Bypass (Hard-Gate hat exit 0 = nicht ausgelöst)

**Output-Snapshots:**
- Bei jedem Lauf: `.run-snapshot/<sha>/threat-model.{md,yaml,sarif.json}` archiviert als Workflow-Artifact (30-Tage-Retention).
- Driftmonitor: separates Job-Step liest die letzten 7 Snapshots und alarmiert bei sprunghaftem Drift (#threats schwankt >50% Lauf-zu-Lauf).

**Skills-Coverage in Tier 3:**

| Skill                            | E2E-Strategie                                                                                          |
|----------------------------------|---------------------------------------------------------------------------------------------------------|
| `create-threat-model`             | Hauptlauf — Matrix oben                                                                                |
| `export-threat-model`             | Folge-Step nach `create-threat-model`; assertet `.pdf`/`.html` Output + nicht-trivial                  |
| `publish-threat-model`            | `--dry-run` Modus (kein Push); assertet generierten Branch-Diff                                        |
| `audit-security-requirements`     | Separater Lauf mit `--requirements <file://local-fixture>`; Tier 2 + Tier 3 Variante                   |
| `threat-model-health`             | Folge-Step; liest erzeugte Artefakte; exit-Code 0                                                       |
| `clean-run-state`                 | Tier 2 reicht — keine LLM-Logik                                                                        |
| `fix-run-issues`                  | Tier 2 Transcript mit absichtlich kaputtem Run-State                                                   |
| `status`                          | Tier 2 reicht                                                                                          |
| `check-permissions`               | Tier 2 reicht — pure Settings-Inspektion                                                                |

### Tier 4 — OPTIONAL: LLM-Drift-Telemetrie

- Offline-Skript läuft `--assessment-depth quick` N-mal gegen synthetic-repo
  (z.B. wöchentlich, N=5).
- Vergleicht: #threats, #components, prose-length verteilung,
  triage-ranking-stabilität.
- Speichert Zeitreihe; alarmiert bei statistisch signifikanter Drift (>2σ).
- **Kein Pass/Fail-Test**, nur Telemetrie für Modell-Updates / Prompt-Änderungen.

---

## 4. Blocker / Risiken

| Risiko                                            | Auswirkung                                                | Mitigation                                                                          |
|---------------------------------------------------|-----------------------------------------------------------|-------------------------------------------------------------------------------------|
| API-Key in CI                                     | Forks können nicht laufen; Secret-Leak-Risiko             | `workflow_dispatch` + `pull_request_target` mit Approval-Gate; Secret nur in main   |
| Cost-Explosion bei jedem PR                       | Unbezahlbar                                               | Tier 3 nur nightly/manual; harte `--max-budget`-Caps; OpenTelemetry-Alert bei >2× Median |
| Modell-Drift bricht Assertion-Bänder              | Flake                                                      | Bänder weit (4–12 Threats), Quarantäne-Marker `@pytest.mark.flaky_llm`              |
| Wall-Time GitHub-Actions-Limit                    | Job-Timeout                                                | `--max-duration 1800`; Stage 2/3 skip-Optionen                                       |
| Claude-Code-Binary-API-Drift (`claude -p` Flags) | Stub-Replay bricht                                         | Stub orientiert sich an JSON-Output, nicht an Stdout-Format                          |
| Hooks brauchen Plugin-Root-Resolve                | Test-Sandbox findet `CLAUDE_PLUGIN_ROOT` nicht            | `CLAUDE_PLUGIN_DIR` env-Override im Test-Harness setzen                              |
| Permission-Prompts in headless                    | Hängt                                                      | `run-headless.sh` setzt `--permission-mode acceptEdits`; pre-flight-Check existiert  |

---

## 5. Aufwand & Priorität (Empfehlung)

| Tier | Aufwand (Tage) | Wert     | Empfehlung                                  |
|------|----------------|----------|---------------------------------------------|
| 1    | 0 (bereits da) | hoch     | behalten                                    |
| 2    | 3–5            | **sehr hoch** | **als nächstes** — schließt größte Lücke |
| 3    | 5–8            | mittel   | danach; sobald Tier 2 stabil läuft         |
| 4    | 2–3            | niedrig  | optional, nach Bedarf                      |

**Begründung Tier 2 first:** 95% des Skill-Codes ist heute **funktional
ungetestet** (SKILL-impl.md, Orchestrator, Phase-Group-Files, Hooks-Sequenz,
Hard-Gate, Retry-Loop) — alle Tests sind statisch (Prompt-Linting) oder
deterministisch (Post-LLM-Scripts). Tier 2 ohne LLM-Kosten ist der einzige
Weg, diese Orchestrierung pro PR zu validieren.

---

## 6. Offene Fragen für Entscheidung

1. **Budget-Cap pro nightly?** $5 / $20 / $100?
2. **Authmode in CI:** API-Billing-Key (CI-freundlich) oder Subscription-Login
   (nicht headless-fähig)? → entscheidet, ob Tier 3 überhaupt CI-fähig ist.
3. **Welches Ziel-Repo für Tier 3:** synthetic erweitern, oder echte Juice-Shop
   als Submodule pinnen?
4. **Soll `audit-security-requirements` mit Live-URL getestet werden** (gegen
   `iso27001.com`-style Sample) oder nur mit lokaler Fixture-URL?
5. **Drift-Telemetrie (Tier 4) — interesse oder skip?**
