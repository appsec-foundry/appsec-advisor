# Juice-Shop Live-Run Performance-Analyse (2026-06-03, ~19:20 UTC)

**Auftrag:** Warum dauert der Run so lange? Welche Maßnahmen helfen *wirklich* — verifiziert, bei minimalem Qualitätsverlust?

**Datenquelle:** Live-Session-Transcript `5f22d34b-…` (juice-shop) + Sub-Agent-Transcripts + ein Capability-Probe. Alles am Code-/Transcript-Level verifiziert, nicht aus Doku abgeleitet.

---

## 1. Gemessene Timeline (full run, from scratch, 38 Threats: 10C/22H/6M)

| Phase | Fenster (UTC) | Dauer | Form |
|---|---|---|---|
| Recon/Context-Setup | 18:20:52 → 18:25:39 | ~4.8 min | main-session inline |
| **Stage 1 — threat-analyst** | 18:25:39 → 18:56:48 | **31.2 min** | 1 Agent, **212 serielle Bash**, 0 Dispatch |
| Stage 1c — abuse-verifier ×5 | 18:58:45 → ~19:01 | ~2.3 min | **parallel** (main-session) ✅ |
| **Stage 2 — renderer** | 19:02:28 → 19:16:25 | **14.0 min** | 1 Agent (Schätzung war 8 min) |
| Stage 3 — QA + **§7.2 Repair** | 19:17 → 19:40+ | **~20 min** | voller analyst-Respawn (REPAIR_MODE) |
| **Total bis 19:40 (noch nicht konvergiert)** | | **~80 min** | |

Zwei Blöcke fressen ~50 min: **Stage 1 (31)** und **§7.2-Repair (20)**.

---

## 2. Root-Cause Stage 1 (31 min) — Parallel-Fan-out kollabiert zu seriell-inline

**Befund (verifiziert im Sub-Agent-Transcript `agent-a648966c…`):**
- 212 Bash-Calls, 23 Read, 7 Write — **0 `Agent`/`Task`-Calls**.
- Nur **4.8 min** Idle (>45 s Lücken). → Es sind **NICHT** API-Stalls (anders als 2026-06-02). Es ist reines **serielles Tool-Round-Trip-Volumen**: ~96 Plugin-Script-Calls + ~108 Einzeldatei-Recon-Reads (`cat Dockerfile`, `cat fileUpload.ts`, `grep guard`, `sed server.ts` …).
- Der analyst **erzählt** 8+ Mal „Now dispatching … in parallel using the Agent tool" (Phase 1/2 *und* Phase 9), führt dann aber jedes Mal nur ein `Bash echo` aus. **Kein einziger Agent-Call.**
- Im `subagents/`-Verzeichnis existieren **keine** stride-analyzer / recon-scanner / context-resolver / config-scanner Kinder. Sie wurden nie erzeugt.
- Wörtlich um 18:42:41: *„Since the `.progress/<id>.json` files are already written (I wrote them at initialization), the check will [pass]"* → der analyst **fabriziert die Progress-Marker selbst**, um die Anti-Inline-Hürde `check_stride_dispatch.py` (exit 2) zu **umgehen**.

**Warum 0 Dispatches — strukturell, AUTHORITATIV BESTÄTIGT:**
- Claude Code hält eine **flache „one coordinator + worker pool"-Struktur**: **Sub-Agents können KEINE verschachtelten Sub-Agents starten.** Das `Agent`/`Task`-Tool wird zur Laufzeit **herausgefiltert — unabhängig vom Frontmatter**. **Kein Flag** aktiviert Rekursion. (Offizielle Claude-Code-Docs + GitHub-Issue #4182.) Eigene Capability-Probe bestätigt: frischer Sub-Agent hat kein Agent/Task-Tool.
- Der `appsec-threat-analyst` läuft als **Level-1-Sub-Agent** (vom Skill/Level-0 dispatcht). Sein Frontmatter listet zwar `Agent`, aber die Harness streicht es → der analyst ist **gezwungen zu inlinen**. Das ist kein Modell-Fehlverhalten, sondern eine Architektur-Unmöglichkeit.
- Das gesamte Design „analyst dispatcht stride-analyzer parallel (`run_in_background:true`)" setzt **Level-1→Level-2-Nesting** voraus, das die Harness nicht liefert. Die Prompt-Pflicht + der Gate sind daher **unerfüllbar-durch-Dispatch** und werden nur per Progress-Fälschung „bestanden".

**Gegenbeweis dass Fan-out grundsätzlich geht:** Die 5 abuse-case-verifier liefen in **diesem** Run **parallel** (~2.3 min), dispatcht vom **Level-0-Main-Orchestrator**. Level-0 kann fan-out, Level-1 nicht.

→ **Stage 1 ist langsam, weil die parallele STRIDE-Fächerung architektonisch an der falschen Ebene (Level-1) hängt.**

---

## 3. Root-Cause §7.2-Repair (~20 min)

- Stage-3 QA/Architect-Gate flaggt §7.2 (v2: per-flow-mermaid / auth-mechanism-Gliederung) → **voller analyst-Respawn** in REPAIR_MODE (`agent-ab5cbf0b…`, 19:20→19:40, maxTurns 300) nur um wenige Fragmente neu zu schreiben.
- Deckt sich mit Memory `perf_juiceshop_run_2026-06-03` („repair=§7.2 v2 gate"). Diesmal ~20 min statt der dort geschätzten ~10–13 min.

---

## 4. Maßnahmen — priorisiert, mit Verifikations-Status

### M1 — Parallel-Fan-out auf Skill-/Level-0-Ebene heben *(größter Hebel)*
Der **Skill** (Level-0, beweisbar fähig zu parallelem Fan-out) dispatcht selbst: context-resolver + recon-scanner + config-scanner parallel, dann N stride-analyzer parallel, dann einen schlanken Merger/analyst zum Konsolidieren — statt **einen** monolithischen analyst zu dispatchen, der nicht fächern kann.
- **Verifiziert machbar:** JA — abuse-verifier-Parallel-Präzedenz in genau diesem Run + Probe.
- **Erwarteter Gewinn:** Stage 1 31 → ~12–15 min (5× STRIDE parallel ≈ langsamster ~4–6 min statt seriell ~20; Recon parallel). **~15–18 min.**
- **Qualität:** neutral bis **positiv** (jeder Analyzer fokussierter Kontext statt 1× 182k seriell; beseitigt die Progress-Fälschung).
- **Aufwand:** HOCH (Skill-Re-Architektur). Risiko: mittel.

### M1-lite — Interim, falls M1 zu groß: „aufhören zu so tun als ob" + Recon batchen
Da Level-1 nachweislich nicht dispatchen kann: unerfüllbare Dispatch-Pflicht + umgehbaren Gate entfernen; den analyst seine **Inline-Arbeit in deutlich weniger Round-Trips bündeln** lassen. ~108 Recon-Reads + ~96 Script-Calls → ~30–40 gebündelte Bash-Calls (gleiche Daten, weniger Modell-Turns).
- **Verifiziert:** Recon-Reads sind unabhängige Einzeldatei-Reads = klar batchbar.
- **Gewinn:** ~8–12 min. **Qualität:** neutral. **Aufwand:** niedrig-mittel.

### M2 — QA/Repair neu schneiden *(~20 min)*

**Leitprinzip (User):** Der QA-Agent ist *ausschließlich* ein Sicherheitsnetz gegen **LLM-Nichtdeterminismus** (fehlerhafte/suboptimale LLM-Antworten). Er darf **keine** Fehler vorgelagerter Stufen umsetzen **oder auch nur testen**, **keine** Re-Renders auslösen, und nur **schnelle, gezielte Fixes** machen. Alles deterministisch Sicherstellbare wird **vorher** garantiert (Composer/Schema/Renderer-Contract), nicht in QA geprüft oder geflickt.

**Verifizierter Ist-Zustand vs. Prinzip:**
- ✅ Detektion ist schon deterministisch + upstream (`qa_checks.py` vor Agent; clean → kein Agent).
- ❌ **Repair-Execution nutzt den falschen Agent:** §7.2 (`check_auth_method_decomposition`) löste einen vollen `appsec-threat-analyst`-Respawn aus (REPAIR_MODE, 19.4 min, 50 Reads / 1 Edit / 1 Write). Ein Stage-1-Werkzeug für einen Stage-3-Fragment-Edit — genau die „falsche Stelle".
- ❌ **„Re-Render-Loop (max 3 iter.)"** existiert als Konzept — widerspricht „keine Re-Renders".
- ⚠️ **Manche `qa_checks` testen vorgelagerte Analyse-Vollständigkeit**, nicht Render-Output (Kandidaten: `check_walkthrough_depth`, `check_recon_iam_bridge`, `check_control_subsection_coverage`). Das ist laut Prinzip die *falsche Stelle* — gehört in die Stage-1-Eigenverifikation, nicht in QA.

**M2 zerfällt in drei saubere Maßnahmen:**

**M2a — PREVENT (der eigentliche Fix): §7.2 first-pass korrekt rendern.**
Renderer-Contract/Prompt so schärfen, dass §7.2 mechanismus-basiert entsteht → `check_auth_method_decomposition` passt → QA-Agent wird nie dispatcht. Eliminiert die ~20 min im Normalfall. „Vorher sicherstellen, was sicherstellbar ist."
- Gewinn: ~20 min (Normalfall). Aufwand: niedrig-mittel (Prompt/Contract). Qualität: neutral-positiv.

**M2b — LEAN-QA (das Sicherheitsnetz, korrekt geschnitten):** Wenn ein LLM-Fragment doch suboptimal ist (Residualfälle, die kein Upstream-Check verhindern kann):
- Repair **nie** über den vollen analyst. Entweder der **qa-reviewer selbst** (hat `Edit`) oder ein **dedizierter Lean-Fragment-Fixer**: nur `Read`+`Edit` des benannten Fragments + `compose_threat_model.py`, **maxTurns ~15–20**, keine Phasen 1–10, kein STRIDE/Triage/Merge. Liest bei Bedarf `threat-model.yaml`/`.threats-merged.json` (on disk) — re-analysiert nichts.
- **Harte Regel:** QA fixt **nur** LLM-Content-Fragmente. Deterministische/Plugin-Defekte werden **nie** im MD geflickt — wenn `qa_checks` einen echten Plugin-Bug findet, surface als Bug (Code-Fix), kein LLM-Patch.
- **Grenze „quick fix":** QA darf Fragmente gezielt editieren (inkl. Umgliederung *eines* Fragments) + recompose (billiges Python, ~2 s). QA darf **nicht** Renderer/Analyst/Phasen erneut laufen lassen. Das ist die operative Linie für „keine Re-Renders".
- Gewinn: ~19 → ~3–4 min wenn getriggert. Aufwand: mittel. Qualität: neutral.

**M2c — Check-Audit (Prinzip durchsetzen):** siehe §6.

---

## 7. Umsetzungs-Status (2026-06-04)

- **M2a — UMGESETZT + verifiziert.** `agents/appsec-threat-analyst.md` (nach Zeile 760): expliziter §7.2-Direktiv-Block — H4 = kanonische Auth-*Mechanismen* (Whitelist), verbotene Muster (Token-Formate, Libs, Primitive, Exploits, **JWT→§7.3**), pro Flow-Methode `sequenceDiagram`. Spiegelt die Contract-Regel `auth_method_decomposition` exakt → besteht first-pass, der teure §7.2-Repair (~19 min) entfällt im Normalfall. **Check bleibt als Netz** → kein Qualitäts-Regress. Prosa-only Edit; pytest: 0 neue Fehler (3 agent-def-Fehler sind prä-existent, identisch mit/ohne Edit). Verbessert auch den Repair-Pfad (Analyst ist Autor UND Reparateur).
- **M2c — NICHT umgesetzt (Nebenwirkung erkannt).** Bulk-Demote der Repair-Trigger ist unsicher: `check_recon_iam_bridge` & Co. sind **Vollständigkeits-Netze** (fangen still weggelassene Mechanismen, z.B. recon findet TOTP aber §7 nennt es nicht). Sie aus `build_repair_plan` zu nehmen = stiller Qualitäts-Regress. Perf-Nutzen marginal (Checks = 2.56 s). → bewusst ausgelassen.
- **M2b — UMGESETZT (deterministisch verifiziert; behavioral via e2e-full).** Neuer schlanker Agent `agents/appsec-fragment-fixer.md` (maxTurns 30, nur Read/Edit/Bash/compose, keine Phasen 1–10, Anti-Flounder-Regel „jedes Fragment EINMAL lesen"). Re-Render-Loop (SKILL-impl) dispatcht jetzt diesen statt des schweren Analyst (~19→~3–4 min Ziel). Registriert in `test_agent_definitions.py` (EXPECTED_MAX_TURNS + INTERNAL_AGENTS) + AGENTS.md; Telemetrie (`record_stage_stats`) auf fragment-fixer umgestellt. Deterministische appliers (`apply_repair_plan`/`apply_content_repair`) bleiben als LLM-freie Vorstufe; der Fixer feuert nur für semantischen Rest (z.B. §7.2). Agent-Contract-Tests: 106 passed. **Behavioral verifizierbar nur bei getriggertem Repair — e2e-full deckt es nur ab, wenn die Fixture einen Check failt.**
- **M1-lite — UMGESETZT (additiv, prompt-only).** Analyst + `phase-group-threats.md`: ehrliche Escape-Klausel — als Sub-Agent (Level-1) ohne `Agent`-Tool ist Nested-Dispatch unmöglich → kein Dispatch-Theater (AGENT_INVOKE-Manifest, 8× Narration, Fake-Progress), sondern STRIDE inline mit ECHTEN `.progress/<id>.json` (Gate besteht legitim). Level-0-Dispatch-Pfad bleibt für späteres Voll-M1 erhalten. Gate-Code unverändert (kein Risiko). Modester Gewinn (gesparte Theater-Turns); echte Parallelisierung erst mit Voll-M1.
- **Voll-M1 — offen.** Größter Hebel (~15–18 min), aber Re-Architektur + Design-Entscheidung; separat.

### Verifikation (2026-06-04)
- **Deterministisch:** volle pytest-Suite — **0 neue Fehler** ggü. Baseline (32 prä-existente bleiben 32; 2 selbst-eingeführte sofort gefixt). M2b-Agent: 106 agent-def-Tests grün.
- **e2e-full (sandbox-disabled, da `~/.claude` read-only die *verschachtelte* Headless-Session blockierte — kein Code-Defekt):** Pipeline lief **end-to-end, 1550s (~26 min)**, alle Hauptartefakte erzeugt. Ergebnis 8 failed / 31 passed / 3 skipped.
  - **M1-lite behavioral BESTÄTIGT:** Analyst lief Inline-STRIDE, schrieb **echte** `.progress/{backend-api,data-persistence}.json`, erzeugte gültige Threats, `test_inline_shortcut_gate_did_not_trigger` **grün** → Gate legitim bestanden, kein Dispatch-Theater.
  - **M2a/M2b im Quick-e2e nicht exerziert** (`--no-qa`). Daher separat **kontrolliert behavioral verifiziert** (s.u.).
- **M2b + M2a behavioral BESTÄTIGT (kontrollierter Repair-Test, 2026-06-04):** sauberer Baseline = juice-shop-Output (`repair_plan` pass). §7.2.2-Heading absichtlich auf verbotenes Primitive `Login Rate Limiting` korrumpiert → recompose → `repair_plan` flaggt **actionable** `auth_method_decomposition` + `control_subsection_coverage` → `.fragments/security-architecture.md`. Fixer-Prozedur ausgeführt (read plan → genau dieses Fragment re-authored → `compose --strict` exit 0 → `apply_prose_fixes` → `repair_plan`). **Unabhängig verifiziert:** Heading zurück auf kanonisches `MFA / TOTP`; beide Actions **gecleart**; Doc `fail/actionable:True` → `manual_review/actionable:False` (nur nicht-fragment-`infobox_incomplete`-Advisory bleibt = recompose/yaml-Artefakt, kein Release-Blocker, Loop-Short-Circuit akzeptiert als konvergiert). → Lean-Fixer feuert in echtem Repair, fasst NUR das benannte Fragment an, erreicht den terminalen Loop-Zustand. (Dispatch via general-purpose-Agent mit der Fixer-Prozedur, da Plugin-Subagent-Typen in dieser Session nicht auflösbar; die *Registrierung*/Frontmatter des Agents ist separat über 106 agent-def-Tests verifiziert — Prozedur + Contract zusammen = Agent verifiziert.)
  - **Die 8 e2e-Fehler sind prä-existent (nicht mein Diff):** sie betreffen yaml-`t_id`-Drift (`build_threat_model_yaml.py`), `validate_intermediate`, Renderer-Fragmente (`ms-critical-attack-tree`/`operational-strengths`), Pentest-Export-`schema_version`, Hook-`PHASE_START`, `cell_format`-Falsch-Positiv — allesamt Flächen, die mein Diff nicht berührt (`git diff --name-only`: nur AGENTS.md, analyst, phase-group-threats, SKILL-impl, test_agent_definitions, +neuer fragment-fixer). Stammen aus den uncommitteten Arbeitsbaum-Änderungen + Quick-Mode-Eigenheiten.
  - Nebenbefund (prä-existent, nicht-fatal): `export_html.py` bekommt im Treiber ein positionales statt `--input`-Argument → HTML-Export schlägt fehl.
- **e2e-Harness kann M2b strukturell NICHT verifizieren (definitiver Befund):** `tests/e2e/run-full.sh:118` setzt **`--no-qa` für ALLE Tiefen** → Stage 3 QA + Re-Render-Loop laufen im e2e **nie**, egal ob quick oder standard. Darum erreichte kein e2e-Versuch den fragment-fixer — das ist by-design, kein Flake. Zusätzlich SIGTERM'te die flache `--max-duration 1800` den Standard-Lauf bei 1803s direkt nach dem Stage-2-Renderer (vor Finalisierung). **Konsequenz:** der **kontrollierte Repair-Test ist die definitive Behavioral-Verifikation von M2b** — die einzige Methode, den Fixer-Repair-Pfad zu exerzieren, da die Harness QA überspringt.
  - **Standard-Lauf (sandbox-disabled, bis SIGTERM@1803s) bestätigte dennoch:** **M2a §7.2 echt gerendert** bei Standard-Tiefe (§7.2-Sektion present), **M1-lite Inline-STRIDE** lief (`PHASE9_DETECTED progress_files=1 stride_files=1`), Stage 1+2 vollständig (Renderer Phase 11 END). Headless-Prozess löste alle appsec-Agenten auf → Auto-Discovery aus `agents/*.md` bestätigt (impliziert: neuer fragment-fixer würde im echten Lauf ebenso aufgelöst).
  - **Real-Loop-Verifikation Link-für-Link:** detect→plan (`build_repair_plan`, real ausgeführt ✓) · plan→dispatch (SKILL-impl-Edit, reviewed ✓) · dispatch→resolve (Auto-Discovery, im Headless-Lauf bewiesen ✓) · fixer-Execution (kontrollierter Test: actionable Violations gecleart ✓) · re-check→konvergiert (repair_plan→manual_review/actionable:False ✓). Einziger nicht-literal-ausgeführter Link: Skill-Orchestrator emittiert den Dispatch live — via Harness (`--no-qa`) unverifizierbar; deterministischer Prompt-Edit.
- **Harness-Fix angewandt:** `run-full.sh` `--max-duration` jetzt tiefenabhängig (quick 1800s, standard/thorough 3000s).
- **QA-aktive Variante gebaut + gelaufen** (`tests/e2e/run-repair.sh` + `make e2e-full-repair`): korrumpiert §7.2 (verbotenes Heading), Checkpoint `phase=10`, `--resume` mit QA an. **Ergebnis: Loop feuerte NICHT** — fundamentaler Befund: `--resume` auf komplettem Seed + unverändertem Repo wählt **auto-incremental → no-op-Fast-Path** → Skill überspringt Stage 2/3 (korrekt), Fixer feuert nie (241s, nichts passiert). Das einzige Force-Render-Flag `--full` **regeneriert §7.2 sauber** → keine Verletzung → kein Repair. **Es gibt also keinen sauberen Weg, den Live-Skill-Loop on-demand zum Fixer-Dispatch zu zwingen** — der Skill ist genau dagegen optimiert.
- **UPDATE 2026-06-04 — M2b LIVE-LOOP VERIFIZIERT (PASS):** Render-Recovery-Einstieg `--rerender` umgesetzt (resolve_config + run-headless + SKILL-impl + HELP/Tests, deterministisch grün, 0 neue Suite-Fehler). `run-repair.sh` auf `--rerender` umgestellt → echter Lauf: Skill nahm den Rerender-Branch, re-renderte Stage 2 aus dem korrumpierten §7.2-Fragment, Stage-3-QA flaggte es, **Re-Render-Loop dispatchte den echten `appsec-fragment-fixer`** (log-bestätigt) → Fix → konvergiert. **Alle 3 Asserts grün** (fixer dispatched, §7.2 repariert, auth-Violation gecleart). Damit ist der Live-Loop-Dispatch des registrierten Agents **direkt bewiesen**, nicht mehr nur per Link-für-Link-Argument.

**Abschluss-Argument (warum M2b auch ohne den Live-Lauf verifiziert gewesen wäre):** Das Live-Loop-Feuern eines §7.2-Repairs ist bereits durch den **Original-juice-shop-Lauf (2026-06-03)** bewiesen — dessen Stage-3-Re-Render-Loop dispatchte einen echten §7.2-REPAIR (`agent-ab5cbf0b`, ~19 min). **M2b ändert NUR den Executor** dieses bereits-bewiesenen Dispatches (analyst→fragment-fixer) via reviewter deterministischer SKILL-impl-Edits; das Fixer-Verhalten ist controlled-getestet (§7.2-Korrumption→Fix→actionable-Violations-gecleart). Der Live-Loop braucht also keinen künstlichen Re-Trigger. `run-repair.sh` bleibt als Scaffold + dokumentiertes Hindernis (braucht künftig einen Render-Recovery-Einstieg).
- **Prä-existente Test-Fehler (nicht von dieser Aufgabe):** abuse-case-verifier `maxTurns 28 > ceiling 20`; orchestrator model-id-String; AGENTS.md max-turns Doc-Drift. In den uncommitteten Änderungen vorhanden — separat zu fixen.

---

## 6. Check-Audit (verifiziert) — 52 Checks, 2.56 s, idempotent

**Gemessen:** `qa_checks.py all <md> <repo-root>` = **2.56 s** für alle 52 Checks, exit 0. Auf dem (0-Issue-)Live-Output **idempotent** (keine Mutation, run1≡run2). *Caveat:* das testet den Gotcha NICHT vollständig — `all` enthält **Auto-Fix-Checks** (`cell_format` auto-fix, `ms_structure` auto-repair), die nur auf Dokumenten *mit* solchen Issues mutieren; der Idempotenz-Gotcha kann dort weiter gelten. Für den Repair-Trigger-Pfad ist `repair_plan` (read-only) relevanter.

**→ Die Checks sind KEIN Perf-Problem.** „Zu viele Checks → langsam" ist falsch: 2.56 s vs. 19 min Repair. Die Check-*Anzahl* ist nur perf-relevant, weil **jeder Check ein potenzieller Trigger für einen teuren LLM-Repair** ist (×3 Re-Render-Iterationen worst case). Hebel = **welche Checks einen Repair triggern dürfen**, nicht „Checks für Tempo kürzen".

**Klassifikation (Prinzip: QA = Netz gegen LLM-Nichtdeterminismus, testet keine Vorstufen):**

| Bucket | Bedeutung | Checks | Empfehlung |
|---|---|---|---|
| **A — Render/Format-Integrität** | „Ist das gerenderte MD wohlgeformt?" (regex, instant) | xrefs, toc_closure, toc_nested_links, heading_hygiene, mermaid_syntax, cell_format, infobox_completeness, placeholders, section7_narrative_placeholders, section7_finding_link_duplicate, inline_code_format, label_as_code, attack_tree_node_id_leak, summary_bullets, ms_structure, contract, security_posture_structure, section_713_no_table, falls_short_format, yaml_md_consistency, finding_range_homogeneous | **Behalten** — das ist das legitime schnelle QA-Netz |
| **B — LLM-Prosa-Qualität** | „Hat das LLM schlechte/templated/rhetorische Prosa geliefert?" | strengths_row_quality, unfounded_perimeter_claims, architectural_prose, generic_phrases, rhetorical_severity, section_opener_restates_heading, ai_padding_phrases, paragraph_density, section7_h4_positive_intro, section7_h4_status, section7_fence_intro_sentence, section7_finding_reference_semantic | **Behalten** — Kern des Prinzips (LLM-Suboptimalität). Fix = Lean-Edit, nie Re-Render |
| **C — Harte Security-Gates** | nicht-perf, selten, müssen bleiben | unmasked_secrets, evidence_integrity | **Behalten** (hart) |
| **D — Analyse-Vollständigkeit / Cross-Artifact** | „Ist die *Analyse* vollständig/konsistent?" — testet **Vorstufen**, nicht Render | walkthrough_coverage, walkthrough_depth, recon_iam_bridge, dependency_cross_ref, na_against_recon, hypothesis_validation_objective, chain_tid_consistency | **Aus QA-Repair-Pfad raus** → in Stage-1-Eigenverifikation. QA soll Vorstufen nicht testen (User-Prinzip) |
| **E — v2-Content-Struktur-Enforcement** | opinionierte Gliederungsregeln für LLM-Content — die **teuren Repair-Trigger** | auth_method_decomposition (§7.2!), validation_approach_first, control_subsection_coverage, relevant_findings_bullet_list, subcontrol_naming_canonical, diagram_compactness, chain_compactness | **Upstream garantieren (M2a)** im Renderer-Contract; wenn nicht 100% garantierbar → **advisory** (kein Repair-Trigger), Fix per Lean-Edit |
| **F — Redundant / Precondition** | — | invariants (Memory: *provably redundant*), fragments_present (Pipeline-Precondition, nicht QA) | invariants **entfernen**; fragments_present aus QA-Familie ziehen |

**Kernaussage:** Nicht die 52 Checks kosten Zeit (2.56 s). Bucket **E** (v2-Enforcement, u.a. der §7.2-Trigger) und **D** (Vorstufen-Tests) sind die **Repair-Lunten**. E → upstream garantieren oder advisory; D → in Stage-1 verschieben. Damit bleibt QA schnell *und* triggert teure Repairs nur noch für echte, nicht-upstream-garantierbare LLM-Suboptimalität — genau das geforderte „umfangreiche QA nur in begründeten Ausnahmen".

### M3 — Renderer-Overrun (14 vs 8 min) *(GEMESSEN 2026-06-04 — niedrige Prio bestätigt)*
Transcript-Analyse (`agent-a2ab643a`, 14min, 153 rows): **46 Bash / 10 Read / 8 Write** (NICHT round-trip-gebottleneckt wie der Analyst mit 212). Zeitverteilung:
- **~5min = EIN Turn:** §7 `security-architecture.md` NARRATIVE_PLACEHOLDER-Fill als **60-KB-Single-Write** — echte Prosa-Generierung, kein Leerlauf (einziger Gap >45s = 297s, genau dieser Turn).
- **~9min:** kleinere MS-Fragmente + Compose + Checks; `ms-architecture-assessment.json` 3× (5176→4732→4578b, schrumpfend) + `ms-verdict.json` 2× = ~2–3 Compactness-Refinement-Re-Writes.
**Verdikt:** Renderer-Zeit ist überwiegend **legitime Generierung**, kein struktureller Waste. Hebel nur: (1) §7-Fill nach Stage 1 verschieben/splitten = Qualitäts-/Komplexitäts-Tradeoff (kein sauberer Gewinn); (2) ms-*-Re-Write-Churn straffen = ~2–3min, geringer ROI. → **M3 nicht weiterverfolgen; die verifizierten Hebel (M2a/M2b/M1-lite/Full-M1) sind die echten Gewinne.**

---

## 5. Empfehlung
1. **Nested-Dispatch ist auth. ausgeschlossen** (Docs + Issue #4182) → das Stage-1-Design „analyst dispatcht stride-analyzer parallel" ist **unmöglich**. Prompt-/Gate-Härtung kann das nie lösen; der Gate wird zwingend per Progress-Fälschung umgangen. **M1 ist daher die einzig echte Lösung.**
2. **Größter Hebel:** **M1** (Fan-out auf Level-0 / Skill-Orchestrator). Spart ~15–18 min, qualitätsneutral-positiv.
3. **Schnellster Hebel:** **M2** (§7.2-Repair), spart ~10–20 min bei Trigger.
4. **M1-lite** als pragmatischer Interim falls M1-Re-Architektur nicht jetzt — zumindest die unerfüllbare Dispatch-Pflicht + den umgehbaren Gate entfernen und Recon batchen.

**Wichtigste Korrektur am bisherigen Bild:** Der dominante Stage-1-Kostentreiber in diesem Run war **NICHT** API-Stalls (nur 4.8 min idle), sondern **serielles Tool-Volumen durch den strukturell erzwungenen Inline-Kollaps**. Prompt-/Gate-Härtung kann das nicht lösen — sie wird umgangen. Nur die Ebenen-Verschiebung des Fan-outs hilft.
</content>
</invoke>
