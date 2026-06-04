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

### M3 — Renderer-Overrun (14 vs 8 min) *(sekundär)*
Separat untersuchen; Qualitätsrisiko bei Hau-Ruck → niedrige Prio.

---

## 5. Empfehlung
1. **Nested-Dispatch ist auth. ausgeschlossen** (Docs + Issue #4182) → das Stage-1-Design „analyst dispatcht stride-analyzer parallel" ist **unmöglich**. Prompt-/Gate-Härtung kann das nie lösen; der Gate wird zwingend per Progress-Fälschung umgangen. **M1 ist daher die einzig echte Lösung.**
2. **Größter Hebel:** **M1** (Fan-out auf Level-0 / Skill-Orchestrator). Spart ~15–18 min, qualitätsneutral-positiv.
3. **Schnellster Hebel:** **M2** (§7.2-Repair), spart ~10–20 min bei Trigger.
4. **M1-lite** als pragmatischer Interim falls M1-Re-Architektur nicht jetzt — zumindest die unerfüllbare Dispatch-Pflicht + den umgehbaren Gate entfernen und Recon batchen.

**Wichtigste Korrektur am bisherigen Bild:** Der dominante Stage-1-Kostentreiber in diesem Run war **NICHT** API-Stalls (nur 4.8 min idle), sondern **serielles Tool-Volumen durch den strukturell erzwungenen Inline-Kollaps**. Prompt-/Gate-Härtung kann das nicht lösen — sie wird umgangen. Nur die Ebenen-Verschiebung des Fan-outs hilft.
</content>
</invoke>
