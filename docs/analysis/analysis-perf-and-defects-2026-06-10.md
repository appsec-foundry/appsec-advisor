# Performance- & Defekt-Audit — 2026-06-10

Drei parallele Audits (Python-Hotspots, Orchestrierung, Defekt-Verifikation) gegen
repo @ `41d6b90`, empirisch gegen reale juice-shop-Artefakte (427 KB Report,
300 KB threat-model.yaml, 68 Threats, 26 Mermaid-Diagramme) gemessen.
Verifikationsstatus: read-only, keine Änderungen vorgenommen.

---

## P1 — Funktionsbug (still): Abuse-Chain-Severity-Fold no-opt im Default-Run

**Status: OFFEN.** Der Aktivierungs-Hook (Step 3b2, `SKILL-impl.md:2456-2460`) ist
gelandet, aber `triage_compute_ranking.py:981-982` exitet sauber, wenn
`APPSEC_TRIAGE_DETERMINISTIC=1` nicht im *Shell*-Env steht — und nichts setzt es
dort (kein Env-Prefix, kein `--force`; `|| true` schluckt die Meldung; user-global
settings.json enthält nur `CLAUDE_PLUGIN_ROOT`/`TZ`). Netto: verifizierte
Abuse-Chains heben `effective_severity`/§1/§8-Ranking **nie** an.

Das ist die dokumentierte Env-var-erreicht-Skill-Bash-nicht-Gotcha in neuer Form.

**Fix-Richtung:** `APPSEC_TRIAGE_DETERMINISTIC=1`-Prefix oder `--force` am
3b2-Aufruf; besser: auf Artefakt-Marker statt Env-Var gaten (z. B.
`.triage-flags.json` ranking-Block).

## P2 — Perf HIGH: export_pdf.py spawnt mmdc/Chrome pro Diagramm, seriell

`scripts/export_pdf.py:315-345`: jeder ```mermaid```-Block →
`subprocess.run(["mmdc", ...])` = Node+Puppeteer+Chrome-Boot (~2–5 s) pro
Diagramm. 26 Diagramme ≈ **1–2+ min** serieller Chrome-Starts pro Export.
Das Batch-Pattern existiert bereits: `scripts/mermaid_validate.mjs --batch-json`
(qa_checks.py:4175 macht EINEN Node-Spawn für alle Blöcke).
**Fix:** Diagramme durch eine Puppeteer-Session batchen (oder 4-way Pool ≈ 4×).

## P3 — Token-/Wall-Clock-Waste: ms-architecture-assessment.json wird jeden Run geauthort, aber nie gerendert

Render-Pfad tot (MS-Compose-Loop `compose_threat_model.py:8191-8210` enthält
`architecture_assessment` nicht; Contract `sections-contract.yaml:523-528` sagt
"merged"). **Aber** die Producer-Seite ist voll live:

- Renderer-Agent contractually verpflichtet (`appsec-threat-renderer.md:31,:123,:170,:267`)
- beide Stage-2-Dispatch-Pfade (`SKILL-impl.md:2578,:2624`)
- `qa_checks.py:8497-8499` REQUIRED_FRAGMENTS **unconditional**
- `validate_ms_compactness.py:83-119` Wortlimit-Gate auf nie-gerendertem Fragment
- Schema + `validate_fragment.py:75,:179`

LLM-Tokens jede Stage-2 + 3 Gates für null Output-Bytes. Entfernung muss
bidirektional sein (AGENTS.md §4) über: Agent-Def, SKILL-impl (2×), qa_checks
(REQUIRED_FRAGMENTS + Repair-Plan-Ref :2118), validate_ms_compactness,
validate_fragment, Schema, compose-Mappings (:135,:154-156,:6309-6336,:13748),
Templates. Bewusster Cleanup-Task, kein Drive-by.

**Verwandt:** `qa_checks.py:~2118-2127` `forbidden_ms_heading`-Remediation nennt
veraltete MS-Reihenfolge ("…/ Architecture Assessment /…") und zeigt
`fragments_to_rewrite` aufs tote Fragment → kann den fragment-fixer in die Irre
schicken (Familie bug_stage2_repair_loop_wrong_fragment).

## P4 — Strukturell: Stage-1-Kopf-Fan-out lebt auf Level-1 (plattform-gefiltert)

`appsec-threat-analyst.md:461-467` instruiert den Level-1-Analyst,
context-resolver/recon-scanner/config-scanner parallel zu dispatchen — nested
Dispatch wird zur Laufzeit gefiltert (Issue #4182) → degradiert zu seriell/inline,
konsistent mit dem gemessenen ~6m24-Recon-Monolith. STRIDE/Abuse/Render wurden
alle auf Level-0 gehoben, dieser Fan-out nicht. Erwarteter Gewinn 1–3 min
(recon-scanner ist long pole). **Vor Invest live verifizieren**, ob Level-1-Dispatch
aktuell inlined.

## P5 — Strukturell: Analyst-B = Voll-Analyst-Respawn für überwiegend deterministischen Tail

`SKILL-impl.md:2011`: Phase 9-merge→10→10b→11(1–3) = meist Script-Plumbing, läuft
aber als voller analyst (300 maxTurns, 1440-Zeilen-Prompt), ~3–6 min serieller
Merge-Barrier-Tail. **Fix:** schlanker merge-coordinator (fragment-fixer-Pattern)
oder deterministische Kette in Skill-Bash hochziehen, nur Phase-10-Judgment im
kleinen Agent (Seam existiert: appsec-threat-merger).

## P6 — Perf MED: agent_logger-Hook ~48 ms × Pre+Post auf jedem Tool-Call

`hooks/hooks.json`: 4 Events → `python3 scripts/agent_logger.py`; 48 ms median
(12 ms Interpreter + ~35 ms Imports). Realer Run: 1246 PostToolUse → ≥2500 Spawns
≈ **~2 min kumulativ pro Scan** (3–5 % eines 40–60-min-Runs), feuert auch in jeder
Dev-Session. **Fix:** Lazy Imports (hashlib/re/datetime in Branches) + Early-Exit
vor Imports für gefilterte Events; Interpreter-Floor bleibt.

## P7 — Perf LOW: compose ohne CSafeLoader + doppeltes Re-Parse

13× `yaml.safe_load` (pure-Python) = 1,27 s von ~3,5–4 s compose-Run;
threat-model.yaml (300 KB) wird in `main()` (L15104/L15191) ZWEIMAL erneut von
Platte geparst (Kommentar L15101 gibt es zu); Taxonomie 3× geparst, nur 1×
gecacht (L12731 umgeht `_TAXONOMY_CACHE`). CSafeLoader ist verfügbar und 11×
schneller — qa_checks hat den Fix schon (`_fast_yaml_load` L229), compose nie
übernommen. ~1,2 s × 2–6 Invocations/Pipeline. Trivial, risikofrei.

## P8 — Lint: 114 Ruff-Fehler in committetem Code

`make lint` FAILS: 44 F401, 37 I001, 17 UP037, 6 F541, **3 F821**, 2 E702, 2 B033;
108 auto-fixbar. F821-Highlights:
- `compose_threat_model.py:3293` — `... if False else None # late init below`,
  undefinierter Name hinter Dead-Guard (reine Verwirrung)
- `pregenerate_fragments.py:3103,:3267` — `Optional` ohne Import (nur durch
  `from __future__ import annotations` gerettet)

pytest-Collection sauber (3751 Tests, 4,85 s, keine Collection-Errors).

## P9 — Latent: qa_checks `_replay_absence_grep` ohne Cache, Default-Pfad `["."]`

`qa_checks.py:2552-2611`: pro Absence-Claim voller `os.walk`+read der
search_paths, kein Cache über Claims. Heute OK (enge Pfade, 1,06 s gesamt), aber
leere `search_paths` defaulten auf `["."]` = N Full-Repo-Scans auf Monorepos.
**Fix:** Memoize (base→filelist, path→text) pro check_evidence_integrity-Call.

## Geklärt / nicht (mehr) offen

- **§7-Numbering-Drift (7.9 AI/LLM): NICHT reproduzierbar auf v2-Pfad.**
  `_SECARCH_SUBSECTIONS` ist v1-only (Konsument nur `gen_security_architecture`);
  v2 hat `_V2_SUBSECTIONS` (pregenerate:4649), deckungsgleich mit Contract
  (7.9 = Cryptography). Nur Verwirrungs-Restrisiko zweier Listen in einer Datei.
- **Phase-10b-Triage-Burn: GEFIXT** (anders als geplant) — kein `--apply` nötig;
  10b ist deterministisch + ein ~30s-Ranking-Agent; deterministic-triage macht
  triage_compute_ranking zum Severity-Owner.
- **fragments_to_rewrite-Scope: GEFIXT** — harte Whitelist
  (phase-group-finalization.md:588-601) + schlanker appsec-fragment-fixer
  (maxTurns=30) statt Voll-Analyst; drift-guarded.
- **STRIDE `\!`-Escapes: GEFIXT deterministisch** —
  `merge_threats.py:125-165` `_strip_invalid_json_escapes` + Pre-Merge-Validation
  mit gebatchtem Re-Dispatch.
- **Requirements-Compliance-§: GEFIXT** (cd88c74) — meta.check_requirements wird
  gesetzt, Fragment geauthort, Skill verdrahtet, E2E-Fixture rendert §7b.
  Randfall: `--rerender` über prä-cd88c74-yaml rendert §7b weiterhin nicht
  (compose liest nur yaml-meta, kein skill-config-Fallback).
- **Alle Repair-/QA-Loops gedeckelt** (max 1+2+3+3), keine unbounded Loops;
  Budget-Flag-Clears vorhanden; Kontext-Hygiene der Agents verteidigt.
- **Sauber gemessen (CLEAN):** qa_checks all 1,06 s; pregenerate 0,74 s;
  merge 0,38 s; triage 0,05 s; alle übrigen Scripts sub-second.

## Kleinkram

- Totes Template-Paar `templates/fragments/management-summary.md.j2`
  (0 Referenzen, included den toten architecture-assessment-Pfad).
- Stale Docstring `pregenerate_fragments.py:21` (ms-architecture-assessment als
  "pregenerated" gelistet — ist LLM-authored).
- §7-Unbundling weiterhin offen: secarch-Rolle authort alle 13 Subsections in
  EINEM Dispatch (Stall-Single-Point, ~5 min); Split 2–3 Sub-Rollen nach
  secarch/ms-Muster — Gewinn eher Stall-Varianz als Mittelwert.
- Stage-2-Inline-Shortcut-Retry re-dispatcht vollen Renderer (max 2×, worst
  +10 min) — begründbar, low priority.

## Empfohlene Reihenfolge

1. **P1** (Funktionsbug, 1-Zeilen-Fix + Test) — Feature ist sonst tot.
2. **P2** (export_pdf batchen — Minuten pro Export).
3. **P8** (`ruff check --fix` + 3 F821 manuell — billig, hygienisch).
4. **P7** (CSafeLoader in compose — trivial).
5. **P6** (agent_logger lazy imports — ~1–2 min/Run).
6. **P3** (architecture-assessment-Cleanup — bewusster bidirektionaler Task).
7. **P4/P5** (strukturell, erst live verifizieren bzw. größerer Umbau).
