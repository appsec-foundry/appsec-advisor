# Bugs (gefunden 2026-05-05, verifiziert 2026-05-05)

Aufgenommen während Quick-Mode-Optimierungs-Analyse anhand des juice-shop-Runs vom 2026-05-04 (`/home/mrohr/juice-shop/docs/security/`). Keiner dieser Bugs ist quick-mode-spezifisch — sie schlagen bei jeder Tiefe zu.

Alle Befunde verifiziert durch Code-Inspektion und Log-Analyse.

---

## Mit Funktions-Impact

### Bug 1 — Stage-3-QA-Routing greift nicht durch

**Quellen-Diskrepanz für das tatsächlich verwendete QA-Modell:**

| Quelle | Wert |
|---|---|
| `.stage-stats.jsonl` | `claude-haiku-4-5` |
| `.hook-events.log` AGENT_SPAWN | `model=sonnet` |
| `.hook-events.log` ASSESSMENT_MODELS | `qa-reviewer=sonnet` |
| `.qa-status.json` (vom Agent geschrieben) | `claude-sonnet-4-6` |

**Verifizierte Root-Cause:**

`SKILL-impl.md:1986-2005` berechnet `QA_MODEL=$QA_ROUTINE_MODEL` (bei haiku-economy/standard = Haiku). `SKILL-impl.md:2008` instruiert: *"Pass `model: $QA_MODEL` in the Agent tool dispatch alongside the prompt parameters."*

**Vergleich mit Stage 4 (Architect, `SKILL-impl.md:2240`)**: dort ist die Anweisung viel stärker formuliert — *"**pass the `model` field explicitly** so the frontmatter default is overridden"*. Stage 3 hat diese explizite Markierung **nicht**, weshalb das LLM den `model:`-Hinweis nicht zwingend als Hard-Override interpretiert.

`agents/appsec-qa-reviewer.md:5` setzt `model: sonnet` als Frontmatter-Default — das greift, wenn der Agent-Tool-Call kein explizites `model:`-Feld bekommt.

Zusätzlich: `SKILL-impl.md:2027` zeigt im `record_stage_stats.py`-Beispiel `--model claude-sonnet-4-6` **hardcoded**. Im juice-shop-Run wurde dort offenbar zur Laufzeit `$QA_MODEL` (Haiku) eingesetzt, während der Agent-Dispatch parallel den Sonnet-Frontmatter-Default griff.

**Impact:** Bei jedem haiku-economy-Run läuft Stage 3 ungewollt auf Sonnet. Geschätzt 2-3 min Mehr-Wall-Clock und ~3× höhere Token-Kosten als beabsichtigt. Cost-Reports unterschätzen die tatsächlichen Ausgaben (stage-stats sagt Haiku, Sonnet wurde abgerechnet).

**Fix-Hinweis:** Z. 2008 mit gleicher Stärke wie Z. 2240 formulieren: explizit als "pass model field explicitly" markieren. Außerdem `record_stage_stats`-Beispiel auf `--model "$QA_MODEL"` ändern.

---

### Bug 2 — `compose_threat_model.py` identifiziert sich als `render_threat_model.py`

**Code:** `scripts/compose_threat_model.py:5512` setzt `prog="render_threat_model.py"` im ArgumentParser.

**Sichtbar im Log** (juice-shop, `.hook-events.log` 06:49:34):
```
cmd=python3 .../compose_threat_model.py ...
resp={'stdout': 'usage: render_threat_model.py [-h] ...'}
```

**Impact:** Bei Argument-Fehlern bekommt der Aufrufer eine `usage:`-Zeile, die auf den **alten, separat existierenden** `render_threat_model.py` (Legacy-Renderer für Marker-Substitution) verweist. Falsche Fehlermeldung → Debugging-Zeit verschwendet. Leftover vom Rename während der Composer-Migration.

**Fix-Hinweis:** Zeile 5512: `prog="compose_threat_model.py"`. Trivial.

---

### Bug 3 — Hex-Color-Typo in `sections-contract.yaml` (verschärfter Befund)

**Symptom war zuerst:** `.qa-status.json` zeigte `status: "pass"` aber `repair_plan_actionable: false`, `contract_status: "manual_review"` mit Notes *"posture_structure E4: attack-arrow linkStyle uses #b71c1c; expected #b91c1c — cosmetic colour difference, non-blocking"*.

**Verifizierter Root-Cause** (deutlich klarer als zunächst angenommen): **Inkonsistenz INNERHALB von `data/sections-contract.yaml`**:

| Stelle | Wert |
|---|---|
| `data/sections-contract.yaml:345` (E4 rule narrative) | `#b91c1c` ⚠️ |
| `data/sections-contract.yaml:534` (style spec) | `#b71c1c` |
| `data/sections-contract.yaml:544` (style spec) | `#b71c1c` |
| `data/sections-contract.yaml:672` (style spec) | `#b71c1c` |
| `scripts/qa_checks.py:3608` | sucht `#b71c1c` |
| `scripts/pregenerate_fragments.py` (5 Stellen) | generiert `#b71c1c` |
| `templates/fragments/security-posture-diagram.md.j2:80` | nutzt `#b71c1c` |

→ Code, Templates und 3 von 4 Contract-Stellen verwenden `#b71c1c`. **Nur Z. 345 ist ein Typo** (`#b91c1c`). Der QA-Check selbst passt — aber ein zweiter Check (vermutlich der "narrative-vs-style"-Konsistenz-Check) liest die Z. 345 als Spec und meldet die Diskrepanz.

**Impact:** User-Status-Output suggeriert "Manual Review needed" für einen Hex-Typo der nirgendwo Verhalten ändert. Kostet Aufmerksamkeit für ein Nicht-Issue.

**Fix-Hinweis:** Eine Zeichen-Änderung in `data/sections-contract.yaml:345`: `#b91c1c` → `#b71c1c`. Trivial.

---

## Logging/Telemetry-Bugs

### Bug 4 — Phase-Boundary-Logging zerschossen (drei separate Issues)

Aus `.agent-run.log` des juice-shop-Runs:

| Phase | PHASE_START | PHASE_END | Verifizierte Ursache |
|---|---|---|---|
| 1 Context | ✓ 15:23:35 | **fehlt** | `phase-group-recon.md:7` dokumentiert Parallel-Dispatch-Pattern für Phase 1+2 ("zero data dependencies"). Phase 1 läuft im Background, kein PHASE_END im Anweisungstext für den Background-Agent-Pfad. |
| 9 STRIDE | ✓ **2×** (15:35:48 + 15:39:10) | ✓ 15:59:12 | **Zwei verschiedene Anweisungsstellen** für Phase 9 PHASE_START mit unterschiedlichem Format: `phase-group-threats.md:316` (`STRIDE Enumeration — dispatching <N> analyzer(s)`) und `appsec-threat-analyst.md:1214` (`STRIDE Threat Enumeration — <n> components (expect ~15m)`). Der Run im Log matcht beide Formate → beide werden ausgeführt. |
| 10/10b | **fehlt** | 3× 15:59:12 | `phase-group-threats.md:1391` definiert PHASE_END für Phase 10. **Keine PHASE_START-Anweisung** für Phase 10 oder Phase 10b im Anweisungstext gefunden. |
| 11 Finalization | **fehlt im Run** | ✓ 16:20:15 | `phase-group-finalization.md:81` definiert PHASE_START und sogar einen crash-safe `trap` (Z. 89) — aber im juice-shop-Run wurde es nicht emitted. LLM hat die Anweisung übersprungen. |

**Konsequenz:** `ASSESSMENT_PHASES`-Aggregator funktioniert auf PHASE_START+PHASE_END-Pairs. Im Run-Summary fehlen die Phasen 1, 10, 10b, 11 komplett:
```
Phase 2 ... Phase 2.5 ... Phase 3 ... Phase 4 ... Phase 5 ... 
Phase 6 ... Phase 7 ... Phase 8 ... Phase 9 ...
```

**Impact:** Phase 11 alleine war 19:47 — die fehlt im Cost-Allokations-Block. Cost-pro-Phase-Telemetrie ist damit **kaputt für die teuerste Phase**.

**Fix-Hinweise:**
- Phase 1 PHASE_END: nach Background-Agent-Return im Skill-Layer emitten
- Phase 9: Doppelt-Definition entfernen — eine der beiden Stellen als kanonisch markieren, andere streichen
- Phase 10/10b: PHASE_START-Anweisungen ergänzen
- Phase 11: PHASE_START-Anweisung verstärken (z.B. als hard requirement im Stage-2-Mode markieren)

---

### Bug 5 — `--help`-Aufrufe und echte Fehler beide als BASH_WARN klassifiziert

**Symptom:** 11× WARN-Events der Form `cmd=python3 .../merge_threats.py --help` — legitime Tool-Discovery-Aufrufe vom Orchestrator. Werden mit gleicher Severity wie 2× **echte** `ugrep`-Regex-Syntax-Errors (negative lookbehind `(?<!\\()`) klassifiziert.

**Verifizierter Root-Cause** (`scripts/agent_logger.py:1763-1782`):

`ERROR_KW`-Trigger-Liste (Z. 1767-1777) enthält `"usage:"` mit explizitem Comment:

> *"Sprint 1B (M3.5): a script that prints `usage:` typically means argparse rejected the invocation — caller almost certainly mistyped a flag. Without this trigger the orchestrator may treat the call as a success and waste the rest of its turn budget waiting (the 2026-04-27 Phase-10b regression burnt 5+ minutes this way)."*

Das war ein bewusster Fix gegen argparse-Fehler — der Filter ist aber zu breit: `--help` produziert ebenfalls `usage:` in stdout, fällt also unter denselben Trigger.

**Impact:** Echte Fehler verschwinden in 11 False-Positive-Warnings. Log-Triage wird ineffizient.

**Fix-Hinweis:** Zusätzliche Bedingung in der WARN-Klassifikation: wenn das Original-Kommando `--help` enthält, **nicht** als WARN klassifizieren. Ein-Zeilen-Fix in agent_logger.py:1778.

---

### Bug 6 — `.config-scan-findings.json = {}` ist schema-invalid

**Symptom:** Phase 2.5 hat agent-dispatch geskippt (kein IaC-Surface), File enthält `{}` (3 bytes).

**Verifizierter Root-Cause:**

`schemas/config-scan-findings.schema.yaml:67` definiert für den `normal`-Pfad: `required: [version, generated_at, checks_run, violations, findings]`. Ein leeres `{}` erfüllt **keinen** der required Fields.

`agents/phases/phase-group-recon.md:180-181` (Skip-Pfad) sagt: *"log a one-line skipped + proceed to Phase 3"* — **schreibt explizit kein File**. Das `{}` muss anderswoher kommen — entweder:
1. LLM hat es "vorbeugend" als Platzhalter angelegt
2. Es gibt einen weiteren Code-Pfad (nicht gefunden), der ein Default-Init-File schreibt

`phase-group-recon.md:207-209` macht Validation non-blocking: *"If validation fails — log a warning and continue. The config-scan is enrichment, not blocking."*

**Impact:** Wahrscheinlich harmlos durch defensive validation. Aber semantisch falsch und verschleiert echte Schema-Violations bei nicht-skippt-Dispatch.

**Fix-Hinweis:** Skip-Pfad in `phase-group-recon.md:180-181` so erweitern, dass ein schema-valides leeres File geschrieben wird, z.B. `{"version": 1, "generated_at": "...", "checks_run": [], "violations": 0, "findings": [], "skipped_reason": "no IaC surface"}`. Schema müsste ggf. um `skipped_reason` erweitert werden.

---

### Bug 7 — Stage-2 ignoriert `fragments_to_rewrite`-Whitelist im internen Repair-Loop

**Symptom:** Innerhalb von Stage 2 (Composition Phase 11) wurden mehrere Fragmente mehrfach neu geschrieben:

| Fragment | Anzahl Writes in Stage 2 | Zeitfenster |
|---|---|---|
| `security-posture-attack-paths.json` | **3×** | 16:06:38, 16:16:03, 16:19:55 |
| `architecture-diagrams.md` | 2× | 16:06:09, 16:13:05 |
| `attack-walkthroughs.md` | 2× | 16:07:45, 16:17:07 |

**Verifizierter Root-Cause** (deckt sich mit existierendem Memory-Eintrag `bug_stage2_repair_loop_wrong_fragment.md` vom 2026-05-01):

`agents/phases/phase-group-finalization.md:464` instruiert den Phase-11-internal-Repair-Loop: *"If compose fails with `RENDER_FAILED:…`/`RENDER_HINT:…` — it has written `.pre-render-repair-plan.json`. Read that file (single `actions[0]` entry), edit **only** the listed `fragments_to_rewrite` path, follow the `remediation` text verbatim, then re-run compose. Do **not** guess which fragment is at fault — the plan is authoritative."*

**Das LLM behandelt `fragments_to_rewrite` als advisory statt als hard constraint** (Memory-Befund). Wenn die Edits den Render-Fehler nicht beheben, loopt es weiter und tappt in lange interne Reasoning-Phasen, die Stream-Timeouts triggern können (12+ min ohne sichtbare Tokens, dann API-Stream-Kill).

`phase-group-finalization.md:195` dokumentiert ein eng verwandtes Pattern (das 2026-04-27-Vorkommen): *"the orchestrator interpreted Step 6 output as a signal to rewrite security-posture-attack-paths.json mid-step"*.

**Impact:** ~7-9 Minuten verschwendete Wall-Clock pro Run. Trifft alle Tiefen — bei standard-Run ~12% der Gesamt-Wall-Clock. **Risiko von Stream-Timeouts** bei längeren Repair-Schleifen.

**Fix-Hinweis** (aus Memory):
1. `fragments_to_rewrite` als hard whitelist im Anweisungstext markieren: "MUST only edit listed paths, MUST NOT touch other fragments"
2. STEP-Logging pro Repair-Versuch, damit Stream nicht stirbt
3. Drift-Guard via Unit-Test mit fake repair-plan, asserting nur das gelistete Fragment wurde modifiziert

---

## Priorisierung

| Bug | Impact | Aufwand | Priorität |
|---|---|---|---|
| #1 QA-Routing greift nicht | Kosten + Performance jede haiku-economy | Klein (Doku-Verstärkung in SKILL-impl.md:2008) | **Hoch** |
| #7 Stage-2 ignoriert Whitelist | ~7-9 min/Run + Stream-Timeout-Risiko | Mittel (Anweisungstext + Test) | **Hoch** |
| #4 Phase-Logging | Cost-Telemetrie für teuerste Phasen broken | Mittel (4 separate Stellen) | Mittel |
| #2 prog-name falsch | Debugging-Zeit | Trivial (1 Zeile) | Niedrig (quick win) |
| #3 cosmetic Hex-Typo | User-Verwirrung | Trivial (1 Zeichen) | Niedrig (quick win) |
| #5 BASH_WARN-Klassifikation | Log-Triage | Klein (1 Zeile in agent_logger.py) | Niedrig |
| #6 leeres config-scan-JSON | Schema-Konsistenz | Klein | Niedrig |
