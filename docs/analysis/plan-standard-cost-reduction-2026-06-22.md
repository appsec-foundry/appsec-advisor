# Plan: standard-depth Kostenreduktion — Resume-Vermeidung, Threat/Komponenten-Cap, QA-Quick-Fix

**Datum:** 2026-06-22
**Anlass:** Ein `standard`-Lauf gegen juice-shop kostete ~$44.73 (erwartet <$30). Diagnose (zwei
Ursachen, vgl. Kostenanalyse): (a) **ein Resume** (`RESUME:1`, Heartbeat-Lücke, ~98 min Idle) → kalter
Prompt-Re-Prefill → Sonnet-Cache-Read 59.1m statt ~26m (~+$10); (b) **echte Mehrtiefe**: 89 STRIDE-Threats
über 9 Komponenten (vs. 77 im Vergleichslauf), b2b als eigene Komponente + eine zusätzliche
QA-Content-Repair-Runde. Beide Läufe liefen real auf `assessment_depth: standard`.

Ziel dieses Docs: analysieren, wie sich **(1) Resume-Vermeidung** und **(2) Threat/Komponenten-Budget-Cap**
bei `standard` umsetzen lassen, plus **QA-Repair als einmaliger Quick-Fix** statt mehrerer Runden.

Status: **IMPLEMENTIERT 2026-06-22** (uncommitted). Umgesetzt: **QA-A** (depth-aware
`max_repair_iterations`, quick/standard=1, thorough=3) + **2A als Opt-in `--stride-cap N`**
(key-gated, Critical-safe, full Tiefe sonst erhalten, meta-Disclosure). Lever 1 (Resume) bewusst
nicht eigenständig umgesetzt — adressiert indirekt über weniger Turns. Volle Suite grün (8434 passed,
55 skipped), Lint sauber. Original-Analyse unten unverändert als Begründung.

---

## Kernerkenntnis vorab: 2 + QA reduzieren 1 indirekt

Ein Resume entsteht primär, wenn der Orchestrator das **Turn-Budget** (`maxTurns: 300`,
`appsec-threat-analyst.md:6`) ausschöpft oder ein **externes Limit** (5h-Session, API-Stall) zuschlägt.
Es gibt **keinen** Default-Wall-Clock-SIGTERM, der mitten in der Phase killt (frühere 1800s-Annahme war eine
E2E-`run-headless.sh --max-duration`-Invocation, kein Default). Damit ist „Resume-Vermeidung" nur begrenzt
direkt steuerbar.

**Aber:** Weniger Threats (Lever 2) und weniger QA-Runden (QA-Quick-Fix) bedeuten **weniger
Orchestrator-Turns** → geringere Wahrscheinlichkeit, das Turn-Budget zu treffen → **weniger Resumes**.
Lever 2 + QA-Quick-Fix sind also gleichzeitig der beste *praktikable* Hebel für Lever 1.

---

## Lever 1 — Resume-Vermeidung

**Befund:** Weitgehend extern. `skill_watchdog.py` ist observe-only (killt nie; Kommentar `:62`). RUN_IDLE/
RUN_RESUMED (`skill_watchdog.py:798-845`) dokumentieren Stalls nur fürs Reporting (`agent_logger.py:987-1055`),
lösen keinen Resume aus. Der „echte" Resume ist die Cut-off-Recovery nach Turn-Budget-Erschöpfung
(`SKILL-impl.md` „Handling turn-budget cut-offs"), Cap `MAX_STAGE1_RESUMES` default 1 (`SKILL-impl.md:651`).

Direkt steuerbare Optionen:

### 1A — Turn-Budget depth-aware machen *(geringer Nutzen, nicht empfohlen als Primärhebel)*
- Heute flach `maxTurns: 300` (`agents/appsec-threat-analyst.md:6`), `DEFAULT_MAX_TURNS=250`
  (`budget_watchdog.py:41`). standard braucht weniger als thorough.
- **Risiko/Aufwand:** AGENTS.md `:143` pinnt „appsec-threat-analyst — Sonnet, 300 max turns" per Regex
  (`tests/test_agent_definitions.py::TestAgentsMdDocDrift`). Änderung = Frontmatter + AGENTS.md-Zeile +
  Test gemeinsam.
- **Caveat:** Das reale Limit ist die Harness-Session, nicht `maxTurns` allein. Turn-Budget anheben hilft nur,
  *wenn* der Cut-off durch `maxTurns` kam — bei API-Stall/5h-Fenster bringt es nichts. **Geringer Erwartungswert.**

### 1B — Resumed Prompt verkleinern *(adressiert Resume-*Kosten*, nicht -Frequenz)*
- Der teure Resume ist der mid-Phase-9 `STAGE1_CUTOFF` (re-entry mit vollem Analyst-Prompt). `STAGE11_CUTOFF`
  ist bereits auf Phase-11-only-Renderer beschränkt.
- **Risiko:** Phase-Group-Lazy-Load + Cache-Order A→B→C sind explizite Nicht-Offensichtlich-Entscheidungen
  (AGENTS.md `:125-126`), Drift-Guard `tests/test_dispatch_prompt_cache_order.py`. Höheres Risiko, feinmaschig.

**Empfehlung Lever 1:** Keine eigenständige Änderung als Primärhebel. Resume-Frequenz primär über **Lever 2 +
QA-Quick-Fix** senken (weniger Turns). 1A nur mitnehmen, falls man die DEPTH_PARAMS ohnehin anfasst und das
Turn-Budget dort mitführt. „Don't regress": Default *kein* `--max-wall-time` lassen (sonst self-inflicted Resumes).

---

## Lever 2 — Threat/Komponenten-Budget-Cap bei standard

**Befund:** Der gewünschte Mechanismus **existiert bereits und ist end-to-end verdrahtet** — er ist bei standard
nur abgeschaltet.

- `max_threats_per_category` (Top-N pro STRIDE-Kategorie pro Komponente, Critical-safe) lebt im
  `QUICK_STRIDE_PROFILE` (`resolve_config.py:170-190`, Wert `1`).
- Gating in `resolve_stride_profile` (`resolve_config.py:582-612`): greift **nur** wenn
  `reasoning_mode == "sonnet-economy" AND depth == "quick"`. Bei standard/thorough → `{"stride_profile_label":
  "full"}` = **kein Cap**.
- Konsument liest es bereits: `agents/appsec-stride-analyzer.md:281` (Cap-Tabelle), Forwarding
  `phase-group-threats.md:414-426`, Plumbing `SKILL-impl.md:840` (`STRIDE_PROFILE_JSON`).
- Banner: `compose_threat_model.py:1903`.

Die **Komponentenzahl** ist dagegen emergent (`select_stride_components`,
`build_stride_dispatch_manifest.py:626-688`); die flache Ceiling `STRIDE_COMPONENT_CEILING=10`
(`resolve_config.py:214`) **shed't nur `_is_internal_only`** (`:658-670`) und *liftet* erworbene
(exposed/crown/cicd) Komponenten statt sie zu droppen (`EXPOSURE_CAP_LIFT`). → Eine Komponenten-Ceiling
greift bei *diesem* 9-Komponenten-Lauf **nicht** (b2b ist exposed, nicht internal-only).

### 2A — `max_threats_per_category` für standard freischalten *(KORRIGIERT nach Verifikation: DESIGN-UMKEHR, nicht „nur ungate")*

> **Verifikation 2026-06-22 widerlegt die ursprüngliche „niedriges Risiko / Mechanismus bereits verdrahtet"-Einschätzung.**
> Drei harte Blocker gefunden:
>
> 1. **Konsument ist label-gated, nicht key-gated.** `agents/appsec-stride-analyzer.md:116,276` aktiviert die
>    gesamte Cap-Tabelle (inkl. `max_threats_per_category`) **nur** wenn
>    `stride_profile_label == "quick (depth-reduced via sonnet-economy)"`. Ein standard-Profil mit anderem Label
>    transportiert den Key zwar, aber der Analyzer **ignoriert ihn**. → Analyzer-Prompt-Aktivierung muss mit-editiert
>    werden (LLM-Prompt-Contract, nicht-deterministische Durchsetzung).
> 2. **Ein Test nagelt das Gegenteil fest.** `tests/test_stride_quick_profile.py:80-94`
>    (`test_profile_full_outside_quick_haiku_economy`) prüft für **genau die User-Config** `("opus","standard")`
>    sowie `("sonnet","standard")`, `("sonnet-economy","standard")` u.a.: `stride_profile_label == "full"` **und**
>    `max_threats_per_category NOT in profile`, mit der Intent-Message **„must keep full STRIDE depth — opt-in only"**.
>    Das ist eine bewusste, dokumentierte Designentscheidung: STRIDE-Tiefenreduktion ist **quick-only / opt-in**.
>    2A **kehrt dieses Prinzip um** → Test muss umgeschrieben werden (= Design-Änderung, kein Bugfix).
> 3. **Kein standard-Banner-Pfad.** `compose_threat_model.py` Banner ist hart auf `is_quick_depth` gated
>    (`if not ctx.eval_context.get("is_quick_depth"): return ""`). Für Transparenz bei standard müsste ein
>    **neuer** Disclosure-Pfad gebaut werden.

- **Producer:** `resolve_config.py:607-612 resolve_stride_profile` — standard-Branch ergänzen (nur
  `{"max_threats_per_category": 2, "stride_profile_label": "standard (per-category cap 2)"}`; **nicht** die übrigen
  quick-Reduktionen wie skip_cvss/skip_greps, da der User-Lauf opus-reasoning fuhr und volle Evidenz/CVSS bei
  standard bleiben soll).
- **Konsument (Pflicht, nicht optional):** `agents/appsec-stride-analyzer.md` — Aktivierung des
  `max_threats_per_category`-Regels vom quick-Label entkoppeln (z.B. „wende den Cap an, sobald der Key im
  STRIDE_PROFILE vorhanden ist") + `phase-group-threats.md:207,414` Forwarding-Doc anpassen („full at Standard").
- **Render:** neuer standard-Disclosure in `compose_threat_model.py` (Banner ist quick-only).
- **Tests:** `tests/test_stride_quick_profile.py:80-94` umschreiben (Intent-Umkehr), `tests/test_resolve_config.py`,
  `tests/test_p3_behavior_tuning.py`, `tests/test_reasoning_model_resolution.py`.
- **Docs (AGENTS.md §4):** `docs/threat-modeler.md`, AGENTS.md „Assessment depth profiles".
- **Risiko:** **MITTEL** (nicht niedrig). Es ist die größte Token-Ersparnis auf die 89-Threat-Zahl, **aber** es
  überschreibt das bewusste Produktprinzip „standard = volle STRIDE-Tiefe, Reduktion nur opt-in". **Braucht
  explizite User-Freigabe** — das ist kein stiller Ungate. Plus: Durchsetzung hängt am LLM-Prompt (weicher als
  ein Python-Cap).

### 2B — depth-aware Komponenten-Ceiling *(optional, nur für Microservice-Estates)*
- `STRIDE_COMPONENT_CEILING` von flach 10 → per-depth-Map (z.B. quick=6/standard=8/thorough=10) in
  `resolve_config.py:214` + `resolve_assessment_depth:303`; Spiegel in `_FALLBACK_DEPTH_PARAMS`
  (`build_stride_dispatch_manifest.py:37`).
- **Caveat:** ändert die dokumentierte Invariante „depth-independent" (AGENTS.md `:206`) und **bringt für den
  konkreten Lauf nichts** (erworbene Komponenten werden geliftet, nicht geshed't). Erworbene zu shed'en würde die
  beim Redesign 2026-06-07 entfernte Blindspot wieder einführen → **nicht tun.**
- **Tests:** `tests/test_dispatch_manifest.py:261,421,444` u.a.
- **Risiko:** MITTEL. Nur mitnehmen, wenn Microservice-Estates explizit Ziel sind.

### 2C — Recon/Authoring-Granularität *(nicht empfohlen)*
- Prosa-Hinweis `appsec-recon-scanner.md:679` + Merge-Regel „Geschwister falten außer hinter distinkter
  Trust-Boundary". Authoring-seitiges Prunen ist contractlich verpönt (`phase-group-architecture.md:876`
  „Author the COMPLETE inventory ... Do NOT pre-prune"). LLM-Prosa ist unzuverlässig — genau das hat hier
  versagt (b2b-Split). **Nicht als Primärhebel.**

**Empfehlung Lever 2:** **2A** umsetzen (Cap=2 für standard). Optional 2B (=8) nur falls Microservice-Estates
relevant werden.

---

## QA-Repair als einmaliger Quick-Fix bei standard

**Befund:** `MAX_REPAIR_ITERATIONS = 3` ist ein **flaches Literal** (`SKILL-impl.md:3435`), nicht depth-aware.
Loop-Tail (`SKILL-impl.md:3498-3534`): bei Erschöpfung **fail-closed `exit 2`** (`:3499-3500`) — kein invalider
Report wird ausgeliefert. Zwei Repair-Pläne: strukturell `.qa-repair-plan.json` (`qa_checks.py:build_repair_plan`,
LLM-Applier `appsec-fragment-fixer`) und inhaltlich `.qa-content-repair-plan.json` (vom QA-Reviewer-Agent emittiert,
deterministisch via `apply_content_repair.py` angewandt). Kein Knopf limitiert heute die Runden.

### QA-A — `max_repair_iterations` in DEPTH_PARAMS *(EMPFOHLEN — Verifikation bestätigt: niedriges Risiko)*

> **Verifikation 2026-06-22 bestätigt die Einschätzung.** `MAX_REPAIR_ITERATIONS = 3` ist ein reines Literal
> (`SKILL-impl.md:3435`), **kein Test pinnt die `3`** (`grep` über `tests/` leer). Loop-Tail
> `repair_iteration >= MAX_REPAIR_ITERATIONS → exit 2` (`:3499-3500`) verifiziert fail-closed. Cap=1 ergibt **genau
> einen** Repair-Pass (mechanischer Applier *oder* ein fragment-fixer-Dispatch), danach Re-Check, danach hart `exit 2`.

- **Producer:** `resolve_config.py:199-204` — Key `max_repair_iterations` in `DEPTH_PARAMS` ergänzen
  (quick=1, standard=1, thorough=3), via `resolve_assessment_depth` emittieren; Spiegel in `_FALLBACK_DEPTH_PARAMS`
  (`build_stride_dispatch_manifest.py:37`, drift-guard `tests/test_dispatch_manifest.py:261`).
- **Konsument:** `SKILL-impl.md:3435` Literal `3` → `$MAX_REPAIR_ITERATIONS` aus RESOLVED_JSON. Die Loop ist
  Prosa-Pseudocode (heute keine Shell-Var) → Skill muss den Wert einmal in eine Var lesen.
- **Korrektheit:** bleibt erhalten — „Quick-Fix" = *ein Versuch, dann fail-closed*, **nicht** *trotzdem ausliefern*.
- **VERIFIZIERTER Seiteneffekt:** Die Loop-Mechanik ist **geteilt** zwischen Stage-3-QA *und* Stage-4-Architect
  (`:3432` „both stages share the same mechanics", `:3622` „Each stage has its own MAX_REPAIR_ITERATIONS budget").
  Ein depth-abgeleiteter Wert cappt daher **beide** Loops auf 1 bei standard. Konsistent mit „single quick-fix",
  aber bewusste Entscheidung: Wenn nur die QA-Loop (nicht Architect) gecappt werden soll, braucht es **zwei**
  Variablen (`MAX_QA_REPAIR_ITERATIONS` / `MAX_ARCHITECT_REPAIR_ITERATIONS`). Hinweis: Architect-Review ist bei
  standard per Default ohnehin meist aus — Seiteneffekt nur relevant bei `--architect-review`.
- **Tests:** `test_skill_documents_exit_code_2_on_exhaustion` (`tests/test_skill_auto_retry.py:94`, prüft nur
  „exit 2"-Substring) bleibt grün. Bei neuem DEPTH_PARAMS-Key: `tests/test_dispatch_manifest.py` (Fallback-Sync) +
  `tests/test_resolve_config.py` Erwartung ergänzen.
- **Docs:** AGENTS.md Depth-Tabelle, `docs/threat-modeler.md`, SKILL-Flag-Tabelle (§4 bidirektional).
- **Risiko:** NIEDRIG (verifiziert).

### Verworfene Variante *(unzulässig)*
Bei Erschöpfung von `exit 2` auf „teil-reparierten Report ausliefern" downgraden → verstößt gegen AGENTS.md §1/§12
und die SKILL-impl Compliance-Contract (`:147`). **Nicht tun.**

**Empfehlung QA:** **QA-A** — `max_repair_iterations` standard=1 über DEPTH_PARAMS, Literal `:3435` ersetzen,
fail-closed `exit 2` beibehalten.

---

## Gesamtempfehlung & erwartete Wirkung

| Hebel | Maßnahme | Hauptdatei | Risiko | Wirkung |
|---|---|---|---|---|
| **2 (Threats)** | `max_threats_per_category: 2` für standard freischalten | `resolve_config.py:582-612` | niedrig | dominanter Hebel auf 89→~ Threats; ↓ Opus-Output + ↓ Merge/Mitigation/QA-Downstream |
| **QA** | `max_repair_iterations: 1` bei standard via DEPTH_PARAMS | `resolve_config.py:199-203` + `SKILL-impl.md:3435` | niedrig | ≤1 Repair-Pass; spart die zusätzliche Sonnet-Repair-Runde |
| **1 (Resume)** | indirekt durch 2+QA (weniger Turns); 1A optional mitnehmen | — | — | ↓ Resume-Frequenz (weniger Turn-Budget-Treffer) |
| 2B (optional) | depth-aware Ceiling=8 | `resolve_config.py:214` | mittel | nur Microservice-Estates; bringt diesem Lauf nichts |

**Reihenfolge (billig → wertvoll):** 2A zuerst (größter Token-Hebel, niedrigstes Risiko, kein Schema), dann QA-A.
Beide teilen sich denselben DEPTH_PARAMS/Docs/Test-Quartett-Sync (AGENTS.md §4 bidirektional), also gemeinsam
committen. 1A nur, falls man das Turn-Budget ohnehin in DEPTH_PARAMS mitführt.

**Bidirektionaler Contract-Sync (für 2A + QA-A gemeinsam):** `resolve_config.py` (Producer) + Konsument
(`SKILL-impl.md` / Analyzer-Prompt) + `tests/test_resolve_config.py` + `tests/test_qa_depth_profile.py` +
`tests/test_dispatch_manifest.py` (`_FALLBACK_DEPTH_PARAMS`-Sync) + Docs (`docs/threat-modeler.md`, AGENTS.md
Depth-Tabelle, SKILL-Flag-Tabelle) im selben Commit.

## Offene Entscheidungspunkte (für den User)
1. **Cap-Wert bei standard:** `max_threats_per_category = 2` (Vorschlag, severity-sortiert, Critical-safe) — oder
   strenger `1` wie quick? 2 hält standard von quick distinkt.
2. **QA bei standard:** strikt 1 Pass (Vorschlag) — oder 2 (ein Retry erlaubt)? 1 = echter Quick-Fix.
3. **2B Ceiling** mitnehmen (=8) oder weglassen? Empfehlung: weglassen, bis Microservice-Estates Ziel sind.
4. **Lever 1A** (depth-aware maxTurns) mitnehmen? Empfehlung: nur falls DEPTH_PARAMS ohnehin angefasst.
