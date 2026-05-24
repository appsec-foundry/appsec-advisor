# Prose-Polisher Agent — Implementierungsplan

> **STATUS (2026-05-24): VERWORFEN zugunsten einer einfacheren Lösung.**
>
> Nach Re-Evaluation: ein nachgelagerter Polisher behandelt das Symptom,
> nicht die Ursache. Statt einen zweiten LLM-Pass zu bauen, der hinter
> dem Renderer aufräumt, werden die Prosa-Verbesserungen **direkt im
> Renderer-Prompt verankert**. Implementiert wurde:
>
> - **`agents/shared/prose-samples.md`** — 5 Before/After-Pairs aus
>   echten Reports, Banned-Vocabulary, Voice-Statement, Pre-Write
>   Self-Check. Companion zu `prose-style.md`.
> - **`agents/appsec-threat-renderer.md`** Style Anchor erweitert: lädt
>   prose-samples.md zusätzlich zu prose-style.md.
> - **`agents/phases/phase-group-finalization.md`** substep-4-Block
>   erweitert: lädt beide Files vor dem ersten Fragment-Write.
> - **`agents/shared/prose-style.md`** "Where this file applies" +
>   neuer Abschnitt "Companion file" mit Verweis auf prose-samples.md.
> - **`tests/test_agent_definitions.py`** drift-guard erweitert: prüft
>   prose-samples.md-Existenz und Referenz in renderer +
>   phase-group-finalization (8/8 tests grün).
>
> **Kosten der gewählten Lösung**: ~30 Minuten Arbeit, null Runtime-
> Overhead, null neue Infrastruktur. Sonnet schreibt Prosa erste-
> Generation besser, kein zweiter Pass nötig.
>
> **Wann dieser Plan reaktiviert wird**: nur wenn 5–10 Runs nach der
> Renderer-Prompt-Erweiterung zeigen, dass die Prosa weiterhin
> AI-flavored bleibt UND ein gemessenes Business-Problem entsteht
> (Stakeholder-Feedback, A/B-Vergleich). Bis dahin: hier dokumentiert
> als "Plan B".
>
> ---
>
> **Original-Plan (für die Historie aufbewahrt):**
>
> Plan-Dokument für einen neuen `appsec-prose-polisher` Agenten, der LLM-authored Prosa in Fragment-Dateien stilistisch verbessert, ohne IDs, Ratings, Evidence, Tabellen, Code-Blöcke oder Links zu verändern.
>
> Stand: 2026-05-24. Status: Plan, NICHT implementiert (siehe Header).

---

## Entscheidungen (vom Benutzer freigegeben)

| Frage | Entscheidung |
|---|---|
| Trigger | **Always-on** — Polisher läuft in jedem Run (nicht data-driven). |
| Scope-Start | **Eng**: nur `ms-verdict.json` + `ms-architecture-assessment.json`. Weitere Fragmente in späterer Iteration. |
| Rollback | **Hart**: automatischer Restore aus `.fragments.pre-polish.tar`-Snapshot bei QA-Verschlechterung. |
| Repair-Op-Type | **Neu**: `prose_rewrite` in `qa-content-repair-plan.schema.json` (kein `other`-Escape). |
| Dev-Doku | `dev.md` wird im Zuge der Umsetzung erweitert (siehe §11). |

---

## 1. Pipeline-Position

Aktueller Fluss:
```
Phase 1–10b (Stage 1)
   → Renderer (Stage 2, sonnet, maxTurns=80)
   → compose_threat_model.py rendert threat-model.md
   → QA (deterministisch via qa_checks.py)
   → Architect-Review (optional, --architect-review)
   → Re-Render Loop (falls .qa-repair-plan.json)
```

Neuer Fluss mit Polisher:
```
Renderer
   → [NEU: Polisher → apply_content_repair.py]
   → compose_threat_model.py
   → QA
   → Architect-Review
```

Polisher läuft **immer**, aber **nach** Renderer-Repair-Loop-Konvergenz (gate: kein offener `.pre-render-repair-plan.json` mehr).

**Begründung**: `apply_content_repair.py` Zeile 30 garantiert *"Writes are restricted to paths under `<output_dir>/.fragments/`. Any other target is rejected with a non-zero exit."* — diese Pipeline wird wiederverwendet. Compose ist der billige re-renderbare Schritt; Polish → Compose → QA matched die existierende Architektur exakt.

---

## 2. Agent-Spezifikation

```yaml
name: appsec-prose-polisher
description: INTERNAL — invoked after renderer, polishes whitelisted prose
             fields in LLM-authored fragments before final compose. Never
             alters IDs, ratings, evidence, tables, code blocks, or links.
tools: Read, Edit, Bash
model: sonnet
maxTurns: 30
```

Lädt zwingend `agents/shared/prose-style.md` (sonst bricht
`tests/test_agent_definitions.py::TestProseStyleAnchor::test_prose_authoring_files_reference_anchor`).

Telemetry-Pflicht (mirror der Renderer-Conventions):
```bash
date +%s > "$OUTPUT_DIR/.phase-epoch"
echo "CHECKPOINT phase=11.5 status=polishing_prose" > "$OUTPUT_DIR/.appsec-checkpoint"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" \
   phase-start "[Phase 11.5/11] Prose polish…" --agent prose-polisher
```

Output-Hygiene-Regeln aus Renderer-Doc übernehmen (keine Prosa zwischen
Tool-Calls, Content lebt in Files). Begründet durch 2026-05-23 juice-shop
Vorfall: 5634 tok/min, $2.83 in 5 min.

---

## 3. Scope-Allowlist (Iteration 1)

Nur diese Felder sind editierbar:

| Fragment | Felder | JSON-Pointer |
|---|---|---|
| `ms-verdict.json` | `verdict_prose` (Opening), `closing_prose` | `/verdict_prose`, `/closing_prose` |
| `ms-architecture-assessment.json` | `framing`, `weaknesses[].description` | `/framing`, `/weaknesses/N/description` |

Folge-Iterationen (NICHT in Scope 1):
- `security-posture-attack-paths.json` → `paths[].narrative`, `paths[].so_what`
- `security-architecture.md` → Prosa zwischen `**Security assessment**` und
  `**Relevant findings**` (nur bei `ENRICH_ARCH_FRAGMENTS=true`)
- `architecture-diagrams.md` → Intro-Sätze (nur bei
  `ENRICH_ARCH_FRAGMENTS=true`)

---

## 3.5 Polish-Qualitätsanker (empirisch begründet)

Die defensiven Guards in §4/§5 garantieren nur, dass nichts *kaputt geht*.
Sie sagen nichts darüber aus, was *guten Polish* ausmacht. Diese Sektion
operationalisiert das **positive** Ziel: menschlich klingende Prosa,
Verständlichkeit, Vermeidung unnötiger Details.

### 3.5.1 Empirische Vorlage

Die fünf Before/After-Pairs liegen in **`prose-samples.md`** —
abgeleitet aus echten Prosa-Passagen des juice-shop-Runs vom 2026-05-23.
Jedes Pair zeigt das AI-Pattern, das humane Rewrite, und die abgeleitete
Regel. Diese Datei wird:

- in den **Polisher-System-Prompt** eingebettet (Sonnet imitiert
  Beispiele zuverlässiger als Regeln)
- in `tests/fixtures/polisher/` als Snapshot-Vergleich verwendet
- bei jeder neuen Iteration (§13) um weitere Pairs erweitert

### 3.5.2 Acht Positive-Regeln (aus Pairs A–E destilliert)

1. **Punchline-Opener**: konkrete Aussage in den ersten 8 Wörtern, nicht die Framing-Phrase
2. **Aktiv statt Passiv** im Opener-Satz
3. **Verben statt Nominalisierungen**: "the implementation of authentication" → "how the app authenticates"
4. **Konkrete Zahl statt Quantor**: "three secrets", nicht "several secrets"
5. **Variable Satz-Länge** (3–15 Wörter, gemischt): Rhythmus statt Symmetrie. Triplet-Kadenzen `X, Y, and Z` mit `-ing`-Formen sind AI-Tells.
6. **Diagnose-Schluss statt Summary-Schluss**: "the missing piece is X", nicht "X is Y across the Z"
7. **Em-Dash für Punchline-Schluss**: `… — no server access required.`
8. **Keine Meta-Narration**: kein `the table below shows…`, kein `as can be seen` — der Leser sieht den Kontext selbst

### 3.5.3 Banned-Vocabulary (in Polisher-Output)

| Kategorie | Verbotene Tokens |
|---|---|
| Decorative Adjektive | `robust`, `comprehensive`, `holistic`, `seamless`, `crucial`, `vital`, `key` (als modifier), `categorical`, `broad-stroke`, `structurally deficient` |
| Decorative Verben | `leverage`, `facilitate`, `ensure`, `enable`, `carry a baseline of` |
| Vage Quantoren | `several`, `multiple`, `various`, `numerous`, `many` (ohne nachfolgende Zahl) |
| Transitions | `furthermore`, `moreover`, `additionally`, `in essence`, `in summary`, `notably`, `importantly` |
| Meta-Floskeln | `it is worth noting`, `it should be noted`, `it is important to note`, `the table below shows`, `as can be seen` |
| AI-Schluss-Kadenzen | `X is Y across the Z`, `X requires Y at the A, B, and C layers`, `X are prerequisites for any Y` |

Vollständige Liste in `prose-samples.md` → "Banned". Post-edit substring-
Scan in Polisher; Verletzung → Rollback dieses Einzel-Edits.

### 3.5.4 Voice-Statement (Top des Polisher-System-Prompts)

> "You are polishing prose that a technical reviewer would write in a PR
> comment thread — not a compliance report, not a consulting deck, not
> marketing copy. The reader is a software engineer or security reviewer
> who is time-pressed and allergic to filler. Write the way you would
> explain what you found to the next engineer on call: punchline first,
> evidence in the next breath, one concrete diagnosis at the end. Short
> sentences are allowed and good. Symmetric triplets ('X, Y, and Z')
> sound machine-generated; break them with em-dashes or split into
> separate sentences. If a sentence could appear in any security report
> for any app, rewrite it until it can only appear in THIS report for
> THIS app."

### 3.5.5 Self-Check-Heuristik (LLM-Selbstprüfung pro Edit)

Nach jedem Edit prüft der Polisher gegen 5 Fragen:

1. Could this sentence appear in a report about a different app?
2. Does it use any banned-vocabulary word?
3. Is the punchline in the first 8 words?
4. Are all sentences in the same length-bracket (±2 words)?
5. Does the final sentence diagnose something, or just summarize?

≥2 negative Antworten → Polisher verwirft seinen eigenen Edit, behält
Original. Diese Heuristik ist **nicht deterministisch falsifizierbar** —
sie verlässt sich auf LLM-Selbstdisziplin. Genau deshalb sind die
Before/After-Pairs in §3.5.1 der wichtigste Hebel: konkrete Beispiele
zwingen Sonnet in das gewünschte Muster.

### 3.5.6 Honest Limitation

Automatisierte "Humanisierung" ist das schwerste Stück dieses Projekts.
Bekannte Restrisiken:

- Sonnet hat eigene Stil-Defaults; Polish kann AI-Geschmack **verstärken**
  statt reduzieren, wenn die Beispiele schwach sind.
- "Menschlich klingen" ist nicht deterministisch messbar.
- Mehrfach-Iteration tendiert zur Mittelmäßigkeit (alles gleich kurz,
  alles gleicher Rhythmus). Daher Idempotenz-Marker (§5).

Konsequenz: Iteration 1 ist klein gehalten (`ms-verdict.json` +
`ms-architecture-assessment.json`), damit Fehler sichtbar bleiben und der
Blast-Radius begrenzt ist. Über 5–10 Runs werden neue Before/After-Pairs
in `prose-samples.md` ergänzt; der Polisher wird evidenz-getrieben
geschärft, nicht regel-getrieben.

---

## 4. Hart-verbotene Edits (Compose-Invarianten)

Verifiziert gegen `compose_threat_model.py`, `qa_checks.py`,
`qa-ms-checks.md`, Renderer-Authoring-Contract:

- Fenced Code Blocks ` ``` ... ``` `
- Tabellen-Zeilen (enthalten `|`)
- Markdown-Links `[…](…)` und Anchors `{#…}`
- T-NNN / F-NNN / M-NNN / CWE-NNN-Tokens
- File-Path-Tokens (regex `\S+\.\w+(:\d+)?`)
- HTML-Tags (`<span>`, `<details>`, …)
- `evidence.excerpt`, `attack_steps`, `mitigation_title`,
  `remediation.steps` (Owner: stride-analyzer)
- Schema-v2 §7.X Struktur-Labels: `**Verdict:**`, `**Controls covered:**`,
  `**Implemented controls:**`, `**Assessment:**`
- Forbidden words aus Renderer-Contract: `defect`, `defects`,
  `vulnerability` (gilt in `ms-architecture-assessment.json`)

---

## 5. Diff-Budget-Guards (post-edit, pre-compose)

Jeder Edit muss alle Guards passieren — sonst rollback dieser Einzel-Edit.

| Guard | Schwelle | Zweck |
|---|---|---|
| Per-Field Char-Delta | ≤ ±30 % | verhindert Total-Rewrite |
| Word-Set Jaccard (before, after) | ≥ 0.5 | verhindert Topic-Drift |
| Number-/ID-Token-Set | byte-equal | Zahlen, CVEs, Anchors bleiben erhalten |
| File-Path-Token-Set | byte-equal | linkify-pass funktional |
| Em-Dash-Encoding | `—` direkt emittieren | verhindert `_normalize_emdashes`-Mutation |
| MS-Verdict-Purity (Opening/Closing) | keine T-/M-/F-IDs, vscode://, Pfade | enforced auch von qa-ms-checks.md §10 |
| Negation-Phrasen | keine `\bno\s+(WAF|firewall|secret\s+scanning|DAM)\b` | User-MEMORY-Regel `feedback_threat_model_no_speculative_negatives` |
| Idempotenz | Marker `<!-- polished: <iso-date> -->` skip-detect | Mehrfach-Polish kollabiert nicht |

Verstoss → Edit verworfen, Log nach `.polish-rejected.jsonl`.

---

## 6. Schema-Migration

`schemas/qa-content-repair-plan.schema.json` Op-Enum erweitern:

```diff
- "linkify_file_path | linkify_evidence_line | remove_placeholder |
-  inject_anchor | fix_anchor_slug | add_section | add_table_column |
-  fix_xref | heading_rename_cascade | other"
+ "… | prose_rewrite | other"
```

`prose_rewrite`-Action-Payload:
```json
{
  "op": "prose_rewrite",
  "target": ".fragments/ms-verdict.json",
  "json_pointer": "/verdict_prose",
  "before_text": "...",
  "after_text": "...",
  "rationale": "drop hedging, tighten to ≤25 words"
}
```

`apply_content_repair.py` braucht neuen Handler in `_OP_HANDLERS` plus
Unit-Test in `tests/test_apply_content_repair.py`. Bestehender
Allowlist-Guard (`ALLOWED_FRAGMENT_PREFIX = ".fragments/"` Zeile 55) gilt
automatisch.

---

## 7. Rollback-Mechanik (hart)

**Snapshot vor Polish:**
```bash
tar -cf "$OUTPUT_DIR/.fragments.pre-polish.tar" \
   -C "$OUTPUT_DIR" .fragments/
sha256sum "$OUTPUT_DIR/.fragments.pre-polish.tar" \
   > "$OUTPUT_DIR/.fragments.pre-polish.sha256"
```

**Restore-Bedingung** (alle in Skill orchestration):
- Post-Polish QA wirft NEUE Flags die vorher nicht da waren, ODER
- Threat-Count in finaler YAML weicht von pre-polish Count ab, ODER
- Anchor-Count in finaler MD weicht von pre-polish Count ab.

**Restore-Befehl:**
```bash
tar -xf "$OUTPUT_DIR/.fragments.pre-polish.tar" -C "$OUTPUT_DIR"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" \
   --output-dir "$OUTPUT_DIR"
```

Restore-Event landet in `.stage-stats.jsonl` mit `stage=polish-rollback`,
sichtbar im Run-Statistics-Appendix (commit `656b6b4f2`).

---

## 8. Nebenwirkungs-Analyse (vollständig)

Jede Zeile verifiziert gegen die Codebasis.

| # | Risiko | Verifikation | Mitigation |
|---|---|---|---|
| 1 | **Token-Cost-Regression** | Renderer hat 2026-05-23 5634 tok/min / $2.83 in 5 min verbrannt (renderer-doc "Output Hygiene"). | `maxTurns: 30`, `model: sonnet`, gleiche Output-Hygiene. Realistische Schätzung für juice-shop Iteration 1 (4–6 edits auf `ms-verdict.json` + `ms-architecture-assessment.json`): **~10–13 k tokens, 30–60 s, ~$0.10–0.20 pro Run** (mit prompt-caching $0.05–0.10). Worst-Case (Narration, Rollback-Loops): ~25–40 k tokens, ~$0.40–0.80. Always-on heisst: jeder Non-quick-Run zahlt; quick-Mode skippt (siehe §10). |
| 2 | **Threat-Count-Drift** | `.merged.json` nicht im Polisher-Scope; compose generiert §8 daraus. | ✅ strukturell unmöglich. Trotzdem Post-Compose-Assert auf `len(threats_yaml) == pre_polish_count`. |
| 3 | **Prose-Style-Drift-Guard** | `tests/test_agent_definitions.py:530-580` parametrisiert `AGENT_FILES_AUTHORING_PROSE`. | Polisher-Agent-File MUSS `shared/prose-style.md` referenzieren; sonst CI red. Test-Liste erweitern. |
| 4 | **Linkify-Pass-Bruch** | `compose_threat_model.py` linkifyt `routes/foo.ts:34` zu vscode-Links. | File-Path-Token-Guard (§5). |
| 5 | **Em-Dash-Normalisierung** | `_normalize_emdashes` (compose) konvertiert `--` → `—` ausserhalb Tabellen. | Polisher emittiert direkt `—`; `test_compose_threat_model.py:835` deckt Invariante. |
| 6 | **§7-v2-Struktur-Bruch** | `check_control_subsection_coverage` enforced `**Verdict:** / **Controls covered:** / **Implemented controls:** / **Assessment:**`-Sequenz. | Iteration 1: §7-Fragmente NICHT im Scope. Folge-Iteration: nur Prosa zwischen `**Security assessment**`-Markern. |
| 7 | **MS-Verdict-Purity-Bruch** | `qa-ms-checks.md §10`: Opening/Closing dürfen kein `[T-`, `[M-`, `vscode://`, file-path enthalten. | Post-edit Regex-Check; Verletzung → Edit-Rollback. |
| 8 | **Forbidden-Words** | Renderer-Contract: `defect`, `defects`, `vulnerability` verboten in `ms-architecture-assessment.json`. | Post-edit Substring-Scan. |
| 9 | **Idempotenz** | Mehrfach-Polish könnte iterativ kürzen bis Bedeutung weg. | Marker `<!-- polished: <iso-date> -->`. Skip wenn vorhanden und keine neuen Prosa-Flags seit Last-Polish. |
| 10 | **Repair-Loop-Konflikt** | Renderer-Repair-Pass-Shortcut wendet ≤3 edits an. Polisher-Edits könnten Re-Trigger. | Polisher läuft NACH Repair-Konvergenz (`.qa-status.json.clean == true` ODER Repair-Loop erschöpft). |
| 11 | **Architect-Reviewer** | Liest finale `threat-model.md` post-compose. | Reihenfolge: Polisher → Compose → Architect. Architect sieht polished prose — gewünscht. |
| 12 | **No-Speculative-Negatives (MEMORY)** | User-Regel: keine "no WAF / no firewall" ohne Evidence. | Negation-Phrase-Detector in Polisher-Prompt + post-edit Substring-Scan. |
| 13 | **§7-Finding-Range** | `[F-016]…[F-021]` nur wenn alle IDs existieren. | §7 nicht in Scope 1; in Folge-Iteration: nur Prosa **zwischen** markdown links. |
| 14 | **Rollback-Mechanik** | Polish kann QA-Worse machen. | Snapshot-Restore (§7). |
| 15 | **Stage-Stats / Telemetry** | `.stage-stats.jsonl` via `record_stage_stats.py`, gelesen von `compose._read_stage_stats` (Zeile 7340). | Polisher emittiert `stage=polish` Row. Sichtbar im Run-Statistics-Appendix. |

---

## 9. Testing-Plan

| Test | Datei (neu/erweitert) | Inhalt |
|---|---|---|
| Allowlist-Enforcement | `tests/test_prose_polisher.py` (neu) | Edits auf nicht-allowlistete Fragmente / Felder werden abgelehnt |
| Diff-Budget-Guards | `tests/test_prose_polisher.py` | Char-Delta > 30 %, Jaccard < 0.5 → rejected |
| ID-Token-Invarianz | `tests/test_prose_polisher.py` | Polish, das `T-007` entfernt → rejected |
| File-Path-Invarianz | `tests/test_prose_polisher.py` | Polish, das `routes/foo.ts:34` entfernt → rejected |
| MS-Verdict-Purity | `tests/test_prose_polisher.py` | Polish, das `[T-001]` ins Opening einfügt → rejected |
| Forbidden-Words | `tests/test_prose_polisher.py` | Polish, das `vulnerability` einfügt → rejected |
| Negation-Phrasen | `tests/test_prose_polisher.py` | Polish, das `no WAF detected` einfügt → rejected |
| Idempotenz | `tests/test_prose_polisher.py` | Zweiter Lauf auf polished input → no-op |
| Em-Dash-Stabilität | `tests/test_prose_polisher.py` | Polisher emittiert `—`, compose lässt unverändert |
| `prose_rewrite`-Handler | `tests/test_apply_content_repair.py` (erweitert) | Neuer Op-Type funktional, JSON-Pointer-Pfad korrekt |
| Drift-Guard-Erweiterung | `tests/test_agent_definitions.py` (erweitert) | `appsec-prose-polisher.md` in `AGENT_FILES_AUTHORING_PROSE` |
| Rollback-E2E | `tests/test_e2e_polish_rollback.py` (neu) | Simulierter QA-Regression triggert Snapshot-Restore |
| E2E mit Renderer-Repair-Convergence | `tests/test_e2e_polish_loop.py` (neu) | Renderer-loop → polish → compose → QA grün |

Fixtures unter `tests/fixtures/polisher/` mit before/after Fragment-Pairs.

---

## 10. Trigger-Strategie

**Always-on** (vom Benutzer entschieden).

Skill-Orchestration:
```bash
# Nach Stage 2 Renderer + Repair-Loop-Konvergenz:
if [ -f "$OUTPUT_DIR/.fragments/ms-verdict.json" ] && \
   [ ! -f "$OUTPUT_DIR/.pre-render-repair-plan.json" ]; then
  dispatch_agent appsec-prose-polisher
fi
```

Skip-Bedingungen (auch im Always-on Modus):
- **`--quick` Mode aktiv** — Polisher wird komplett gedroppt, analog zum
  bestehenden Walkthrough-Skip (MEMORY-Regel
  `feedback_quick_skip_walkthroughs_completely.md`). Begründung: quick
  signalisiert *Iteration, nicht Publikation*; Polish ist Publikations-
  Politur ohne Korrektheits-Wert. Spart die +30–60 s und ~$0.10–0.20
  die im quick-Mode am stärksten durchschlagen (kurzer Baseline → hoher
  relativer Polisher-Anteil).
- Fragmente fehlen (Renderer-Output unvollständig)
- Bereits poliert (Marker `<!-- polished -->`) UND keine neuen Prosa-Flags seit Last-Polish
- Repair-Loop noch aktiv

---

## 11. Dev-Doku-Update (`dev.md`)

`dev.md` ist deutscher Developer-Guide, 779 Zeilen, 14 Sektionen. Folgende
Stellen erweitern:

### 11.1 Neue Sektion §7a — Prose Polisher (Ebene 4)

Einfügen direkt nach §7 (Stage 2 Renderer + Repair Loop), vor §8 (QA +
Architect Review). Inhalt:

- Position in Pipeline (Renderer → Polisher → Compose → QA)
- Allowlist (Iteration 1: nur ms-verdict + ms-architecture-assessment)
- Guards (Char-Delta, Jaccard, ID-Invarianz, etc.)
- Rollback via `.fragments.pre-polish.tar`
- `prose_rewrite` Op-Type in repair-plan
- Telemetry: `.stage-stats.jsonl` row `stage=polish`
- Hinweis: Polisher-System-Prompt enthält Before/After-Pairs aus
  **`prose-samples.md`** als Imitations-Vorlage (Sonnet folgt Beispielen
  zuverlässiger als Regeln). Diese Datei muss gepflegt werden.
- Verweis auf prose.md (dieses Dokument) als ausführliche Spezifikation
- Verweis auf prose-samples.md als empirische Vorlage

### 11.2 §3 Pipeline-Diagramm

Im ASCII-/Mermaid-Diagramm der Stages den Polisher-Schritt einfügen:
`Renderer → Polisher → Compose → QA → Architect`.

### 11.3 §8 QA + Architect Review

Hinweis ergänzen: QA-Checks `check_generic_phrases`,
`check_rhetorical_severity`, `check_ai_padding_phrases`,
`check_architectural_prose` werden nach Polish erneut gelaufen — falls
trotz Polish noch Flags da sind, ist die Polish-Iteration zu eng.

### 11.4 §9 Artefakt-Datenfluss

Neue Artefakte:
- `.fragments.pre-polish.tar` (Snapshot)
- `.fragments.pre-polish.sha256` (Snapshot-Integrität)
- `.polish-rejected.jsonl` (verworfene Edits mit Begründung)
- `.polish-applied.jsonl` (akzeptierte Edits)
- Erweiterung in `.qa-content-repair-plan.json` Schema: neuer Op-Type
  `prose_rewrite`

### 11.5 §11 Konfiguration

Hinweise:
- Polisher hat **keine** Toggle-Flag im Normal-Mode (always-on).
- Im **`--quick` Mode wird der Polisher nicht dispatched** — gleicher
  Skip-Pattern wie §3 Walkthroughs. quick = Iteration, nicht
  Publikation. Erwartete Ersparnis pro quick-Run: 30–60 s,
  ~$0.10–0.20 (relativ stärker da quick-Baseline kürzer).
- Wer Polish im Non-quick-Mode deaktivieren will, muss den
  Agent-Dispatch in der Skill-Orchestration auskommentieren (kein
  CLI-Flag vorgesehen).

### 11.6 §13 Erweitern — wo füge ich was hinzu?

Eintrag für "neues Fragment polishable machen":
1. Fragment-Pfad + JSON-Pointer in Polisher-Allowlist eintragen
2. Field-spezifische Guards in `prose_guards.py` ergänzen (falls custom)
3. Fixture in `tests/fixtures/polisher/` anlegen
4. Test in `tests/test_prose_polisher.py` parametrisieren
5. **Mindestens 1 Before/After-Pair in `prose-samples.md` ergänzen**
   (aus einem echten Run für das neue Fragment). Ohne neues Pair fehlt
   dem Polisher die Imitations-Vorlage und er fällt auf generische
   Sonnet-Defaults zurück.

Eintrag für "neues AI-Tell entdeckt im Output":
1. Pattern in `prose-samples.md` → "Banned-Vocabulary" ergänzen
2. Ggf. neues Before/After-Pair anlegen, das den Pattern-Fix zeigt
3. Polisher-Prompt wird beim nächsten Run automatisch aktualisiert
   (da er `prose-samples.md` zur Build-Zeit einliest)

---

## 12. Umsetzungsreihenfolge (Sicherheits-priorisiert)

```
1. Schema-Migration prose_rewrite + apply_content_repair-Handler + Unit-Tests
2. Allowlist + Guard-Library (shared util: scripts/prose_guards.py)
3. Polisher-Agent-File (agents/appsec-prose-polisher.md) mit:
   - prose-style.md Referenz (drift-guard)
   - prose-samples.md eingebettet/inkludiert als Imitations-Vorlage
   - Voice-Statement (§3.5.4) am Prompt-Top
   - Banned-Vocabulary-Liste (§3.5.3)
   - Self-Check-Heuristik (§3.5.5)
4. Snapshot/Rollback-Mechanik in scripts/snapshot_fragments.py
5. Skill-Orchestration: Always-on Dispatch nach Repair-Loop-Konvergenz
6. Drift-Guard-Test erweitern (test_agent_definitions.py)
7. Banned-Vocabulary post-edit Substring-Scan-Tests
8. E2E-Test auf juice-shop frozen-run Fixture, Vergleich gegen
   prose-samples.md "AFTER"-Versionen
9. dev.md Updates (§7a neu, §3 / §8 / §9 / §11 / §13 erweitern)
```

Jeder Schritt einzeln testbar, jeder Rollback-fähig. Nach jedem Schritt
ein atomarer Commit (Signed-off, conventional-commit-Stil).

---

## 13. Open Items / Followups (out of scope Iteration 1)

- Scope-Erweiterung auf `security-posture-attack-paths.json` (Iteration 2)
- Scope-Erweiterung auf `security-architecture.md` §7-Prosa (Iteration 3,
  benötigt `ENRICH_ARCH_FRAGMENTS=true` und §7-spezifische Struktur-Guards)
- `architecture-diagrams.md` Intro-Polish (Iteration 4)
- Optional: Data-driven Skip-Optimisation (`if Prosa-Check-Flags > 0
  then dispatch`) — derzeit deaktiviert, da User Always-on entschieden hat.
  Kann später als Token-Cost-Optimierung nachgezogen werden ohne
  Architektur-Änderung.
