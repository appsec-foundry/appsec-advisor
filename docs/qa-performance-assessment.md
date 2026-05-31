# QA-Performance — ehrliche, verifizierte Einschätzung

_Datum: 2026-05-31 · Frage: QA-Agent(en) performanter machen bei minimalem Qualitätsverlust?_

> Korrektur-Hinweis: Eine frühere Fassung dieser Datei war falsch (basierte auf
> verfälschten Tool-Outputs während einer Kanalstörung). Diese Fassung beruht auf
> zwei unabhängigen, sauberen Codebase-Scans + direkter Quelltextlektüre.

## TL;DR (ehrlich)

**Es gibt genau einen QA-Agenten — `appsec-qa-reviewer` (sonnet) — und der ist
bereits aggressiv optimiert.** Auf sauberen Runs wird er **gar nicht erst
gestartet** (deterministischer Gate signiert allein). Die großen, sicheren
Performance-Hebel sind *schon umgesetzt*. Es gibt **kein freies Mittagessen
mehr**. Der einzige sofort shippbare Hebel ist „Routine-Repairs per Default auf
Haiku" (mittel-riskant); alles andere ist entweder tiefe, qualitätsneutrale
Engineering-Arbeit oder echter Qualitätsverlust. Meine Empfehlung: **keine
blinde Änderung shippen** — erst messen (Infra dafür existiert: `measure_run.py`
→ `.run-metrics.json`, `.stage-stats.jsonl`).

## Verifizierte Architektur (file:line)

QA läuft in **3 Schichten**, nicht als ein dicker LLM-Call:

| Schicht | Datei | Art | Belegt durch |
|--------|-------|-----|--------------|
| 1. Deterministische Pre-Pass | `scripts/qa_checks.py` (9.078 Z., 57 Checks, `cmd_all` @ L3172) | Python, 0 Tokens | 2× Explore-Scan, `ls -la` (414 KB), `find` |
| 2. Deterministischer Prosa-Fixer | `scripts/apply_prose_fixes.py` (799 Z., idempotent) | Python, 0 Tokens | vollständig gelesen |
| 3. LLM-Review (Stage 3) | `agents/appsec-qa-reviewer.md` (611 Z., `model: sonnet`, `maxTurns: 120`) | LLM | 2× Explore-Scan |

> Die ursprünglich genannten Agenten `qa-prose-auditor`, `appsec-qa-fixer`,
> `appsec-doc-qa` **existieren nicht**. Einziger QA-Agent: `appsec-qa-reviewer`.

## Bereits umgesetzte Optimierungen (= warum kein freier Hebel mehr da ist)

1. **Deterministische Pre-Pass nimmt dem LLM die Strukturarbeit ab** (57 Checks
   in `qa_checks.py`), exakt und gratis.
2. **Fast-Path:** Bei sauberer Pre-Pass signiert die Pipeline über
   `.qa-status.json` (`source: deterministic-pre-agent`) **ohne den LLM-Agenten
   überhaupt zu starten** (`SKILL-impl.md` Compliance-Contract).
3. **Split-Model-Routing (M3.5):** `QA_ROUTINE_MODEL` (mechanische Repairs) vs.
   `QA_CONTENT_MODEL` (Semantik). Haiku via `haiku-economy`-Profil verfügbar;
   Default beide `claude-sonnet-4-6` (`SKILL-impl.md:749-750`).
4. **Pfad+JSON-Invocation statt Volltext:** Der Agent bekommt Pfade +
   vorab berechnete JSONs (`.qa-prepass.json`, `.qa-repair-plan.json`) und
   _„must not re-read the full Markdown unless the pre-pass or repair plan names
   a specific semantic ambiguity"_ → Token-Eingabe schon minimiert.
5. **Teurer Pass 2c (Deep-Repo-Scan) ist retired** — `--qa-scan-repo` ist nur
   noch ein No-Op-Kompatibilitätsflag (`SKILL-impl.md:601`).
6. **Skip-Pfade:** `--no-qa`/`--quick`/`PR_MODE`/`DRY_RUN` überspringen Stage 3;
   `STAGE2_NOOP_SKIP` überspringt Renderer+QA bei unverändertem YAML.

Deckt sich mit Memory `project_token_optimization_exhausted` (sichere Quick-Wins
erledigt, nur noch ein mittel-riskanter Hebel offen).

## Rest-Hebel — ehrlich nach ROI sortiert

### 1. Repair-Plan-Häufigkeit / Re-Render-Loop-Iterationen senken  ⟶ höchstes Potenzial, tiefe Arbeit
**Wichtig:** Der Agent läuft auf sauberen Runs ohnehin nicht (Agent-Spec L13:
_„On clean runs the skill … never dispatches this agent"_). Er wird nur erzwungen
durch (a) `QA_DEPTH=extended` / `APPSEC_FORCE_QA_AGENT=1`, (b) einen vorhandenen
Repair-Plan, oder (c) einen fehlgeschlagenen Gate. Der Kostentreiber, wenn er
feuert, ist die **Re-Render-Loop** (Agent → Repair-Plan → Re-Render → Agent …).
Echter Gewinn = die deterministische Pre-Pass + `compose_threat_model.py` lösen
mehr Defekte sofort, sodass **seltener Repair-Pläne entstehen** und die Loop
früher konvergiert. Das ist **qualitätsneutral** (gleiche Checks, nur effizienter
erfüllt), aber **tiefe Engineering-Arbeit**, kein Config-Flip. **Voraussetzung,
die ich NICHT verifizieren konnte:** wie oft Repair-Pläne real entstehen und wie
viele Loop-Iterationen typisch sind. Infra existiert (`measure_run.py`,
`.stage-stats.jsonl`), aber in diesem Checkout liegen **keine Run-Artefakte** vor
(`find` → leer). **Vorgehen:** N Runs mit `measure_run.py` vermessen, dann gezielt
die häufigsten Repair-Plan-Ursachen deterministisch schließen.

### 2. `QA_ROUTINE_MODEL` per Default auf Haiku  ⟶ einziger „heute shippbarer" Hebel, mittel-riskant
Mechanische Repairs (Links/Anker/Xrefs) sind quasi-deterministisch. Plumbing
existiert bereits (`haiku-economy`); Änderung = Haiku zum Default machen.
Latenz-/Kostengewinn real, aber **begrenzt** (Mechanik ist nur ein Teil der
Agent-Turns). Mittleres Qualitätsrisiko → erst an Stichprobe Repair-Korrektheit
messen, dann defaulten. Das ist der „B1"-Hebel aus der Vor-Analyse.

### 3. `qa_checks.py` I/O-Mikrooptimierung  ⟶ NICHT empfohlen (Falle)
`cmd_all` macht read→check→write→Cache-Reset→re-read (×5–6) und baut Indizes
(`_load_label_index`, `_load_th_label_index`) pro Check ohne Cross-Check-Cache.
Trotzdem **nicht anfassen:** (a) **geringer Wall-Clock-Payoff** — Sekunden Python
gegen Minuten LLM-Stages, die die Laufzeit dominieren (Memory
`bug_recon_api_latency_stalls`); (b) **hohes Regressionsrisiko** — `qa_checks.py`
hat subtile Idempotenz-Contracts (Memory `gotcha_qa_checks_all_not_idempotent`:
re-run von `cmd_all` erfindet Phantom-Issues). I/O-Umordnung kann genau die
brechen.

### 4. `maxTurns: 120` senken  ⟶ kein Perf-Hebel
Das ist eine Obergrenze, keine Pro-Run-Kosten. Senken bringt nur etwas, wenn Runs
das Limit treffen — dann ist es ein Timeout-/Korrektheitsthema, kein Tempo.

## Fazit

Der QA-Agent ist an der Optimierungsgrenze — auf sauberen Runs läuft er gar
nicht. **Hebel 2** (Routine-Repairs per Default Haiku) ist der einzige sofort
shippbare, mittel-riskant → Stichprobe zuerst. **Hebel 1** (Repair-Pläne/Loop
seltener) ist der größte qualitätsneutrale Gewinn, aber tiefe Arbeit und braucht
erst Messdaten (`measure_run.py`). **Hebel 3 und 4** sind keine sinnvollen
Optionen. Nettoeinschätzung: **kein risikofreier Schnellgewinn übrig** — die
ehrliche Antwort ist, dass die QA-Schicht bereits performant ausgelegt ist.

## Umgebungs-Caveat
Der Tool-Output-Kanal dieser Session hat wiederholt große/mehrzeilige Outputs
verworfen, dupliziert und verzerrt (leere Rückgaben, vertauschte Zeilennummern,
eingestreute Fremdzeichen). Alle obigen Architektur-Befunde wurden über
**mehrere unabhängige saubere Läufe** bestätigt → hohe Konfidenz. Die *eine*
nicht abschließbare Messung (Repair-Plan-Häufigkeit + Loop-Iterationen für
Hebel 1) ist oben klar als offen markiert: dafür `measure_run.py` über mehrere
echte Runs laufen lassen — in diesem Checkout liegen keine Run-Artefakte vor.
