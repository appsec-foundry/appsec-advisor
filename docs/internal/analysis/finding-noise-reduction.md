# Finding-Rauschen reduzieren — Analyse

Frage: Kann man unwahrscheinliche/irrelevante Findings besser aussortieren,
ohne echte Architektur-Weaknesses zu verlieren?

Basis: `examples/threat-modeler/*v0.5.yaml`, verifiziert am Code.

## Sicherheitsargument zuerst: warum Architektur-Weaknesses nicht betroffen sind

Architektur-Aussagen leben **nicht** in `threats[]`, sondern im separaten
Register `weaknesses[]`. juice-shop standard, 8 Einträge:

```
W-001 Critical  Database access relies on concatenated queries      (2 Instanzen)
W-002 Critical  Authorization is implemented route by route         (3)
W-003 Critical  Secrets are committed to source instead of a store  (4)
W-004 High      Endpoints reachable without enforced authentication (2)
W-005 High      Input handling lacks enforced boundary validation   (1)
W-006 High      Build pipeline trusts mutable third-party refs      (5)
W-007 Medium    Weak cryptographic primitives                       (0)
W-008 Medium    Frontend rendering lacks output encoding            (0)
```

Das ist bereits die Pyramide, die `threats[]` fehlt — und inhaltlich genau die
Design-Ebene, die erhalten bleiben muss.

**Aber:** `build_weakness_register()` rollt diese Weaknesses **aus den
Threat-Instanzen** hoch. Wer Threats löscht, hungert das Weakness-Register aus.
W-007/W-008 stehen bereits bei 0 Instanzen.

Daraus die bindende Design-Regel für alles Weitere:

> **Abwerten, niemals löschen.** Eine Severity-Abwertung erhält die Instanz für
> den Rollup; ein Drop zerstört sie.

## Was die Verifikation widerlegt hat

**Erreichbarkeits-/Pfadfilterung bringt nichts.** Von 68 Findings zeigt genau
**eines** auf einen Test-/Demo-Pfad (`test/smoke/Dockerfile`, Medium). Alle 68
haben eine `evidence.file`. Die Input-Filter (`security_relevance_filter.py`,
`scan-excludes.yaml`) arbeiten bereits sauber. Diese Idee ist tot.

**Mehr Dedup bringt nichts.** 68 Findings verteilen sich auf ~45 verschiedene
CWEs, Long Tail mit 1–2 Treffern je CWE. Es gibt keine Duplikat-Masse.
`merge_threats.py` fährt ohnehin schon 7 Konsolidierungsstufen.

**`register_severity_floor` anheben bringt nichts.** Steht default auf
`medium`, Lows sind längst weg. Auf `high` würde 12 Mediums killen und die
82 % Crit+High unangetastet lassen.

Das Rauschen ist also **kein Mengenproblem, sondern ein Kalibrierungsproblem**:
82–96 % aller Findings sind Critical oder High, dadurch priorisiert nichts mehr.

## Ursache 1 — Der Evidence-Verifier liefert auf standard nichts (Bug)

Nicht "under-sampling", wie zunächst vermutet, sondern **zwei unabhängige
Defekte, die sich überlagern**:

**(a) Falsches Modell im Dispatch.** `agents/phases/phase-group-threats.md:1570`
und `:1576` dispatchen `model: haiku` / `MODEL_ID=haiku`. Beide anderen
Spec-Dateien widersprechen:

- `agents/appsec-threat-analyst.md:530` → `MODEL_ID=claude-sonnet-4-6`
- `agents/appsec-evidence-verifier.md:30` → "**Do not use Haiku here**"

Der Sonnet-Fix von 2026-07-05 wurde in beide Doku-Dateien eingetragen, aber nie
in die Phase-Datei propagiert, die die Agent-Parameter tatsächlich trägt.
Haiku stempelt dokumentiert jedes Finding `ambiguous` (0 verified / 0 refuted).

**(b) Der deterministische Floor wird überschrieben.**
`scripts/validate_evidence_lines.py:340` liest und schreibt ausschließlich
`threat-model.yaml` — nie `.threats-merged.json`. Rund 150 Zeilen später in
derselben Stage regeneriert `skills/create-threat-model/SKILL-impl.md:2711-2712`
`threat-model.yaml` aus `.threats-merged.json` und löscht damit jeden
Floor-Verdict.

Das erklärt die kontraintuitive Verteilung: **quick verifiziert mehr als
standard**, weil Abuse-Case-Verification auf quick übersprungen wird
(`resolve_config.py:355-364`), der Rebuild dort also nie feuert.

| Lauf | verified | unchecked | fehlt |
|---|---|---|---|
| quick | 33 | 0 | 0 |
| standard | **0** | 56 | 12 |
| thorough | 20 | 33 | 7 |

`guard_evidence_verification.py` greift nicht: `MIN_SAMPLE=5`, und
`is_degenerate` liefert bei `sampled < MIN_SAMPLE` False. Der Guard fängt
*all-ambiguous*, nicht *all-nothing*.

Testlücke: `tests/test_auto_emitter_pass.py:30` prüft, dass der Floor in der
Emitter-Sequenz läuft — nichts prüft, dass sein Output im finalen YAML ankommt.
Deshalb blieb das über drei Fixture-Regenerationen unbemerkt.

## Ursache 2 — Die Severity-Pipeline trichtert nach High

`triage_compute_ranking.py:484-486` garantiert, dass `effective_severity` nie
unter die Roh-Severity fällt. Gemessen über alle vier Fixtures: **35
Eskalationen, 0 Abwertungen.**

Verschärfend: in `data/severity-caps.yaml` ist **jeder** Cap `max: High`. Die
Caps drücken Critical → High und vergrößern damit genau das Band, das ohnehin
überläuft. Es gibt keinen einzigen Cap auf Medium.

Ungecappte Hygiene-CWEs im Register, alle auf High:
CWE-400 (4×, Resource Exhaustion), CWE-829 (3×), CWE-922, CWE-330.
CWE-1104 und CWE-200 sind gecappt — aber eben nur auf High.

`_PRACTICE_TIER_CWES` (`merge_threats.py:1834`) umfasst nur 6 Krypto-CWEs.
Deshalb landen 93 % im Tier `confirmed-exploitable`, das dadurch als
Diskriminator wertlos ist.

## Optionen

### Option 1 — Evidence-Verifier reparieren *(UMGESETZT)*

Reiner Bugfix, kein neues Konzept.

1. **Strukturell:** `validate_evidence_lines.persist_to_merged()` spiegelt die
   Floor-Verdicts nach `.threats-merged.json` (Join-Key `t_id` ↔ `id`), bevor
   `drop_refuted_findings()` das aktive Modell bereinigt. Damit überlebt der
   Floor jeden Rebuild, unabhängig davon, wie viele Rebuild-Sites es gibt. Die
   Never-lower-Regel gilt auch hier: ein echtes LLM-Verdict wird nie
   überschrieben. Fehlende/kaputte Merged-Datei ist kein Fehler.
2. **Modell-Routing:** `evidence_verifier` fehlte komplett in
   `resolve_config.py` — deshalb stand im Dispatch ein Literal (`haiku`) statt
   einer Variable wie bei *jeder* anderen Rolle. Jetzt reguläre Rolle, auf
   `SONNET` gepinnt für alle Tier/Depth-Kombinationen inkl. sonnet-economy,
   übersteuerbar via `APPSEC_EVIDENCE_VERIFIER_MODEL`. Dispatch nutzt
   `$EVIDENCE_VERIFIER_MODEL`. Das in `appsec-threat-analyst.md:530`
   versprochene CLI-Flag `--evidence-verifier-model` existierte nie — die
   Doku ist auf die reale Env-Variable korrigiert.
3. **Test:** `test_floor_verdicts_survive_yaml_rebuild` fährt Floor → Rebuild
   und prüft, dass `verified` überlebt und `refuted` vom Rebuild-Filter
   gedroppt wird. Die alte Suite prüfte nur, *dass* der Floor läuft — nie, dass
   sein Output ankommt. Genau deshalb blieb der Bug über drei
   Fixture-Regenerationen unentdeckt.

Wirkung: Die drei Konsumenten sind bereits verdrahtet — `refuted` fällt hart
raus (`build_threat_model_yaml.py:850`), `ambiguous` verliert Chain-Elevation.

**Risiko für Architektur-Weaknesses: keines.** `refuted` heißt, die zitierte
`file:line` existiert nicht — ein Phantom-Finding per Definition. Der Floor
respektiert zudem `_is_inferred` (`:182-188`) und cappt arch-/coverage-gap-
Findings auf `ambiguous` statt sie zu verifizieren oder zu verwerfen.

Nur (2) ohne (1) reicht nicht: der Floor bliebe verworfen.

### Option 2 — Practice-Tier ausweiten + Medium-Caps zulassen

`_PRACTICE_TIER_CWES` über die 6 Krypto-CWEs hinaus auf Hygiene-/DoS-/
Supply-Chain-CWEs erweitern (CWE-400, 829, 922, 330, 1104) und in
`severity-caps.yaml` `max: Medium` erlauben.

Wirkung: komprimiert das Crit+High-Band dort, wo es fachlich falsch ist.
Reine Abwertung — Instanzen bleiben, Weakness-Rollup unberührt.

Contract-Änderung ist bidirektional (Producer + Schema + Consumer + Validation
+ Tests, AGENTS.md §4). `evidence_tier` behält seine Semantik; ein neues Feld
ist nicht nötig.

### Option 3 — Weakness-Register als primäre Linse *(unabhängig, billig)*

Die 8 Weaknesses sind bereits die fokussierte Sicht. Sie im Report vor das
68-Zeilen-Threat-Register ziehen, Threats werden Drill-down.

Ändert keine Daten, nur die Darstellung — deshalb ohne Risiko für die
Weaknesses und parallel zu 1/2 machbar.

### Ausdrücklich nicht empfohlen

- Pfad-/Erreichbarkeitsfilter (widerlegt: 1 von 68)
- Weiteres Dedup (ausgereizt)
- `register_severity_floor` anheben (trifft nur die 12 Mediums)
- LLM-Selbsteinschätzung `confidence` (schlecht kalibriert; widerspricht
  "Prefer deterministic Python over LLM")

## Reihenfolge

Option 1, dann messen, dann Option 2. Ohne verlässliches `evidence_check` lässt
sich die Wirkung von Option 2 nicht bewerten. Option 3 ist davon unabhängig.
