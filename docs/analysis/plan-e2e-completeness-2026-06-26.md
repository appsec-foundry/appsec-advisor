# Plan: E2E-Vollständigkeit — „grün ⇒ Ergebnis korrekt"

**Datum:** 2026-06-26
**Ziel:** Wenn alle E2E-Tests grün sind, soll bewiesen sein, dass (a) der deterministische
Schwanz — Generator, Contracts, Renderer, Exporte — korrekt arbeitet **und** (b) das
LLM-erzeugte Bedrohungsmodell inhaltlich geerdet, vollständig genug und qualitativ über
einer Schwelle ist.

---

## 1. Die ehrliche Grenze

Deterministisch zu beweisen, dass das LLM *alle* realen Bedrohungen findet, ist
unentscheidbar (man bräuchte die Ground-Truth aller Bedrohungen — genau das Ergebnis).
Erreichbar ist stattdessen ein geschichtetes, präzises „grün ⇒ korrekt":

| Schicht | Garantie bei grün |
|---|---|
| **A** | Generator/Contracts/Renderer/Exporte deterministisch korrekt |
| **B** | LLM-Output strukturell geerdet — zitiert echten Code, keine halluzinierten Belege |
| **C** | Bekannte, *gepflanzte* Vulnerabilities werden gefunden (Recall gegen Oracle) |
| **D** | Semantische Qualität über Schwelle (Judge: Plausibilität, Coverage, Severity) |

**Vollständigkeit = alle vier Schichten dicht + Breite des Oracle-Korpus.**
Recall-Vollständigkeit ist ein *wachsender Korpus* (Vuln-Klassen × Sprachen ×
Architekturen), kein einzelner grüner Haken.

---

## 2. Bestand: Maschinerie existiert, ist aber unverdrahtet

| Schicht | Prüft | Existiert | Automatisch? | Lücke |
|---|---|---|---|---|
| **A** | Struktur, Determinismus, Schema, Completeness-Contract | `tests/test_e2e_pipeline.py` (frozen-run), `compose_threat_model.render()` gegen `data/sections-contract.yaml`, `scripts/validate_intermediate.py`, Completeness-Contract (commit `5b8a9db`) | ✅ `make test` | Export-Kette + Byte-Golden + Fixture-Vielfalt fehlen |
| **B** | jede `file:line` existiert, absence-grep-replay | `check_evidence_integrity` (`scripts/qa_checks.py:2929–3051`) | ⚠️ **im E2E abgeschaltet** (`tests/test_full_run_e2e.py:219`) | läuft auf **keinem** echten Repo automatisch |
| **C** | „diese N Vulns MÜSSEN erscheinen" | `scripts/e2e_fixture.sh` + `<oracle>/verify_threat_model.py` + `expected-signals.json` | ❌ extern, manuell, nie CI/Nightly | gebündeltes `synthetic-repo` hat **kein** Oracle; keine Recall-Schwelle |
| **D** | Plausibilität/Coverage/Severity/Actionability/missed-surface | `skills/eval-threat-model/`, `scripts/eval_threat_model.py`, `agents/appsec-eval-judge.md` (5 Dim., refute-by-default, exit 0/1) | ❌ rein manuell/dev | kein Gate — exit-1 könnte shippen |

**Kernbefund:** Für C und D ist alles gebaut (Oracle-Muster, Judge-Loop, Exit-Codes) —
es läuft nur in keinem automatischen Lauf. B ist gebaut **und bewusst deaktiviert**, weil
das winzige `synthetic-repo` Rausch-Zitate erzeugt.

### Heute verifizierte deterministische „grün aber kaputt"-Löcher (Schicht A)

1. **Export-Kette in keinem CI-E2E.** `test_e2e_pipeline.py` fährt compose → annotate →
   pentest, aber **nicht** `export_sarif.py` / `export_pdf.py` / `export_html.py` /
   `render_review_report.py`. Diese haben nur isolierte Unit-Tests mit **eigenen**
   handgebauten YAML-Fixtures (`tests/test_export_sarif.py` etc.) — entkoppelt vom echten
   Generator-Output. SARIF wird sonst nur im manuellen LLM-`make e2e-full` strukturell
   geprüft. ⇒ Schema-Bruch im Generator → Export-Contract bricht → `make test` grün.
2. **Kein Content-/Byte-Golden in CI.** `test_e2e_pipeline.py` prüft nur Struktur-Invarianten
   (MS-Heading, zero-warning, idempotent), nicht Golden-Gleichheit. Der Byte-Golden-Diff
   existiert (`scripts/threat_fixture.py replay`, Scrubbing inklusive), **skippt aber in CI**
   (`tests/test_threat_fixture.py:184` — braucht git-ignored `_last-run` oder externes Repo).
3. **Fixture-Monokultur.** Nur eine In-Tree-Form (minimale Node-App). Folgen: `<2` Criticals
   ⇒ `ms-critical-attack-tree`-Renderpfad nie *positiv* gerendert; keine LLM-Komponente ⇒
   §9/AI-Exposure kalt; `requirements-compliance` skippt offline. Die Fixture-Verzeichnisse
   `b2b-api/`, `multi-tenancy/`, `ci-pipeline/` werden von **keinem** CI-Test konsumiert.

---

## 3. Maßnahmen — zwei Tiers

LLM-Schichten kosten Budget, daher nicht per-PR.

### Tier 1 — per-PR, deterministisch, CI (kein LLM)

- **M1 — Export-Chain-Test auf frozen-run. ✅ ERLEDIGT 2026-06-26.** Umgesetzt in
  `tests/test_e2e_pipeline.py` (nicht neue Datei — die hat schon `rendered_run`/`_run_script`
  und repliziert denselben frozen-run; Docstring „every script a real assessment would
  invoke"). `export_sarif` (rein Python, läuft immer; validiert via `validate_sarif`, ein
  Result pro Threat → kein Silent-Drop), `export_html`/`export_pdf` konditional über ihren
  eigenen `--check-only`-Preflight. `render_review_report` bewusst NICHT in der Kette —
  konsumiert `.requirements-verification.json`, nicht `threat-model.yaml`. Schließt Loch A.1.
- **M2 — In-Tree-Golden-Master + Vollständigkeits-/Integritäts-Assertions. ✅ ERLEDIGT
  2026-06-26.** Statt `threat_fixture replay` direkt: committetes Golden
  `tests/fixtures/e2e/golden/{threat-model.md,threat-model.sarif.json}` + Byte-Diff-Tests
  (Regen über `APPSEC_UPDATE_GOLDEN=1`). Zusätzlich (Nutzer-Anforderung „alle Elemente da +
  fehlerfrei"): `report_integrity_ok`/100%/0-degraded/0-empty aus `.render-integrity.json`,
  kuratierte CORE_SECTIONS (inkl. Mitigation Register) + literale CORE_HEADINGS, Mitigation-
  Register-nicht-leer, Placeholder-Leak-Check. Schließt Loch A.2 + den Vollständigkeits-Gap.
- **M3 — evidence_integrity im E2E reaktivieren. ⛔ BLOCKIERT (deferred).** Geht NICHT mit
  den aktuellen Fixtures: die frozen-run-Threats haben keine `evidence.file`-Zitate und
  `synthetic-repo` enthält keine Quelldateien (nur Dockerfile/package.json) — genau deshalb
  skippt der echte E2E evidence_integrity. Braucht ein Fixture mit echten Quelldateien +
  zitierenden Threats (Fixture-Bau, kein Wiring). Schicht B bleibt offen bis dahin.

### Tier 2 — Nightly / Release-Gate, mit LLM-Budget

- **M4 — In-Tree-Oracle fürs synthetic-repo.** Gepflanzte Vulns + `expected-signals.json` +
  Recall-Assertion in `make e2e-full`. Macht den einzigen In-Tree-LLM-Lauf von „strukturell
  valide" zu „findet die gepflanzten Vulns + zitiert echten Code". Schicht C in-tree.
- **M5 — `e2e_fixture.sh`-Suite als Nightly** über die 6 Sprach-Fixtures (spring-boot, python,
  rust, go, node-typescript, python-langchain-llm) mit Recall-Schwelle. Schicht-C-Breite.
- **M6 — `eval_threat_model.py` als Release-Soft-Gate.** Fail auf High/Critical Judge-Defekte.
  Macht Schicht D zum Gate statt Dekoration.

---

## 4. Coverage-Matrix (Schicht C — wächst über Zeit)

Recall-Vollständigkeit = gefüllte Zellen. Jede Zelle = mind. ein Oracle-Signal, das in
mind. einem Fixture erscheinen muss.

| STRIDE / Klasse | node-ts | spring-boot | python | go | rust | langchain-llm |
|---|---|---|---|---|---|---|
| Spoofing / AuthN | | | | | | |
| Tampering | | | | | | |
| Repudiation | | | | | | |
| Info Disclosure | | | | | | |
| DoS | | | | | | |
| Elevation / AuthZ (BOLA/IDOR) | | | | | | |
| Injection (SQLi/cmd) | | | | | | |
| SSRF / Deserialization | | | | | | |
| Secret-Exposure | | | | | | |
| LLM (LLM01/07/10) | n/a | n/a | n/a | n/a | n/a | |

> Zellen füllen = `expected-signals.json` je Fixture erweitern. Die Matrix ist die
> messbare Definition von „vollständig" für Recall.

---

## 5. Endzustand

Wenn Tier 1 + Tier 2 stehen, bedeutet „grün":

> Generator/Contracts/Exporte deterministisch korrekt **und** das LLM zitiert echten Code
> **und** findet die bekannten (gepflanzten) Vulns **und** besteht den Qualitäts-Judge.

Das ist die vollständige Definition von Korrektheit, soweit sie bei einer LLM-Pipeline
überhaupt erreichbar ist.

---

## 6. Reihenfolge / Risiko

1. **M1, M2** zuerst — gratis, CI, schließt deterministisches „grün aber kaputt" sofort.
2. **M3, M4** — erste echte LLM-Korrektheits-Scheibe (Grounding reaktivieren + ein Oracle).
3. **M5, M6** — reine Korpus-Verbreiterung.

## 7. Housekeeping (nebenbei)

- Verirrtes Verzeichnis `tests/fixtures/e2e/_last-run-req\`` (Backtick-Artefakt) entfernen.
- Ungenutzte Fixture-Verzeichnisse (`b2b-api/`, `multi-tenancy/`, `ci-pipeline/`) entweder
  in M4/M5 als Oracle-Fixtures aktivieren oder löschen.
