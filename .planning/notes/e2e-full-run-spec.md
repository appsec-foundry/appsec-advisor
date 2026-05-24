# Full-Run E2E Test — Konzept

**Datum:** 2026-05-24
**Status:** Spec — keine Umsetzung
**Scope:** Ein vollständiger End-zu-End-Lauf (echter LLM, alle Stages, alle
Outputs), **manuell** ausgelöst nach größeren Umbauten — nicht pro PR.

Ergänzung zu [`e2e-test-analysis.md`](./e2e-test-analysis.md) — dort Tier 3 nur
skizziert; hier ausgearbeitet.

---

## 1. Zielbild

**Ein Befehl, ein Lauf, ein Verdict.** Entwickler tippt nach einem Refactor:

```bash
make e2e-full           # oder: gh workflow run e2e-full.yml
```

→ Pipeline läuft 15–25 min, prüft alles, was ein echter User-Lauf produziert,
und liefert einen einzigen Pass/Fail-Report mit Cost-Summary und Snapshot-
Diff zur letzten Baseline.

**Bewusst kein per-PR-Trigger:** zu teuer, zu lang, zu flaky. Stattdessen
**Gate vor Release / nach jedem Milestone-Abschluss / nach größeren Refactors**
(Phase-Group-Änderung, Schema-Bump, Renderer-Refactor, Hook-Änderung, Model-
Routing-Update).

---

## 2. Trigger

| Trigger                                                            | Wann                                              |
|--------------------------------------------------------------------|---------------------------------------------------|
| `gh workflow run e2e-full.yml` (`workflow_dispatch`)               | Standard — manueller Knopf                        |
| `make e2e-full` (lokal, gleiche Logik wie CI)                      | Lokal vor Push, vor PR-Merge                      |
| PR-Label `e2e-full` (auto-dispatch durch zweiten Workflow)         | Maintainer setzt Label → 1 Lauf pro Label-Edit    |
| Optional: cron weekly (`0 4 * * 1`) auf `main`                      | Drift-Check, kein Blocker                         |

**Bewusst keine** Auslösung pro `git push` / pro PR / pro Commit.

---

## 3. Inputs (alles, was ein User-Lauf bekommt)

| Input                       | Quelle                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| Target-Repo                 | `tests/fixtures/e2e/synthetic-repo/` (erweitert) — gepinnt, committed                         |
| Plugin-Config               | `config.json` aus Repo-HEAD                                                                   |
| Skill-Args                  | `--repo $REPO --output $OUT --assessment-depth quick --sarif --with-sca`                       |
| Business-Kontext            | `tests/fixtures/e2e/business-context.yaml` (NEU — Org-Profile-artig)                          |
| Requirements-Quelle          | `file://tests/fixtures/e2e/requirements-fixture.yaml` (NEU — lokale URL)                       |
| API-Key                     | `${{ secrets.ANTHROPIC_API_KEY_E2E }}` (separater Key mit Budget-Cap im Anthropic-Dashboard)  |
| Modell-Pin                  | `--model claude-haiku-4-5` für STRIDE; `--reasoning-model claude-sonnet-4-6` für Merger        |
| Cost-Cap                    | `--max-budget 5.00 --max-duration 1800`                                                       |

### 3.1 Synthetic-Repo Erweiterung (Voraussetzung)

Heute: 2 Files (`Dockerfile`, `package.json`).

**Erweitern auf 20–30 Files** mit **bewusst gepflanzten** Schwachstellen, damit
Assertions vorhersagbare Treffer haben:

```
synthetic-repo/
├── package.json                      # deps mit 1 bekannten CVE → SCA trifft
├── Dockerfile                        # privileged + latest-tag → config-scan trifft
├── docker-compose.yml                # exposed port + plain HTTP
├── .env.example                      # JWT_SECRET=dev-only → secret-scan-near-miss
├── src/
│   ├── server.ts                     # Express + JWT-Mw
│   ├── routes/
│   │   ├── login.ts                  # SQL string-concat → STRIDE Tampering/EoP findet T-SQLi
│   │   ├── search.ts                 # SSRF via user-controlled URL → STRIDE T-SSRF
│   │   ├── upload.ts                 # path-traversal in filename → STRIDE T-PathTrav
│   │   └── profile.ts                # XSS via bypassSecurityTrustHtml-Equivalent → T-XSS
│   ├── db.ts                         # Sequelize ORM (positive Strength)
│   └── auth.ts                       # JWT mit RS256 (positive Strength)
├── infra/
│   ├── terraform/main.tf             # public S3 bucket → config-scan
│   └── k8s/deploy.yaml               # runAsNonRoot:false → config-scan
└── docs/
    └── ARCHITECTURE.md               # Recon nimmt Komponenten auf
```

→ erwartet: **min. 4 Threats, alle 6 STRIDE-Kategorien adressiert (T/I/D/E/S
ausreichend, R optional), 2 positive Controls, 2 SCA-Findings, 3+ Config-
Findings**.

### 3.2 Business-Kontext (NEU)

`tests/fixtures/e2e/business-context.yaml`:

```yaml
org:
  name: "Acme E-Commerce"
  domain: "retail"
  data_sensitivity: "PII + payment_partial"
  compliance: ["PCI-DSS-SAQ-A", "GDPR"]
trust_boundaries:
  - name: "Internet"
    description: "Anonymous public users"
  - name: "Admin Backoffice"
    description: "Internal staff via VPN"
threat_actors:
  - profile: "opportunistic-cybercriminal"
    motivation: "credit-card-fraud"
  - profile: "insider"
    motivation: "data-exfiltration"
```

→ Skill liest via `--context-file <path>` (falls Flag existiert) oder via
`config.json`-Override; Assertion: Renderer übernimmt `compliance` ins
Management-Summary-Infobox.

### 3.3 Requirements-Fixture (NEU)

`tests/fixtures/e2e/requirements-fixture.yaml`:

```yaml
requirements:
  - id: REQ-AUTH-01
    category: SEC-AUTH
    title: "Strong password policy"
    must: true
  - id: REQ-INPUT-01
    category: SEC-INPUT
    title: "Server-side input validation"
    must: true
  - id: REQ-CRYPTO-01
    category: SEC-CRYPTO
    title: "TLS 1.2+ for all external traffic"
    must: true
```

→ Aufruf: `--requirements file://$PWD/tests/fixtures/e2e/requirements-fixture.yaml`.
Assertion: erzeugte `requirements-report.{md,json}` referenziert alle 3 IDs,
mappt sie auf gefundene Threats / Mitigations.

---

## 4. Lauf-Matrix

**Ein Workflow-Lauf = mehrere Skill-Calls in Sequenz.** Spart Setup-Zeit,
prüft Skill-Interop (Output von Skill A ist Input von Skill B).

| Step | Skill                          | Args                                                          | Voraussetzung           |
|------|--------------------------------|---------------------------------------------------------------|--------------------------|
| 0    | `clean-run-state`              | `--force`                                                     | —                        |
| 1    | `check-permissions`            | —                                                             | —                        |
| 2    | `create-threat-model`          | `--with-sca --sarif --assessment-depth quick`                  | sauberes OUTPUT_DIR      |
| 3    | `status`                       | (read-only)                                                    | Step 2 done              |
| 4    | `threat-model-health`           | —                                                              | Step 2 done              |
| 5    | `export-threat-model`          | `--pdf --html`                                                 | Step 2 done              |
| 6    | `audit-security-requirements`   | `--requirements file://… --save-report`                         | Step 2 done              |
| 7    | `publish-threat-model`          | `--dry-run` (kein echter Push)                                  | Step 2+5 done            |
| 8    | `create-threat-model --resume`  | (Checkpoint-Restore-Test)                                       | Step 2 done              |
| 9    | `create-threat-model --incremental --base HEAD~1` | (Delta-Lauf-Test)                            | Step 2 done + 1 dummy-commit |

**Nur Step 2 ist teuer** (~$0.30 quick / haiku). Steps 0,1,3,4,5,6,7 sind
LLM-leicht oder rein deterministisch (<$0.10 zusammen). Step 8 (resume) ist
fast gratis (greift gecachte Stages). Step 9 (incremental) ist quick ohne
Stage 1 — ~$0.05.

**Total erwartet:** **~$0.50–1.00 pro Voll-Lauf** mit `quick`+`haiku`.

---

## 5. Assertions (pro Step)

### Step 2 — `create-threat-model` (Hauptlast)

#### 5.1 Existenz-Assertions (must-have files)
```
$OUT/threat-model.md
$OUT/threat-model.yaml
$OUT/threat-model.sarif.json          # weil --sarif
$OUT/pentest-tasks.yaml
$OUT/.fragments/{ms-verdict.json, ms-architecture-assessment.json,
                  critical-attack-chain.json, attack-walkthroughs.md,
                  system-overview.md, assets.md, attack-surface.md,
                  architecture-diagrams.md, security-architecture.md,
                  out-of-scope.md, operational-strengths-overrides.json}
$OUT/.threats-merged.json
$OUT/.triage-flags.json
$OUT/.recon-summary.md
$OUT/.dep-scan.json
$OUT/.appsec-cache/baseline.json
```
Jede fehlende Datei → fail.

#### 5.2 Schema-Validierung
- `threat-model.yaml` ↔ `schemas/threat-model.schema.yaml`
- `*.sarif.json` ↔ `schemas/sarif-2.1.0.schema.json`
- `pentest-tasks.yaml` ↔ `schemas/pentest-tasks.schema.yaml`
- `.threats-merged.json`, `.triage-flags.json`, `.stride-*.json`, `.dep-scan.json` ↔ jeweilige `schemas/*.schema.{json,yaml}`
- jede `.fragments/*.json` ↔ `schemas/fragments/<name>.schema.json`
→ Wiederverwendet `scripts/validate_intermediate.py all`.

#### 5.3 Struktur-Invarianten (Renderer-Verträge)
- `compose.render(CONTRACT, $OUT)` warnings == [] (ähnlich wie `test_compose_threat_model`)
- Management Summary unnummeriert; 6 kanonische Subsections in Reihenfolge
- Top-Findings-Table hat 7 Spalten
- Alle `[X](#y)` Anchor-Links zeigen auf existierende `<a id="y">` oder Heading-Slugs
- Heading-Hierarchie ohne Sprünge (`##` → `####` verboten)
- Risk-Distribution-Count == Threat-Register-Row-Count
→ Wiederverwendet `test_render_properties.py` Assertions, programmatisch gegen den frischen Output.

#### 5.4 Inhalt-Bänder (fuzzy, robust gegen LLM-Drift)
- `4 ≤ len(threats) ≤ 12`
- `len(components) ≥ 3`
- STRIDE-Coverage: mind. **4 von 6** STRIDE-Kategorien adressiert über alle Threats (T, I, D, E, S, R)
- mind. **2** `security_controls` mit `positive_framing: true`
- mind. **1** Threat mit `risk: Critical` oder `risk: High`
- **Keyword-Floor** (Treffer im Markdown, case-insensitive):
  - "SQL" + "Injection" → wegen `login.ts` SQLi-Pfad
  - "SSRF" oder "server-side request forgery" → wegen `search.ts`
  - "JWT" → wegen `auth.ts`
  - "container" + "privileged" oder "root" → wegen Dockerfile/k8s
- **Keyword-Ceiling** (sollte nicht auftauchen):
  - "TODO", "FIXME", "PLACEHOLDER", "tbd", "lorem ipsum"
  - "n/a" außerhalb erwarteter Tabellen-Cells

#### 5.5 Gate-Assertions
- `scripts/check_inline_shortcut.py` exit 0 (kein LLM-Bypass)
- `scripts/qa_checks.py all` exit 0 (alle QA-Checks grün)
- kein `--fail-on` Trigger

#### 5.6 Cost & Budget
- `scripts/verify_run_costs.py` exit 0
- `total_cost_usd < $2.00` (haiku-Tier quick)
- pro Phase: `phase_duration < phase_budgets.yaml[quick][phase]` für alle Phasen
- Stage 1 turn-usage < 200 (von 250 Budget) — wenn ≥240, Warning

#### 5.7 Hook-Log
- `$OUT/.hook-events.log` existiert, ist non-empty
- Jeder dispatched Sub-Agent (`appsec-recon-scanner`, `appsec-config-scanner`, `appsec-stride-analyzer`, `appsec-threat-merger`, `appsec-evidence-verifier`, `appsec-triage-validator`, `appsec-threat-renderer`, `appsec-qa-reviewer`) erscheint mit ≥1 `PHASE_START` und passendem `PHASE_END`
- kein `BASH_WARN` für `cat`/`head`/`sed` auf Source-Files (Hygiene-Regel)

### Step 5 — `export-threat-model`
- `$OUT/threat-model.pdf` existiert, MIME-Type "application/pdf"
- `$OUT/threat-model.html` existiert, parsed als valides HTML5
- PDF-Page-Count ≥ 5 (Sanity)

### Step 6 — `audit-security-requirements`
- `$OUT/requirements-report.md` und `.json` existieren
- Alle 3 fixture-REQs werden referenziert
- mind. 1 REQ-MUST-Verletzung gefunden (REQ-INPUT-01 sollte wegen SQLi-Pfad fallen)
- exit-Code = 1 (Findings present, gewünschtes Verhalten unter `--save-report`)

### Step 7 — `publish-threat-model --dry-run`
- exit 0
- Output enthält Branch-Diff-Preview
- **keine** echten Git-Operationen (no commits, no push)

### Step 8 — `--resume`
- exit 0
- erkennt Checkpoint, überspringt Stages 0–1 (Logfile-Assertion)
- erzeugt **byte-identisches** `threat-model.md` wie Step 2 (Resume-Determinismus)

### Step 9 — `--incremental --base HEAD~1`
- exit 0
- Change-Summary referenziert genau den dummy-commit
- Cost < $0.10 (kein voller Re-Scan)

---

## 6. Snapshot- & Diff-Strategie

### 6.1 Was archiviert wird (Workflow-Artifact, 30 Tage Retention)
```
e2e-run-<short-sha>/
├── threat-model.md
├── threat-model.yaml
├── threat-model.sarif.json
├── threat-model.pdf
├── pentest-tasks.yaml
├── requirements-report.{md,json}
├── .fragments/                       # full
├── .threats-merged.json
├── .triage-flags.json
├── .recon-summary.md
├── .hook-events.log
├── .agent-run.log
├── cost-summary.json                  # aus verify_run_costs.py
└── e2e-report.md                      # Pass/Fail pro Assertion + Diff-Summary
```

### 6.2 Diff gegen Baseline
- Baseline: letzter "grün" geflaggter Snapshot in `tests/fixtures/e2e/baseline-snapshot/`.
- Im Workflow-Job `diff-vs-baseline`:
  - YAML-Diff `threat-model.yaml`: erlaubt **drift in `meta.generated`,
    `threats[].id` (Reihenfolge), `meta.run_id`, Cost-Felder**; alles andere
    diff-frei wenn Modell+Repo unverändert
  - Bei strukturellen Unterschieden → **Job markiert "drift" aber nicht "fail"**;
    Maintainer entscheidet manuell, ob Baseline aktualisiert wird
- **Refresh-Knopf**: `gh workflow run e2e-full.yml -f mode=refresh-baseline` →
  überschreibt Baseline mit aktuellem Snapshot nach grünem Lauf.

### 6.3 Determinismus-Caveat
LLM-Outputs sind **nicht** byte-deterministisch. Daher:
- Byte-Diff nur auf **Renderer-Output bei identischen Fragments** (Tier 1 covered).
- Snapshot-Diff hier: **strukturell** (count threats, count sections, schema-shape).
- Drift > 1σ in 7-Tage-Rolling-Window → Warning.

---

## 7. CI-Workflow Shape

`.github/workflows/e2e-full.yml`:

```yaml
name: e2e-full

on:
  workflow_dispatch:
    inputs:
      mode:
        type: choice
        options: [verify, refresh-baseline]
        default: verify
      assessment_depth:
        type: choice
        options: [quick, standard, thorough]
        default: quick
      model_tier:
        type: choice
        options: [haiku, opus-cheap, opus]
        default: haiku

concurrency:
  group: e2e-full-${{ github.ref }}
  cancel-in-progress: false           # Lauf nicht abbrechen, kostet sonst Geld

jobs:
  full-run:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    environment: e2e                  # GitHub-Environment mit manual-approval-Gate
    steps:
      - uses: actions/checkout@v4
        with: { submodules: false }

      - name: Setup Python
        uses: actions/setup-python@v5
        with: { python-version: '3.12', cache: pip }

      - name: Install
        run: |
          pip install -r tests/requirements-test.txt
          pip install -r scripts/requirements.txt

      - name: Install Claude Code CLI
        run: npm install -g @anthropic-ai/claude-code@latest

      - name: Run E2E pipeline (10 steps)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY_E2E }}
        run: |
          ./tests/e2e/run-full.sh \
            --depth ${{ inputs.assessment_depth }} \
            --model-tier ${{ inputs.model_tier }} \
            --mode ${{ inputs.mode }}

      - name: Run assertions
        run: pytest tests/test_full_run_assertions.py -v --tb=short

      - name: Diff vs baseline
        if: ${{ inputs.mode == 'verify' }}
        run: python tests/e2e/diff_baseline.py

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-run-${{ github.sha }}
          path: tests/fixtures/e2e/_last-run/
          retention-days: 30

      - name: Refresh baseline (gated)
        if: ${{ inputs.mode == 'refresh-baseline' && success() }}
        run: |
          rm -rf tests/fixtures/e2e/baseline-snapshot/*
          cp -r tests/fixtures/e2e/_last-run/* tests/fixtures/e2e/baseline-snapshot/
          # PR statt direct-push: maintainer reviewed die Snapshot-Änderung
          gh pr create --title "chore(e2e): refresh baseline snapshot" --body "auto"
```

**`environment: e2e`** → GitHub Settings → "Required reviewers" → 1 Maintainer
muss den Run approven, bevor er den Secret-Key sieht. Schützt vor PR-Forks
und versehentlichen Massenläufen.

---

## 8. Lokaler Lauf (`make e2e-full`)

`Makefile` Target:
```make
.PHONY: e2e-full
e2e-full:
	@test -n "$$ANTHROPIC_API_KEY" || (echo "ANTHROPIC_API_KEY missing"; exit 1)
	./tests/e2e/run-full.sh --depth quick --model-tier haiku --mode verify
	pytest tests/test_full_run_assertions.py -v
	python tests/e2e/diff_baseline.py
```

Output:
```
[1/10] clean-run-state       ✓
[2/10] check-permissions     ✓
[3/10] create-threat-model   ✓  ($0.34, 8m12s)
[4/10] status                ✓
[5/10] threat-model-health   ✓  ($0.02, 24s)
[6/10] export-threat-model   ✓  ($0.00, 8s, PDF 6 pages)
[7/10] audit-requirements    ✓  ($0.09, 1m38s)
[8/10] publish (--dry-run)   ✓  ($0.00)
[9/10] resume                ✓  (cache-hit)
[10/10] incremental          ✓  ($0.04, 22s)

assertions: 47/47 passed
drift vs baseline: 0 structural, 3 cosmetic (text-only)

TOTAL: $0.49, 12m08s
artifact: tests/fixtures/e2e/_last-run/
```

---

## 9. Was bei "Drift" passiert

Drift-Klassen:

| Klasse                                       | Aktion                                                       |
|----------------------------------------------|---------------------------------------------------------------|
| Schema-Drift (Schema-File hat sich geändert) | Hard-fail; Spec aktualisieren                                |
| Threat-Count außerhalb Band                  | Soft-fail; Maintainer entscheidet (Modell-Update? Refactor?) |
| Strukturelle Section verschwindet            | Hard-fail; Renderer-Regression                                |
| Cosmetic (Text-Variation in Prosa)           | Info-only                                                     |
| Cost > Cap                                   | Hard-fail; Tuning nötig                                       |
| Phase-Budget überschritten                   | Soft-fail; Performance-Regression untersuchen                |
| `--resume`-Output nicht byte-identisch       | Hard-fail; Cache-Bug                                          |

→ Baseline-Refresh nur nach explizitem Maintainer-Review (eigener PR durch
Workflow generiert).

---

## 10. Implementierungs-Tasks (geplante Reihenfolge)

| #   | Task                                                                                                                   | Datei                                                                |
|-----|-------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| T1  | Synthetic-Repo erweitern (20–30 Files mit gepflanzten Vulns)                                                            | `tests/fixtures/e2e/synthetic-repo/**`                                |
| T2  | `business-context.yaml` + `requirements-fixture.yaml` Fixtures                                                          | `tests/fixtures/e2e/*.yaml`                                            |
| T3  | Driver-Skript: `tests/e2e/run-full.sh` — wrappt `run-headless.sh` + alle 10 Steps + Cost-Aggregation                    | `tests/e2e/run-full.sh`                                                |
| T4  | Assertion-Test-Datei                                                                                                    | `tests/test_full_run_assertions.py`                                    |
| T5  | Diff-Tool gegen Baseline                                                                                                 | `tests/e2e/diff_baseline.py`                                           |
| T6  | Baseline-Bootstrap (erster grüner Lauf → Snapshot eingecheckt)                                                          | `tests/fixtures/e2e/baseline-snapshot/`                                |
| T7  | `Makefile` Target `e2e-full`                                                                                              | `Makefile`                                                             |
| T8  | GitHub-Workflow `e2e-full.yml` + Environment `e2e` mit required-reviewer                                                 | `.github/workflows/e2e-full.yml` + Repo-Settings                       |
| T9  | Doku                                                                                                                     | `docs/e2e-testing.md` + Hinweis in `README.md` + `AGENTS.md`            |
| T10 | First-run + Baseline-Commit + Onboarding                                                                                | manueller Lauf                                                          |

**Geschätzter Aufwand:** 5–7 Tage Solo, davon
- T1 (synthetic-repo) ist die Hauptaufgabe (Vulns plausibel, deterministisch
  triggerbar, aber nicht "zu offensichtlich" damit STRIDE-Analyzer realistisch
  bleibt) — 1.5 Tage
- T4 (Assertions) — 1.5 Tage (~50 Asserts; Wiederverwendung der existierenden Property-Tests)
- T3 + T5 (Driver + Diff) — 1 Tag
- T7 + T8 (CI) — 0.5 Tag
- T6 + T10 (Bootstrap, Iteration bis Baseline stabil) — 1 Tag
- T2 + T9 — 0.5 Tag

---

## 11. Was bewusst NICHT abgedeckt wird

| Nicht-Ziel                                            | Begründung                                                                          |
|--------------------------------------------------------|--------------------------------------------------------------------------------------|
| Per-PR-Trigger                                         | Zu teuer, zu lang. Tier 1 (50+ Python-Tests) bleibt der per-PR-Schutz.              |
| Multi-Modell-Matrix in einem Lauf (haiku × sonnet × opus) | $$$. Default haiku. `model_tier` Input erlaubt einmaligen Sonnet-Lauf bei Bedarf.   |
| Multi-Repo-Matrix (Juice Shop + synthetic + Strapi …)  | $$$. Synthetic-Repo deckt alle wichtigen Pfade. Juice-Shop optional via separater workflow_dispatch. |
| Byte-deterministischer Vergleich auf Prose             | Per Definition unmöglich. Strukturelle Asserts + Drift-Tracking ersetzen das.       |
| LLM-Prosa-Qualität (Lesbarkeit, Stil)                  | Subjektiv, gehört in Review nicht in CI. Optional Tier 4 später.                    |
| Adversarial-Inputs (Prompt-Injection, große Repos)     | Eigener Test-Track, nicht E2E-happy-path.                                            |
| Per-Tier-Permissions (juniors dürfen nicht refreshen) | `environment: e2e` löst das via GitHub-Settings.                                     |

---

## 12. Eskalations-Plan

Wenn nach 3 grünen Läufen einer rot wird:

1. Artifact runterladen → `e2e-report.md` lesen
2. `diff_baseline.py` Output prüfen → strukturell oder kosmetisch?
3. **Strukturell:** Code-Review der letzten Commits seit letztem Grün; meist
   ein Refactor in `compose_threat_model.py`, `sections-contract.yaml`,
   Schema-File, oder einem Agent-Prompt.
4. **Cost-Overshoot:** `cost-summary.json` per Phase; korrelieren mit
   `phase-budgets.yaml`.
5. **Hard-Gate-Trigger:** `check_inline_shortcut.py` hat einen direkten
   Markdown-Write erkannt → Agent-Prompt-Regression.
6. **Schema-Fail:** `validate_intermediate.py` schmeißt; Schema-Datei oder
   Fragment-Writer kaputt.
7. Fix als eigenen PR → Tier 1 + Tier 2 (falls existiert) müssen grün sein →
   `e2e-full` re-run → bei grün: optional `refresh-baseline`.
