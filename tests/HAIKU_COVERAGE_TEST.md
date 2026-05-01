# Coverage-Test-Plan: Haiku-Economy gegen Sonnet-Default

## Zweck

Validiert dass `--reasoning-model haiku-economy --assessment-depth quick` keine
Quality-Regression gegenüber dem heutigen Default (`--assessment-depth quick`,
implizit `--reasoning-model sonnet`) verursacht.

Dieser Test ist **manuell** auszuführen — er erfordert echte LLM-Token-Kosten
(~$15-25 einmalig) und Wallclock (~30-60 min für beide Runs zusammen) und kann
nicht von der automatischen Test-Suite ausgeführt werden.

## Voraussetzungen

- Plugin-Version: aktueller `main` (mit haiku-economy-Patch)
- Reference-Repo: ein bewährtes Test-Projekt (siehe Empfehlung unten)
- Anthropic-API-Quota: ~$25 verfügbar
- Zeit: ~90 min für beide Runs + Vergleich

## Empfohlene Reference-Repos

| Repo | Größe | Stack | Kosten Sonnet | Kosten Haiku |
|---|---|---|---|---|
| OWASP juice-shop | mittel | Node/Express/Angular | ~$3-4 | ~$1-2 |
| pyca/cryptography | klein-mittel | Python | ~$2-3 | ~$1 |
| Eigenes Test-Mini-Repo (~30 files) | klein | beliebig | ~$1-2 | ~$0.50 |

**Empfehlung:** juice-shop, weil komplexer Stack mit Auth/DB/Frontend → testet
volle Pipeline.

## Test-Prozedur

### Schritt 1: Baseline-Run (Sonnet)

```bash
cd <reference-repo-path>

# Lokale Output-Dir, damit nichts ins Repo committet wird
mkdir -p /tmp/coverage-test-baseline

# Saubere Ausgangslage
rm -rf /tmp/coverage-test-baseline/.appsec-cache
rm -rf /tmp/coverage-test-baseline/.fragments

# Baseline-Run
time /appsec-advisor:create-threat-model \
    --assessment-depth quick \
    --output /tmp/coverage-test-baseline \
    --no-confirm \
    --yaml \
    2>&1 | tee /tmp/coverage-test-baseline/run.log

# Cost extrahieren
python3 scripts/verify_run_costs.py /tmp/coverage-test-baseline
```

Erwartung: `threat-model.yaml` vorhanden, Findings ≥ 5, kein hard error.

### Schritt 2: Treatment-Run (haiku-economy)

```bash
mkdir -p /tmp/coverage-test-treatment
rm -rf /tmp/coverage-test-treatment/.appsec-cache
rm -rf /tmp/coverage-test-treatment/.fragments

time /appsec-advisor:create-threat-model \
    --assessment-depth quick \
    --reasoning-model haiku-economy \
    --output /tmp/coverage-test-treatment \
    --no-confirm \
    --yaml \
    2>&1 | tee /tmp/coverage-test-treatment/run.log

python3 scripts/verify_run_costs.py /tmp/coverage-test-treatment
```

### Schritt 3: Vergleich

```bash
# Wallclock + Cost
echo "=== Baseline ==="
grep -E "real|cost" /tmp/coverage-test-baseline/run.log
echo "=== Treatment ==="
grep -E "real|cost" /tmp/coverage-test-treatment/run.log

# Findings-Count
echo "=== Findings Count ==="
yq '.threats | length' /tmp/coverage-test-baseline/threat-model.yaml
yq '.threats | length' /tmp/coverage-test-treatment/threat-model.yaml

# Severity-Verteilung
echo "=== Baseline Severity ==="
yq '.threats[].severity' /tmp/coverage-test-baseline/threat-model.yaml | sort | uniq -c
echo "=== Treatment Severity ==="
yq '.threats[].severity' /tmp/coverage-test-treatment/threat-model.yaml | sort | uniq -c

# Critical-Findings
echo "=== Baseline Critical ==="
yq '.threats[] | select(.severity == "Critical") | .title' /tmp/coverage-test-baseline/threat-model.yaml
echo "=== Treatment Critical ==="
yq '.threats[] | select(.severity == "Critical") | .title' /tmp/coverage-test-treatment/threat-model.yaml
```

## Acceptance-Kriterien

| Metrik | Acceptance |
|---|---|
| **Findings-Count-Drift** | ≤ ±10 % (Treatment darf max 10 % weniger Findings haben) |
| **Critical-Erhalt** | 100 % — jede Critical aus Baseline muss in Treatment auch existieren (semantisch matchen) |
| **High-Erhalt** | ≥ 80 % — Treatment behält mindestens 80 % der Baseline-Highs |
| **Severity-Verteilung-Drift** | ≤ ±15 % pro Severity-Klasse |
| **Wallclock-Reduction** | ≥ 20 % (erwartet: 25-30 %) |
| **Cost-Reduction** | ≥ 25 % (erwartet: ~33 %) |
| **Schema-Validität** | beide YAMLs passen `validate_intermediate.py` |

## Ergebnis-Dokumentation

Wenn alle Acceptance-Kriterien erfüllt:
- `tests/HAIKU_COVERAGE_RESULTS.md` mit Datum + Repo + Metriken
- Empfehlung an Plugin-Maintainer: Default-Switch erwägen

Wenn ein Kriterium scheitert:
- Detail-Analyse welcher Aspekt verloren geht
- Falls Critical fehlt → kein Default-Switch, möglicherweise Patch zurücknehmen
- Falls nur Wallclock-Win marginal → Plan revidieren

## Wann diesen Test ausführen

- Vor dem Default-Switch von haiku-economy auf Quick-Default (= Plugin-Maintainer-Entscheidung)
- Nach jedem Sonnet/Haiku Modell-Update von Anthropic
- Nach signifikanten Änderungen an `agents/appsec-stride-analyzer.md` Quick-Profile-Sektion
- Bei Bug-Reports "Haiku-Modus findet weniger Threats"

## Automatisierung als Roadmap

Manuelle Ausführung ist OK für initiale Validierung. Längerfristig sollte
dieser Test in das E2E-CI-Test-Setup integriert werden (Roadmap §8 #2):

- Reference-Repo als Submodule oder Fixture
- Beide Runs als CI-Job (täglich oder wöchentlich)
- Dashboard mit Findings-Count-Trend und Cost-Trend
- Auto-Alert bei Acceptance-Verletzung

## Status

- [ ] Schritt 1 ausgeführt: Datum / Reviewer
- [ ] Schritt 2 ausgeführt: Datum / Reviewer
- [ ] Schritt 3 ausgewertet: Datum / Reviewer
- [ ] Ergebnis dokumentiert in `HAIKU_COVERAGE_RESULTS.md`
- [ ] Default-Switch-Entscheidung getroffen
