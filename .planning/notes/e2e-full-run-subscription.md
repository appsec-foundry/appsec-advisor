# Full-Run E2E mit Subscription-Auth — Addendum

**Datum:** 2026-05-24
**Status:** Analyse — keine Umsetzung
**Bezug:** Ergänzung zu [`e2e-full-run-spec.md`](./e2e-full-run-spec.md)

**Frage:** Geht das Full-E2E auch mit einer Claude-Code-**Subscription**
(Pro/Max) statt API-Key?

---

## TL;DR

| Szenario                        | Geht?       | Empfehlung                                              |
|---------------------------------|-------------|----------------------------------------------------------|
| **Lokal** (Dev-Maschine)        | ✅ trivial   | **Default-Pfad** für post-Refactor-Runs                  |
| **Self-hosted GitHub-Runner**    | ⚠️ technisch ja, aber fragil + ToS-Grauzone | nur wenn lokal nicht reicht |
| **GitHub-hosted Runner**         | ❌            | nicht machbar — kein Browser, kein persistentes `~/.claude` |
| **Geteilte CI** (mehrere Devs)   | ❌            | ToS verletzt; Subscription ist personal use              |

**Empfehlung:** **Lokal nur.** Den teuren Voll-Lauf nimmst Du selbst auf
Deiner Maschine, weil Du ihn nur "nach größeren Umbauten" brauchst — das passt
exakt zum Subscription-Modell. API-Key bleibt optional für den Fall, dass Du
mal von einer anderen Maschine oder aus CI laufen lassen willst.

---

## 1. Wie Subscription-Auth in Claude Code funktioniert

1. `claude /login` (oder `claude login` aus Shell) öffnet Browser → OAuth-Flow → Token landet in `~/.claude/` (genauer Pfad version-abhängig, aber lokal in Home).
2. `claude -p "…"` und alle Subagent-Calls nutzen automatisch dieses Token, **kein** `ANTHROPIC_API_KEY` nötig.
3. `run-headless.sh` ruft `claude -p` auf → funktioniert identisch ob via Subscription oder API-Key. Der Skript-Header sagt das auch explizit:
   ```
   ANTHROPIC_API_KEY       Anthropic API key (optional — uses subscription if unset)
   ```
4. Pre-flight Auth-Check in `run-headless.sh` verifiziert nur, dass *irgendeine*
   Auth da ist — er prüft nicht, ob es API-Key oder Subscription ist.

→ **Aus Tooling-Sicht ist Subscription transparent.** Der Skill kann nicht
unterscheiden, ob ein Token aus OAuth oder API-Key kommt.

---

## 2. Was sich konkret ändert vs. API-Key-Setup

### 2.1 Lokaler Lauf (`make e2e-full`)

**Diff zur Spec:** **null Änderung am Tooling.** Nur die env-Variable
`ANTHROPIC_API_KEY` weglassen.

```make
.PHONY: e2e-full
e2e-full:
	@claude --version >/dev/null 2>&1 || (echo "claude CLI missing"; exit 1)
	# kein API-Key-Check mehr — subscription auth via ~/.claude/
	./tests/e2e/run-full.sh --depth quick --model-tier sonnet --mode verify
	pytest tests/test_full_run_assertions.py -v
	python tests/e2e/diff_baseline.py
```

**Output identisch.** Cost-Tracking (`verify_run_costs.py`) zeigt die internen
Token-Counts; bei Subscription bedeutet "Cost" nur **Quota-Verbrauch**, nicht
echte USD-Belastung.

**Modell-Wahl:** mit Subscription macht **Sonnet als Default** mehr Sinn als
Haiku — bei Pro/Max sind alle Modelle inklusive, also nimmst Du die bessere
Qualität für den Verify-Lauf. Quota statt USD bremst.

### 2.2 Cost-Cap-Semantik dreht sich um

| Setting             | API-Key                            | Subscription                               |
|---------------------|-------------------------------------|---------------------------------------------|
| `--max-budget 5.00`  | hartes Dollar-Cap                 | sinnlos — Subscription kennt keine USD       |
| `--max-duration 1800` | wichtig (Cost)                    | wichtig (Quota + Wall-Time)                  |
| Per-Step-Cost-Assertion | "cost < $X"                    | "tokens_used < N" — eigene Threshold-Tabelle  |
| `verify_run_costs.py` | exit 0 wenn Dollar-Cap ok        | exit 0 wenn Token-Cap ok                    |

→ **Assertion-Set 5.6 in der Spec muss umgeschrieben werden** auf
Token-/Turn-Counts statt USD, oder zwei-stufig: USD wenn API-Key da, sonst
Tokens. `verify_run_costs.py` bekommt einen `--auth-mode` Flag.

### 2.3 Quota-Risiko

Ein Voll-Lauf (10 Steps, ~$0.50 mit Haiku) entspricht roughly:
- **Haiku:** ~50–100 Messages → ~5–10% einer Pro-5h-Window
- **Sonnet:** ~80–150 Messages → ~30–50% einer Pro-5h-Window
- **Opus:** ~80–150 Messages → ~80–100% einer Pro-5h-Window (Opus ist limitierter)

→ **Mehr als 1–2 Voll-Läufe pro 5h-Window** bei Sonnet/Opus = Quota-Exhaustion.
Bei "nach jedem größeren Refactor" passt das, weil das selten ist. Bei
Iterieren auf einem fehlschlagenden Lauf wird's eng.

**Mitigation:**
- Modell-Tier auf Haiku setzen, wenn iterativ debuggt wird
- Re-Run via `--resume` (greift Cache, kostet kaum Quota)
- Quota-Status sichtbar machen: am Anfang von `run-full.sh` ein `claude /usage`-Equivalent ausgeben (falls existent)

---

## 3. Warum CI mit Subscription nicht geht

### 3.1 Technische Blocker

| Problem                                          | Konsequenz                                                       |
|--------------------------------------------------|-------------------------------------------------------------------|
| GitHub-hosted Runner haben kein persistentes Home | OAuth-Token ist nicht zwischen Runs verfügbar                    |
| Keine Browser-UI im Runner                       | `claude /login` kann nicht laufen                                  |
| Token kopieren in CI Secret?                     | OAuth-Tokens refreshen, sind device-gebunden, expiren → kaputt nach Tagen |
| Anthropic könnte Device-Binding erzwingen        | Token zickt selbst wenn kopiert                                   |
| Refresh-Token im Secret offenlegen                | Token-Leak-Risiko hoch; rotation manuell                          |

### 3.2 Anthropic Terms of Service

Subscription-Pläne (Pro/Max) sind **personal use**. Automation in
geteilten CI-Pipelines fällt typischerweise nicht darunter. Für CI-Automation
will Anthropic, dass Du API-Key (Pay-as-you-go) nutzt.

→ Selbst wenn Du den Token technisch ins CI bekommst (siehe self-hosted unten),
ist es **ToS-Grauzone**. Bei Auffälligkeit (z.B. starke parallel-Last) Risiko
für Account-Sperre.

### 3.3 Self-hosted Runner — der "geht-technisch" Pfad

Wenn Du **unbedingt** auf CI laufen willst ohne API-Key:

1. **Self-hosted GitHub-Actions-Runner** auf einer Maschine, die Dir gehört.
2. Auf der Runner-Maschine **einmalig** `claude /login` interaktiv ausführen.
3. Token liegt in `~/.claude/` des Runner-User-Accounts.
4. Workflow läuft als dieser User → findet das Token automatisch.

**Was Du dafür akzeptierst:**
- Maschine muss 24/7 laufen oder zur Lauf-Zeit verfügbar sein
- Token-Refresh kann den Runner stillschweigend kaputt machen → manuelle Re-Auth alle paar Wochen
- ToS-Risiko (siehe oben)
- Nur **eine** Person/Maschine — kein Team-CI
- Runner-Maintenance (Updates, Security-Patches) ist Dein Problem

**Workflow-Anpassung:**
```yaml
runs-on: [self-hosted, claude-subscription]   # statt ubuntu-latest
```
Rest des Workflows bleibt identisch. **Kein** `ANTHROPIC_API_KEY` mehr nötig.

**Bewertung:** für "nach größeren Umbauten manuell" lohnt sich der Self-hosted-
Setup **nicht** — lokales `make e2e-full` ist einfacher und identisch im Effekt.

---

## 4. Hybrider Default (Empfehlung)

Der Skill und der Test-Driver brauchen **keine Auth-Mode-Entscheidung** —
beide Modi laufen mit dem gleichen Code. Nur das **CI-Setup** unterscheidet
sich.

### 4.1 Lokal (Standard-Pfad)
- Subscription-Auth (Du bist eh angemeldet)
- `make e2e-full`
- Modell-Tier: Sonnet als Default (Qualität, Quota egal)
- "Cost"-Assertions auf Token-Counts

### 4.2 CI (Bedarfs-Pfad, optional)
- API-Key (separater `ANTHROPIC_API_KEY_E2E` Secret)
- `gh workflow run e2e-full.yml`
- Modell-Tier: Haiku als Default (Cost-Sensitiv)
- "Cost"-Assertions auf USD

### 4.3 Switch-Logik im Driver

`tests/e2e/run-full.sh` macht **gar nichts** Spezielles:
- Hat `ANTHROPIC_API_KEY` Wert → nutzt API-Key (Claude Code automatisch)
- Sonst → nutzt Subscription-Token aus `~/.claude/`
- Pre-flight ruft `claude --version` und einen 1-Token-Probe-Call (`claude -p "hi" --max-turns 1`) → exit 0 reicht

`verify_run_costs.py` bekommt zwei Modi:
```bash
# API-Key-Modus
verify_run_costs.py --max-budget-usd 5.00 ./output/

# Subscription-Modus
verify_run_costs.py --max-tokens 500000 ./output/
```
Auto-Detect via `[[ -n "$ANTHROPIC_API_KEY" ]]`.

### 4.4 Assertions, die unabhängig von Auth sind

**95% der ~50 Assertions ändern sich nicht.** Schema-Validierung,
Struktur-Invarianten, Content-Bänder, Keyword-Floors, Gate-Checks, Hook-Logs,
Resume-Determinismus — alles auth-unabhängig. Nur **Cost-Assertion (5.6)**
wechselt zwischen USD-Cap und Token-Cap.

---

## 5. Konkrete Anpassungen an der Spec

| Spec-Sektion       | Änderung für Subscription-Default                                                    |
|--------------------|----------------------------------------------------------------------------------------|
| §3 Inputs          | `API-Key` Zeile wird optional; "kein Setup nötig wenn `claude /login` schon gelaufen" |
| §4 Lauf-Matrix     | Default-Modell `claude-sonnet-4-6` statt Haiku                                         |
| §5.6 Cost-Asserts  | Token-basierte Caps; USD-Caps nur in CI-Variante                                       |
| §7 CI-Workflow     | bleibt API-Key-Variante; **optional** zweiter Workflow `e2e-full-selfhosted.yml`        |
| §8 `make e2e-full` | API-Key-Check entfernen; nur `claude --version` Check                                    |
| §11 NICHT-Ziele    | "geteilte CI-Subscription" explizit als Nicht-Ziel aufnehmen                            |

---

## 6. Empfehlung

**Bau das Full-E2E primär für lokalen Subscription-Lauf.**

Gründe:
- Dein Use-Case "nach größeren Umbauten" passt zum manuellen lokalen Trigger.
- $0 zusätzliche Kosten (Subscription hast Du eh).
- Kein Secret-Management.
- Kein ToS-Risiko.
- Sonnet-Qualität gratis.
- Self-hosted-Runner ist Overhead ohne ROI bei seltenem Lauf.

**API-Key-Variante als zweite Schiene** (separater Workflow) — nur wenn Du
später doch nightly oder Team-CI willst. Sie ist eine **Variante**, kein
Ersatz: gleicher Driver, gleicher Assertion-Code, andere Cost-Caps.

**Implementierungs-Reihenfolge geändert vs. Spec §10:**

| #   | Task                                                                          | Auth-Abhängigkeit       |
|-----|--------------------------------------------------------------------------------|--------------------------|
| T1–T6 | (wie Spec)                                                                   | auth-unabhängig          |
| T7  | `Makefile` Target `e2e-full` (lokal, Subscription-default)                     | Subscription             |
| T8a | `verify_run_costs.py --max-tokens` Modus                                       | beide                    |
| T9  | Doku — Schwerpunkt **lokaler Lauf**                                              | Subscription              |
| **(später, optional)** T8b | GitHub-Workflow `e2e-full.yml` mit API-Key + `environment: e2e` | API-Key                  |
| **(später, optional)** T8c | Self-hosted-Workflow-Variante                                     | Subscription              |

**Aufwand-Delta:** −1 Tag (Subscription-only skipt CI-Auth-Hardening, Environment-Setup, Secret-Rotation-Doku). Self-hosted-Variante wäre +0.5 Tag.
