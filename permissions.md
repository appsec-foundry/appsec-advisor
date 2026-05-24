# Permission-Cleanup — Umsetzungsplan

Beseitigung der `Bash(*)` + `Read(**)/Write(**)/Edit(**)`-Inkonsistenz zwischen
`data/required-permissions.yaml` und der committed `.claude/settings.json`:
Single-Source-of-Truth durchsetzen, committed `settings.json` raus,
Self-Dogfooding-Cat-28b-Finding (siehe `SECURITY.md:81` „Known issues —
untrusted repositories") auflösen.

> Verifiziert am 2026-05-24. Keine Phase ist umgesetzt. Zahlen und Zeilen
> spiegeln den aktuellen Git-Stand der Datei (`git ls-files .claude/settings.json`
> liefert noch einen Treffer).

## Kontext (Bestandsaufnahme, verifiziert)

| Artefakt | Stand heute | Problem |
|---|---|---|
| `data/required-permissions.yaml` | kanonisch laut `AGENTS.md:115`; **34** path-scoped File-Einträge **plus genau eine** Bash-Zeile: `Bash(*)` (line 189) | argumentiert philosophisch für `Bash(*)`, weil Claude Codes Prefix-Matcher Compound-Commands nicht deckt |
| `.claude/settings.json` | committed; `Read(**)/Write(**)/Edit(**)` (lockerer als YAML) + **30** kuratierte Bash-Einträge **ohne** `Bash(*)` (strikter als YAML) | widerspricht der YAML in beide Richtungen; Contributor-RCE-Vektor; Self-Dogfooding-Cat-28b |
| `scripts/check_permissions.py` | liest YAML als SoT, `--scope local` default → `.claude/settings.local.json` (`scripts/check_permissions.py:356`) | OK, kein Eingriff am Code, aber Default-Bash-Policy wird unverändert in End-User-Settings geschrieben |
| `tests/test_check_permissions.py` | enthält `test_shipped_settings_is_covered_by_yaml` (line 228) Drift-Guard auf die committed `.claude/settings.json` | passt heute nur durch `Bash(*)`-Catch-all in YAML; muss nach Cleanup refit werden |
| `schemas/required-permissions.schema.*` | **existiert nicht** | kein formaler Vertrag für die YAML |
| `CONTRIBUTING.md:64` | `.claude/settings.json` framed als „Plugin-level Bash permission allow-list" | sachlich falsch — ist Contributor-Convenience, nicht Plugin-Distribution |
| `.gitignore` | enthält bereits `.claude/settings.local.json` (line 43), **nicht aber** `.claude/settings.json` | Schritt 8 muss `.claude/settings.json` ergänzen |

## Entscheidungsfragen (vor jedem Code-Change zu klären)

### Q1 — Bash-Policy für End-User

Die strategische Frage. Determiniert alle weiteren Schritte.

| Variante | Beschreibung | Vorteile | Nachteile |
|---|---|---|---|
| **(a)** `Bash(*)` beibehalten | YAML deklariert `Bash(*)`; check-permissions schreibt das in User-Settings | Compound-Commands prompt-frei; YAML konsistent mit Code-Realität; kein Pipeline-Refactor | Plugin self-flaggt sich Cat-28b Critical bei eigenem Scan → schlechte Marketplace-Optik; widerspricht jeder anderen Security-Empfehlung des Plugins |
| **(b)** Curated allow-list | YAML auf ~25 Bash-Einträge (heutige settings.json minus `rm`/`chmod`/`tee`/`xargs`/`curl`); Pipeline-Code refaktorieren um Compound-Bash zu vermeiden | echte Härtung; Plugin-on-Plugin-Scan ist clean; konsistente Security-Story | Pipeline-Refactor (Background-Launches, Phase-Epoch-Arithmetik, Lock-Sequenzen); breaking change für Contributor-Workflows; hoher Hebel |
| **(c)** Profil-Switch | YAML hat `profiles: {strict: [...curated], permissive: [Bash(*)]}`; User wählt beim `--update`, Default `strict` mit Warnung vor `permissive` | flexibel; Marketplace zeigt strict by default; Power-User können opt-in | komplexer; Drift-Risiko zwischen Profilen; YAML-Schema und `check_permissions.py` brauchen Profil-Logik |

**Empfehlung: (b) light.**
Pragmatisch: YAML auf den heutigen `.claude/settings.json`-Set umstellen, *ohne* zunächst den Pipeline-Refactor erzwingen. Welche der 30 Bash-Einträge wirklich genutzt werden, klärt Phase-0-Schritt-2-Audit — vor dem Audit ist nicht belegt, dass `rm:*`, `chmod:*`, `mv:*`, `tee:*`, `xargs:*`, `curl:*` ungenutzt sind; sie wurden aus dem Bauchgefühl der ursprünglichen Risiko-Sortierung herausgegriffen. Compound-Command-Hits werden vom End-User initial geprompted; ein Bug-Report listet konkrete Prompt-Stellen → diese werden zielgerichtet refaktoriert. So gibt es kein big-bang-Refactor und gleichzeitig kein `Bash(*)` mehr in der Distribution.

Falls dieser inkrementelle Pfad zu schmerzhaft ist: fallback auf (c) mit explizitem Default-Strict.

### Q2 — File-Scope-Drift

YAML hat `Read(${REPO_ROOT}/**)` etc. (path-scoped). settings.json hat `Read(**)` (unrestringiert).

**Empfehlung: YAML-Scope ist korrekt.** Settings-Template muss path-scoped sein. Contributor-Komfort minimal verschlechtert (Debug-Reads außerhalb Repo prompten), aber das ist der ehrliche Default.

### Q3 — Drift-Test-Refit

`test_shipped_settings_is_covered_by_yaml` (`tests/test_check_permissions.py:228`) testet derzeit die committed `.claude/settings.json` gegen die YAML.

**Empfehlung:** Test umrouten auf `.claude/settings.example.json` (neue Template-Datei) **und** zusätzlichen Test `test_no_committed_runtime_settings_file` ergänzen, der grep auf `git ls-files` macht und assertiert, dass weder `.claude/settings.json` noch `.claude/settings.local.json` getrackt sind.

### Q4 — Schema für required-permissions.yaml

**Empfehlung: Schema schreiben.** Analog zu `schemas/related-repos.schema.yaml`. Pflichtfelder: `version: 1`, `required: list[{entry: str, reason: str, category: enum[file, shell]}]`. `check_permissions.py` validiert beim Laden. Aufwand ~30 min.

---

## Umsetzungsplan (sequenziell, jeder Schritt mit Verify-Kriterium)

Voraussetzung: Q1–Q4 entschieden. Nachfolgende Schritte basieren auf den
Empfehlungen Q1=(b)-light, Q2=path-scoped, Q3=refit+anti-test, Q4=schema.

### Phase 0 — ADR + Audit (Vorarbeit, kein Code)

1. **ADR `docs/adr/0001-permission-policy.md` schreiben** (1 Seite).
   Inhalt: Q1-Entscheidung mit Begründung, Q2/Q3/Q4 als Folge-Decisions
   referenzieren, Migrationsrisiken aufzählen.
   → verify: Datei existiert, durchgelesen vom Maintainer, in `git log`.

2. **Bash-Audit der Pipeline.**
   Greppen aller `Bash(...)`-Aufrufe in `agents/`, `skills/`,
   `scripts/`, und herausfinden, welche der 30 heute in
   `.claude/settings.json` gelisteten Bash-Prefixes real benutzt werden.
   Für die im Verdacht stehenden Kandidaten:
   `git grep -nE '\b(rm|chmod|mv|tee|xargs|curl)\b' agents/ skills/ scripts/`
   Für jeden Treffer entscheiden: behalten in YAML / streichen.
   → verify: `docs/permission-audit.md` listet jeden Bash-Befehl aus der
     heutigen settings.json mit Spalte „Used in:" (Pfad+Zeile) oder „UNUSED".

### Phase 1 — Schema-Vertrag

3. **`schemas/required-permissions.schema.yaml` erstellen.**
   ```yaml
   $schema: "https://json-schema.org/draft-07/schema#"
   type: object
   required: [version, required]
   properties:
     version: {type: integer, enum: [1]}
     required:
       type: array
       minItems: 1
       items:
         type: object
         required: [entry, reason, category]
         additionalProperties: false
         properties:
           entry:    {type: string, minLength: 3}
           reason:   {type: string, minLength: 10}
           category: {type: string, enum: [file, shell]}
   ```
   → verify: `python3 -c "import yaml,jsonschema; jsonschema.validate(yaml.safe_load(open('data/required-permissions.yaml')), yaml.safe_load(open('schemas/required-permissions.schema.yaml')))"` exit 0.

4. **`scripts/check_permissions.py:load_required` mit Schema-Validierung.**
   Nach `yaml.safe_load`: `jsonschema.validate(doc, schema)`. Schema-Datei
   path-resolved relativ zu `PLUGIN_ROOT / "schemas"`. Bei Validation-Error
   `SystemExit(2)` mit klarer Message.
   → verify: bewusst kaputtes YAML (z. B. `category: bogus`) macht
     `check_permissions.py` exit 2 mit Schema-Error.

5. **Neuer Test `test_yaml_validates_against_schema`.**
   `tests/test_check_permissions.py` ergänzen.
   → verify: `pytest tests/test_check_permissions.py -k schema` grün.

### Phase 2 — YAML auf curated Set umstellen (Q1=(b)-light)

6. **`data/required-permissions.yaml` editieren.**
   - File-Block (34 Einträge) unverändert.
   - Bash-Block: `Bash(*)`-Zeile (line 189) und den darüber stehenden
     „Why Bash(*) instead…"-Kommentarblock löschen.
   - Stattdessen pro Audit-Ergebnis (Schritt 2) je einen Eintrag mit
     `category: shell` und kurzer `reason:`. Erwartete Größenordnung
     ~20–30 Einträge (heutige settings.json abzüglich der vom Audit als
     ungenutzt belegten Prefixes).
   - Kommentar-Block oben anpassen: nicht mehr „nur `Bash(*)` funktioniert",
     sondern „kuratierte Liste; bekannte Prompt-Quellen siehe ADR-0001".
   → verify:
     - `python3 scripts/check_permissions.py --plugin-dir . --repo-root .`
       exit 1 (heutige `.claude/settings.json` deckt die neuen Entries
       inhaltlich, aber sicherheitshalber durchspielen).
     - `pytest tests/test_check_permissions.py` grün.
     - Schema-Validierung exit 0.

### Phase 3 — Template und committed-File migrieren

7. **`.claude/settings.example.json` generieren.**
   Kleines Helfer-Script `scripts/render_settings_example.py` schreiben, das
   `data/required-permissions.yaml` einliest, Platzhalter literal lässt
   (`${REPO_ROOT}` etc. — Claude Code expandiert sie nicht; Contributor copiert
   und resolves, oder das Script ersetzt durch `.` bei Render). Output schreibt
   in `.claude/settings.example.json` mit Header-Kommentar:
   ```jsonc
   // Contributor convenience template. Single-source-of-truth ist
   // data/required-permissions.yaml. Vor dem Öffnen des Repos in Claude Code:
   //   cp .claude/settings.example.json .claude/settings.local.json
   // Für End-User-Installation:
   //   /appsec-advisor:check-permissions --update
   ```
   → verify: `python3 scripts/render_settings_example.py` produziert
     deterministisches Output (zwei Läufe = byte-gleich); JSON ist valide.

8. **`.gitignore` erweitern.**
   `.claude/settings.local.json` ist bereits ignoriert (`.gitignore:43`).
   Ergänzen ist `.claude/settings.json`. Bestehende Zeile entweder ersetzen
   durch einen kommentierten Block:
   ```
   # Claude Code local permission overrides — never commit
   .claude/settings.json
   .claude/settings.local.json
   ```
   oder eine einzelne neue Zeile `.claude/settings.json` neben Zeile 43.
   → verify: `git check-ignore -v .claude/settings.json` zeigt die Regel.

9. **`git rm .claude/settings.json`** und commit.
   → verify: `git ls-files | grep -E '\\.claude/settings(\\.local)?\\.json$'`
     ist leer.

### Phase 4 — Drift-Tests refit (Q3)

10. **`tests/test_check_permissions.py:test_shipped_settings_is_covered_by_yaml`
    umrouten** auf `.claude/settings.example.json`.
    → verify: Test grün, und ein bewusstes Drift-Experiment (Bash-Entry im
      Template ohne YAML-Entsprechung) lässt den Test fehlschlagen.

11. **Neuer Test `test_no_committed_runtime_settings_file`.**
    ```python
    def test_no_committed_runtime_settings_file():
        out = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
        forbidden = [".claude/settings.json", ".claude/settings.local.json"]
        leaked = [p for p in out if p in forbidden]
        assert not leaked, f"runtime settings files must not be committed: {leaked}"
    ```
    → verify: Test grün heute; rotes Re-add via `git add -f` zeigt den Fail.

12. **Neuer Test `test_example_matches_rendered`.**
    Rendert das Template in tmp-Pfad, vergleicht byte-gleich mit committed
    `.claude/settings.example.json`.
    → verify: Test grün; jede manuelle Änderung am Template ohne YAML-Update
      schlägt fehl.

### Phase 5 — Dokumentation und Cross-Refs

13. **`CONTRIBUTING.md:64` umformulieren.**
    Aktuelle Zeile lautet:
    > `| `.claude/settings.json` | Plugin-level Bash permission allow-list |`
    Ersetzen durch:
    > `| `.claude/settings.example.json` | Contributor-Convenience-Template; nach `.claude/settings.local.json` kopieren (gitignored). End-User installieren Permissions via `/appsec-advisor:check-permissions --update`. SoT: `data/required-permissions.yaml`. |`
    → verify: `git diff CONTRIBUTING.md` zeigt nur diese eine Tabellen-Zeile.

14. **`SECURITY.md` synchronisieren.**
    Verifizierte Vorkommen: `SECURITY.md:87` (Issue #1 Tabellenzeile) und
    `SECURITY.md:109` (Recommended-Mitigations).
    - Issue #1 (`SECURITY.md:87`): `Bash(*)`-Text durch „kuratierte
      Bash-Allow-Liste" ersetzen; Risiko-Profil neu beschreiben (kein
      `Bash(*)` mehr, aber `python3`, `awk`, `sed` bleiben RCE-Primitives
      bei Prompt-Injection — ehrlich bleiben).
    - Recommended-Mitigations (`SECURITY.md:109`): Punkt „Drop the `Bash(*)`
      requirement" entfernen (erledigt).
    - Section „Planned: untrusted-repo mode" (`SECURITY.md:102`): Hinweis
      ergänzen, dass die Bash-Härtung Teil dieses Cleanups bereits erfolgt
      ist; der untrusted-repo-Modus bleibt separater Workstream.
    → verify: `grep -nE 'Bash\(\*\)' SECURITY.md README.md` zeigt nur noch
      Vorkommen, die explizit als Anti-Pattern markiert sind.

15. **`README.md:48`** updaten (Warn-Block).
    Aktuelle Zeile enthält „required `Bash(*)` permission". Ersetzen durch
    „kuratierte Allow-List mit RCE-relevanten Primitives (`python3`, `awk`,
    `sed`, …) — siehe SECURITY.md". `README.md:100` („This checks and
    updates the allow-list…") bleibt unverändert.
    → verify: `grep -nE 'Bash\(\*\)' README.md` zeigt nur dokumentierte
      Anti-Pattern-Erwähnungen.

16. **`docs/security-hardening-plan.md` P1.3** aktualisieren oder als
    erledigt markieren (Section wird durch diesen Plan obsolet).
    → verify: P1.3-Heading hat `Status: done (resolved by permissions.md)`.

17. **`AGENTS.md:115`, `AGENTS.md:284`** cross-checken — sollten heute schon
    korrekt auf `data/required-permissions.yaml` zeigen. Nur prüfen, nicht
    ändern. (`arch.md` ist im aktuellen Branch entfernt (`git status: D arch.md`);
    die ursprünglichen `arch.md:112`/`arch.md:683`-Referenzen entfallen.)
    → verify: `grep -nE 'required-permissions' AGENTS.md` zeigt unveränderte
      Referenzen.

### Phase 6 — CI-Härtung

18. **`.github/workflows/tests.yml`** ergänzen um expliziten Schritt:
    ```yaml
    - name: Verify permission contract
      run: |
        python3 -c "
        import yaml, jsonschema
        s = yaml.safe_load(open('schemas/required-permissions.schema.yaml'))
        d = yaml.safe_load(open('data/required-permissions.yaml'))
        jsonschema.validate(d, s)
        print('schema ok')
        "
        python3 scripts/render_settings_example.py --check
    ```
    `--check`-Mode des Renderers: rendert in temp, diffed gegen committed
    Template, exit 1 bei Mismatch.
    → verify: PR mit gezieltem YAML/Template-Drift wird von CI rot.

### Phase 7 — Self-Dogfooding-Validierung

19. **Plugin gegen sich selbst laufen lassen.**
    ```
    /appsec-advisor:create-threat-model --repo /home/mrohr/appsec-advisor
    ```
    → verify:
    - Kein Cat-28b-Critical-Finding auf das eigene `.claude/`-Verzeichnis
      (es ist leer / nur `settings.example.json`).
    - Cat-28c-Finding zu den eigenen Hooks bleibt erwartet (Hooks sind
      legitim Plugin-Funktion), aber als Informational/Low.
    - Run läuft prompt-frei durch (oder die Prompts sind dokumentiert und
      adressiert).

20. **Smoke-Test Contributor-Workflow.**
    Frischen Checkout in Container, ohne `~/.claude/settings.json`. Hook:
    ```
    cp .claude/settings.example.json .claude/settings.local.json
    # öffne Claude Code, starte einen Test-Run
    ```
    → verify: Run läuft mit dokumentierten Prompt-Stellen (falls (b)-light
      noch nicht alle Compound-Bash refactored hat) durch. Liste der
      Prompts → Bug-Liste für Phase-2-Followup.

---

## Out-of-scope für diesen Plan

- Pipeline-Refactor zur Eliminierung aller Compound-Bash-Aufrufe.
  Erfolgt iterativ pro Bug-Report aus Schritt 20.
- Untrusted-Repo-Modus (siehe `SECURITY.md:81` „Known issues — untrusted
  repositories" und `SECURITY.md:102` „Planned: untrusted-repo mode").
  Separater Plan.
- Manifest-Felder (`license`, `repository`, …) — separater Plan, nicht
  Bestandteil dieses Cleanups.

## Geschätzter Gesamtaufwand

- Phase 0–1 (Schema, ADR, Audit): 2–3 h
- Phase 2 (YAML-Umstellung): 1–2 h
- Phase 3–4 (Template, .gitignore, Tests refit): 1–2 h
- Phase 5 (Docs): 1 h
- Phase 6 (CI): 30 min
- Phase 7 (Validierung): 1 h

**Summe: 6–10 h** für (b)-light. Variante (a) wäre 1–2 h, Variante (c) wäre
zusätzlich +3–4 h für Profil-Logik.

## Rollback-Plan

Jede Phase ist atomar committable. Bei Problemen:
- Phase 2 zurücknehmen → YAML zurück auf `Bash(*)`.
- Phase 3 zurücknehmen → `.claude/settings.json` aus Git-History wieder einchecken,
  `.gitignore` rückgängig.
- Tests bleiben grün, weil Drift-Guard auf den jeweils committed Stand zeigt.

Kein Schritt verliert Daten; alle Änderungen sind im Repo, kein externer State.
