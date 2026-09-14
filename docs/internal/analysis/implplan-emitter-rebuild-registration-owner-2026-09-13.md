# Umsetzungsplan: Emitter-Ergebnisse überleben Stage 1d, ein Owner für offene Registrierung, Rollen in Figure 1

Stand 2026-09-13. Basis: Branch `feature/figure1-dfd` @ `70c5804c`.
Referenzlauf mit behaltenen Laufzeitdateien: `/home/mrohr/juice-shop2/docs/security`
(Run `1e797fd8-ce60-442a-9a4d-a2cea0ba9e45`, full/thorough, 0.6.0-beta.3). Alle Belege unten stammen aus diesem
Verzeichnis oder dem Plugin-Code. Vor dem Überschreiben durch einen neuen Lauf eine Kopie ziehen.

## 1. Symptom

Figure 1 zeigt für Juice Shop sechs Akteure: „Anonymous Browser User“, „Authenticated User“, „Admin User“,
A1 „Anonymous Internet Attacker“, A2 „Authenticated Internet Attacker“, A3 „Internal Developer“.
Fachlich richtig wären ein User (anonym = registriert, weil die Registrierung offen ist), ein Admin und ein
Internet-Angreifer. Dieselben Ursachen verwerfen weitere Report-Inhalte, siehe Root Cause 1.

## 2. Verifizierte Befunde

### Root Cause 1: Der YAML-Rebuild in Stage 1d verwirft den deterministischen Emitter-Pass (plugin-weit)

- `auto_emitter_pass.sh` läuft im Stage-1-Finalizer `_context_v2_finalize`
  (`scripts/orchestration_controller.py:5512`, YAML-Build davor bei `:5494`). Seit `74846143` (2026-08-07) bzw.
  `c240a276` (2026-08-19).
- Die Emitter schreiben direkt in `threat-model.yaml`.
- Danach baut `finalize_abuse` die YAML neu, sobald Abuse-Verdicts existieren
  (`scripts/orchestration_controller.py:6220`, `if verdicts.is_file()`; Rebuild seit `eb264882`, 2026-08-01).
  Ein Emitter-Pass folgt dort nicht.
- `build_meta` in `scripts/build_threat_model_yaml.py` übernimmt aus der alten YAML nur `project`; Threats,
  Assets und Controls kommen aus Sidecars. Alles, was der Pass in die YAML geschrieben hat, ist danach weg.
- Weiterer Rebuild-Pfad: `_upgrade_bootstrap_yaml` (`:6414`, aufgerufen bei `:6803`). Prüfen, ob dort ein Pass folgt.

Beleg im Referenzlauf (`.agent-run.log`, Block vor `AUTO_EMITTER_END` um 21:08:55Z; `ABUSE_FINALIZE_COMPLETE`
um 21:12:11Z; die finale YAML enthält bereits `abuse_case_id`/`abuse_case_step`, ist also nach Stage 1d gebaut):

| Vom Pass geschrieben (Log) | In der finalen `threat-model.yaml` |
|---|---|
| `emit_threat_vektors: total=64 filled=64` | `vektor` auf 0 von 65 Threats |
| `emit_severity_rationale: annotated=5` | `severity_rationale` auf 0 Threats |
| `emit_auth_coverage: appended 4` (u. a. „User Registration“) | keiner der 4 Controls vorhanden |
| `enrich_asset_links: +93 added` | `linked_threats` auf allen 8 Assets leer |
| `detect_public_repo: public_source_repo=True` (Z. 325) | `meta.public_source_repo` fehlt |

Warum kein Test anschlug: `tests/test_auto_emitter_pass.py:76` prüft nur, dass der Controller das Skript aufruft;
`tests/test_orchestration_controller.py:3580` nur die Reihenfolge im Stage-1-Finalizer.
`data/completeness-contract.yaml` prüft weder `vektor` noch `severity_rationale` noch die Meta-Flags.

### Root Cause 2: Die offene Registrierung hat keinen einzigen Owner

- Recon (LLM) setzte `has_open_self_registration: false`, `signal_evidence.status: "none"`, keine Locations
  (`.recon-signals.json`). Die Route wurde nicht einmal als `candidate` erfasst.
- Der Resolver faltet nur bei wahrem Signal (`scripts/resolve_actors.py:390` → keine `collapse_reason`).
- `scripts/build_threat_model_yaml.py:2934-2938` schreibt daraus `open_user_registration: false` und immer
  `open_registration_source: actor-resolution` (seit `89b51eed`, 2026-09-12).
- `detect()` in `scripts/detect_open_registration.py:170` vertraut dem und überspringt die Routen-Prüfung.
  Log: `detect_open_registration: open_user_registration=False (validated actor reach equivalence)` (Z. 324).
  Ohne die Early-Return liefert `detect()` für dieselben Daten `True` (`POST /api/Users`).
- Gleichzeitig sagen drei deterministische Quellen „Registrierung existiert“:
  - `.route-inventory.json`: 4× `POST /api/Users`, `authn_signal: middleware_present`, `authz_signal: unknown`,
    `file`/`line` leer.
  - `.source-auth-findings.json`: `AUTHZ-008` („Sensitive REST route registered without authentication
    middleware“) an `server.ts:408` (SAF-038), weitere an `:420`, `:421`.
  - `emit_auth_coverage`: „User Registration“ (erkannt über `GET /api/Users`, falsche Methode).
- Fachlich bestätigt: `server.ts:408` `app.post('/api/Users', …)` ohne `security.isAuthorized()`,
  `GET` bei `:363` mit.
- Folge über die Figure hinaus: AC-T-004 „Privilege Escalation via Mass-Assignment on Registration“ steht in
  `.abuse-case-matches.json` als `not_applicable` („required signal(s) absent: has_open_self_registration“),
  obwohl Schritt 1 bereits auf T-015 (`server.ts:484`) gematcht hatte.
- Die bestehende Routen-Regel ist auf Juice Shop getunt: `_route_is_open_registration` ignoriert Auth-Middleware
  komplett, weil die Inventur für `GET /api/Users` (mit `isAuthorized`) und `POST` gleichermaßen
  `middleware_present` meldet. In anderen Repos würde ein Admin-`POST /api/users` mit Rollenprüfung im Handler
  als offene Registrierung zählen. Nicht ungeprüft als Backstop übernehmen.

### Figure 1: Rollen und Angreifer kommen aus zwei unverbundenen Modellen

- Grüne Karten: `external_entities` mit `kind: legitimate-role` aus `.data-flows.json` (Architektur-Agent).
  `scripts/figure1_dfd.py:600` zeichnet jede Rolle einzeln; es gibt keinen Fold für Rollen.
- Angreifer A1–A3: Pfad-Akteure aus `.fragments/security-posture-attack-paths.json`, gefaltet über
  `overview_actor_slug()` (`scripts/detect_open_registration.py:100`) anhand von `meta.open_user_registration`
  und `meta.public_source_repo`. Beide Flags fehlen bzw. sind falsch (Root Cause 1 und 2).
- Die Entity-Schemas erlauben nur `id/name/kind/description/evidence` bei `additionalProperties: false`:
  `schemas/fragments/data-flows.schema.json`, `schemas/trust-boundary-assessment-input.schema.json`,
  `schemas/threat-model.output.schema.yaml`. Ein Fold wäre heute nur über Namensraten möglich.

### Geprüft und keine Ursache (nicht erneut verfolgen)

- `auto_emitter_pass.sh` ist verdrahtet (siehe oben). Eine frühere Aussage „kein Aufrufer“ war ein Suchfehler.
- `equivalent_to`, `equivalent_when`, `collapse_primary` liest außer dem YAML-Builder niemand; an die STRIDE-Slices
  geht nur das statische `severity_modulation` (`scripts/slice_actors.py:182`). Ein Fix für Root Cause 2 ändert
  also keine STRIDE-Bewertungen.
- `detect_public_repo.detect()` liefert für juice-shop2 korrekt `True` („OSI license file + public-host source URL“).

## 3. Arbeitspakete

Reihenfolge: AP1 → AP2 → AP4 (Verifikation) → AP3.

### AP1: Emitter-Pass nach dem letzten YAML-Rebuild (Root Cause 1)

1. In `finalize_abuse` nach dem erfolgreichen Rebuild `_run_auto_emitter_pass(output_dir, cfg, receipts)` aufrufen,
   dazu die Gates, die in `_context_v2_finalize` auf den Pass folgen (Zeilen nach `:5512` prüfen, u. a.
   `validate_mitigation_quality.py`). Den Pass im Stage-1-Finalizer belassen: Gates hängen davon ab
   (`tests/test_gate_preconditions.py`, P1/P2-Actionability).
2. `_upgrade_bootstrap_yaml` (`:6414`) genauso behandeln, falls dort ohne Pass neu gebaut wird.
3. Idempotenz prüfen: Die neu gebaute YAML ist frisch, aber Emitter, die zusätzlich Sidecars schreiben
   (Kandidaten: `emit_review_mitigations`, `emit_config_scan_mitigations`, `emit_finding_fix_mitigations`,
   `hydrate_mitigation_details`, `emit_general_mitigation_titles`), dürfen beim zweiten Lauf nichts doppelt anhängen.
4. Absicherungen:
   - Der Pass stempelt am Ende `meta` mit einem Marker (z. B. `enrichment_pass: {completed_at, yaml_sha256}`);
     `scripts/assert_completeness.py` (Phase `render`) schlägt fehl, wenn der Marker fehlt oder nicht zur finalen
     YAML passt. Eintrag in `data/completeness-contract.yaml`.
   - Controller-Test: Jeder Pfad, der `build_threat_model_yaml.py` ausführt, führt danach den Pass aus
     (Aufrufe per gemocktem `_run_script` aufzeichnen, inkl. `finalize_abuse` mit vorhandener Verdict-Datei).
5. Langfristig (nicht in diesem AP): Emitter schreiben in Sidecars, der Builder ist einziger YAML-Writer.

Abnahme auf einer Kopie des Referenzlaufs:

```bash
cp -a /home/mrohr/juice-shop2/docs/security "$TMPDIR/ref"
python3 scripts/build_threat_model_yaml.py "$TMPDIR/ref" --repo-root /home/mrohr/juice-shop2 --plugin-root .
# erwartet: vektor fehlt (Ist-Zustand reproduziert)
bash scripts/auto_emitter_pass.sh "$TMPDIR/ref" /home/mrohr/juice-shop2 "$PWD" false
# erwartet: vektor auf allen Threats, meta.public_source_repo=true, 4 Auth-Coverage-Controls, linked_threats > 0
```

### AP2: Ein Owner für die offene Registrierung (Root Cause 2)

1. Eine Funktion, z. B. `resolve_open_registration(signal_doc, routes, source_auth_findings) -> (bool, reason,
   evidence)` in `scripts/detect_open_registration.py`. Aufruf in `resolve()` beim Laden der Signale
   (`scripts/resolve_actors.py:422-432`, `output_dir` ist verfügbar), bevor `apply_reach_equivalence` läuft (`:587`).
   Nur das Signal im Speicher setzen, `.recon-signals.json` nicht ändern: Der Validator verlangt für `true`
   `status: supporting` (`scripts/validate_intermediate.py:1730`), außerdem hängen Receipts am Hash.
   Reihenfolge ist garantiert: Route-Inventur (`:4320`) vor Resolver (`:4346`) in `_context_v2_after_recon`;
   Source-Auth läuft schon in den Prepasses (`:1749`).
2. Regel:
   - Recon `true` (`supporting`) → offen.
   - Registrierungsförmige `POST`-Route ohne Rollen-Gate (`authz_signal` nicht `decorator_present`/
     `middleware_present`, kein `management_surface`) **und** entweder expliziter Name (register, signup, sign-up,
     `/auth/register`) **oder** ein `AUTHZ-008`-Finding an genau dieser Route → offen, mit file:line als Beleg.
   - Sonst geschlossen. Fand nur eine generische `/users`- oder `/accounts`-Route ohne `AUTHZ-008` einen Treffer,
     oder meldet Recon `candidate`: als strittig vermerken und als offene Frage fürs Team ausgeben (baut auf
     `2e8298ec` auf, siehe Abschnitt 5), nicht still als geschlossen.
3. Route und `AUTHZ-008` zusammenführen: Das Finding hat `file`/`line`, aber keinen Pfad; die Inventur hat den
   Pfad, aber `file`/`line` leer. Bevorzugt `scripts/route_inventory.py` so erweitern, dass Route-Registrierungen
   file:line tragen, und dann darüber matchen. Notlösung: Methode und Pfad aus `evidence_snippet` parsen.
4. Beleg in `.actors-resolved.json` ablegen; `build_threat_model_yaml.py:2934-2938` schreibt ihn mit ins `meta`.
   Die Early-Return in `detect()` bleibt, weil der Resolver jetzt deterministische Eingaben hat;
   `detect_open_registration.py` im Emitter-Pass nutzt dieselbe Funktion oder protokolliert nur Abweichungen.
   `tests/test_detect_open_registration.py:225` bleibt gültig.
5. Nebenbei: `emit_auth_coverage` erkennt „User Registration“ über `GET /api/Users`; Methode korrigieren.
6. Erwartete Wirkung: Figure 1 faltet A2 in A1 und zeigt den Gruppierungshinweis; Heatmap und MS-Akteure folgen;
   AC-T-004 wird anwendbar (ein Verifier-Agent mehr in Stage 1d). Keine Änderung an STRIDE-Bewertungen.
7. Tests (`resolve()`-Integration, bestehende `apply_reach_equivalence`-Tests unverändert):
   - Recon `none` + `POST /api/Users` + `AUTHZ-008` an derselben Stelle → Kollaps.
   - Recon `none` + `POST /api/users` ohne `AUTHZ-008` → kein Kollaps, strittig vermerkt.
   - Rollen-Gate an der Route → kein Kollaps.
   - `POST /register` ohne `AUTHZ-008` → Kollaps.
   - Recon `supporting` → Kollaps; Recon `candidate` ohne `AUTHZ-008` → kein Kollaps, strittig.
8. Grenzen, im CHANGELOG benennen: `AUTHZ-008` deckt Java/Node/Python/TypeScript ab. Nicht abgedeckt:
   Go/.NET/Ruby/PHP-Handler, GraphQL-Mutationen, Self-Sign-up über externe IdPs (Cognito, Keycloak, Auth0,
   Firebase; `data/config-iac-checks.yaml` hat dafür keinen Check). Dort bleibt das Recon-Urteil plus Teamfrage.

Abnahme: `resolve_actors.py --plugin-root . --repo-root /home/mrohr/juice-shop2 --output-dir "$TMPDIR/ref"
--signals "$TMPDIR/ref/.recon-signals.json"` → ACT-D-01/02 mit `collapse_reason: open-self-registration`;
Builder → `meta.open_user_registration: true`; `match_abuse_cases.py` → AC-T-004 anwendbar.

### AP3: Rollen in Figure 1 zusammenlegen

1. Optionales Feld `access` für `kind: legitimate-role` in den drei Entity-Schemas (siehe 2.), Werte aus dem
   Akteursvokabular: `internet-anon`, `internet-user`, `internet-priv-user`.
2. `agents/appsec-architecture-analyst.md:90`: `access` aus Belegen setzen.
3. Durchreichen prüfen: `scripts/build_threat_model_yaml.py:2966` und
   `scripts/build_trust_boundary_assessment_input.py:561` kopieren Entities; sicherstellen, dass nichts Felder
   filtert.
4. `scripts/figure1_dfd.py:598ff`: Rollen über `overview_actor_slug(access, meta)` abbilden; Rollen mit gleichem
   Ziel-Slug zu einer Karte zusammenführen (Label aus dem Vokabular, z. B. „User (anonymous or self-registered)“),
   `from_entity`-Flows umhängen; privilegierte Rollen bleiben getrennt. Ohne `access` keine Zusammenlegung.
5. Tests: Figure-1-Unit-Tests mit/ohne offene Registrierung und mit/ohne `access`; Schema-Tests.
6. Referenz: `ext-anon-user` (3 Flows) und `ext-auth-user` (4 Flows) → eine Karte; `ext-admin-user` (1 Flow) bleibt.
7. Preis: Die Figure zeigt nicht mehr, welche Flows einen Login brauchen.

### AP4: Öffentliches Repo (A3)

1. Mit AP1 überlebt das Ergebnis von `detect_public_repo.py`. Abnahme: nach dem Replay `meta.public_source_repo:
   true`; Figure 1 faltet A3 in A1. Fachlich richtig: Der A3-Pfad ist `sensitive-data-exposure` über Secrets im
   Quellcode (T-006, T-008, T-013, T-019, T-034); Lesezugriff genügt.
2. Overrides `open_user_registration_pinned` / `public_source_repo_pinned` haben keine Konfigurationsquelle, sie
   stehen nur in der YAML und gehen bei jedem Rebuild verloren. Aus `.skill-config.json` bzw. Org-Profil lesen
   (optional).
3. Grenzen: Selbstgehostetes öffentliches GitLab/Gitea wird nicht erkannt (A3 bleibt, sichere Voreinstellung);
   ein privates GitHub-Repo mit OSI-Lizenz gilt fälschlich als öffentlich (wirkt nur auf die Darstellung).

## 4. Konventionen

`AGENTS.md` (u. a. Ursachenanalyse vor Limit-Erhöhungen), CHANGELOG unter „Unreleased“, Entscheidungen mit Test
in `docs/internal/decisions.md`, Skript-Test-Bindungen in `data/requirement-bindings.yaml`, vor dem Commit
`make release-check`. Die Fix-Session im Plugin-Repo starten (oder mit `APPSEC_PLUGIN_DEV=1`), sonst blockiert
das Write-Gate.

## 5. Offen aus derselben Session, nicht Teil dieses Plans

- Die Commits `2e8298ec` (Teamfragen statt „Manual threat modeling follow-up“) und `d40db602` (Worst-Case-Tabelle)
  liegen nur im Scratch-Klon
  `/tmp/claude-1000/-home-mrohr-juice-shop/dbacf079-92d0-45f4-8c70-7647b7bdafa7/scratchpad/plugin-dev`,
  Branch `fix/team-questions` (Basis `2b78fc69`). Das Verzeichnis kann verschwinden. Sichern:
  `git -C /home/mrohr/appsec-advisor fetch <scratch-pfad> fix/team-questions:fix/team-questions`.
  Cherry-Pick auf `70c5804c` konfliktet nur in `CHANGELOG.md`.
- Next Steps: Laut Nutzer gab es früher konkrete Beispielfragen für ask-threat-model; der aktuelle Code
  (`build_next_steps` in `scripts/render_completion_summary.py`, aus `50b9b2de`/`2e7c8ca9`, 2026-08-31) zeigt zwei
  generische. Nicht untersucht.
