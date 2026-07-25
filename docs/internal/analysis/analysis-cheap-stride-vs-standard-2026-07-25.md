# `--cheap-stride` vs. Standard — juice-shop, gemessen 2026-07-25

Vergleich zweier Full-Runs auf demselben Commit (`33518f5a0`):

| | CHEAP (`c27f6fdc`) | STANDARD2 (`e20148a7`) |
|---|---|---|
| Invocation | `--cheap-stride` | `--slug … --keep-runtime-files` |
| Plugin | 0.5.1-dev | 0.5.0-beta |
| Kosten (ground truth) | **~$34** (User-`/cost`) | **$43.71** (`cost.txt`) |
| Kosten (Hook-Log, Haupt-Session) | $10.60 | $12.55 |
| Net-Wall (`run_timing.py`) | 6444 s (1h47) | 8187 s (2h16) |
| Komponenten analysiert | 11 (5 davon `screening`) | 8 (alle volle Tiefe) |
| Σ Dispatch-Turn-Budget | **214** | **180** |
| Threats | 74 | 68 |
| Distinct CWEs | **42** | **49** |
| Risk Critical / High / Medium | 14 / 39 / 21 | 12 / 43 / 13 |
| Evidence-Verifier | lief (35 verified / 39 ambiguous) | `unchecked` (56) |
| QA-Gate | `pass` (deterministisch) | `manual_review` + Repair-Plan |

Ersparnis: **~$10 (≈22 %)** und **~20 % Net-Wall**. Pro Komponente: $3.09 (cheap)
vs. $5.46 (standard) → **−43 %**, die fairere Messung des Hebels.

## Was cheap tatsächlich gescreent hat

`_cheap_stride_target` (`build_stride_dispatch_manifest.py:451-461`) screent
`_priority(c) > 2` außer File-Upload/Realtime. `_priority` gibt 3 für
crown-jewel/data-store — und `_is_exposed` hängt an kanonischen Zone-Tokens.
Im Run trugen 7 Backend-Units `['server']` (ZONE_DRIFT, siehe
`analysis-run-defects-2026-07-24.md` §1) → exposure-unknown → Priority 3 → gescreent:

| Komponente | Turns cheap | Turns standard |
|---|---|---|
| `backend-api` (Express REST, crown jewel) | **8** | 31 |
| `b2b-api` | 8 | – |
| `sqlite-db` | 8 | (in `data-persistence`, 22) |
| `mongodb` | 8 | (dito) |
| `ci-cd-pipeline` | 8 | 15 |
| `frontend-spa` | 48 (Footprint-Floor) | 22 |
| `file-handling` | 34 (Footprint-Floor) | – |

Zwei Konsequenzen:

1. **Der Flag traf die größte Angriffsfläche, nicht den „internal tail".**
   Die Haupt-API lief mit 8 statt 31 Turns, beide Datastores mit 8.
2. **Die Ersparnis wurde von anderswo aufgefressen.** Σ Turn-Budget war unter
   cheap *höher* (214 vs. 180) — 3 Komponenten mehr plus Footprint-Floors
   (frontend-spa 48, file-handling 34). Der reale Kostenhebel dieses Repos sind
   die Floors, nicht der gescreente Tail.

Der Zone-Fix ändert das **nicht**: `server` bleibt per Design
`RUNTIME_ONLY_ZONES` → exposure-unknown → `backend-api` wird weiterhin gescreent.

## Coverage-Delta

Der CWE-Code-Diff (42 vs. 49 distinct) **überzeichnet die Lücke**: dieselbe
Schwachstelle trägt in beiden Runs unterschiedliche Codes. `CWE-798` (std2,
frontend-spa) und `CWE-522` (cheap T-007) sind dasselbe
OAuth-Derived-Password-Problem; std2s generisches `CWE-434` („upload without
content validation") entspricht in cheap drei konkreteren Findings (XXE, ZIP
Slip, Null-Byte-Bypass). Auf Klassenebene ist der Diff **symmetrisch** (~7:7).

**Nur cheap** — std2 hat XXE und ZIP Slip *nur* in den Attack-Surface-Notes der
Recon, nie als Finding materialisiert:

| Klasse | cheap |
|---|---|
| XXE in File-Upload | T-010 **Critical** `fileUpload.ts:76` |
| ZIP Slip | T-028 `fileUpload.ts:34` |
| Poison-Null-Byte FTP-Allowlist-Bypass | T-018 `fileServer.ts:28` |
| Unauth FTP-Directory-Listing / Download | T-041 `fileServer.ts:14` |
| Access-Log-Serving | T-040 `logfileServer.ts:10` |
| Wide-open CORS | T-035 `server.ts:183` |
| Change-Password ohne aktuelles Passwort | T-024 `changePassword.ts:39` |
| Rate-Limit-Bypass via X-Forwarded-For | T-073 `resetPassword.ts:17` |
| LLM-Tiefe (Role-Injection, SSE-Leak, SSRF via LLM-URL, NoSQL via Tool) | 8 Findings vs. 4 |

**Nur std2:**

| Klasse | std2 |
|---|---|
| `express-jwt 0.1.3` veraltet (SCA) | T-017 |
| Conditional-Sanitize-Bypass im User-Model | T-027 `models/user.ts:48` |
| Keine serverseitige JWT-Revocation | T-052 |
| YAML-Bomb via `yaml.load` | T-047 `fileUpload.ts:109` |
| SQLite-Datei im Working Directory (CWE-552) | T-041 `models/index.ts:41` |
| Kein Query-Timeout / Pool-Limit | T-049 |
| `pull_request_target` exponiert `ORG_ADMIN_TOKEN` | T-067 |
| TOTP-Pre-Auth-Token in localStorage | T-033 / T-042 |
| Prometheus-`/metrics` unauthentifiziert | T-034 |

Die Ursache ist **nicht** die Screening-Tiefe, sondern die Zerlegung: cheap hatte
`file-handling` als eigene Komponente mit 34 Turns Volltiefe, std2 hat Uploads in
`backend-api`/`data-persistence` gefaltet.

## Was dem Screening tatsächlich zuzurechnen ist

1. **`backend-api` (8 statt 31 Turns): kein Einbruch.** 18 Findings, 4 Criticals —
   SQLi `search.ts:23`, JWT-`none`, JWT-Verify, IDOR, `$where`-NoSQL, SSRF, Path
   Traversal, CORS, Rate-Limiting, MD5. Screening spart Verifikations-Greps und
   Re-Reads, nicht die *Entdeckung* — und in juice-shop sind die schweren Fälle
   ohne Verifikationsrunde erkennbar.
2. **`ci-cd-pipeline` (8 Turns): ~gratis.** 10 vs. 11 Findings, weil die Substanz
   vom deterministischen `config-scanner` kommt (7 Findings `source: config-scan`),
   nicht vom STRIDE-Analyzer.
3. **Datastores (`sqlite-db`, `mongodb`, je 8 Turns): echter Verlust.** 6 Findings,
   alle „data at rest" (MD5-Hash, Plaintext-PAN/TOTP, Audit-Log). Die
   *Design*-Themen, die std2s `data-persistence` mit 22 Turns fand
   (Sanitize-Bypass `user.ts:48`, DB-Datei-Lage, fehlende Query-Timeouts), fehlen
   komplett. Genau diese Klasse braucht die Verifikationsrunde.

## Maßnahmen-Qualität

Innerhalb des cheap-Runs, gescreent vs. Volltiefe:

| | gescreent (n=33) | Volltiefe (n=41) |
|---|---|---|
| Ø Steps | 2.9 | 3.5 |
| Ø Länge | 422 | 539 |
| mit `code_example` | 22 (67 %) | 37 (90 %) |
| mit `verification` | 33 (100 %) | 41 (100 %) |

→ ~20 % dünner, ein Drittel ohne Code-Beispiel. Die Threat-Prosa ist gleich
(Ø `remediation` 1003 Zeichen cheap vs. 985 std2).

Gegen std2 ist die Maßnahmen-Qualität **nicht** vergleichbar: 0.5.0-beta hatte
kein `steps`/`verification`/`code_example` (Ø `remediation` 15 Zeichen, T-075 ganz
ohne Maßnahme). Versionsfortschritt, kein Cheap-Effekt.

## Sichtbarkeit

Offengelegt, aber irreführend formuliert. MS-Scope-Zeile: „6 of 11 components
received full STRIDE analysis … 5 further **internal** component(s) received a
reduced-budget screening pass". `backend-api` ist die internet-erreichbare
Haupt-API, nicht „internal" — der Satz behauptet, der Trade sei am Rand gemacht
worden, obwohl er das Zentrum traf. Zusätzlich `Screened` in der
§3-Komponententabelle (5×) und `analysis_depth: screening` in
`.stride-selection.json`.

Keine weiteren Artefakt-Abfälle: cheap war QA-clean (std2 brauchte einen
`manual_review`-Repair), Scenario-Länge gescreent 519 vs. full 732 Zeichen,
Evidence-Ambiguität bei gescreenten Komponenten sogar niedriger (45 % vs. 59 %).

## Konfundierungen (Messung ist kein reiner A/B-Test)

* Plugin-Version 0.5.1-dev vs. 0.5.0-beta (9 Tage Codedrift).
* Unterschiedliche Architektur-Zerlegung (11 vs. 8 Komponenten) — Phase-3-Output,
  nicht Folge des Flags.
* Evidence-Verifier + `priority`-Feld nur im cheap-Run vorhanden.
* Beide `stride_model=claude-sonnet-4-6`, `reasoning_model=sonnet-economy` → das
  Modell ist *nicht* die Erklärung.

## Empfehlung

**Inhaltlich war cheap nicht schlechter** — Findings-Klassen ~7:7 symmetrisch,
74 vs. 68 Threats, mehr Criticals (14 vs. 12), QA-clean, und zwei echte
juice-shop-Klassiker (XXE, ZIP Slip) fand *nur* der cheap-Run. Der Preis war
nicht Coverage, sondern zweierlei:

* **Design-Findings in gescreenten Datastores** (Sanitize-Bypass,
  DB-Datei-Lage, Query-Timeouts) — 8 Turns reichen für „data at rest", nicht
  für Modell-Design.
* **~20 % dünnere Maßnahmen** bei gescreenten Komponenten, ein Drittel ohne
  Code-Beispiel.

**Trotzdem nicht als Default im aktuellen Zustand** — nicht wegen der
gemessenen Qualität, sondern weil das Screening-Set unzuverlässig bestimmt wird:
`backend-api` (internet-erreichbare Haupt-API) landete darin, weil `_is_exposed`
nur auf kanonische Zone-Tokens anspringt und der Analyst `server` (Runtime-Tier)
statt einer Reachability-Zone schrieb — und der Run nannte das Ergebnis in der MS
„internal components". Dass es inhaltlich gut ausging, ist eine Eigenschaft von
juice-shop (Schwachstellen liegen offen), keine Eigenschaft des Flags.

Reihenfolge:

1. ✅ **Umgesetzt.** `_cheap_stride_target` hat jetzt drei Schutzregeln:

   ```python
   if _is_cicd(c) and not _is_exposed(c):      # rollen-identifiziert, gemessen ~0 Verlust
       return True
   if not _reachability_zones(c):              # exposure-unknown NIE screenen (Fail-Safe)
       return False
   return _priority(c) > 2 and not (
       _is_file_upload(c) or _is_realtime(c) or _is_datastore(c) or _is_core_backend(c))
   ```

   * **Exposure-unknown wird nie gescreent.** Genau das hatte die Haupt-API ins
     Screening-Set gebracht: `deployment_zones: ["server"]` ist ein Runtime-Tier,
     keine Reachability-Zone → `_is_exposed` False → Priority 3. Der Selektor hat
     diesen Fail-Safe längst (`_droppable_at_ceiling:417`), die Tiefe hatte ihn
     nicht. Screening behauptet „das ist Tail" — ohne Zone ist nichts bewiesen.
   * **`_is_datastore` verschont** (Typ-Anker, 2/11 bzw. 1/8) — die gemessene
     Verlustklasse.
   * **`_is_core_backend` verschont** (neu): Hint-Anker auf `id`+`name`+`type`
     (`api`, `gateway`, `backend`, `rest`, `graphql`, `bff`, `monolith`) — trifft
     `backend-api`+`b2b-api` bzw. `backend-api`. Auth ist über den Priority-0-Floor
     schon immer verschont. Damit sind Auth und zentrale Backend-Komponenten
     unabhängig von Zonen-Tags nie screenbar.
   * **`CHEAP_STRIDE_INERT`** auf stderr, wenn nichts gescreent wurde — ein
     Vollpreis-Run darf nicht als verbilligter durchgehen.

   Regressionen: `test_builder_cheap_stride_spares_auth_and_core_backend`,
   `..._spares_datastores_not_crown_jewels`, `..._never_screens_exposure_unknown`,
   `..._announces_inert_run`, `..._inert_note_silent_when_screening_happened`.

   **Wirkung auf die beiden Runs: gescreent wird nur noch `ci-cd-pipeline`**
   (1/11 bzw. 1/8, vorher 5/11). Auf juice-shop ist der Flag damit fast wirkungslos —
   das ist die ehrliche Konsequenz aus der Zonen-Drift, nicht ein Nebeneffekt.
   Auf einem sauber gezonten Repo greift er weiter: geprüft an einem synthetischen
   Microservice-Set werden `batch-worker`, `report-renderer` und
   `release-pipeline` gescreent, während `payments-api`, `auth-svc` und
   `warehouse-db` volle Tiefe behalten.

   **Crown-jewel spart absichtlich nicht.** `_is_crown_jewel` ist nur
   `bool(handles_sensitive_data)` — ein LLM-Flag, das über-taggt: **6/11** im
   cheap-Run, **6/8** in standard2. Darauf zu verschonen hätte den Flag
   stillgelegt (nur `ci-cd-pipeline` wäre übrig geblieben, 1/11). `_is_datastore`
   ist dagegen ein Typ-Anker (`component_type`/`tech_stack`/`framework`) und
   trifft 2/11 bzw. 1/8 — selektiv genug. Die Messung stützt genau diese
   Aufteilung: der gescreente crown-jewel-API zeigte **keinen** Verlust
   (18 Findings, 4 Criticals bei 8 Turns), die gescreenten Datastores schon.

   Screening-Set auf juice-shop danach: `backend-api`, `b2b-api`,
   `ci-cd-pipeline` (3/11 statt 5/11) — Ersparnis bleibt, beide gemessenen
   Verluste sind weg.
2. ✅ **Umgesetzt.** MS-Scope-Zeile sagt nicht mehr „internal component(s)",
   sondern „N further component(s) received a reduced-budget screening pass …
   and are marked `Screened` in the component table". Regression:
   `test_verdict_scope_coverage_counts_screening_separately`.
3. ✅ **Umgesetzt (Entscheidung des Nutzers):** cheap-stride ist jetzt **Default
   bei quick und standard**, aus bei thorough (`resolve_cheap_stride`), mit
   `--cheap-stride` / `--no-cheap-stride` als Overrides und `cheap_stride_label`
   in der Pre-flight-Zeile, damit sichtbar ist, wer entschieden hat.
   Vertretbar ist das nur wegen des Reachability-Fail-Safes: ein unzuverlässiges
   Komponentenmodell kostet dann Budget, nie Tiefe.

   End-to-End gegen die echten juice-shop-Komponenten verifiziert
   (resolve → `.skill-config.json` → Manifest):

   | Aufruf | gescreent |
   |---|---|
   | standard (Default) | `ci-cd-pipeline` (8 Turns), 10× volle Tiefe |
   | quick (Default) | nichts — ci-cd wird bei quick gar nicht selektiert → `CHEAP_STRIDE_INERT` |
   | thorough (Default) | nichts, 11× volle Tiefe |
   | standard `--no-cheap-stride` | nichts, 11× volle Tiefe |

   Auf diesem Repo ist der Default also faktisch ein Ein-Komponenten-Hebel bzw.
   bei quick ein No-op. Der Ertrag steigt erst mit sauberen `deployment_zones`.
4. **Offen:** der größere Kostenhebel ist die Footprint-Floor-Inflation
   (`classify_component._footprint_turn_floor`) — 48 Turns für `frontend-spa`
   gegen 22 im Standard-Run. Eigene Analyse nötig, nicht Teil dieses Fixes.
