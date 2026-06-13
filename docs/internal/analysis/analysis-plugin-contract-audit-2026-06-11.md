# Plugin-Audit: Contracts, Injection-Exposure, Gates, Permissions, Tests, Wartbarkeit — 2026-06-11

Audit-Scope: Agent-Prompts, Phasen-Instruktionen, Schemas, Templates, Renderer,
QA-Checks, Permission-Contract und Tests des Plugins — Dimensionen: Contract-Drift
(CD), Prompt-Injection-Exposure (PI), Permission-Contract (PC), fehlende
deterministische Gates (DG), Test-/Drift-Guard-Lücken (TG), Verantwortlichkeiten &
Wartbarkeit (MR). Methode: 6 parallele Read-only-Audit-Agents, jede High-Findung
anschließend manuell auf file:line-Ebene nachverifiziert. **Nur Findings — keine
Code-Änderungen vorgenommen.**

Nicht enthalten (bereits dokumentiert): P1–P9 aus
`analysis-perf-and-defects-2026-06-10.md`, Requirements-Section-unwired-Bug,
toter ms-architecture-assessment-Pfad, qa_checks-`all`-Nichtidempotenz.

---

## Top-Prioritäten (alle High, einzeln verifiziert)

| ID | Kurzfassung |
|---|---|
| CD-1 | STRIDE-Write-first-Stub ist per Konstruktion schema-invalid — hebelt den eigenen Zweck aus |
| DG-1 | Stage-1-Cut-off-Detection schließt aus stale `[ -f threat-model.md ]` fälschlich auf Erfolg; `MD_PRE_STAGE1` wird erfasst, aber nie konsumiert |
| DG-2 | Komplette Stage-1c-Abuse-Pipeline läuft mit ignorierten Exit-Codes (`\|\| true`, `2>/dev/null`) |
| TG-1 | `publish_threat_model.py` liest `t_id` (existiert im Artefakt nicht); Test-Fixture spiegelt den Bug → Feature tot, Test grün |
| TG-2 | Top-level `schemas/*.schema.json` entgehen beiden Schema-Drift-Guards; `qa-content-repair-plan.schema.json` von nichts validiert |
| PI-1 | recon-scanner liest rohen Target-Repo-Text ohne generellen Untrusted-Data-Guard (Downstream-Lieferant für alle Phasen) |
| PC-1 | Eingechecktes `.claude/settings.json` weicht beidseitig vom kanonischen Contract ab: `Read/Write/Edit(**)`-Übergrants + fehlendes `Bash(*)` |
| PC-2 | fix-run-issues editiert Plugin-Dateien per Edit-Tool, granted ist nur `Read(${PLUGIN_ROOT}/**)` → Permission-Prompt bei jedem Fix |
| MR-1 | `harvest-requirements.py` → `harvest_requirements.py` umbenannt; README, CONTRIBUTING, docs/harvester.md, Audit-Skill-Doku zeigen auf den alten Namen |

Querbezug: DG-2 verschärft P1 (Abuse-Fold-No-op) — Matcher-/Merger-Crashes sind
von „keine Abuse Cases anwendbar" ununterscheidbar, §9 + Severity-Fold degradieren
doppelt lautlos.

---

## CD — Contract-Drift

### [CD-1] STRIDE-Write-first-Stub schema-invalid (High)
- `agents/appsec-stride-analyzer.md` (Write-first guarantee): Stub soll `component_id`, `started_at`, `threats` + `partial`/`skipped_categories` enthalten. `schemas/stride.schema.yaml:86`: `required: [component_id, component_name, analyzed_at, threats]`; `started_at`/`partial`/`skipped_categories` sind im Schema nirgends deklariert (grep: 0 Treffer). Orchestrator validiert jede Stride-Datei (`agents/phases/phase-group-threats.md:496` → `validate_intermediate.py stride`, keine Stub-Toleranz).
- Folge: Budget-Cut hinterlässt eine Datei, die das Gate ablehnt — „partial-but-valid" wird zu „invalid → kompletter Re-Dispatch", exakt der Failure-Mode, gegen den der Stub eingeführt wurde.
- Fix (bidirektional, §4): Stub im Prompt um `component_name` + `analyzed_at` ergänzen (beide in Step 1 bekannt) UND `started_at`/`partial`/`skipped_categories` im Schema deklarieren.

### [CD-2] §4e beschreibt vscode://-Links, die compose nicht mehr emittiert (Med)
- `AGENTS.md:89` + `docs/internal/contracts/schema-invariants.md:65` verlangen `[basename:line](vscode://file/…)` in §8; `grep -rn "vscode://" scripts/compose_threat_model.py` → 0 Treffer; §8-Karte rendert `**Location:** \`file:line\`` (compose:11934, :1469). Doku ist die stale Seite (Card-Layout-Redesign 2026-05 ist der gewollte Stand) → §4e in beiden Docs aktualisieren.

### [CD-3] `threat_category_id` Pflicht in Prompt + Hard-Gate, fehlt in beiden Schemas (Med)
- `agents/appsec-stride-analyzer.md:468` (REQUIRED) + `scripts/validate_intermediate.py:244` (Hard-Gate RC.G.1/RC.I) vs. `schemas/stride.schema.yaml` / `schemas/threats-merged.schema.yaml`: 0 Treffer. Schema („single source of truth", validate_intermediate.py:6) schweigt zu einem Feld, ohne das Merger-TH-Dedup und §8-Gruppierung kollabieren. → Feld (`^TH-\d{2}$`, nullable) in beiden Schemas deklarieren.

### [CD-4] `threats[].source`-Enum drei-Wege-Drift Prompt / merged-Schema / Output-Schema (Med)
- `agents/appsec-threat-analyst.md:648` nennt u. a. `known-threats`; `schemas/threats-merged.schema.yaml:77-88` kennt das nicht, hat dafür `architecture-coverage`/`threat-hypothesis`/`config-scan`/`configuration-defect`; `schemas/threat-model.output.schema.yaml:636` enthält noch das 2026-05 entfernte `dep-scan`; Output-Schema required (:406-414) lässt `source` weg, obwohl `phase-group-finalization.md:288` „mandatory" sagt. → Analyst-Enum an merged-Schema angleichen, `dep-scan` aus Output-Enum streichen, `source`-Pflicht entscheiden (Schema oder Prompt anpassen).

### [CD-5] Finalization-Prompt nennt tier_root_causes-Keys, die das Schema ablehnt (Med)
- `agents/phases/phase-group-finalization.md:56`: „`client:`, `application:` (alias `server`), `data:`" vs. `threat-model.output.schema.yaml:247-260`: `additionalProperties: false`, Keys `edge`/`server`/`data`; `phase-group-threats.md:38` (echter Producer) stimmt mit dem Schema überein. Alias-Behauptung ist falsch (`tier_alias` in build_threat_model_yaml.py:762 mappt Komponenten-`tier`, nicht diese Keys). → finalization.md:56 auf `edge`/`server`/`data` korrigieren (betrifft REPAIR_MODE-Edits).

### [CD-6] Phase 10b vs. 10c vs. Stage 1c; AGENTS.md-Phase-Map ohne 2.7 und 10c (Med)
- `AGENTS.md:226` (Roster: „Phase 10b") vs. `phase-group-threats.md:1790` („Phase 10c") vs. `SKILL-impl.md:2412` („Stage 1c"); Phase-Map (AGENTS.md:256-276) hat weder 2.7 (existiert: `phase-group-recon.md:344`) noch 10c. → Phase-Map + Roster (+ Pinning-Test in test_agent_definitions.py) auf EINEN konsistenten Namen ziehen; Phasen-Dateien sind die operative Wahrheit.

### [CD-7] §4a-„only legal producer"-Claim von compose widerlegt (Med)
- `docs/internal/contracts/schema-invariants.md:14-15` / `AGENTS.md:85`: nur `qa_checks.py:linkify_anchors` produziert titled Cross-Refs — aber `compose_threat_model.py:459/509` (`linkify_with_label`, F-/M-/TH-) und :2252 (`_format_finding_link`) emittieren sie ebenfalls. §12-geleitete Editoren fixen sonst den falschen Producer. → §4a-Doku um die sanktionierten compose-Producer ergänzen.

### [CD-8] Compose-Pre-Pass-Map verfehlt zwei registrierte Fragmente (Low)
- compose:1608 („validate every known JSON fragment") — `_KNOWN_JSON_FRAGMENT_SCHEMAS` (compose:161) fehlt `ms-ai-exposure.json` + `ms-top-mitigations.json` (beide in validate_fragment.py:79-80 registriert); `ms-top-mitigations.json` wird ganz ohne Schema-Check konsumiert (compose:6579); `check_fragment_registry.py:154` prüft nur declared→disk. → beide Dateinamen ergänzen; Registry-Check bidirektional machen.

### [CD-9] §4b-Konsequenz-Claim stale (Low)
- `docs/internal/contracts/schema-invariants.md:46` behauptet `threats[].mitigations` rendere `—`; compose:7409/7471/7987 hat inzwischen den Fallback `t.get("mitigation_ids") or t.get("mitigations")`. → Konsequenz-Satz in der Doku aktualisieren (Fallback ist Härtung, kein Bug).

### [CD-10] `_SECARCH_SUBSECTIONS` „7.9 AI / LLM" — verifiziert: nur v1-Pfad, latent (Low)
- `pregenerate_fragments.py:2843` vs. `data/sections-contract.yaml:1275` („7.9 Cryptography…"). Default ist v2 (`gen_security_architecture_v2`, pregenerate:6536-6540); die stale Liste füttert nur den Legacy-v1-Pfad (`--schema-v1`). Dazu widersprüchliches Kommentar-Paar pregenerate:3861-3871 (Suppress vs. Stub-Emit; Code emittiert Stub). → als v1-legacy annotieren oder v1-Pfad bei EOL löschen; Kommentare bereinigen.

### [CD-11] `$APPSEC_SESSION_ID` in logging-standard.md fiktiv (Low)
- `agents/shared/logging-standard.md:14` nennt die Variable; repo-weit setzt/liest sie nichts (Session-IDs kommen aus Hook-Payloads, agent_logger.py:571, event_log.py:38-39). → Doku auf die reale Quelle umschreiben.

---

## PI — Prompt-Injection / Untrusted-Data-Exposure

### [PI-1] recon-scanner ohne generellen Untrusted-Data-Guard (High)
- Liest als ERSTER Agent rohen Target-Repo-Text (recon-scanner.md:45/:60/:96); einzige „untrusted"-Hinweise sind Cat-28-/Red-Flag-scoped (:148, :204, :502) — kein selbst-angewandter Guard wie in stride-analyzer.md:82, threat-renderer.md:83, context-resolver.md:628, threat-analyst.md:1172 (`<untrusted-data>`). `.recon-summary.md` steuert downstream Komponenten-Auswahl/Scope/Severity — injizierte Direktive („auth module out of scope") schrumpft das Assessment lautlos. → identischen Guard-Block an den Prompt-Kopf.

### [PI-2] config-scanner, evidence-verifier, abuse-case-verifier ohne Injection-Guard (Med)
- grep (`never follow|treat.*as data|untrusted…`) → 0 Treffer in allen dreien; alle lesen attacker-kontrollierte Quellen (Dockerfile/Workflows; `evidence.file ±5`; Sink-Tracing). Injizierter Kommentar neben einem Finding kann Verdicts kippen (`confirmed`→`blocked`, `refuted` zur Critical-Unterdrückung). → Shared-Guard-Zeile in alle drei Prompts.

### [PI-3] Report-HTML-Escape ist Denylist mit konkreten Bypässen; Export ungesanitized durch pandoc (Med)
- `compose_threat_model.py:10024-10027` `_DANGEROUS_HTML_TAG_RE`: nur script|iframe|svg|object|embed|form|style|link|meta|code + img/onerror + Handler onerror|onload|onclick|onmouseover. Bypässe: `<a href="javascript:…">`, alle übrigen Handler (`onfocus`, `ontoggle`, `onmouseenter`, `onanimationstart`, …); `PROTECTED_RE` (:10045-10047) lässt `<details>/<pre>/<code>`-Inhalte wörtlich durch. export_pdf: `PANDOC_FORMAT="gfm+…"` ohne Sanitize. Repo-Kommentar → verbatim `evidence.notes` (stride-analyzer.md:82) → XSS beim Öffnen des exportierten HTML (z. B. CI-publiziert). → Escape-by-default für LLM-/Repo-stämmige Prose statt Denylist, oder Allowlist-Sanitizer vor Export.

### [PI-4] fetch_requirements ohne den SSRF-Guard, den load_related_repos hat (Low)
- `fetch_requirements.py:80-83`: `urlopen` ohne `validate_target_url` (grep → 0); `:158-159` akzeptiert `file://` als Lokal-Read. Quelle ist Operator-/Org-Profil-Config (deshalb Low), aber `http://169.254.169.254/…` und `file:///etc/passwd` sind erreichbar. → durch `_url_guard.validate_target_url` routen, `file://` explizit gaten — analog load_related_repos.py:198.

---

## PC — Permission-Contract

### [PC-1] `.claude/settings.json` weicht beidseitig vom kanonischen Contract ab (High)
- Eingecheckt (git ls-files); enthält `Read(**)`, `Write(**)`, `Edit(**)` (Zeilen 4-6) — kanonisch sind drei gescope-te Roots (`data/required-permissions.yaml:54-76`); zugleich FEHLT `Bash(*)` (grep → 0), das die YAML verlangt (:102), die 30 Einzel-Bash-Entries matchen laut YAML-Eigendoku (:31-35) nur das erste Token → Compound-Commands prompten weiter. → per `check_permissions.py --update --scope project` regenerieren. Achtung: Datei ist in dieser WSL-Session gesperrt (vgl. Memory-Gotcha) — Änderung außerhalb der Session/manuell.

### [PC-2] fix-run-issues braucht `Edit(${PLUGIN_ROOT}/**)`, granted ist nur Read (High)
- `skills/fix-run-issues/SKILL.md:134-136`: „use the **Edit tool** … resolved relative to `$CLAUDE_PLUGIN_ROOT`"; YAML hat nur `Edit(${OUTPUT_DIR}/**)` (:70) + `Edit(${REPO_ROOT}/.gitignore)` (:74). Jeder auto-applied Fix promptet. → `Edit(${PLUGIN_ROOT}/**)` (oder enger `…/agents/**`) mit Begründung ergänzen.

### [PC-3] `_rule_covers`-Globmatcher: nackter Prefix matcht Sibling-Pfade (Med)
- `check_permissions.py:188`: `startswith(base)` ohne Separator — `Read(/srv/app/**)` „deckt" `/srv/app-security/**`; kein Testfall (test:118-123 prüft nur `/other/x`). Checker meldet „configured", realer Run promptet. → Klausel auf `== base` + `startswith(base + "/")` einengen; Sibling-Testfall ergänzen.

### [PC-4] Drift-Guard vacuous; keine Instanz prüft tatsächliche Nutzungsflächen (Med)
- `tests/test_check_permissions.py:268` prüft nur Bash-Entries — mit `Bash(*)` in der YAML (:102) und Wildcard-Kurzschluss im Checker (:172-173) unfehlbar. Write/Edit exempt mit stale Begründung (:260-261, „absolute maintainer paths" — real sind es `**`-Globs); `Read(**)` wird gar nicht eingesammelt. Kein Script parst agents/, SKILL-impl.md oder hooks/ nach genutzten Commands/Targets (check_permissions.py:442-450 difft nur YAML↔settings.json). PC-1/PC-2 sind strukturell unentdeckbar. → Drift-Test auf Read/Write/Edit ausweiten (shipped ⊆ expandierte YAML) + minimale Usage-Extraktion (s. a. TG-6).

### [PC-5] AGENTS.md §7 verlangt „sub-agent dispatches" zu erfassen — Schema + Test machen das unrepräsentierbar (Med)
- AGENTS.md:114 vs. `schemas/required-permissions.schema.yaml:45` (`enum: [file, shell]`) und test:70 (`{"Bash","Write","Edit","Read"}`); YAML hat 0 Dispatch-Entries bei 15+ Dispatch-Sites. Runtime-harmlos (Claude Code gated Task/Agent nicht über permissions.allow), aber tote Instruktion. → Bullet aus §7 streichen oder Doku-Kategorie im Schema ergänzen.

### [PC-6] `Edit(${REPO_ROOT}/.gitignore)` stale (Low)
- Begründung „publish-threat-model patches .gitignore", real macht das `scripts/publish_threat_model.py:92` script-seitig; kein Edit-Tool-Consumer mehr. → Entry entfernen oder Reason korrigieren.

### [PC-7] Schema-Header zitiert nicht-existente Consumer (Low)
- `schemas/required-permissions.schema.yaml:9-11` nennt `scripts/render_settings_example.py` + `.claude/settings.example.json` — beide existieren nicht. → zwei Zeilen löschen.

### [PC-8] hooks.json-Commands außerhalb des Permission-Modells, Header schweigt dazu (Low)
- `hooks/hooks.json:8` (security_steering.py auf jedem UserPromptSubmit), :18-48 (agent_logger auf Pre/Post/Stop). Runtime-korrekt (Hook-Approval beim Plugin-Enable), aber die kanonische YAML erklärt ihren Scope nicht. → ein Header-Satz „hooks execute outside this allow-list".

---

## DG — Fehlende/schwache deterministische Gates

### [DG-1] Stage-1-Cut-off-Detection vertraut stale `[ -f threat-model.md ]` (High)
- `SKILL-impl.md:2685-2688` (Detection = bare Existenz-Check); :2586-2588 benennt die Klasse selbst („STALE prior render … falsely read as success"), gefixt nur für den Parallel-Compose-Pfad. Snapshot `MD_PRE_STAGE1` wird NUR incremental erfasst (:1931) und NIE konsumiert (grep: nur Definition :1934/:1942 + Export :1947); kein `rm -f`/Archiv vor Stage 1; Stage-2-Recovery-Erfolg ebenfalls bare `[ -f … ]` (:2768).
- Folge: `--full`-Re-Run über bestehendes OUTPUT_DIR, Stage 1 stirbt nach STRIDE vor dem Phase-11-YAML-Write → stale md/yaml passieren alle Checks, Stage 2 liefert den VORHERIGEN Report als frisches Ergebnis aus.
- Fix: `YAML_PRE_STAGE1`/`MD_PRE_STAGE1` in allen Modi erfassen und Cut-off-Detection per `mtime:size`-Vergleich (Mechanik existiert: :2217-2220), oder Deliverables zu Stage-1-Beginn von Full-Runs löschen/archivieren.

### [DG-2] Stage-1c-Abuse-Pipeline: alle Exit-Codes ignoriert (High)
- `SKILL-impl.md:2442-2453`: `match … || true`; `CANDIDATES=$( … 2>/dev/null)`; `verify_abuse_cases.py merge … || true`; `finalize … || true`; leeres `$CANDIDATES` ⇒ Skip mit Not-applicable-Katalog.
- Folge: Crash ist von „nichts anwendbar" ununterscheidbar; §9 rendert lautlos den Katalog, Verdict-Sidecars fehlen/stale, 3b2-Severity-Fold self-gated zum No-op (Verstärkung von P1) — Severity-Under-Reporting ohne Fehlersignal.
- Fix: Exit-Codes erfassen; nonzero ⇒ `ABUSE_PIPELINE_FAILED` (Log + Banner + explizites `incomplete` in §9) statt Konflation mit leerem Ergebnis.

### [DG-3] `.threats-merged.json`/`.triage-flags.json`-Validatoren existieren, sind aber nur prompt-wired (Med)
- Skill-Gate ist Existenz-only (:2062-2064); einzige skill-seitige validate_intermediate-Invocation ist `threat_model_output` (:2156-2157); `threats_merged`/`triage_flags`-Modi (validate_intermediate.py:54-56) laufen nur in Agent-Prompts (finalization:302/391, threats:496) — die eigene Rationale „LLM prompt is not a hard technical barrier" (:2098) wird hier nicht angewandt. → Gate auf beide Modi ausweiten (ms-billig, gleiche exit-2-Plumbing).

### [DG-4] STRIDE-Stub-Detector klassifiziert korruptes JSON als gesund (Med)
- `SKILL-impl.md:1992-2001`: `except Exception: print('no')` — unparsebares `.stride-<id>.json` (truncated write, invalid escape) gilt als analysiert, kein Re-Dispatch. → fail-closed `print('yes')` oder drittes Verdict `corrupt`.

### [DG-5] Dead-prior-run-Detector: 1-Spawn-Invariante durch Default-Parallel-STRIDE gebrochen (Med)
- `SKILL-impl.md:255-258` zählt `AGENT_SPAWN.*appsec-threat-analyst` mit Kommentar „exactly one per run" — aber :1912 dispatcht Analyst-A + Analyst-B (zwei Spawns, eine Summary); Log append-only über Runs (:248-249), einzige Scope-ung ist `HK_AGE>300` (:270). Nach einem erfolgreichen Default-Run ist Spawns>Summaries permanent → `DEAD_PRIOR_BY_HOOKLOG=true` + stilles `APPSEC_TRACING=1` (:282-284); gleiche Annahme verfälscht den 24h-Zähler (:428). → Zählung auf Einträge nach der letzten `ASSESSMENT_SUMMARY` scopen (analog `generated_at`-Bounding in check_stride_dispatch.py:195-197).

### [DG-6] qa_checks: YAML-abhängige Checks auto-passen bei Exceptions (Med)
- `qa_checks.py:7226-7228` `except Exception: report.ok = 1; return report` (gleiches Muster :7257-7259, :7396-7398, :7405-7407; weicher :3384, :507). Fehlendes/korruptes threat-model.yaml zur QA-Zeit ⇒ §7-/CWE-Checks melden clean. Kontrast: :2718-2719 warnt wenigstens. → bei Exception Warning/Issue anhängen; existent-aber-unparsebar ⇒ fail.

### [DG-7] LLM-authored `.components.json`/`.actors-discovered.json` ohne Schema-Gate konsumiert (Med)
- `build_stride_dispatch_manifest.py:267` `_read_json(…, {})` (silent default); validate_intermediate kennt keine `components`/`actors`-Modi; kein top-level components-Schema (nur Render-Fragment); Pflicht-Keys nur in Prosa (`phase-group-architecture.md:62`); `resolve_actors.py:274-285` schluckt Load-Errors mit WARNING-print. → `components`-Modus in validate_intermediate + Gate am Manifest-Builder; `.actors-discovered.json` vor dem Layering validieren.

### [DG-8] Route-Inventory-Pre-Pass schluckt Fehler inkl. stderr (Med)
- `SKILL-impl.md:1680-1682`: `route_inventory.py … >/dev/null 2>&1 || true` (ebenso architecture_coverage_checks.py); „second line of defence" ist ein LLM-Prompt, der laut Abschnitt selbst unter Turn-Druck entfällt (:1697). Dokumentiertes §5-Symptom („4 vs. 52 Routen", :1673) kann weiter shippen — jetzt ohne Diagnose. → stderr nach `.agent-run.log` umleiten; YAML-Gate flaggt `attack_surface[]` ohne Inventory auf Web-Framework-Repos.

### [DG-9] PS_FAIL-Fallback lässt invalides Dispatch-Manifest liegen, dem das STRIDE-Gate später vertraut (Low)
- `SKILL-impl.md:1968-1976`: build-ok/validate-fail ⇒ Inline-Fallback ohne Manifest-Cleanup; `check_stride_dispatch.py:178-197` erwartet dann Analyzer-Spawns gemäß Manifest ⇒ legitimer Degraded-Run kann mit exit 2 am teuersten Punkt abgebrochen werden. → `rm -f .stride-dispatch-manifest.json` (oder `fallback: true`-Marker, den das Gate honoriert) im PS_FAIL-Zweig.

### [DG-10] QA-Agent hand-exekutiert mechanische Exact-String-Transformationen (Low)
- `appsec-qa-reviewer.md:381-383` (Badge→Emoji Exact-String), :332 (Key-takeaway-Insert), `phase-group-architecture.md:297` (Check-8-Rewrite). Klassischer Fall für den deterministischen Autofix-Pass (apply_prose_fixes.py) — und per §12 gehört der Badge-Fix in den Producer (compose besitzt `effectiveness_badge`, compose:250/602). → 11a/Insert in den Autofix-Pass; Producer emittiert keine Legacy-Spans mehr.

### [DG-11] Compose leert Requirements-Mapping still bei unlesbarer `.requirements.yaml` (Low)
- compose:7052-7055 `except Exception: return {}` (ähnlich :2462, :2512, :12556). Run, der das fail-closed Fetch-Gate passierte, kann mit still-leerem Mapping rendern. → in `--strict`: „absent" (legitimer Skip) von „present-but-unparseable" (ContractError) unterscheiden.

---

## TG — Test-/Drift-Guard-Lücken

### [TG-1] `t_id`-Fixture maskiert toten Code in publish_threat_model (High)
- `publish_threat_model.py:169` `t.get("t_id", "")` — kanonischer Key ist `id` (output-Schema: kein `t_id`; test_full_run_e2e.py:263-264 sagt es explizit). Test-Fixture spiegelt den Bug (`test_publish_threat_model.py:127` `{"t_id": "T-001", …}`) und asserted die Top-Threat-Zeilen nicht ⇒ „top: T-NNN title"-Commit-Zeilen rendern in realen Runs nie, Test bleibt grün. → Fixture auf `id`, Assertion auf Message-Body, Script liest `id` (Legacy-Fallback wie export_sarif.py:89-90). Hinweis: in `.threats-merged.json` ist `t_id` KORREKT (threats-merged.schema.yaml:25) — nur das Final-Artefakt nutzt `id`.

### [TG-2] Top-level `schemas/*.schema.json` entgehen beiden Drift-Guards (High)
- `test_schemas.py:20` globbt nur `*.schema.yaml`; `test_schema_integrity.py:29` nur `schemas/fragments/`. Von 6 top-level `.schema.json` hat nur requirements-verification einen Meta-Check; route-inventory/architecture-coverage/cross-repo-register/threat-summary nur instance-loaded; **qa-content-repair-plan.schema.json wird von 0 Tests und 0 Runtime-Code geladen** — apply_content_repair.py macht einen Hand-Check (:223) und dokumentiert trotzdem Exit-Code „3 — schema validation failed against …" (:42). → zweiter Glob über `schemas/*.schema.json` (Draft-2020-12-Meta-Check + Orphan-required-Walk); Test: apply_content_repairs akzeptiertes `op`-Set == Schema-Enum.

### [TG-3] Stale „dormant"-Exclusion: critical-attack-tree-Mutation läuft nie, Sektion seit 2026-05-28 aktiv (Med)
- `test_enforcement_mutations.py:197-202` („currently dormant") + Mutation fehlt in `MUTATIONS` (:190-214) vs. `sections-contract.yaml:362-364` („activated dormant section") + compose:13717/:13997. → Mutation gegen ≥2-Critical-Fixture aktivieren, Kommentar löschen.

### [TG-4] 16 von 20 referenzierten `agents/shared/*.md` von keinem Test gepinnt (Med)
- Prompts referenzieren 19 Shared-Files; Tests pinnen nur logging-standard, prose-style, prose-samples, ms-template (test_agent_definitions.py:415/553-560/608-624). Rename von z. B. secret-handling.md (5 Refs) bricht den Runtime-`cat` lautlos mid-run. → ein parametrisierter Test: jede `shared/*.md`-Referenz aus agents/+phases/+skills/ existiert auf Disk.

### [TG-5] `INTERNAL_AGENTS`-Hardcode ohne Vollständigkeits-Assert — Lücke biss schon einmal (Med)
- test_agent_definitions.py:54-67 (Inline-Geständnis :63 „set was missing it" für actor-discoverer); INTERNAL-Marker-/MODEL_ID-Checks iterieren nur das Hardcode-Set; `_CONTEXT_FILE_AGENTS` (:254) gleiches Muster. → `assert INTERNAL_AGENTS == set(EXPECTED_MAX_TURNS) - {ORCHESTRATOR}`.

### [TG-6] Kein Prompt→required-permissions.yaml-Drift-Guard (Med)
- test_check_permissions.py greift weder agents/ noch skills/ an (grep: 0); §7-Non-negotiable rein konventionsgesichert. Deckt sich mit PC-4. → heuristischer Test: `scripts/*.py`-Invocations aus Prompts extrahieren, Subsumption via vorhandener check_permissions-Logik.

### [TG-7] Kein Orphan-/Unwired-Template-Guard (Low)
- test_contract_integrity.py:114-129 prüft nur contract→template; `top-threats.md.j2`/`top-findings.md.j2` sind über hartkodierte `env.get_template` (compose:6170/:6193/:8038) unsichtbar verdrahtet; nichts asserted, dass jedes `*.j2` referenziert ist (vgl. ms-architecture-assessment-Episode). → Test: Contract-`template:`-Keys ∪ `get_template("…")`-Literale == On-Disk-`*.j2`-Menge.

### [TG-8] = MR-6 (Backtick-Fixture-Verzeichnis), siehe dort.

### [TG-9] Permanente Dangling-Anchor-Whitelist in Render-Property-Tests (Low)
- test_render_properties.py:155-161/:233-238 exempted `{8c-compound-attack-chains, 8d-architectural-findings, critical-attack-tree}` bedingungslos („tolerated correctness gap") — Regression bei PRÄSENTEN Fragmenten permanent maskiert. → Exemption an Fragment-Absenz koppeln.

### [TG-10] SKILL.md-Strukturtests nur für create-threat-model (Low)
- test_integration.py:52-56 (Glob-Existenz) + :213-243 (Phrase-Invarianten, nur create-threat-model); check-permissions/clean-run-state-SKILL.md von 0 Tests referenziert; kein Frontmatter-Validity-Test. → parametrisierter Frontmatter-Test über `skills/*/SKILL.md`.

---

## MR — Verantwortlichkeiten & Wartbarkeit

### [MR-1] Harvester-Rename bricht 4 user-facing Doks (High)
- Real: `scripts/harvest_requirements.py` (Commit 3033e8e). Stale: README.md:217, CONTRIBUTING.md:110+:127, docs/harvester.md:9/22/75/78, docs/security-requirements-audit-skill.md:61 — alle `harvest-requirements.py`. Ironie: docs/internal/runbooks/refactoring-plan.md:573 lehnte den Rename ab, „weil er Caller bricht". → Sweep-Replace in den 4 Doks (oder Kompat-Wrapper).

### [MR-2] validate_finding_refs.py + apply_finding_refs_repair.py an nichts verdrahtet (Med)
- Referenzieren nur einander (grep über agents/skills/scripts/tests/hooks/Makefile: nichts); komplette validate→repair→apply-Pipeline ohne Aufrufer driftet still vom Renderer-Contract weg. → in QA-/Repair-Loop verdrahten oder entfernen (Owner-Entscheid).

### [MR-3] `.budget-state.json` in der Cleanup-Policy unklassifiziert (Med)
- Per-Run geschrieben (budget_watchdog.py:34), aber in keiner Liste von runtime_cleanup.py, nicht in cleanup-whitelist.md, nicht in audit-artifacts.md. Live-Leftover beobachtet (skills/create-threat-model/docs/security/ — untracked, gitignored). → ALWAYS_FILES (+ `.budget-critical`-Familie) oder NEVER mit Rationale.

### [MR-4] cleanup-whitelist.md listet aus dem Code entfernte Einträge; Guard einseitig (Med)
- Doku nennt `.dep-scan.pid`/`.dep-scan.stdout` (Code-seitig entfernt in 1de38be); test_runtime_cleanup.py:305-313 prüft nur Code→Doku, Doku-only-Extras fallen nie auf — entgegen dem Doku-Claim „pinned … cannot drift". → zwei Zeilen löschen; Test bidirektional (Doku-Block ⊆ Konstanten).

### [MR-5] Reale Run-Artefakte im synthetic-repo-Scan-Target-Fixture committed (Med)
- Tracked: `tests/fixtures/e2e/synthetic-repo/docs/security/.active-tool-calls/toolu_*.json`, `.budget-state.json`, `.fragments/data-relations.json` (Commits 27cadb9, 4747ed1; vor der gitignore-Regel `.gitignore:23`). Von nichts referenziert. Pipeline-OUTPUT im Pipeline-INPUT-Fixture kann e2e-Runs vergiften (stale budget state, prior fragments). → `git rm -r --cached` (Owner-Confirm: kein Incremental-Test hängt dran).

### [MR-6] Ghost-Fixture-Verzeichnis mit literalem Backtick im Namen (Med, = TG-8)
- ``tests/fixtures/e2e/_last-run-req` ``/`` (trailing Backtick): 3 tracked Files (2× toolu_*.json, .session-agent-map), Shell-Quoting-Unfall aus 7ee6d1b; Untrack-Commit b5fc5c1 erfasste nur das echte `_last-run-req/`. Bricht naive Globs. → `git rm -r 'tests/fixtures/e2e/_last-run-req`'` (Quoting!).

### [MR-7] verify-vs-audit-Skill-Abgrenzung nur einseitig dokumentiert (Low)
- verify-requirements/SKILL.md:3 nennt den Full-Repo-Sibling; audit-security-requirements/SKILL.md erwähnt verify-requirements mit 0 Worten (grep: 0). → ein Satz „diff-scoped sibling: verify-requirements" in die Audit-Skill-Description.

### [MR-8] CONTRIBUTING-Layout-Tabelle untertreibt skills/ (Low)
- CONTRIBUTING.md:122 nennt 2 von 10 Skills; :127 zusätzlich den stalen Harvester-Namen (s. MR-1). → „10 user-invocable skills (primary: create-threat-model)" + Namen aktualisieren.

### [MR-9] `scripts/run-tests.sh` Orphan (Low, Entfernungs-Kandidat)
- 0 Referenzen repo-weit; letzter Commit 2026-04-21; Makefile `test:`-Target + CONTRIBUTING „Targeted tests" ersetzen es. Voller scripts/-Orphan-Scan: dieses + MR-2-Paar waren die einzigen Zero-Ref-Treffer. → nach Owner-Confirm löschen.

### [MR-10] Stale Agent-Worktrees unter `.claude/worktrees/` (Low, Umgebungs-Hygiene)
- 2 geparkte Worktrees auf 41d6b90; volle Repo-Kopien verfälschen repo-weite Greps (auch die der Plugin-Agents). → `git worktree remove`.

---

## Geprüft & sauber (Auszug — erspart Re-Audits)

- **§4f-Fünf-Registry-Regel**: unabhängiger AST-Cross-Diff aller 5 Maps + Contract + Schemas + Templates = vollständige Übereinstimmung; `check_fragment_registry.py` grün (Ausnahme: CD-8-Lücke in der compose-Pre-Pass-Map).
- **Verdict-/Fragment-Contracts**: abuse-case-verifier↔abuse-cases-Schema, triage-validator↔triage-flags, config-scanner↔config-scan-findings, renderer-Fragment-Enums (ms-verdict, ms-anti-patterns, ms-ai-exposure, critical-attack-tree) — alle deckungsgleich.
- **§4b/§4c/§4d-Invarianten** halten im Code (validate_intermediate.py:928-947; pregenerate:1195-1201; qa_checks↔sections-contract Spiegelung).
- **Component-ID→Pfad**: `^[a-z0-9][a-z0-9-]*$`-Pin im Manifest-Schema + Gate vor Dispatch — kein Traversal.
- **Mermaid**: serverseitig mmdc→PNG/SVG, kein securityLevel:loose, kein Client-mermaid.js.
- **YAML-Loading**: durchgängig CSafeLoader/safe_load auf Untrusted-Input.
- **load_related_repos**: validate_target_url, Scheme-Reject, Redirect-Header-Strip — Vorbild für PI-4.
- **Injection-Guards vorhanden**: threat-analyst, stride-analyzer, threat-renderer, context-resolver (`<untrusted-data>`-Blöcke).
- **Gates verdrahtet & exit-geprüft**: fetch_requirements-Pre-Fetch (exit 2), YAML-Hard-Gate, check_stride_dispatch (count-based, zeit-gebunden), compose-Hoist (exit-code + retry + incomplete-Checkpoint), check_inline_shortcut (GATE_EXIT 0–3), validate_dispatch_manifest (modulo DG-9), merge_threats-Escape-Sanitizer.
- **Die zwei bekannten stale e2e-Assertions sind GEFIXT** (test_full_run_e2e.py:107-113 konditional, :263-265 kanonisches `id`).
- **AGENTS.md-Pins halten heute**: test_agent_definitions + runtime_cleanup + lazy_phase_group + dispatch_prompt_cache_order + reasoning_model_resolution → 261 passed.
- **Agent-Roster vollständig**: alle 15 agents/*.md im Roster (inkl. appsec-reviewer als „standalone"), alle dispatcht; Reviewer-Grenzen (reviewer/architect/qa/fragment-fixer) in den Prompts disjunkt formuliert; alle 20 agents/shared/*.md ≥1× referenziert.
- **Skill-Zuständigkeiten disjunkt** mit explizitem Handoff (health→clean-run-state; fix-run-issues besitzt `.run-issues.json`).
- **SARIF-Export**: Untrusted-Strings nur als JSON-Strings — kein Interpretations-Sink.
- **Runtime-Files unter skills/create-threat-model/docs/security/**: untracked + gitignored (nur Cleanup-Klassifizierung offen, MR-3).

## Empfohlene Reihenfolge

1. **DG-1 + DG-2** (stille Falsch-Ergebnisse: stale Report als frisch; Severity-Under-Reporting) — beides reine SKILL-impl-Edits.
2. **CD-1** (Write-first-Stub reparieren: Prompt + Schema zusammen) — schützt teuerste Pipeline-Stufe.
3. **TG-1 + TG-2** (toter publish-Code + ungeprüfte Schemas; kleine, in sich geschlossene Test-/Script-Fixes).
4. **PC-1 + PC-2 + PC-3** (ein Permission-Sweep: settings regenerieren, Edit-Grant, Matcher-Fix + Tests).
5. **PI-1 + PI-2** (Guard-Block in 4 Prompts kopieren — minimal-invasiv), danach PI-3 als eigenes Design-Stück (Escape-Strategie).
6. **MR-1** (Doku-Sweep) + Rest der Med/Low nach Gelegenheit; CD-Doku-Fixes (CD-2/7/9) gebündelt als schema-invariants.md-Pflege.
