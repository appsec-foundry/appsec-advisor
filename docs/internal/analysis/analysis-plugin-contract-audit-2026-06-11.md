# Plugin Audit: Contracts, Injection Exposure, Gates, Permissions, Tests, Maintainability — 2026-06-11

Audit scope: agent prompts, phase instructions, schemas, templates, renderer,
QA checks, permission contract and tests of the plugin — dimensions: contract drift
(CD), prompt-injection exposure (PI), permission contract (PC), missing
deterministic gates (DG), test-/drift-guard gaps (TG), responsibilities &
maintainability (MR). Method: 6 parallel read-only audit agents, each High finding
then manually re-verified at the file:line level. **Findings only — no
code changes made.**

Not included (already documented): P1–P9 from
`analysis-perf-and-defects-2026-06-10.md`, requirements-section-unwired bug,
dead ms-architecture-assessment path, qa_checks `all` non-idempotence.

---

## Top priorities (all High, individually verified)

| ID | Summary |
|---|---|
| CD-1 | STRIDE write-first stub is schema-invalid by construction — defeats its own purpose |
| DG-1 | Stage-1 cut-off detection wrongly infers success from a stale `[ -f threat-model.md ]`; `MD_PRE_STAGE1` is captured but never consumed |
| DG-2 | Entire Stage-1c abuse pipeline runs with ignored exit codes (`\|\| true`, `2>/dev/null`) |
| TG-1 | `publish_threat_model.py` reads `t_id` (does not exist in the artifact); test fixture mirrors the bug → feature dead, test green |
| TG-2 | Top-level `schemas/*.schema.json` escape both schema-drift guards; `qa-content-repair-plan.schema.json` validated by nothing |
| PI-1 | recon-scanner reads raw target-repo text without a general untrusted-data guard (downstream supplier for all phases) |
| PC-1 | Checked-in `.claude/settings.json` deviates from the canonical contract in both directions: `Read/Write/Edit(**)` over-grants + missing `Bash(*)` |
| PC-2 | fix-run-issues edits plugin files via the Edit tool, but only `Read(${PLUGIN_ROOT}/**)` is granted → permission prompt on every fix |
| MR-1 | `harvest-requirements.py` renamed to `harvest_requirements.py`; README, CONTRIBUTING, docs/harvester.md, audit-skill docs point to the old name |

Cross-reference: DG-2 aggravates P1 (abuse-fold no-op) — matcher/merger crashes are
indistinguishable from "no abuse cases applicable"; §9 + severity fold degrade
silently, twice over.

---

## CD — Contract Drift

### [CD-1] STRIDE write-first stub schema-invalid (High)
- `agents/appsec-stride-analyzer.md` (write-first guarantee): the stub should contain `component_id`, `started_at`, `threats` + `partial`/`skipped_categories`. `schemas/stride.schema.yaml:86`: `required: [component_id, component_name, analyzed_at, threats]`; `started_at`/`partial`/`skipped_categories` are declared nowhere in the schema (grep: 0 hits). The orchestrator validates every stride file (`agents/phases/phase-group-threats.md:496` → `validate_intermediate.py stride`, no stub tolerance).
- Consequence: a budget cut leaves a file that the gate rejects — "partial-but-valid" becomes "invalid → full re-dispatch", exactly the failure mode the stub was introduced to prevent.
- Fix (bidirectional, §4): extend the stub in the prompt with `component_name` + `analyzed_at` (both known in Step 1) AND declare `started_at`/`partial`/`skipped_categories` in the schema.

### [CD-2] §4e describes vscode:// links that compose no longer emits (Med)
- `AGENTS.md:89` + `docs/internal/contracts/schema-invariants.md:65` require `[basename:line](vscode://file/…)` in §8; `grep -rn "vscode://" scripts/compose_threat_model.py` → 0 hits; the §8 card renders `**Location:** \`file:line\`` (compose:11934, :1469). The docs are the stale side (the 2026-05 card-layout redesign is the intended state) → update §4e in both docs.

### [CD-3] `threat_category_id` mandatory in prompt + hard gate, missing in both schemas (Med)
- `agents/appsec-stride-analyzer.md:468` (REQUIRED) + `scripts/validate_intermediate.py:244` (hard gate RC.G.1/RC.I) vs. `schemas/stride.schema.yaml` / `schemas/threats-merged.schema.yaml`: 0 hits. The schema ("single source of truth", validate_intermediate.py:6) is silent about a field without which merger TH dedup and §8 grouping collapse. → declare the field (`^TH-\d{2}$`, nullable) in both schemas.

### [CD-4] `threats[].source` enum three-way drift: prompt / merged schema / output schema (Med)
- `agents/appsec-threat-analyst.md:648` lists `known-threats` among others; `schemas/threats-merged.schema.yaml:77-88` doesn't know it, but has `architecture-coverage`/`threat-hypothesis`/`config-scan`/`configuration-defect` instead; `schemas/threat-model.output.schema.yaml:636` still contains the `dep-scan` removed in 2026-05; the output schema's required (:406-414) omits `source`, even though `phase-group-finalization.md:288` says "mandatory". → align the analyst enum to the merged schema, strike `dep-scan` from the output enum, decide the `source` requirement (adjust schema or prompt).

### [CD-5] Finalization prompt names tier_root_causes keys that the schema rejects (Med)
- `agents/phases/phase-group-finalization.md:56`: "`client:`, `application:` (alias `server`), `data:`" vs. `threat-model.output.schema.yaml:247-260`: `additionalProperties: false`, keys `edge`/`server`/`data`; `phase-group-threats.md:38` (the real producer) matches the schema. The alias claim is false (`tier_alias` in build_threat_model_yaml.py:762 maps a component's `tier`, not these keys). → correct finalization.md:56 to `edge`/`server`/`data` (affects REPAIR_MODE edits).

### [CD-6] Phase 10b vs. 10c vs. Stage 1c; AGENTS.md phase map without 2.7 and 10c (Med)
- `AGENTS.md:226` (roster: "Phase 10b") vs. `phase-group-threats.md:1790` ("Phase 10c") vs. `SKILL-impl.md:2412` ("Stage 1c"); the phase map (AGENTS.md:256-276) has neither 2.7 (exists: `phase-group-recon.md:344`) nor 10c. → pull the phase map + roster (+ pinning test in test_agent_definitions.py) onto ONE consistent name; the phase files are the operational truth.

### [CD-7] §4a "only legal producer" claim refuted by compose (Med)
- `docs/internal/contracts/schema-invariants.md:14-15` / `AGENTS.md:85`: only `qa_checks.py:linkify_anchors` produces titled cross-refs — but `compose_threat_model.py:459/509` (`linkify_with_label`, F-/M-/TH-) and :2252 (`_format_finding_link`) emit them too. Otherwise §12-guided editors fix the wrong producer. → extend the §4a docs with the sanctioned compose producers.

### [CD-8] Compose pre-pass map misses two registered fragments (Low)
- compose:1608 ("validate every known JSON fragment") — `_KNOWN_JSON_FRAGMENT_SCHEMAS` (compose:161) is missing `ms-ai-exposure.json` + `ms-top-mitigations.json` (both registered in validate_fragment.py:79-80); `ms-top-mitigations.json` is consumed entirely without a schema check (compose:6579); `check_fragment_registry.py:154` only checks declared→disk. → add both filenames; make the registry check bidirectional.

### [CD-9] §4b consequence claim stale (Low)
- `docs/internal/contracts/schema-invariants.md:46` claims `threats[].mitigations` renders `—`; compose:7409/7471/7987 has meanwhile added the fallback `t.get("mitigation_ids") or t.get("mitigations")`. → update the consequence sentence in the docs (the fallback is hardening, not a bug).

### [CD-10] `_SECARCH_SUBSECTIONS` "7.9 AI / LLM" — verified: v1 path only, latent (Low)
- `pregenerate_fragments.py:2843` vs. `data/sections-contract.yaml:1275` ("7.9 Cryptography…"). The default is v2 (`gen_security_architecture_v2`, pregenerate:6536-6540); the stale list feeds only the legacy v1 path (`--schema-v1`). Plus a contradictory comment pair pregenerate:3861-3871 (suppress vs. stub-emit; the code emits a stub). → annotate as v1-legacy or delete the v1 path at EOL; clean up the comments.

### [CD-11] `$APPSEC_SESSION_ID` in logging-standard.md fictitious (Low)
- `agents/shared/logging-standard.md:14` names the variable; nothing across the repo sets/reads it (session IDs come from hook payloads, agent_logger.py:571, event_log.py:38-39). → rewrite the docs to the real source.

---

## PI — Prompt Injection / Untrusted-Data Exposure

### [PI-1] recon-scanner without a general untrusted-data guard (High)
- Reads raw target-repo text as the FIRST agent (recon-scanner.md:45/:60/:96); the only "untrusted" hints are Cat-28-/red-flag-scoped (:148, :204, :502) — no self-applied guard like in stride-analyzer.md:82, threat-renderer.md:83, context-resolver.md:628, threat-analyst.md:1172 (`<untrusted-data>`). `.recon-summary.md` drives downstream component selection/scope/severity — an injected directive ("auth module out of scope") silently shrinks the assessment. → add the identical guard block to the prompt head.

### [PI-2] config-scanner, evidence-verifier, abuse-case-verifier without an injection guard (Med)
- grep (`never follow|treat.*as data|untrusted…`) → 0 hits in all three; all read attacker-controlled sources (Dockerfile/workflows; `evidence.file ±5`; sink tracing). An injected comment next to a finding can flip verdicts (`confirmed`→`blocked`, `refuted` to suppress a Critical). → add the shared guard line to all three prompts.

### [PI-3] Report HTML escaping is a denylist with concrete bypasses; export unsanitized through pandoc (Med)
- `compose_threat_model.py:10024-10027` `_DANGEROUS_HTML_TAG_RE`: only script|iframe|svg|object|embed|form|style|link|meta|code + img/onerror + handlers onerror|onload|onclick|onmouseover. Bypasses: `<a href="javascript:…">`, all remaining handlers (`onfocus`, `ontoggle`, `onmouseenter`, `onanimationstart`, …); `PROTECTED_RE` (:10045-10047) lets `<details>/<pre>/<code>` contents through verbatim. export_pdf: `PANDOC_FORMAT="gfm+…"` without sanitize. Repo comment → verbatim `evidence.notes` (stride-analyzer.md:82) → XSS when opening the exported HTML (e.g. CI-published). → escape-by-default for LLM-/repo-derived prose instead of a denylist, or an allowlist sanitizer before export.

### [PI-4] fetch_requirements without the SSRF guard that load_related_repos has (Low)
- `fetch_requirements.py:80-83`: `urlopen` without `validate_target_url` (grep → 0); `:158-159` accepts `file://` as a local read. The source is operator/org-profile config (hence Low), but `http://169.254.169.254/…` and `file:///etc/passwd` are reachable. → route through `_url_guard.validate_target_url`, gate `file://` explicitly — analogous to load_related_repos.py:198.

---

## PC — Permission Contract

### [PC-1] `.claude/settings.json` deviates from the canonical contract in both directions (High)
- Checked in (git ls-files); contains `Read(**)`, `Write(**)`, `Edit(**)` (lines 4-6) — canonical are three scoped roots (`data/required-permissions.yaml:54-76`); at the same time `Bash(*)` is MISSING (grep → 0), which the YAML requires (:102); the 30 individual Bash entries, per the YAML's own docs (:31-35), only match the first token → compound commands still prompt. → regenerate via `check_permissions.py --update --scope project`. Note: the file is locked in this WSL session (cf. memory gotcha) — change it outside the session/manually.

### [PC-2] fix-run-issues needs `Edit(${PLUGIN_ROOT}/**)`, only Read is granted (High)
- `skills/fix-run-issues/SKILL.md:134-136`: "use the **Edit tool** … resolved relative to `$CLAUDE_PLUGIN_ROOT`"; the YAML only has `Edit(${OUTPUT_DIR}/**)` (:70) + `Edit(${REPO_ROOT}/.gitignore)` (:74). Every auto-applied fix prompts. → add `Edit(${PLUGIN_ROOT}/**)` (or the tighter `…/agents/**`) with a justification.

### [PC-3] `_rule_covers` glob matcher: bare prefix matches sibling paths (Med)
- `check_permissions.py:188`: `startswith(base)` without a separator — `Read(/srv/app/**)` "covers" `/srv/app-security/**`; no test case (test:118-123 only checks `/other/x`). The checker reports "configured", the real run prompts. → narrow the clause to `== base` + `startswith(base + "/")`; add a sibling test case.

### [PC-4] Drift guard vacuous; no instance checks actual usage surfaces (Med)
- `tests/test_check_permissions.py:268` only checks Bash entries — with `Bash(*)` in the YAML (:102) and a wildcard short-circuit in the checker (:172-173), it's infallible. Write/Edit are exempt with a stale justification (:260-261, "absolute maintainer paths" — really they're `**` globs); `Read(**)` isn't collected at all. No script parses agents/, SKILL-impl.md or hooks/ for used commands/targets (check_permissions.py:442-450 only diffs YAML↔settings.json). PC-1/PC-2 are structurally undetectable. → extend the drift test to Read/Write/Edit (shipped ⊆ expanded YAML) + minimal usage extraction (see also TG-6).

### [PC-5] AGENTS.md §7 requires capturing "sub-agent dispatches" — schema + test make that unrepresentable (Med)
- AGENTS.md:114 vs. `schemas/required-permissions.schema.yaml:45` (`enum: [file, shell]`) and test:70 (`{"Bash","Write","Edit","Read"}`); the YAML has 0 dispatch entries against 15+ dispatch sites. Runtime-harmless (Claude Code does not gate Task/Agent via permissions.allow), but a dead instruction. → strike the bullet from §7 or add a doc category to the schema.

### [PC-6] `Edit(${REPO_ROOT}/.gitignore)` stale (Low)
- Justification "publish-threat-model patches .gitignore", but that's actually done script-side by `scripts/publish_threat_model.py:92`; no Edit-tool consumer anymore. → remove the entry or correct the reason.

### [PC-7] Schema header cites non-existent consumers (Low)
- `schemas/required-permissions.schema.yaml:9-11` names `scripts/render_settings_example.py` + `.claude/settings.example.json` — neither exists. → delete the two lines.

### [PC-8] hooks.json commands outside the permission model, header silent about it (Low)
- `hooks/hooks.json:8` (security_steering.py on every UserPromptSubmit), :18-48 (agent_logger on Pre/Post/Stop). Runtime-correct (hook approval at plugin enable), but the canonical YAML doesn't explain their scope. → one header sentence: "hooks execute outside this allow-list".

---

## DG — Missing/Weak Deterministic Gates

### [DG-1] Stage-1 cut-off detection trusts a stale `[ -f threat-model.md ]` (High)
- `SKILL-impl.md:2685-2688` (detection = bare existence check); :2586-2588 names the class itself ("STALE prior render … falsely read as success"), fixed only for the parallel-compose path. The `MD_PRE_STAGE1` snapshot is captured ONLY in incremental mode (:1931) and NEVER consumed (grep: only definition :1934/:1942 + export :1947); no `rm -f`/archive before Stage 1; Stage-2 recovery success is also a bare `[ -f … ]` (:2768).
- Consequence: a `--full` re-run over an existing OUTPUT_DIR, Stage 1 dies after STRIDE before the Phase-11 YAML write → stale md/yaml pass all checks, Stage 2 ships the PREVIOUS report as a fresh result.
- Fix: capture `YAML_PRE_STAGE1`/`MD_PRE_STAGE1` in all modes and do cut-off detection via `mtime:size` comparison (the mechanism exists: :2217-2220), or delete/archive the deliverables at the start of Stage 1 for full runs.

### [DG-2] Stage-1c abuse pipeline: all exit codes ignored (High)
- `SKILL-impl.md:2442-2453`: `match … || true`; `CANDIDATES=$( … 2>/dev/null)`; `verify_abuse_cases.py merge … || true`; `finalize … || true`; empty `$CANDIDATES` ⇒ skip with not-applicable catalog.
- Consequence: a crash is indistinguishable from "nothing applicable"; §9 silently renders the catalog, verdict sidecars are missing/stale, the 3b2 severity fold self-gates to a no-op (amplifying P1) — severity under-reporting with no error signal.
- Fix: capture exit codes; nonzero ⇒ `ABUSE_PIPELINE_FAILED` (log + banner + explicit `incomplete` in §9) instead of conflating with an empty result.

### [DG-3] `.threats-merged.json`/`.triage-flags.json` validators exist, but are only prompt-wired (Med)
- The skill gate is existence-only (:2062-2064); the only skill-side validate_intermediate invocation is `threat_model_output` (:2156-2157); the `threats_merged`/`triage_flags` modes (validate_intermediate.py:54-56) run only in agent prompts (finalization:302/391, threats:496) — the skill's own rationale "LLM prompt is not a hard technical barrier" (:2098) is not applied here. → extend the gate to both modes (cheap, same exit-2 plumbing).

### [DG-4] STRIDE stub detector classifies corrupt JSON as healthy (Med)
- `SKILL-impl.md:1992-2001`: `except Exception: print('no')` — an unparseable `.stride-<id>.json` (truncated write, invalid escape) counts as analyzed, no re-dispatch. → fail-closed `print('yes')` or a third verdict `corrupt`.

### [DG-5] Dead-prior-run detector: 1-spawn invariant broken by default parallel STRIDE (Med)
- `SKILL-impl.md:255-258` counts `AGENT_SPAWN.*appsec-threat-analyst` with the comment "exactly one per run" — but :1912 dispatches analyst-A + analyst-B (two spawns, one summary); the log is append-only across runs (:248-249), the only scoping is `HK_AGE>300` (:270). After one successful default run, spawns>summaries permanently → `DEAD_PRIOR_BY_HOOKLOG=true` + silent `APPSEC_TRACING=1` (:282-284); the same assumption corrupts the 24h counter (:428). → scope the count to entries after the last `ASSESSMENT_SUMMARY` (analogous to `generated_at` bounding in check_stride_dispatch.py:195-197).

### [DG-6] qa_checks: YAML-dependent checks auto-pass on exceptions (Med)
- `qa_checks.py:7226-7228` `except Exception: report.ok = 1; return report` (same pattern :7257-7259, :7396-7398, :7405-7407; softer :3384, :507). A missing/corrupt threat-model.yaml at QA time ⇒ §7/CWE checks report clean. Contrast: :2718-2719 at least warns. → attach a warning/issue on exception; exists-but-unparseable ⇒ fail.

### [DG-7] LLM-authored `.components.json`/`.actors-discovered.json` consumed without a schema gate (Med)
- `build_stride_dispatch_manifest.py:267` `_read_json(…, {})` (silent default); validate_intermediate has no `components`/`actors` modes; no top-level components schema (only a render fragment); mandatory keys only in prose (`phase-group-architecture.md:62`); `resolve_actors.py:274-285` swallows load errors with a WARNING print. → add a `components` mode to validate_intermediate + a gate at the manifest builder; validate `.actors-discovered.json` before layering.

### [DG-8] Route-inventory pre-pass swallows errors including stderr (Med)
- `SKILL-impl.md:1680-1682`: `route_inventory.py … >/dev/null 2>&1 || true` (likewise architecture_coverage_checks.py); the "second line of defence" is an LLM prompt that, per the section itself, drops out under turn pressure (:1697). The documented §5 symptom ("4 vs. 52 routes", :1673) can keep shipping — now without a diagnosis. → redirect stderr to `.agent-run.log`; a YAML gate flags `attack_surface[]` without an inventory on web-framework repos.

### [DG-9] PS_FAIL fallback leaves an invalid dispatch manifest that the STRIDE gate later trusts (Low)
- `SKILL-impl.md:1968-1976`: build-ok/validate-fail ⇒ inline fallback without manifest cleanup; `check_stride_dispatch.py:178-197` then expects analyzer spawns per the manifest ⇒ a legitimate degraded run can be aborted with exit 2 at the most expensive point. → `rm -f .stride-dispatch-manifest.json` (or a `fallback: true` marker the gate honors) in the PS_FAIL branch.

### [DG-10] QA agent hand-executes mechanical exact-string transformations (Low)
- `appsec-qa-reviewer.md:381-383` (badge→emoji exact string), :332 (key-takeaway insert), `phase-group-architecture.md:297` (Check-8 rewrite). A classic case for the deterministic autofix pass (apply_prose_fixes.py) — and per §12 the badge fix belongs in the producer (compose owns `effectiveness_badge`, compose:250/602). → move 11a/insert into the autofix pass; the producer emits no legacy spans anymore.

### [DG-11] Compose silently empties the requirements mapping on an unreadable `.requirements.yaml` (Low)
- compose:7052-7055 `except Exception: return {}` (similar :2462, :2512, :12556). A run that passed the fail-closed fetch gate can render with a silently empty mapping. → in `--strict`: distinguish "absent" (legitimate skip) from "present-but-unparseable" (ContractError).

---

## TG — Test-/Drift-Guard Gaps

### [TG-1] `t_id` fixture masks dead code in publish_threat_model (High)
- `publish_threat_model.py:169` `t.get("t_id", "")` — the canonical key is `id` (output schema: no `t_id`; test_full_run_e2e.py:263-264 says so explicitly). The test fixture mirrors the bug (`test_publish_threat_model.py:127` `{"t_id": "T-001", …}`) and does not assert the top-threat lines ⇒ "top: T-NNN title" commit lines never render in real runs, the test stays green. → fixture to `id`, assertion on the message body, script reads `id` (legacy fallback like export_sarif.py:89-90). Note: in `.threats-merged.json` `t_id` is CORRECT (threats-merged.schema.yaml:25) — only the final artifact uses `id`.

### [TG-2] Top-level `schemas/*.schema.json` escape both drift guards (High)
- `test_schemas.py:20` only globs `*.schema.yaml`; `test_schema_integrity.py:29` only `schemas/fragments/`. Of 6 top-level `.schema.json`, only requirements-verification has a meta check; route-inventory/architecture-coverage/cross-repo-register/threat-summary are only instance-loaded; **qa-content-repair-plan.schema.json is loaded by 0 tests and 0 runtime code** — apply_content_repair.py does a hand check (:223) and still documents exit code "3 — schema validation failed against …" (:42). → a second glob over `schemas/*.schema.json` (Draft-2020-12 meta check + orphan-required walk); test: apply_content_repairs' accepted `op` set == schema enum.

### [TG-3] Stale "dormant" exclusion: critical-attack-tree mutation never runs, section active since 2026-05-28 (Med)
- `test_enforcement_mutations.py:197-202` ("currently dormant") + the mutation is missing from `MUTATIONS` (:190-214) vs. `sections-contract.yaml:362-364` ("activated dormant section") + compose:13717/:13997. → activate the mutation against a ≥2-Critical fixture, delete the comment.

### [TG-4] 16 of 20 referenced `agents/shared/*.md` pinned by no test (Med)
- Prompts reference 19 shared files; tests only pin logging-standard, prose-style, prose-samples, ms-template (test_agent_definitions.py:415/553-560/608-624). Renaming e.g. secret-handling.md (5 refs) silently breaks the runtime `cat` mid-run. → one parametrized test: every `shared/*.md` reference from agents/+phases/+skills/ exists on disk.

### [TG-5] `INTERNAL_AGENTS` hardcode without a completeness assert — the gap has bitten before (Med)
- test_agent_definitions.py:54-67 (inline confession :63 "set was missing it" for actor-discoverer); the INTERNAL-marker/MODEL_ID checks iterate only the hardcode set; `_CONTEXT_FILE_AGENTS` (:254) same pattern. → `assert INTERNAL_AGENTS == set(EXPECTED_MAX_TURNS) - {ORCHESTRATOR}`.

### [TG-6] No prompt→required-permissions.yaml drift guard (Med)
- test_check_permissions.py touches neither agents/ nor skills/ (grep: 0); the §7 non-negotiable is purely convention-secured. Overlaps with PC-4. → a heuristic test: extract `scripts/*.py` invocations from prompts, subsumption via the existing check_permissions logic.

### [TG-7] No orphan-/unwired-template guard (Low)
- test_contract_integrity.py:114-129 only checks contract→template; `top-threats.md.j2`/`top-findings.md.j2` are invisibly wired via hardcoded `env.get_template` (compose:6170/:6193/:8038); nothing asserts that every `*.j2` is referenced (cf. the ms-architecture-assessment episode). → test: contract `template:` keys ∪ `get_template("…")` literals == on-disk `*.j2` set.

### [TG-8] = MR-6 (backtick fixture directory), see there.

### [TG-9] Permanent dangling-anchor whitelist in render-property tests (Low)
- test_render_properties.py:155-161/:233-238 exempt `{8c-compound-attack-chains, 8d-architectural-findings, critical-attack-tree}` unconditionally ("tolerated correctness gap") — a regression on PRESENT fragments is permanently masked. → couple the exemption to fragment absence.

### [TG-10] SKILL.md structure tests only for create-threat-model (Low)
- test_integration.py:52-56 (glob existence) + :213-243 (phrase invariants, only create-threat-model); check-permissions/clean-run-state SKILL.md referenced by 0 tests; no frontmatter-validity test. → a parametrized frontmatter test over `skills/*/SKILL.md`.

---

## MR — Responsibilities & Maintainability

### [MR-1] Harvester rename breaks 4 user-facing docs (High)
- Real: `scripts/harvest_requirements.py` (commit 3033e8e). Stale: README.md:217, CONTRIBUTING.md:110+:127, docs/harvester.md:9/22/75/78, docs/security-requirements-audit-skill.md:61 — all `harvest-requirements.py`. Irony: docs/internal/runbooks/refactoring-plan.md:573 rejected the rename "because it breaks callers". → sweep-replace in the 4 docs (or a compat wrapper).

### [MR-2] validate_finding_refs.py + apply_finding_refs_repair.py wired to nothing (Med)
- They only reference each other (grep over agents/skills/scripts/tests/hooks/Makefile: nothing); a complete validate→repair→apply pipeline with no caller silently drifts from the renderer contract. → wire into the QA/repair loop or remove (owner decision).

### [MR-3] `.budget-state.json` unclassified in the cleanup policy (Med)
- Written per run (budget_watchdog.py:34), but in no list of runtime_cleanup.py, not in cleanup-whitelist.md, not in audit-artifacts.md. Live leftover observed (skills/create-threat-model/docs/security/ — untracked, gitignored). → ALWAYS_FILES (+ the `.budget-critical` family) or NEVER with a rationale.

### [MR-4] cleanup-whitelist.md lists entries removed from the code; guard one-sided (Med)
- The docs name `.dep-scan.pid`/`.dep-scan.stdout` (removed code-side in 1de38be); test_runtime_cleanup.py:305-313 only checks code→docs, docs-only extras are never caught — contrary to the docs' claim "pinned … cannot drift". → delete two lines; make the test bidirectional (docs block ⊆ constants).

### [MR-5] Real run artifacts committed into the synthetic-repo scan-target fixture (Med)
- Tracked: `tests/fixtures/e2e/synthetic-repo/docs/security/.active-tool-calls/toolu_*.json`, `.budget-state.json`, `.fragments/data-relations.json` (commits 27cadb9, 4747ed1; before the gitignore rule `.gitignore:23`). Referenced by nothing. Pipeline OUTPUT inside the pipeline INPUT fixture can poison e2e runs (stale budget state, prior fragments). → `git rm -r --cached` (owner confirm: no incremental test depends on it).

### [MR-6] Ghost fixture directory with a literal backtick in the name (Med, = TG-8)
- ``tests/fixtures/e2e/_last-run-req` ``/`` (trailing backtick): 3 tracked files (2× toolu_*.json, .session-agent-map), a shell-quoting accident from 7ee6d1b; the untrack commit b5fc5c1 only caught the real `_last-run-req/`. Breaks naive globs. → `git rm -r 'tests/fixtures/e2e/_last-run-req`'` (quoting!).

### [MR-7] verify-vs-audit skill boundary documented only one-sidedly (Low)
- verify-requirements/SKILL.md:3 names the full-repo sibling; audit-security-requirements/SKILL.md mentions verify-requirements in 0 words (grep: 0). → one sentence "diff-scoped sibling: verify-requirements" in the audit-skill description.

### [MR-8] CONTRIBUTING layout table understates skills/ (Low)
- CONTRIBUTING.md:122 names 2 of 10 skills; :127 additionally the stale harvester name (see MR-1). → "10 user-invocable skills (primary: create-threat-model)" + update the names.

### [MR-9] `scripts/run-tests.sh` orphan (Low, removal candidate)
- 0 references repo-wide; last commit 2026-04-21; the Makefile `test:` target + CONTRIBUTING "Targeted tests" replace it. Full scripts/ orphan scan: this + the MR-2 pair were the only zero-ref hits. → delete after owner confirm.

### [MR-10] Stale agent worktrees under `.claude/worktrees/` (Low, environment hygiene)
- 2 parked worktrees at 41d6b90; full repo copies distort repo-wide greps (including those of the plugin agents). → `git worktree remove`.

---

## Checked & clean (excerpt — saves re-audits)

- **§4f five-registry rule**: independent AST cross-diff of all 5 maps + contract + schemas + templates = full agreement; `check_fragment_registry.py` green (exception: the CD-8 gap in the compose pre-pass map).
- **Verdict-/fragment contracts**: abuse-case-verifier↔abuse-cases schema, triage-validator↔triage-flags, config-scanner↔config-scan-findings, renderer fragment enums (ms-verdict, ms-anti-patterns, ms-ai-exposure, critical-attack-tree) — all congruent.
- **§4b/§4c/§4d invariants** hold in the code (validate_intermediate.py:928-947; pregenerate:1195-1201; qa_checks↔sections-contract mirroring).
- **Component-ID→path**: `^[a-z0-9][a-z0-9-]*$` pin in the manifest schema + gate before dispatch — no traversal.
- **Mermaid**: server-side mmdc→PNG/SVG, no securityLevel:loose, no client-side mermaid.js.
- **YAML loading**: CSafeLoader/safe_load throughout on untrusted input.
- **load_related_repos**: validate_target_url, scheme reject, redirect-header strip — the model for PI-4.
- **Injection guards present**: threat-analyst, stride-analyzer, threat-renderer, context-resolver (`<untrusted-data>` blocks).
- **Gates wired & exit-checked**: fetch_requirements pre-fetch (exit 2), YAML hard gate, check_stride_dispatch (count-based, time-bounded), compose hoist (exit code + retry + incomplete checkpoint), check_inline_shortcut (GATE_EXIT 0–3), validate_dispatch_manifest (modulo DG-9), merge_threats escape sanitizer.
- **The two known stale e2e assertions are FIXED** (test_full_run_e2e.py:107-113 conditional, :263-265 canonical `id`).
- **AGENTS.md pins hold today**: test_agent_definitions + runtime_cleanup + lazy_phase_group + dispatch_prompt_cache_order + reasoning_model_resolution → 261 passed.
- **Agent roster complete**: all 15 agents/*.md in the roster (incl. appsec-reviewer as "standalone"), all dispatched; reviewer boundaries (reviewer/architect/qa/fragment-fixer) phrased disjointly in the prompts; all 20 agents/shared/*.md referenced ≥1×.
- **Skill responsibilities disjoint** with explicit handoff (health→clean-run-state; fix-run-issues owns `.run-issues.json`).
- **SARIF export**: untrusted strings only as JSON strings — no interpretation sink.
- **Runtime files under skills/create-threat-model/docs/security/**: untracked + gitignored (only cleanup classification open, MR-3).

## Recommended order

1. **DG-1 + DG-2** (silent wrong results: stale report as fresh; severity under-reporting) — both pure SKILL-impl edits.
2. **CD-1** (repair the write-first stub: prompt + schema together) — protects the most expensive pipeline stage.
3. **TG-1 + TG-2** (dead publish code + unchecked schemas; small, self-contained test/script fixes).
4. **PC-1 + PC-2 + PC-3** (one permission sweep: regenerate settings, Edit grant, matcher fix + tests).
5. **PI-1 + PI-2** (copy the guard block into 4 prompts — minimally invasive), then PI-3 as its own design piece (escape strategy).
6. **MR-1** (docs sweep) + the rest of the Med/Low as opportunity allows; CD docs fixes (CD-2/7/9) bundled as schema-invariants.md maintenance.
