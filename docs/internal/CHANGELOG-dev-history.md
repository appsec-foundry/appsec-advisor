# Changelog

## 0.4.0-beta — 2026-06-13

### QA pre-pass performance — defer the detector battery off the clean path

The Stage-3 deterministic QA pass ran `qa_checks.py all` (≈50 checks) on **every** run to populate `.qa-prepass.json`. But the dispatch gate is driven solely by `qa_checks.py repair_plan`; the `all` exit code is discarded, and on the clean fast path the QA agent is skipped — so `.qa-prepass.json` was written and never read. The detector battery ran for nobody.

- **New `qa_checks.py autofix` subcommand** — runs only the five in-place mutating passes (links, anchors, MS structure, cell-format, heading-attribute strip), no detector battery, no JSON. The skill now calls `autofix` at the gate (always) and defers the full `all` → `.qa-prepass.json` to the agent-dispatch branch, where the JSON is actually consumed. Clean runs no longer execute ~45 detector checks. (`scripts/qa_checks.py`, `skills/create-threat-model/SKILL-impl.md`)
- **Retired nine no-actuator checks from the `all` pre-pass** — `summary_bullets`, `hypothesis_validation_objective`, `attack_tree_node_id_leak`, `section_713_no_table`, and the §7 clarity group `section7_narrative_placeholders` / `section7_h4_positive_intro` / `section7_fence_intro_sentence` / `section7_finding_link_duplicate` / `section7_finding_reference_semantic`. None reached a consumer (absent from `build_repair_plan`, absent from the QA-reviewer handoff table); the underlying authoring rules are enforced at the renderer. All nine remain callable as standalone subcommands for CI / manual regression use (three new subcommands added for the previously subcommand-less guards).
- **`check_invariants` numeric battery removed** — the Risk-Distribution sum, STRIDE-Coverage sum, and §8 heading-count parity were guaranteed by construction (the composer renders all three from one `threats[]` grouping; the output-schema gate enums `stride`/`risk` before Stage 2) and the §8-heading branch matched a stale `### 8.1 Critical (N)` format the card-layout composer no longer emits. The guarantee is now pinned by `tests/test_compose_threat_model.py::test_section8_counts_equal_threat_total`. The live PHASE_BURST log diagnostic is unchanged. The orphaned `STRIDE_COVERAGE_RE` / `SECTION_8_SUB_RE` constants are deleted; the QA-reviewer Check 7c handoff is updated accordingly.
- **Retired eight warning-only §7 prose checks from the `all` pre-pass** — `paragraph_density`, `finding_range_homogeneous`, `dependency_cross_ref`, `na_against_recon`, `architectural_prose`, `generic_phrases`, `rhetorical_severity`, `section_opener_restates_heading`. None reached an actuator (absent from `build_repair_plan`, no agent handoff action) and the underlying authoring rules are enforced at the renderer. Each gains a standalone subcommand for CI / manual use. (`rhetorical_severity`'s one-phrase auto-rewrite in `apply_prose_fixes.py` is independent and unaffected.)
- **Secret-leak detection promoted to a hard, always-on gate** — the deferral of the `all` battery off the clean path meant `check_unmasked_secrets` would no longer populate `.qa-prepass.json` on clean runs, and its `all` exit code was already discarded (the documented release-block was toothless on the automated path). The skill now runs the dedicated `unmasked_secrets` subcommand on every gate pass, writes `.qa-secret-scan.json`, and **aborts with exit 2** on a hit. To make fail-closing safe, `secret_scan.py` gains a precision fix: the loose `generic_credential_assignment` pattern now skips unquoted code-identifier references (camelCase / PascalCase / dotted attribute paths such as `secret: publicKey`, `password: security.hash`) — these are variable names in code excerpts, not literal secrets. Quoted literals, opaque tokens, and digit-bearing values still flag. (`scripts/secret_scan.py`, `tests/test_secret_scan.py` +2 parametrized cases.) Note: a doc carrying a genuinely unmasked value (e.g. a quoted hardcoded password or a `-----BEGIN … PRIVATE KEY-----` evidence excerpt) is now correctly blocked until masked per `agents/shared/secret-handling.md`.

Net test delta: zero new failures (verified against the pre-change baseline).

### §9 Abuse Cases — verifiable, scenario-level attack chains

The report gains a new **§9 Abuse Cases** section between §8 Threat Register and the mitigation register. Abuse cases (`AC-NNN`) are narrative, end-to-end attack scenarios that chain individual findings into a verified exploitation path, each carrying a deterministic chain verdict (`⚠ Fully viable` / `◐ Partially blocked` / `✓ Mitigated` / `? Inconclusive`). Cases are either **mandatory** (a plugin standard library plus org-profile definitions, evaluated on every run) or **discovered** from the finding register.

- **Section numbering shift** — inserting §9 Abuse Cases renumbers **Mitigation Register §9 → §10** and **Out of Scope §10 → §11**. `data/sections-contract.yaml`, `compose_threat_model.py` (anchors + new `_render_abuse_cases` handler), `pregenerate_fragments.py`, the QA-reviewer heading contract, and the affected fixtures/tests are updated atomically. §8 Threat Register and `T-NNN`/`F-NNN` finding ids are unchanged.
- **Data model** — `schemas/abuse-cases.schema.yaml` (case definition + chain steps with `grants`/`requires` and code `probe`s), `data/abuse-cases/default-library.yaml` (Account Takeover, Bulk Exfiltration, Privilege Escalation), and an `abuse_cases` block in `schemas/org-profile.schema.yaml` (`inherit_defaults` / `disable` / `add`). Resolution + validation in `scripts/resolve_abuse_cases.py` and `validate_org_profile.py`.
- **Matching + verification** — `scripts/match_abuse_cases.py` (deterministic matcher + chain-verdict finalizer), `scripts/verify_abuse_cases.py` (verdict merge + budget guard), and a new Phase-10c parallel fan-out (`agents/appsec-abuse-case-verifier.md`, Haiku, one agent per candidate) that confirms each chain step against the code. The chain verdict is computed deterministically from per-step verdicts — never rated by the LLM — so §9 is auditable and diff-stable.
- **Rendering** — `scripts/render_abuse_cases.py` produces the deterministic §9 fragment (summary table, per-case attack-chain table with verdict-derived status icons, combined-risk rationale, blocking-mitigation table) from `.abuse-case-verdicts.json`; `reserve_ids.py` gains the `AC` id type.

Net test delta: zero new failures (verified against the pre-change baseline).

### §3.1 Attack Chain Overview — removed (consolidated into the Critical Attack Tree)

The report narrated attack paths in three places: the top-level `## Critical Attack Tree` (AND/OR goal decomposition), the §3.1 Attack Chain Overview (linear `graph LR` kill-chains), and the §3.2+ per-finding walkthroughs. §3.1 was the redundant middle layer — it re-expressed the tree's cross-finding logic in a weaker linear form (the tree already carries a "Path to admin" table), it did not have the per-finding exploit steps of §3.2+, and it was the most error-prone surface (false causal edges between independent findings, mirror-duplicate chains, cryptic node labels). **§3.1 is removed.** §3 is now a flat list of per-Critical walkthroughs (`### 3.1`, `### 3.2`, …); the single cross-finding/strategic view is the `## Critical Attack Tree`.

- **`scripts/walkthrough_renderer.py`** — `render_attack_walkthroughs_md` no longer emits §3.1; walkthroughs renumber from `### 3.1`; the §3 intro points to the Critical Attack Tree. The deterministic chain catalogue (`derive_attack_chains`), the per-chain renderer, the chain label helpers, the `MAX_CHAINS`/`CHAIN_CLASSDEFS` constants, and the now-orphaned `VEKTOR_ACTOR_LABEL` table are deleted.
- **`data/sections-contract.yaml`** — the §3.1 required subsection, the `graph LR` required pattern, the entire `chain_compactness` block, and the chain-specific `walkthrough_depth` keys (`min_chain_overview_nodes_per_block`, `require_chain_key_takeaway`, `require_chain_subsection_heading`) are removed. §3 coverage is enforced solely by `per_critical_subsection` + the `sequenceDiagram` required pattern.
- **`scripts/compose_threat_model.py`** — `_build_finding_to_chain_map` drops the `#### Chain N` parser and now reads each walkthrough's owner from its `**Source:** [T-NNN]` line (robust to the deterministic renderer keeping headings T-NNN-free); the §3 default intro and `_inject_attack_walkthroughs_intros` lose their §3.1 branch.
- **`scripts/qa_checks.py`** — `check_walkthrough_coverage` / `check_walkthrough_depth` no longer skip §3.1 (every §3.N is a walkthrough now); the Critical-Attack-Tree presence check (Check 4) no longer accepts §3.1 as a substitute. `check_chain_compactness` / `check_chain_tid_consistency` degrade to no-ops once the contract block is gone.
- **`scripts/pregenerate_fragments.py`** — the now-unconsumed `_chain-skeleton.md` helper (`gen_attack_walkthroughs_skeleton`) delegates to the deterministic per-Critical generator so it can never reintroduce §3.1.
- **Agent prompts / schemas** — the §3.1 authoring section in `phase-group-architecture.md`, the §3.1 chain palette/keyword rules in `appsec-threat-analyst.md`, the §3.1 `graph LR` template + mentions in `appsec-threat-renderer.md`, the §3 contract row in `phase-group-finalization.md`, and the §3.1 references in `phase-group-threats.md` and the fragment schemas are all updated to describe the per-finding-only §3 and point cross-finding analysis at the Critical Attack Tree.

Net test delta: zero new failures (verified against the pre-change baseline).

**Critical Attack Tree residual** — the authoring example in `agents/appsec-threat-renderer.md` referenced an internal node id (`AND_JWT subtree`) in prose, which the model imitated (`… subtree (OR_FORGE)`). The example is corrected, a "never expose a node id in prose" rule added, and `scripts/qa_checks.py` gains `check_attack_tree_node_id_leak` (warning-only) to catch regressions.

### §7 control-narrative readability — concrete openers, no purpose-padding, multi-issue bullets

Generated §7 Security Architecture narratives drifted into a recognisable AI shape: nearly every H4 control intro opened with the formulaic `The application <verb>s …` stem, padded with a textbook-purpose tail (`with the intention that …`, `with the expectation that …`, `preventing X from being Y`), and every `**Security assessment**` welded multiple discrete weaknesses into one dense paragraph. The contract and structure are unchanged; the prose-authoring guidance is tightened so the output reads like a seasoned architect wrote it.

- **`agents/appsec-threat-renderer.md`** — the §7.X authoring pattern now requires each H4 intro to lead with the concrete artifact (route / file / library / component), caps the `The application/system/server …` stem at ≤1 per §7.X section, and bans textbook-purpose padding clauses. `**Security assessment**` blocks covering ≥2 discrete weaknesses should use a short bullet list (one weakness per bullet) instead of one dense paragraph. Self-check item 4 and the banned-vocabulary list updated; the §7.5.1 worked example re-led with a concrete subject.
- **`agents/shared/prose-style.md`** — new Rule 7 (*Lead with the concrete thing; cut the textbook purpose*) with before/after pairs, plus a rejection-list entry.
- **`agents/shared/prose-samples.md`** — new worked Pairs F (H4 intro opener) and G (dense assessment → framing sentence + bullets); loader scope note widened to cover §7 narratives; banned-vocabulary list extended with the opener stems and padding clauses.
- **`scripts/qa_checks.py` → `check_architectural_prose`** — `_ARCH_PROSE_BANNED_PATTERNS` gains the padding clauses; a new aggregated warning fires when ≥3 H4 intros across §7 share the formulaic stem. Documented in `agents/shared/sec7-quality-bar-rules.md` as `qb7_concrete_openers` / extended `qb7_no_floskeln`. Warnings only — flows through the existing QA pipeline, no new hard-fail gate.

### Supply-chain scope refactor (sca.md) — **Breaking change**

The pre-2026-05 `scripts/dep_scan.py` SCA producer is **removed**. The plugin no longer competes with dedicated SCA tools (Snyk / Trivy / Dependabot / OSV-Scanner / language-native audit) on per-CVE reporting — that lane is solved industry and the plugin's bundled 17-entry heuristic list never won on freshness. Supply-chain risk is now surfaced where it belongs: as architectural posture.

**The plugin is now passive-only for supply-chain detection.** It never runs `npm audit` / `pip-audit` / `govulncheck` / `snyk` / any package-manager or CVE-database tool, and never makes a network request to npmjs / PyPI / osv.dev. Detection is pure file-system inspection plus `git log` (commit-cadence signal) plus an optional best-effort `gh pr list` (skipped silently when unavailable).

**Three new deterministic emitters run in Phase 10:**

- `scripts/emit_dep_update_activity.py` — passive `git log` over a 90-day window on dependency manifests. Classifies cadence as `active` / `sporadic` / `inactive` / `unknown` based on commit count + bot-authored commit count (`dependabot[bot]` / `renovate[bot]`). Optional `gh pr list` count when GitHub CLI is on PATH.
- `scripts/emit_sca_practice.py` — three §7.11 *Operations Runtime and Supply Chain Controls* rows: **Automated SCA scanning** / **Automated dependency updates** / **Lockfile hygiene**. Each is rated `Adequate` / `Partial` / `Missing` by walking `.github/workflows/*.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `.circleci/config.yml`, `Jenkinsfile`, `.github/dependabot.yml`, `renovate.json*`, and the per-ecosystem lockfiles. **The dep-update activity sidecar lifts the "Automated dependency updates" rating** for repos that patch on cadence without Dependabot / Renovate config files — covers Renovate hosted-app mode, Dependabot security-updates-only, and disciplined manual updates. When any row is `Missing` / `Partial`, MF-NNN candidates are written to `.sca-practice-findings.json` with severity scaled by `asset_tier` via `data/sca-practice-severity.yaml`.
- `scripts/emit_known_bad_libs.py` — matches manifest dependencies against `data/known-bad-libs.yaml` (curated 30-entry initial list across npm / pip / go / maven / gem / composer; track-record framing — abandoned, protestware incidents, unfixed critical CVEs, sandboxed-deprecated). Each hit emits an MF-NNN architectural-choice finding routed to §7.11. Names are keyed by `(ecosystem, package)` tuple — `request` (npm) does not collide with `requests` (python). Severity capped by asset tier.

A single derived **patch-management posture** row is rendered in §7.13 Defense-in-Depth Summary as the worst-of-three across the new control rows.

**Migration / hard-removal:**

- `--with-sca` / `--no-sca` CLI flags: **hard-removed**. argparse rejects the flag with an error; users must drop it from their invocations. No deprecation alias.
- Org-profile `with_sca: true|false`: **hard-removed** from the schema. `additionalProperties: false` rejects org-profiles that still carry the field — they must be updated to drop the `with_sca` line. Supply-chain posture is always produced now; there is no opt-in/opt-out.
- Persisted threats with `source: dep-scan` are no longer valid — the source enum value was removed from `schemas/threats-merged.schema.yaml`. The first run after migration produces a one-time `_resolved` / `_new` cohort shift in the incremental delta: old dep-scan T-IDs disappear; SCA posture appears as MF-NNNs and §7.11 rows.
- SARIF rule-IDs that previously carried `source: dep-scan` no longer emit; downstream consumers (GitHub Security tab, DefectDojo, …) will see those rules close. Acceptable because users were already running dedicated SCA tooling in CI for the per-CVE coverage.

**Files removed (since 2026-05-28):**

- `scripts/dep_scan.py`
- `data/dep-scan-heuristics.yaml`
- `schemas/dep-scan.schema.yaml`
- `tests/test_dep_scan.py` + `tests/fixtures/dep_scan_error_stub.json` + `tests/fixtures/valid_dep_scan.json`
- `tests/fixtures/e2e/frozen-run/.dep-scan.json`
- Phase 2 Step 2 background dep-scan launch (`phase-group-recon.md`)
- Phase 9 STRIDE-Merge `known_vulns_seen` dedup index (no longer needed — no CVE-shaped feed to dedup against)

**Files added:**

- `data/sca-practice-severity.yaml`
- `data/known-bad-libs.yaml`
- `scripts/_lib_manifest.py`
- `scripts/emit_sca_practice.py`
- `scripts/emit_known_bad_libs.py`
- `scripts/emit_dep_update_activity.py`

**Renovate parity (related):** `data/config-iac-checks.yaml` ships three Renovate config-detection rules (IAC-033 / IAC-034 / IAC-035) covering `renovate.json`, `.github/renovate.json`, and `.renovaterc.json`. Renovate is now first-class peer of Dependabot for the auto-updates indicator. Hosted-app mode (no file in repo) remains a known false-negative — flagged in the IAC rule's `rationale`.

See `sca.md` for the full scope rationale and design proposal that motivated this change.

---

**TodoWrite subjects: em-dash → hyphen-minus.** The six top-level stage subjects (`Preparing workspace`, `Stage 1 - Threat Analysis and Triage`, `Stage 2 - Report Rendering`, `Stage 3 - QA Review`, `Stage 4 - Architect Review`, `Final summary + cleanup`) now use hyphen-minus (`-`) instead of em-dash (`—`). The Claude Code TodoWrite TUI renderer mis-handles the em-dash's UTF-8 width (1 column / 3 bytes) on partial redraws, causing adjacent task labels to bleed together (observed: `Final summary` + `Stage 3 — QA Review` rendered as `Final 3ummQA Review`). Section headers and prose in `SKILL-impl.md` keep em-dashes where rendering is unaffected.

> **Version reset.** Internal dev tagging ran up to 0.9.x during private
> development. The first public release is published as `0.4.0-beta` to
> better reflect actual maturity. Versions 0.5.x–0.9.x existed only in
> internal development and were never publicly released. Subsequent
> releases follow normal SemVer.

### Actor Layer (Phase 2.7, org-profile v2, §1.5 Actor table)

New actor modeling layer adds structured threat-actor attribution to every finding.

**`api_version: appsec-advisor.org-profile/v2`** — additive extension. v1 profiles are auto-upgraded on load with an `info` notice in run-issues.json; no manual migration required. Adds an `actors:` block with `inherit_defaults`, `disable` (with required `disable_reason`), and `add` (glob to actor definition files).

**Default actor library** (`data/actors/default-library.yaml`) — nine threat actor classes (ACT-D-01 through ACT-D-09) ship with the plugin and activate automatically from recon signals (no configuration required):

| ID | Label | Typical activation |
|---|---|---|
| ACT-D-01 | anonymous-internet-attacker | has_public_routes |
| ACT-D-02 | authenticated-low-priv-user | has_auth_surface |
| ACT-D-03 | authenticated-high-priv-user | has_role_concept |
| ACT-D-04 | malicious-insider-dev | has_secrets_in_repo or has_ci_pipeline |
| ACT-D-05 | malicious-insider-ops | has_ci_pipeline |
| ACT-D-06 | supply-chain-attacker | has_ci_pipeline |
| ACT-D-07 | compromised-third-party-service | has_external_apis |
| ACT-D-08 | physical-device-holder | has_client_storage |
| ACT-D-09 | tenant-from-adjacent-tenancy | has_multi_tenancy_signal (two-signal) |

**New pipeline phase: Phase 2.7 — Actor Layer Resolution & Discovery** — runs between config-iac-scan (Phase 2.5) and architecture modeling (Phase 3). Resolves four actor layers (plugin → enterprise → repo → LLM-discovery) and writes `.actors-resolved.json`. Quick-mode skips LLM discovery; static layers remain active.

**Per-finding actor attribution** — every finding now carries `actor_ids[]`, `primary_actor`, and `actor_adjusted_likelihood`. Primary actor is selected by argmax adjusted likelihood; reach-equivalence collapses ACT-D-01 and ACT-D-02 when open self-registration is detected.

**New report section §1.5 — Identified Actors** — table of all active actors per run including layer, status, finding counts, and relevant components. Proposed actors from discovery appear in a "please confirm" sub-section.

**Architect review Check 15 — Actor Coverage** — five sub-checks validate activated-but-unused actors, disabled-without-rationale actors, components without actor attribution, discovery proposals without findings, and unreviewed `inputs_questioned` flags.

**New scripts:** `scripts/resolve_actors.py`, `scripts/slice_actors.py`.

**New agent:** `agents/appsec-actor-discoverer.md` (Phase 2.7 LLM-discovery step).

**Heatmap slug mapping** (`data/actor-id-to-heatmap-slug.yaml`) — maps ACT-D-* IDs to the six existing §0/§1 display slugs. Custom actors use an optional `heatmap_slug:` field; missing slug falls back to `internet-user` with a run-issue (`actor_missing_heatmap_slug`, severity info).

**Repo-layer overrides:** `<repo>/.appsec/actors.yaml` now honors `inherit_org: false` (excludes enterprise actors with an `info` run-issue), accepts `disable:` as either a flat ID list or `{id, reason}` objects (missing `disable_reason` emits a `defect` run-issue per actors.md §6/§7), and exposes `renamed_from` aliases through `_provenance.aliases` plus a top-level `alias_map` in `.actors-resolved.json`.

**Incremental cache fingerprint:** `scripts/resolve_actors.py` now writes `.actor-fingerprints.json` with `actors_inputs_fingerprint` (sha256 over plugin default-library + enterprise actor files + repo `.appsec/actors.yaml`). Re-runs without input drift produce identical fingerprints; any input file edit flips the fingerprint — foundation for the §13 incremental scan behaviour.

**Discovery cache key — five-input composition (actors.md §8):** Phase 2.7 Step 2 now hashes recon-summary + config-scan + `actors_inputs_fingerprint` + sha(discoverer agent file) + explicit `DISCOVERY_PROMPT_VERSION` semver marker. Bumping any of the five invalidates the discovery cache and forces re-discovery on the next run.

**Default-library audit visibility (Done-criterion #1):** plugin-layer actors that fail their activation conditions now emit `default_actor_skipped` info run-issues with the missing signal name, so no default class disappears silently between runs.

**§1.5 Identified Actors report section (actors.md §14):** new `identified_actors` section rendered between §1 System Overview and §2 Architecture Diagrams. Computed from `.actors-resolved.json` + `threat-model.yaml.threats[].actor_ids[]` — table of every active actor with layer, status, finding count, and per-component relevance. Sub-sections for proposed (discovery), inputs-questioned (flag-for-review), disabled (with rationale), and dormant findings. Conditional on `has_resolved_actors`; legacy / pre-Phase-2.7 runs gracefully skip. Sections contract bumped to `contract_version: 4`.

**§8 Threat Register Actor column + obsolete/dormant markers (actors.md §10):** `_render_threat_register` adds an Actor column between Component and Criticality. Each row shows `primary_actor` (link to §1.5) plus a `<sub>+N</sub>` badge when more than one actor was tagged. Findings whose `actor_ids` list is empty render `_[obsolete-actor]_`; findings with `_status: dormant` render `_dormant_` (stable-ID guarantee, cases 2 & 3).

**Threat schema hardening:** `schemas/threat-model.output.schema.yaml` now declares the actor fields explicitly (`actor_ids`, `primary_actor`, `base_likelihood`, `actor_adjusted_likelihood`, `_status`) with `ACT-[A-Z]-\d+` pattern enforcement and `_status` enum constrained to `[active, dormant, null]`. STRIDE outputs that previously slipped through `additionalProperties: true` now validate explicitly.

**Per-component slice-diff STRIDE re-dispatch (actors.md §13):** `baseline_state.py` now hashes `.actors-for-*.json` into `baseline.json.slice_files`. `phase-group-threats.md` and `appsec-threat-analyst.md` extend the incremental decision tree with a 5th condition: components whose actor slice changed are re-dispatched even when no code diff exists — pure actor-input edits now trigger surgical per-component STRIDE re-runs instead of either full-scan or stale carry-forward.

> **Note:** the §13 edge-case "split `profile_fingerprint` into core+actors" is already addressed: actor files were never part of `profile_fingerprint` (it covers only the profile YAML and `llm_context_documents`), so `actors_inputs_fingerprint` (new in this release) is the de-facto independent actor fingerprint the spec asks for.

### Triage validator downgraded from Opus to Sonnet at `opus-cheap`

`MODEL_MATRIX["opus-cheap"]["triage"]` is now `claude-sonnet-4-6` (was
`claude-opus-4-7`). Rationale: `scripts/triage_validate_ratings.py`
provides the deterministic floor (outlier thresholds, completeness
counts, CVSS eligibility, P1/P2 prioritisation rules) — the agent only
does judgment-call validation on top of structured input. Opus
reasoning here was overkill.

Merger stays on Opus (semantic dedup decisions benefit from deeper
reasoning). Triage still lifts to Opus at `--reasoning-model opus`.

Cost impact: at default `standard` / `thorough` runs, triage tokens
shift from Opus pricing to Sonnet pricing. `_MODEL_FACTOR["opus-cheap"]`
in `scripts/estimate_duration.py` lowered from 1.10 → 1.05.

### Documentation: flat stage numbering

The intermediate "Stage 1b" label was a migration artifact from the
M2.12 Phase-11 split — it implied a sub-relationship to Stage 1 that
did not exist operationally (Composition has its own task entry,
turn budget, dispatch, and retry loop). Renamed to a flat sequence:

| old | new |
|-----|-----|
| Stage 1 — Threat Model Orchestrator (Phases 1–10b) | unchanged |
| Stage 1b — Composition (Phase 11) | **Stage 2 — Composition (Phase 11)** |
| Stage 2 — QA Review | **Stage 3 — QA Review** |
| Stage 3 — Architect Review | **Stage 4 — Architect Review** |

The user-facing pipeline is now four numbered stages with no `b`
suffix. Internal env vars (`STAGE1_PHASE_LIMIT`) and state files
(`.stage1-resume-count`) keep their names — they belong to Stage 1,
which did not move. CHANGELOG entries for M2.12 and M2.13 retain
their original "Stage 1b" wording as historical record.

Test file renamed: `tests/test_skill_stage1b.py` →
`tests/test_skill_composition_split.py`.

### User-facing stage labels

The visible stage/task labels were tightened up to read like a pipeline rather
than an implementation detail dump:

| old | new |
|-----|-----|
| Pre-flight intermediate wipe | **Preparing workspace** |
| Stage 1 — Threat Model Orchestrator (Phases 1–10b) | **Stage 1 — Threat Analysis & Triage** |
| Stage 2 — Composition (Phase 11) | **Stage 2 — Report Rendering** |
| Completion summary + cleanup | **Final summary + cleanup** |

This rename is intentionally user-facing only. Internal runtime contracts
remain unchanged: `STAGE1_PHASE_LIMIT=10b`, `phase=10b status=completed
need_render=true`, `Phase-10b precondition gate`, `Phase 10b Triage
Validation`, and `Phase 11 Finalization`.

### Stage-D contract enforcement (M2.9 – M2.13)

The 2026-04-25 juice-shop Run 4 incident exposed that a single Sonnet
orchestrator session, under Phase-11 turn-budget pressure, can quietly
take an "inline-shortcut": skipping the fragment renderer and hand-
authoring `threat-model.md` directly. The result was a 90 KB document
missing the Security Posture at a Glance heatmap, with a broken TOC,
untitled multi-link cells, and inconsistent mitigation grouping. Worse,
the skill body's Bash detector was loose enough that the LLM executor
interpreted the gate trip as a "soft warning" and continued into Stage 2.

Stage-D closes that whole class of failures with five coordinated changes:

### M2.9 — Bump orchestrator `maxTurns` from 75 to 120

`agents/appsec-threat-analyst.md` — same rationale as the QA-reviewer
M2.8 bump: Phase 11 (write 12 fragments + compose + qa_checks +
placeholder-patch) is the dominant turn consumer. 120 turns gives ~50%
headroom, which empirically eliminates the inline-shortcut attempt
under normal load. Test ceiling raised from 80 to 120 in
`tests/test_agent_definitions.py`.

### M2.10 — Hard inline-shortcut gate as standalone script

New `scripts/check_inline_shortcut.py` (218 lines) replaces the old
~50-line inline Bash detector in `SKILL-impl.md`. The script:

- Re-uses `qa_checks.py fragments` as one indicator (REQUIRED_FRAGMENTS
  list stays the source of truth).
- Adds three skill-level indicators (A1: dir missing; A2: dir present
  but `< MIN_FRAGMENTS`; B: `.threats-merged.json` missing while MD
  exists; C: `.triage-flags.json` missing at standard+ depth).
- Prints the canonical inline-shortcut banner to stderr and exits 2.
- Optional `--write-repair-plan` writes
  `.inline-shortcut-repair-plan.json` for the auto-retry consumer.

Skill body now invokes it with `|| { … exit }` — the Bash short-circuit
is impossible to "soft-interpret" away. 14 unit tests pin the exit
codes, banner contents, and repair-plan schema.

### M2.11 — Deterministic pre-generation of structural fragments

New `scripts/pregenerate_fragments.py` (~400 lines) generates 6 of the
8 REQUIRED_FRAGMENTS deterministically from `threat-model.yaml` and the
Phase-3-8 outputs:

- `system-overview.md` (project meta + components prose)
- `architecture-diagrams.md` (4 sub-sections + 3 Mermaid blocks)
- `assets.md` (asset table)
- `attack-surface.md` (5.1 unauthenticated + 5.2 authenticated)
- `security-architecture.md` (all 14 sub-sections, populated from
  `security_controls[]`)
- `out-of-scope.md` (from `meta.scope.out_of_scope` or default)

Idempotent: never overwrites an LLM-authored fragment. Wired into
`SKILL-impl.md` to run before the hard gate. Reduces Phase-11 LLM load
to just 4 qualitative fragments (`ms-verdict.json`,
`ms-architecture-assessment.json`, optionally `attack-walkthroughs.md`
and `security-posture-attack-paths.json`). 37 unit tests cover every
generator + the CLI driver flags (`--force`, `--only`, `--dry-run`).

### M2.12 — Always-on Stage 1b (Phase-11 split)

Phase 11 used to share the orchestrator's turn budget with Phases 1–10.
Now `STAGE1_PHASE_LIMIT=10b` makes Stage 1 stop cleanly after Phase 10b
(`agents/appsec-threat-analyst.md` new branch), and the skill always
dispatches a separate `Stage 1b — Composition` agent with `RENDER_ONLY=true`
and a fresh 120-turn budget. Stage 1b authors only the 2 mandatory LLM
fragments, then runs `compose_threat_model.py --strict` +
`render_completion_summary.py --patch-placeholders` + `qa_checks.py all`.

The Stage 1b task is pre-created in the bootstrap (no longer a
recovery-only conditional). 14 doc-drift tests in
`tests/test_skill_stage1b.py` keep the contract internally consistent
across `SKILL-impl.md` and the orchestrator agent.

### M2.13 — Auto-Retry Loop on hard-gate trip

If `check_inline_shortcut.py` returns exit 2 (despite M2.9–M2.12
reducing the probability), the skill enters a recovery loop with
`MAX_INLINE_RETRIES=2`. Each iteration:

1. Recovery sequence — best-effort reconstruction of any missing
   Phase-9/10b artefacts:
   - `merge_threats.py collect` → `merge_threats.py finalize` if
     `.threats-merged.json` is missing and `.stride-*.json` exist.
   - `triage_validate_ratings.py` if `.triage-flags.json` is missing.
   - `pregenerate_fragments.py` (idempotent) for any structural gaps.
2. Re-dispatch Stage 1b (`RENDER_ONLY=true`) with a fresh 120-turn
   budget.
3. Re-run the hard gate.

Exit conditions: gate passes → break, proceed to Stage 2. Counter
exhausted → exhausted-retries banner + exit 2 (preserves repair plan
on disk for inspection). Counter file (`.inline-shortcut-retry-count`)
is reaped on success via `runtime_cleanup.py POST_QA_FILES_IF_PASS`.
23 tests in `tests/test_skill_auto_retry.py` cover the loop contract,
recovery scripts, and runtime-cleanup integration.

### Cumulative effect

Compliance posture is now: **compliant or at most 2× retry — failing
that, hard exit 2 with the repair plan preserved on disk for manual
inspection**. At normal repo sizes (≤8 components) the expected success
rate without any manual intervention is ~99%. No malformed threat
model is ever persisted to `docs/security/`.

### M2.14 — Composition observability (Sprint 6)

Stage-D guarantees compliance, but a successful run could still hide
non-blocking issues from the user — soft warnings, internal compose
retries, or a single auto-retry-loop firing all collapse into "it
worked" with no trail. Sprint 6 closes that observability gap by
persisting composition health in three coordinated places:

1. **`scripts/compose_threat_model.py` writes `.compose-stats.json`**
   on every successful render. Records soft warnings (categorized via a
   heuristic mapper), per-section compose-retry counts (read from the
   pre-render repair plan before deletion), and a clean/warned status
   flag. Schema-versioned for forward compatibility.

2. **`## Appendix: Composition Notes` is added to threat-model.md** —
   a new conditional section in `data/sections-contract.yaml` between
   Run Statistics and Vektor Taxonomy. Only emitted when the
   `compose_warned` eval-context flag is True (any of: `.compose-stats.json`
   shows non-clean status, or `.inline-shortcut-retry-count > 0`). When
   present, lists soft warnings as a table, section retries as a table,
   and skill-level auto-retry events as bullets. The MD-embedded form is
   the canonical persistence — it survives `runtime_cleanup`, git commits,
   and PR reviews.

3. **`-- Composition Health --` block in the completion summary** —
   `render_completion_summary.py` reads the same sources and emits a
   conditional CLI block between Run Statistics and Next Steps. Shows
   warnings/retries/auto-retries with up to 2 inline warning previews
   plus a pointer to the MD appendix for the full picture.

When the pipeline runs cleanly (default case), all three artefacts are
either absent (`.compose-stats.json`) or omitted (the MD appendix and
the CLI block) — no extra noise on successful runs.

`runtime_cleanup.py` reaps `.compose-stats.json` along with the other
QA bookkeeping at successful completion.

### M2.15 — Run Issues + auto-fix engine (Sprint 7)

Sprint 6 made the composition pipeline transparent. Sprint 7 extends the
same pattern to the **whole run**: errors, warnings, performance
anomalies, and recovery events from `.agent-run.log` and
`.hook-events.log` are now aggregated, classified, paired with
structured fix recommendations, and exposed via three coordinated
surfaces. A new user-facing skill applies auto-eligible fixes
non-interactively after confirmation.

The 2026-04-25 juice-shop runaway (Phase 1 ran 8 hours, cost $51, no
visible alarm) was the canonical motivating incident — Sprint 7 ensures
that class of issue is impossible to miss in any future run.

1. **`scripts/aggregate_run_issues.py`** parses the three log files plus
   `.compose-stats.json` and `.inline-shortcut-retry-count`. Produces
   `.run-issues.json` with categorized issues:
     * `error` (TOOL_ERROR, MAX_TURNS, RENDER_FAILED)
     * `warning` (BASH_WARN, SESSION_STOP with reason=unknown,
       high-token-usage)
     * `perf_anomaly` (phase wall-time exceeds depth-specific limit;
       hard ceiling 30 min flagged regardless of depth)
     * `recovery_event` (auto-retry firings, compose section retries)
   Tolerant against missing PHASE_END events (uses next PHASE_START as
   approximate end timestamp).

2. **`scripts/recommend_fixes.py`** reads `.run-issues.json` and adds a
   structured `fix_recommendation` per issue:
   ```
   category         agent_def | config_tune | yaml_edit | skill_spec
                    | user_action | rerun | investigate | no_fix
   auto_applicable  bool — only True for well-bounded changes
   confidence       high | medium | low
   risk_level       low | medium | high
   summary          one-line description
   rationale        why this fix is recommended
   actions          ordered list of {type, target, find, replace}
   verification     commands to run after applying (e.g. pytest)
   ```
   Per-category recommenders implement the fix logic; unknown categories
   get a default `investigate` recommendation rather than being dropped.

3. **`## Appendix: Run Issues` in threat-model.md** (conditional, only
   when `run_warned` eval-context flag is True) — groups issues by
   severity, lists each with evidence, fix category, summary, rationale,
   actions, and verification commands. Auto-applicable fixes carry a
   `✓ auto-applicable` badge with a pointer to the fix-skill.

4. **`-- Run Issues --` block in completion summary** (conditional) —
   shows counts, top 2 issues, and an "Apply fixes" pointer when at
   least one auto-fix is ready.

5. **New skill `/appsec-advisor:fix-run-issues`** — reads
   `.run-issues.json`, presents each issue interactively (or with
   `--yes` non-interactively), applies auto-eligible `edit_file` actions
   via the Edit tool, runs the `verification` commands, and persists an
   audit trail in `.run-issues-fixes.json`. Hard safety rails:
     * Never applies non-`auto_applicable` or non-`high`-confidence fixes.
     * Never modifies `threat-model.md`, `threat-model.yaml`, or anything
       outside `$CLAUDE_PLUGIN_ROOT`.
     * Rate limits to max 5 auto-fixes per invocation.
     * Verification failure marks fix as `applied_with_verification_failure`.

Initial auto-applicable category: **`agent_def`** (bumping `<agent>.md`
maxTurns by 50% on first MAX_TURNS event, mirroring the M2.8/M2.9
manual fixes). Additional categories are opt-in as patterns prove safe
through repeated production runs.

`runtime_cleanup.py` reaps `.run-issues.json` and `.run-issues-fixes.json`
on successful completion — the canonical persistence is the §Run Issues
appendix in `threat-model.md`.

### First public release foundation

Works well enough for guided use; not yet something I'd leave unattended
in CI overnight.

- New `publish-threat-model` skill so reports don't get committed by accident.
- Multi-repo scanning (`--repo`, `--output`).
- `docs/related-repos.yaml` pulls upstream findings into STRIDE at trust boundaries.
- Headless runner for CI (`scripts/run-headless.sh`).
- Incremental mode with a noise-only fast path — docs/IDE-only changes exit immediately.
- Triage validator split: steps 1–5 are plain Python now, only ranking stays on the LLM.
  Cut triage cost by ~10x.
- Architect reviewer (Opus, advisory only) auto-runs at `--assessment-depth thorough`.
- QA reviewer with a bounded repair loop (max 3 iterations).
- SARIF v2.1.0 and pentest-task export.
- Prompt-caching contract for Phase 9 dispatches — stable payload first, volatile last.
- Schema/contract enforcement on every intermediate artefact.
- Default reasoning model is now `opus-cheap` (Opus for triage + merger, Sonnet for the rest).
- Rendering went single-source: agents emit fragments, `compose_threat_model.py` writes the report.

### Known issues

- `appsec-config-scanner` is defined but not wired up yet. Will either land
  as Phase 2.5 or be removed before 1.0.
- On a fresh install, run `/appsec-advisor:check-permissions --update` once.
  Otherwise the first assessment will stop every 30 seconds for a permission prompt.
- No full-pipeline E2E test in CI yet. Unit coverage is fine.
