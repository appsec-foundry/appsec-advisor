# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

- `--stride-cap N` — opt-in cost lever that keeps at most N threats per STRIDE
  category per component. Critical-safe (Criticals are never dropped); trims only
  the High/Medium/Low tail while keeping full depth (CVSS, evidence, verification
  greps). Off by default — `standard`/`thorough` keep full STRIDE depth. The cap
  is disclosed in the report's Run Statistics appendix.
- `--stride-model` / `--triage-model` / `--merger-model` (`sonnet`|`opus`) —
  per-stage model overrides settable inline on the command line (the equivalent
  of the `APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL` env vars, but without
  `settings.json` + a session restart). They win over the tier and the env vars;
  `--no-opus` still clamps Opus→Sonnet last. The sweet spot for a cheap-but-
  calibrated `standard` run is `--reasoning-model sonnet-economy --triage-model opus`
  (Sonnet STRIDE, Opus triage). The resolved per-stage mix is recorded in the
  report's Run Statistics (`Reasoning models` row).
- Report Run Statistics now records the **exact invocation** (the full
  `create-threat-model` flags) and names the **reasoning tier** alongside the
  per-stage models, so a report states precisely what parameterization produced
  it and how to reproduce it. Persisted to `meta.invocation` (survives runtime
  cleanup); falls back to `.skill-config.json` for older runs.

### Changed

- The console now shows which components get a STRIDE pass and which are skipped
  (each with its reason — e.g. `out-of-scope at depth=standard`) right before the
  analysis fans out, mirroring the report's §1 Scope and §11 Out of Scope. Re-render it
  any time with `build_stride_dispatch_manifest.py --print-selection <output-dir>`.
- The console run-plan now adds a short hint on `standard` runs that
  `--assessment-depth thorough` may surface more (deeper per-component analysis +
  architect review, Opus reasoning) at higher cost and time. Always shown at
  standard depth (including no-op reruns); not on quick/thorough.
- Component selection no longer silently drops high-risk components. Three fixes:
  (1) AI/LLM components are now a mandatory role at every depth — a chatbot tagged as an
  internal zone used to be dropped ("out-of-scope at depth=standard"), skipping its OWASP
  LLM Top-10 pass and leaving prompt-injection / excessive-agency / prompt-leakage
  uncovered. (2) The exposed-zone vocabulary now matches the synonyms the analysis actually
  emits (`internet-facing`, `external`, `public`, `browser`, …), not just `internet` — so
  genuinely internet-facing services (a Socket.IO channel, a file-upload handler) are no
  longer mis-classified as internal and shed. (3) File-upload/parser and real-time/WebSocket
  components are now mandatory at standard+ regardless of zone (upload CWE-434 / zip-path
  traversal / XXE, and channel injection/authz). On Juice Shop this took standard-depth
  coverage from 7 components to all 10, with nothing dropped.
- AI/LLM detection is now deterministic. The `### AI / LLM Exposure` report section was
  driven by an LLM grep that needed a full agentic RAG stack to fire and could be skipped
  under load; it now comes from `recon_patterns.py` and triggers on any real SDK, framework,
  vector DB, or model id (and on SDK-less integrations that co-locate a prompt with model
  config). A plain `openai` chatbot is now reliably detected.
- The orchestrator no longer reads the whole `SKILL-impl.md` up front. The initial load
  now stops at a lazy-load boundary after Stage 1; the Stage 2/3/4/Completion tail (~30k
  tokens) is read just-in-time at the Stage-2 handoff. This drops the context window at
  pre-flight from ~77% to ~62% and avoids the auto-compaction that previously fired right
  before the STRIDE dispatch.
- Trimmed the orchestrator's resident context: the rebuild-wipe and auto-incremental
  full-scan-recommendation branches now lazy-load from `modes/*.md` only when their
  mode runs, instead of sitting inline in the always-read `SKILL-impl.md`. A standard
  or full scan no longer carries those incremental/rebuild-only branches in context.
- QA re-render is now a single quick-fix pass at `quick`/`standard` depth (was up
  to 3 rounds). One repair attempt, then fail-closed if the contract still does
  not hold — never ships an invalid report. `thorough` keeps the 3-round budget.
- QA re-render no longer triggers on cosmetic-only findings (diagram/chain
  compactness, walkthrough depth, list shape, recon hints). They're reported as
  advisories instead. Real defects — broken diagrams, missing sections, §7 drift,
  wrong T-ID references — still re-render. Set `APPSEC_QA_COSMETIC_BLOCKING=1` for
  the old behaviour.
- Threat reasoning now defaults to `sonnet-economy` at `standard` (and `quick`);
  only `thorough` defaults to Opus. A clean A/B (Juice Shop, 2026-06-23) found
  Opus reasoning ~$10.77 (+36 %) more expensive than sonnet-economy with no
  measurable quality or coverage gain — the earlier "Opus is cheaper/better for
  STRIDE" rationale was refuted (Opus-STRIDE never actually ran in the
  measurements behind it; the cost-inversion was an Opus-triage/merger artifact).
  Opt into Opus at standard with `--reasoning-model opus`, or upgrade only the
  severity stage with `--triage-model opus`. (Supersedes the earlier
  Opus-default-at-standard change from this same Unreleased cycle.)
- Dropped the large-repo reasoning auto-downgrade. Repository size is now
  informational only; it no longer forces a cheaper model.

## 0.4.0-beta — 2026-06-19

First public release. (Internal development reached 0.9.x; the public release
resets to 0.4.0-beta to reflect real-world maturity. Future releases follow
SemVer.) This is a beta — it works well for guided use, but isn't something to
leave running unattended in CI yet.

### Threat modeling

- Generate a STRIDE threat model straight from a Git repository: architecture
  model, trust boundaries, risk-ranked findings, affected components,
  remediation guidance, and diagrams. Run with
  `/appsec-advisor:create-threat-model`.
- Pick the depth — `quick`, `standard`, or `thorough`. The components analyzed
  follow the repository's attack surface rather than a fixed limit.
- **Threat-actor attribution** — every finding is tied to the actors who could
  realistically reach it (anonymous internet user, low-privilege user,
  malicious insider, supply-chain attacker, …), activated automatically from
  what the scan finds in the repo.
- **Abuse cases** — a report section that chains individual findings into
  end-to-end attack scenarios and marks each as viable, partially blocked, or
  mitigated, based on what the code actually allows.
- **Incremental scans** — re-running after a change only re-analyzes what
  changed; docs- or IDE-only edits finish almost instantly.

### Giving the analysis context

- `docs/business-context.md` — state what the code can't show: revenue-critical
  flows, regulatory drivers, crown-jewel data. Findings are weighted
  accordingly.
- `docs/known-threats.yaml` — prior pentest findings and accepted risks the
  scan re-checks on every run.
- `docs/related-repos.yaml` — pull a called service's threat model in as
  context at the trust boundary.
- Organization profiles — set company-wide actors, abuse cases, requirements
  catalog, and risk tiers once, centrally.

### Output & integration

- Reports in Markdown and YAML, with optional PDF, HTML, SARIF (for
  code-scanning dashboards), and pentest task lists.
- Headless CI runs with hard time and cost budgets.
- Grade a repository against a security-requirements catalog as a faster,
  standalone check (`/appsec-advisor:audit-security-requirements`).
- `/appsec-advisor:publish-threat-model` to commit a reviewed report
  deliberately — reports are git-ignored by default, since they contain
  vulnerability detail.

### Supply chain

Supply-chain risk is reported as architectural posture — whether the project
runs SCA scanning, keeps dependencies updated, and keeps lockfiles clean —
rather than per-CVE findings. The scan stays fully passive (no package-manager
or network calls); use a dedicated tool (Dependabot, Snyk, Trivy, OSV-Scanner)
for CVE-level coverage.

### Known limitations

- On first install, run `/appsec-advisor:check-permissions --update` once to
  avoid repeated permission prompts during a scan.
- Large repositories (beyond ~8–10 analyzed components) are slower and
  costlier; the scan still covers them but isn't parallelized yet.
- No full end-to-end pipeline test in CI yet.
