# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

- `--stride-cap N` — cap of N threats per STRIDE category per component.
  Critical-safe (Criticals never dropped); trims only the High/Medium/Low tail.
  Off by default.
- `--stride-model` / `--triage-model` / `--merger-model` (`sonnet`|`opus`) —
  inline per-stage model overrides; `--no-opus` still clamps last. Cheap-but-
  calibrated `standard` combo: `--reasoning-model sonnet-economy --triage-model opus`.
- Context-window problems are now logged for later analysis: a pre-flight warning
  when the session is too large (cached-token bloat) and an unclean mid-run abort.
  Both show in `/appsec-advisor:status --live`.
- Reports record the exact invocation (full flags) and reasoning tier, so a report
  states how it was produced and how to reproduce it.

### Changed

- Pre-flight is clearer about scope and cost: it lists which components get a
  STRIDE pass and which are skipped (with reason), always shows the STRIDE cap
  (or "full depth"), surfaces abuse-case verification when toggled, and on
  `standard` runs hints that `thorough` digs deeper at higher cost.
- `--rebuild` now reports only what it actually wiped; a first-ever rebuild says
  "nothing to discard" instead of listing files and caches that never existed.
- Component selection no longer drops high-risk components: AI/LLM is mandatory at
  every depth, file-upload and real-time/WebSocket components at `standard`+, and
  internet-facing detection now matches the exposure terms the analysis emits.
- AI/LLM detection is deterministic (pattern-based), so a plain `openai` chatbot is
  reliably detected and gets its OWASP LLM Top-10 pass.
- Threat reasoning defaults to `sonnet-economy` at `quick`/`standard` (cheaper, no
  measured quality loss); only `thorough` defaults to Opus. Opt in with
  `--reasoning-model opus` or just `--triage-model opus`.
- Repository size is informational only — it no longer forces a cheaper model.
- QA re-render is a single quick-fix pass at `quick`/`standard`, fail-closed if the
  report is still invalid; `thorough` keeps 3 rounds. Cosmetic-only findings no
  longer trigger a re-render (reported as advisories); `APPSEC_QA_COSMETIC_BLOCKING=1`
  restores the old behaviour.
- Lower pre-flight context use: the orchestrator lazy-loads the Stage 2+ and
  rebuild/incremental parts of its playbook instead of reading everything up front,
  avoiding the auto-compaction that previously fired before STRIDE.

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
