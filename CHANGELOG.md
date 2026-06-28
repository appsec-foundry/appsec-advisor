# Changelog

All notable changes to this project are documented here.

## 0.4.0-beta — 2026-06-28

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
  follow the repository's attack surface rather than a fixed limit, and
  high-risk components are never dropped: AI/LLM at every depth, file-upload and
  real-time/WebSocket at `standard`+.
- Tune cost against depth. `--stride-cap N` caps findings per STRIDE category
  per component (Critical-safe — Criticals are never dropped, only the
  High/Medium/Low tail is trimmed). Threat reasoning defaults to the cheaper
  `sonnet-economy` core at `quick`/`standard` (no measured quality loss) and
  Opus at `thorough`; override per stage with `--reasoning-model`,
  `--stride-model`, `--triage-model`, or `--merger-model` (`--no-opus` clamps
  last).
- AI/LLM detection is deterministic (pattern-based), so a plain `openai`
  chatbot is reliably detected and gets its OWASP LLM Top-10 pass.
- **Threat-actor attribution** — every finding is tied to the actors who could
  realistically reach it (anonymous internet user, low-privilege user,
  malicious insider, supply-chain attacker, …), activated automatically from
  what the scan finds in the repo.
- **Abuse cases** — a report section that chains individual findings into
  end-to-end attack scenarios and marks each as viable, partially blocked, or
  mitigated, based on what the code actually allows.
- **Incremental scans** — re-running after a change only re-analyzes what
  changed; docs- or IDE-only edits finish almost instantly, and re-scanning
  unchanged code reports "no changes since the previous run" instead of churning
  the register from run-to-run analysis variance.

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
- Every report records the exact invocation (full flags) and reasoning tier, so
  it states how it was produced and how to reproduce it.
- A full change-log audit ships beside the report — `threat-model-changelog.md`
  (readable) and `threat-model-changelog.jsonl` (machine) — listing every
  added, changed, and removed finding, mitigation, abuse case, instance, and
  component, uncapped (unlike the summarized Change Log inside the report).
  `--rebuild` archives the prior pair into `changelog-history/`.
- Pre-flight states scope and cost up front: which components get a STRIDE pass
  and which are skipped (with reason), the active STRIDE cap (or "full depth"),
  and whether abuse-case verification is on; `--rebuild` reports only what it
  actually wiped.
- Report validity is gated automatically — a QA re-render pass (a single
  quick-fix pass at `quick`/`standard`, fail-closed if the report is still
  invalid; up to three rounds at `thorough`), with cosmetic-only findings
  reported as advisories rather than forcing a re-render.
- Context-window issues are surfaced for later analysis: a pre-flight warning
  when the session is too large (cached-token bloat) and a flag on any unclean
  mid-run abort, both visible in `/appsec-advisor:status --live`.
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
  costlier; the scan still covers them but isn't parallelized yet. Repository
  size is informational only — it never forces a cheaper model.
- A manual full-run E2E validates the complete QA/schema/export chain against a
  clean code fixture and an external planted-vulnerability oracle (standard and
  thorough targets cover Stage 3 and Stage 4), but it isn't wired into CI yet.
- An opt-in deterministic pre-flight and thin runtime
  (`APPSEC_THIN_ORCHESTRATOR=1`) cuts the live pre-Stage-2 playbook by about
  64%; the compatibility path remains the default until parity runs pass.
