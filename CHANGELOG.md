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

### Changed

- QA re-render is now a single quick-fix pass at `quick`/`standard` depth (was up
  to 3 rounds). One repair attempt, then fail-closed if the contract still does
  not hold — never ships an invalid report. `thorough` keeps the 3-round budget.
- QA re-render no longer triggers on cosmetic-only findings (diagram/chain
  compactness, walkthrough depth, list shape, recon hints). They're reported as
  advisories instead. Real defects — broken diagrams, missing sections, §7 drift,
  wrong T-ID references — still re-render. Set `APPSEC_QA_COSMETIC_BLOCKING=1` for
  the old behaviour.
- Threat reasoning defaults to Opus at `standard` and `thorough` depth (`quick`
  stays on Sonnet). Opt out with `--reasoning-model sonnet-economy`. Note: the
  quality/cost payoff isn't validated yet, and earlier runs showed STRIDE
  falling back to Sonnet despite the default — a `stride_model_mismatch` run-issue
  now flags that case.
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
