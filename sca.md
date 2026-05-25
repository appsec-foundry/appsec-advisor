# SCA Scope in appsec-advisor — Analysis and Proposal

**Status:** Analysis / design proposal — no code changes yet.
**Date:** 2026-05-25
**Audience:** Plugin maintainers deciding on the supply-chain scope of the threat-modeling pipeline.

---

## 1. Goal and scope philosophy

### 1.1 What this plugin is for

`appsec-advisor` is a **threat-modeling** plugin. It produces a code-anchored security architecture and threat model — STRIDE findings at trust boundaries, missing control gaps, attack chains, evidence-linked to file:line. The audience is AppSec engineers and security architects who need a repeatable starting point for review.

### 1.2 What this plugin is explicitly NOT

| Adjacent discipline | Owned by | Why not us |
|---|---|---|
| Software Composition Analysis (SCA) | Snyk, GitHub Advanced Security, Dependabot, Trivy, OSV-Scanner, language-native audit (`npm audit`, `pip-audit`, `govulncheck`, …) | Live CVE feeds, transitive-dep walking, exploit-chain databases — solved industry, continuously updated by dedicated teams we cannot match on freshness |
| Static Application Security Testing (SAST) | CodeQL, Semgrep, SonarQube, Bandit, Brakeman, gosec, … | Per-rule lint of source code, taint-tracking, dataflow proofs at expression level — a different abstraction than "does this trust boundary make sense?" |
| Secret scanning | gitleaks, trufflehog, GitHub Secret Scanning | Live entropy + format detection across full git history, with revocation hooks |
| Dynamic Application Security Testing (DAST) | OWASP ZAP, Burp Suite, Strix | Live-traffic exploitation, runtime probes |
| Container / IaC vulnerability scanning | Trivy, Checkov, tfsec, Kubescape | Image-layer CVE matching, policy-as-code evaluation against deployed manifests |

The plugin should never try to **be** one of these tools. Each of those tools has a multi-year head start, a dedicated update pipeline, and an industry user base.

### 1.3 Where the plugin DOES add value on these topics

The plugin's job is the **architectural angle** of every domain — the question the dedicated tools don't answer. Examples per adjacent discipline:

- **SCA**: not *"which CVEs?"* but *"does this team practice SCA at all, and are the chosen libraries architecturally defensible?"*
- **SAST**: not *"is this `eval` reachable from user input?"* but *"why does this trust boundary allow `eval` at all?"*
- **Secret scanning**: not *"is `AKIA…` in git history?"* but *"is the architecture set up so secrets *can* leak — committed keys, no secret-store integration, missing rotation?"*
- **DAST**: not *"can the login bypass be exploited live?"* but *"is the authentication flow's trust model coherent before we test it?"*
- **IaC scanning**: not *"is this S3 bucket public?"* but *"is the deployment topology making cross-service trust assumptions that the threat model doesn't acknowledge?"*

In every case the plugin asks the **structural question** the dedicated tool cannot — and *cites* the dedicated tool's existence (or absence) as part of the architectural answer.

### 1.4 Scope test

When deciding whether a new check belongs in this plugin, apply this test:

> Does this check produce a finding that an architecture reviewer would write into a threat model, citing trust boundaries, control coverage, or design rationale? Or does it produce a finding that a vulnerability scanner already produces better?

If the answer is the second, route around it — detect the *practice* (yes/no/partial), cite the *evidence in CI*, and let the dedicated tool own the per-CVE / per-rule reporting.

### 1.5 The unifying frame: patch management maturity as supply-chain risk

The central question this plugin should answer about supply chain risk is **not** *"which CVEs?"* but:

> **Does this team practice patch management, and is the resulting library stack architecturally defensible?**

Patch management maturity is a *single architectural property* of the repo — one that AppSec reviewers ask about in every audit, and one that no dedicated tool surfaces as a coherent signal. Dedicated SCA tools answer *"which CVEs?"* but they cannot tell you whether the *team* has a working process; they only run when invoked and report what they find.

Three observable indicators **converge on the same underlying property**:

| Indicator | What it tells you about patch management | Where to detect it |
|---|---|---|
| Automated SCA in CI present and blocking | Process: vulnerabilities are caught at build time, not in production | `.github/workflows/*.yml`, `snyk test` / `trivy fs` / `npm audit` / `pip-audit` / `govulncheck` / `cargo audit` / `bundle audit` / `composer audit` / `dependency-check` invocations |
| Automated dependency updates configured | Process: outdated packages get PRs raised automatically, not by ad-hoc heroics | `.github/dependabot.yml`, `renovate.json` / `renovate.json5` / `.renovaterc*` |
| No use of historically-bad / abandoned libraries | Outcome: even if the process works, the architectural choices made are defensible | Manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, …) compared to a curated known-bad list |

A repo can fail all three, pass all three, or show mixed signals — but the diagnostic value is the **combined picture**, not the three signals in isolation. A repo with Dependabot or Renovate but no SCA still patches; a repo with SCA but no auto-update tool (neither Dependabot nor Renovate) patches reactively; a repo with both but using abandoned libraries gets churn for libraries that will never have a patched version. The threat model should reflect the combination, not three independent table rows.

### 1.6 The specific goal of this proposal

Apply the scope test (§1.4) and the unifying frame (§1.5) to the plugin's current supply-chain handling. Today, `dep_scan.py` produces CVE-typed threats — a vulnerability-scanner finding shaped wrong for both the abstraction (§1.4) and the underlying question (§1.5). This document proposes:

1. **Remove `--with-sca` / `dep_scan.py`** — stop competing with SCA tools on their home turf (§1.4 scope test).
2. **Add Proposal 1 — SCA-practice + auto-updates + lockfile hygiene as structured §7.11 control rows** — the *process* signals for patch management maturity (§1.5 indicators 1 + 2 + lockfile-hygiene sub-signal).
3. **Add Proposal 2 — Static known-bad-libs as architectural meta-findings (MF-NNN)** routed to §7.11 — the *outcome* signal for patch management maturity (§1.5 indicator 3).
4. **Surface the combined picture** — both proposals route to §7.11, and the renderer's §7.13 *Defense-in-Depth Summary* row for "patch management" derives a single overall rating from the converging signals.

The result: the plugin produces one coherent **patch management posture** finding per repo — process + outcome — at the architectural abstraction it actually owns. Supply chain risk is surfaced where it belongs: as a property of the team and the codebase, not as a CVE list copied from a tool the team should already be running.

---

## 2. The current question

Does `dep_scan.py` belong in a threat-modeling tool, or is it scope creep into SCA territory?

**Short version:** Today the plugin ships an opt-in Software Composition Analysis (SCA) scanner (`--with-sca`) that calls `npm audit`, `pip-audit`, `govulncheck`, `mvn dependency-check`, with `data/dep-scan-heuristics.yaml` as a 17-entry fallback. Output flows into the threat list as CVE-typed threats.

That puts the plugin in two unrelated lanes at once — *architecture-level threat modeling* and *vulnerability scanning* — competing with established SCA tooling (Snyk, GitHub Advanced Security, Dependabot, Trivy, OSV-Scanner) that the user's organisation likely already has. Per the scope test in §1.4, that is the wrong side of the line.

---

## 3. Current state (verified against the codebase)

### 3.1 `dep_scan.py` — what it does today

- Opt-in via `--with-sca` (default `false`), resolved in `scripts/resolve_config.py:856` and gated in `agents/phases/phase-group-threats.md:1440` (Phase 10 Step 2).
- Invokes native audit tools when available (`npm audit`, `pip-audit`, `govulncheck`, `mvn dependency-check`).
- Falls back to `data/dep-scan-heuristics.yaml` — a static curated list, **17 entries** (7 npm / 5 python / 2 go / 3 maven), each with `cve`, `severity`, `vulnerable_below`.
- Output: `.dep-scan.json` → merged into `.threats-merged.json` → rendered as CVE-shaped threats in §8.
- **Replaces** the former `appsec-dep-scanner` LLM agent (documented in `dep_scan.py` header).

### 3.2 SCA-practice detection — what already exists in recon

The recon scanner detects whether SCA is *practiced* — but only records it in recon-summary prose, not as a structured control row:

- `agents/appsec-recon-scanner.md:247-263` — Grep checklist for: Renovate (`renovate.json`), Dependabot (`.github/dependabot.yml`), Snyk, Trivy, Grype, OSV-Scanner, `npm audit`, `pip-audit`, `cargo audit`, `bundle audit`, `composer audit`, `dotnet list --vulnerable`, OWASP Dependency-Check, `govulncheck`, Mend/WhiteSource.
- `scripts/recon_patterns.py:374:scan_ci_supply_chain()` — programmatic detection (Category 14).
- `agents/shared/recon-output-template.md:265-280` — output template with explicit "If no SCA tooling detected: `No SCA tooling found in CI workflows.`" slot.
- `data/config-iac-checks.yaml:197-225` — Dependabot configuration rules (`iac_type: dependabot`, 3 entries). The section header reads "Dependabot / Renovate" but **no `renovate` rules exist** — Proposal 1 needs to add them in parallel so both tools are treated as first-class evidence for the auto-updates indicator.
- `data/sections-contract.yaml:1305` — §7.11 *Operations Runtime and Supply Chain Controls* exists with `clusters: [outdated_deps]` and `library_token_match: true`.
- `scripts/enforce_control_taxonomy.py:188-194` — token-routing table maps `dependabot` / `renovate` / `npm audit` → §7.11.

**Critical gap:** none of these signals **emit** a structured `security_controls[]` row for §7.11. The routing in `enforce_control_taxonomy.py` only fires *after* something else has named a control with one of those tokens. There is no proactive emitter that says "this repo has SCA / does not have SCA" as a §7.11 control row, and no F-finding emission when SCA is absent.

### 3.3 Static known-bad-libs — what already exists

`data/dep-scan-heuristics.yaml` already contains 17 entries shaped as CVE findings. The comparison logic in `dep_scan.py` parses manifests against this list. Today this only runs under `--with-sca` and emits as CVE-typed threats, not as architectural choice-level findings.

---

## 4. Why `dep_scan.py` doesn't belong in this tool

Honest design critique:

1. **Different abstraction level.** Threat modeling asks *"which architectural risks exist, which controls are missing, which trust boundaries are unsafe?"*. SCA asks *"which CVEs are in which version?"*. The second question is solved industry — Snyk, GitHub Advanced Security, Dependabot, Trivy, OSV-Scanner.
2. **Cannot win on freshness.** Dedicated SCA tools update CVE databases continuously; a bundled heuristic list of 17 entries cannot compete and pretending otherwise misleads users.
3. **Network dependency.** Live SCA via osv.dev introduces a new failure mode (offline runs, rate limits, latency) to a pipeline that is otherwise self-contained on the repo.
4. **Output noise.** A repo with 142 transitive CVEs produces 142 threat-list rows — drowning the 3–5 architectural findings that are the actual TM value.
5. **Duplication risk.** Most orgs running this plugin already have an SCA tool in CI. Two scanners reporting on the same dependency tree produce duplicate findings and conflict-resolution debt.
6. **Wrong question.** The TM-relevant supply-chain question is not *"is there a CVE in package X?"* but *"does this team have an SCA process?"* and *"are the library choices architecturally defensible?"*.

---

## 5. Proposal 1 — SCA practice as a §7.11 control row

### 5.1 Goal

Promote the existing recon-side SCA-tooling detection into a structured §7.11 *Operations Runtime and Supply Chain Controls* row, with explicit positive / partial / missing semantics. When absent, emit an architectural finding sized to the asset tier.

### 5.2 What gets emitted

Three control rows for §7.11, each independently rated:

| Control name | Covered | Partial | Missing |
|---|---|---|---|
| Automated SCA scanning | Snyk / Trivy / Grype / OSV-Scanner / dependency-check / language-native audit in CI, blocking on High+ | Tool present but advisory only, or only one of multiple ecosystems covered | No SCA tool found in any CI workflow |
| Automated dependency updates | Dependabot or Renovate config present, covering all ecosystems detected by recon | Config covers some but not all ecosystems | No Dependabot / no Renovate |
| Lockfile hygiene | Lockfile present, committed, install uses lockfile-frozen mode in CI | Lockfile present but install uses non-frozen mode, or only some ecosystems pinned | Lockfile missing, gitignored, or generation disabled |

### 5.3 F-finding emission policy

When *missing*, emit one F-finding per missing control with severity scaled to `asset_tier` (resolved in Phase 1 by context-resolver):

| Asset tier | Missing-SCA severity | Missing-dep-updates severity | Missing-lockfile severity |
|---|---|---|---|
| Tier-1 (production, customer-facing, regulated) | Critical | High | High |
| Tier-2 (internal production) | High | Medium | Medium |
| Tier-3 (internal tools, demos) | Medium | Low | Low |
| Tier-4 (samples, prototypes) | Low | Informational | Informational |

Severity policy lives in a new data file (`data/sca-practice-severity.yaml`) so it can be tuned without code changes.

### 5.4 Implementation sketch

New script `scripts/emit_sca_practice.py`:

```text
read .recon-summary.md → §7.4 (Dependency Management) tables
read .threat-modeling-context.md → asset_tier
for each of {scanning, dep_updates, lockfile_hygiene}:
    classify covered | partial | missing
    write security_controls[] row → .security-controls.json
    if missing: write F-finding → .meta-findings.json
exit 0
```

Wiring:

- Add `emit_sca_practice.py` to `agents/phases/phase-group-threats.md` Phase 10 Step 1 (after recon, before merger).
- Update `schemas/security-controls.schema.json` to recognise the three new control names as canonical.
- `data/sections-contract.yaml` — no change required (§7.11 already configured).

### 5.5 Effort

- Script: ~150 LOC, mostly recon-output parsing
- Severity-policy file: ~30 lines
- Schema delta: 1 enum extension
- Tests: 4 cases (covered / partial / missing-tier1 / missing-tier4)
- **Estimated: 4-6 hours, low risk**

### 5.6 Why this is the high-leverage change

The detection logic already exists in three independent places (`recon-scanner.md`, `recon_patterns.py`, `config-iac-checks.yaml`). The classification taxonomy exists in `enforce_control_taxonomy.py`. The output section exists in `sections-contract.yaml`. Only the emitter dispatch in between is missing — every other piece is already drift-guarded by tests.

---

## 6. Proposal 2 — Static known-bad-libs as meta-findings

### 6.1 Goal

Detect inclusion of libraries with a well-known historically-bad track record (abandoned, protestware incidents, repeated unfixed CVEs, sandboxed-deprecated). Emit as architectural choice-level meta-findings (MF-NNN) routed to §7.11, framed as a library-choice signal — not as a CVE scan.

### 6.2 Framing distinction

A CVE scan output: *"libxmljs2@0.30 has CVE-2023-XYZ Critical severity"* → SCA-tool territory.

A TM meta-finding: *"Repo includes `libxmljs2@0.30` — a library with multiple unfixed XXE CVEs since 2022 and no active maintainer. The architectural choice to depend on this parser warrants review regardless of which specific CVE is currently outstanding."* → TM territory.

The difference is **emphasis on the choice**, not the version. A current-version copy of an abandoned library is still an architectural risk.

### 6.3 List shape and curation

Two options:

| Option | Description | Trade-off |
|---|---|---|
| **A** — Reuse `dep-scan-heuristics.yaml` | Relabel current 17 entries from CVE-framing to track-record framing | Cheaper now; mixes CVE-data into a track-record file |
| **B** — New `data/known-bad-libs.yaml` | Separate curated list, `dep-scan-heuristics.yaml` retired with `--with-sca` removal | Cleaner separation; one new file to maintain |

**Recommendation: B.** The framing is meaningfully different and mixing them will rot. New file shape:

```yaml
version: 1
known_bad:
  - ecosystem: npm
    package: libxmljs2
    reason: abandoned + multiple unfixed XXE CVEs since 2022
    category: abandoned_with_known_cves
    severity: High
  - ecosystem: npm
    package: request
    reason: deprecated since 2020, no security fixes
    category: deprecated_abandoned
    severity: Medium
  - ecosystem: npm
    package: node-serialize
    reason: CVE-2017-5941 unsafe deserialization RCE, never patched
    category: unfixed_critical_cve
    severity: Critical
  - ecosystem: npm
    package: event-stream
    reason: 2018 backdoor incident — supply-chain compromise precedent
    category: historical_supply_chain_compromise
    severity: Medium
  - ecosystem: npm
    package: colors
    reason: 2022 protestware incident (infinite-loop sabotage)
    category: protestware_incident
    severity: Medium
  # … expand toward 50-80 entries
```

**Categories** (for downstream filtering and rendering):

- `abandoned_with_known_cves`
- `deprecated_abandoned`
- `unfixed_critical_cve`
- `historical_supply_chain_compromise`
- `protestware_incident`
- `sandboxed_deprecated` (e.g. `vm`, `notevil` — known-broken sandboxes still used as security boundary)

### 6.4 Implementation sketch

New script `scripts/emit_known_bad_libs.py`:

```text
read package.json / requirements.txt / go.mod / pom.xml / Gemfile / composer.json
for each manifest dep:
    match against data/known-bad-libs.yaml
    if hit: emit MF-NNN meta-finding
        title: "Library {pkg}@{version} has known track record: {category}"
        prose: {reason}
        evidence: {manifest_path}:{line}
        section: §7.11
        severity: {category-driven, capped by asset_tier}
```

Wiring:

- Shared helper `scripts/_lib_manifest.py` (~80 LOC) for manifest parsing — also usable by Proposal 1 if it ever needs to enumerate dependencies.
- Add `emit_known_bad_libs.py` to Phase 10 Step 1 alongside Proposal 1's emitter.
- Schema update: `meta-findings.schema.json` to recognise the new category enum.
- Tests: 3 cases (clean repo, one hit, multiple hits across ecosystems).

### 6.5 Curation effort — the real cost

The 17 entries in `dep-scan-heuristics.yaml` are too few for the architectural-quality angle. Realistic minimum for credibility: **50-80 entries** covering npm / python / go / maven / ruby / php / .NET / rust.

This is iterative work, not a one-shot. Suggested cadence:

- **Initial ship**: ~30 curated entries focused on npm + python (highest userbase coverage)
- **Quarterly review**: 10-15 entries per pass, retire entries when libraries get rehabilitated (rare but happens)
- **Community contribution**: file structure simple enough that a PR-based contribution model works

The list **is not** a CVE feed — entries should be stable for years, not days.

### 6.6 Effort

- Script: ~100 LOC
- Shared manifest helper: ~80 LOC
- Initial curated list (30 entries): 2-4 hours research per ecosystem
- Schema delta: 1 enum extension
- Tests: 3 cases
- **Estimated: 6-8 hours code + ongoing curation**

---

## 7. Removing `--with-sca` / `dep_scan.py`

### 7.1 What goes away

| File | Action |
|---|---|
| `scripts/dep_scan.py` | Delete |
| `data/dep-scan-heuristics.yaml` | Delete (replaced by `data/known-bad-libs.yaml` under Proposal 2B) |
| `scripts/resolve_config.py:856` | Remove `--with-sca` / `--no-sca` argparse entries |
| `scripts/resolve_config.py:1256-1257` | Remove `with_sca` resolution |
| `skills/create-threat-model/HELP.txt:53` | Remove `--with-sca` line |
| `skills/create-threat-model/SKILL-impl.md:579,2391,3163` | Remove all `WITH_SCA` references |
| `agents/phases/phase-group-threats.md:1438-1520` | Remove Phase 10 Step 2 (SCA Results) section entirely |
| `tests/test_dep_scan.py` (if present) | Delete |
| `tests/fixtures/e2e/*` referencing `.dep-scan.json` | Update fixtures |

### 7.2 What stays

- All the existing SCA-practice **detection** in recon (already TM-shaped, just needs Proposal 1's emitter to surface as a control row).
- All the existing lockfile / supply-chain rules in `data/config-iac-checks.yaml`.
- `agents/shared/supply-chain-patterns.md` (covers MCP and lockfile cases — distinct from CVE scanning).

### 7.3 Migration impact

- **Existing reports referencing `.dep-scan.json`**: incremental fingerprint comparison handles missing inputs gracefully (`baseline_state.py` already designed for opt-in artifacts).
- **Existing SARIF consumers**: SCA findings disappear from SARIF. Acceptable — those were already opt-in. Document in CHANGELOG.
- **Existing threat-model.yaml schemas**: SCA threats had `source: dep-scan-native` / `source: dep-scan-heuristic`. Schema can either retain those source enums (deprecated, never emitted) or remove them. Cleaner: remove and bump schema version.

### 7.4 What users lose

A first-time TM run on a repo *without* any SCA tooling will no longer surface a starter list of vulnerable dependencies. Counter-argument: **those users should fix the SCA-process gap first** (which Proposal 1 surfaces clearly), then their SCA tool will find the CVEs.

That said, this is the only legitimate use case for `dep_scan.py` — a one-shot bootstrap for SCA-less repos. If preserving that capability matters, three softer alternatives to outright deletion:

- **Soft**: Keep `dep_scan.py` but reposition in docs as "discovery aid only — not a substitute for proper SCA tooling. Run once when bootstrapping SCA, then disable."
- **Softer**: Keep `--with-sca` but mark it deprecated; emit a deprecation warning that points to "run your SCA tool" guidance.
- **Hardest**: Delete entirely (this proposal's default).

---

## 8. Doing both proposals together

The two proposals are **converging signals of one risk concept** — patch management maturity (§1.5) — not two independent checks. Proposal 1 supplies the **process indicators**; Proposal 2 supplies the **outcome indicator**. Both route to §7.11 and feed a single derived "patch management" posture in the §7.13 Defense-in-Depth Summary.

| | Question answered | Indicator type (per §1.5) | Source signal |
|---|---|---|---|
| Proposal 1 | Does the team practice SCA + auto-updates? | Process indicators 1 + 2 | CI workflow contents + repo config files |
| Proposal 2 | Are the library choices architecturally defensible? | Outcome indicator 3 | Manifest contents vs. curated known-bad list |

A repo can:

- Fail both (no SCA, no Dependabot or Renovate, uses `libxmljs2`) — **broken patch management posture**, high supply-chain risk
- Pass both (SCA + Dependabot/Renovate + only actively-maintained libs) — **healthy patch management posture**
- Show mixed signals — surfaced as such; the §7.13 derived rating reflects the weakest component
  - Process good, outcome bad: SCA + Dependabot or Renovate present, but a known-bad library is still pinned (process catches CVEs but the team is choosing libraries with no upstream to patch from)
  - Process bad, outcome good: no SCA, no auto-update tool (neither Dependabot nor Renovate), but all libs are well-maintained — the team is one CVE away from unmanaged risk; the *posture* is unhealthy even though today's outcome looks OK

### 8.1 Shared architecture

```text
emit_sca_practice.py      ─┐
emit_known_bad_libs.py    ─┼─→ merge_threats.py → triage → render
arch_coverage_to_threats  ─┤
emit_meta_findings.py     ─┘
        │
        └────────────────→ security_controls[] (§7.11 row)
```

Both new emitters fit the existing fan-in. `merge_threats.py` is the single coordination point — both write into the same merge contract.

### 8.2 Shared code

- `scripts/_lib_manifest.py` — manifest parsing (npm / pip / go / maven / rb / php / .NET / rust) — used by Proposal 2 and potentially by future emitters
- `data/sca-practice-severity.yaml` — tier-driven severity matrix (used by Proposal 1)
- `data/known-bad-libs.yaml` — curated track-record list (used by Proposal 2)
- Shared test fixtures — synthetic repo with: no Dependabot/Renovate, no SCA in CI, manifest including `libxmljs2`

### 8.3 Combined effort estimate

| Phase | Work | Effort |
|---|---|---|
| Phase A | Build Proposal 1 (emit_sca_practice + severity matrix + schema + tests) | 4-6h |
| Phase B | Remove `--with-sca` and `dep_scan.py` (file deletions + reference cleanup + tests) | 2-3h |
| Phase C | Build Proposal 2 (emit_known_bad_libs + shared manifest helper + initial 30-entry list + tests) | 6-8h |
| Phase D | Documentation update (AGENTS.md, dev.md, README.md, diagrams.md, CHANGELOG) | 2h |
| **Total** | | **14-19h** |

Phases A and B can ship independently. Phase C requires curation work that should not block A and B.

---

## 9. Tradeoffs and decisions needed

### 9.1 Decisions

1. **Delete `dep_scan.py` outright, or reposition as "discovery aid"?** Outright deletion is scope-clean. Repositioning preserves a use case for SCA-less repos at the cost of ongoing maintenance.
2. **Proposal 2 list shape — reuse `dep-scan-heuristics.yaml` or new `known-bad-libs.yaml`?** Recommendation: new file (B above).
3. **Severity policy for missing SCA — tier-driven or fixed?** Recommendation: tier-driven, since impact varies dramatically (Critical for Tier-1 prod, Low for samples).
4. **Phasing — ship Proposal 1 alone first, or bundle with 2?** Recommendation: ship Proposal 1 + `dep_scan.py` removal as one change (they fit together semantically), follow with Proposal 2 once curation list is ready.

### 9.2 Risks

- **List staleness (Proposal 2).** Mitigation: framing as track-record (decade-stable) not CVE-feed (days-stable). Quarterly review cadence.
- **False positives (Proposal 2).** A repo using `request` for a one-off internal script is technically a hit, but architecturally irrelevant. Mitigation: emit at Medium severity by default; rely on triage-validator's existing rate-of-change logic.
- **§7.11 row explosion (Proposal 1).** Three new control rows on every report — verbose but consistent. Mitigation: each row is short (one line) and the controls were always part of the §7.11 taxonomy; this just makes them explicit.
- **Breaking change for current `--with-sca` users.** Mitigation: deprecation warning for one release before removal; clear CHANGELOG entry; suggest migration path (run your real SCA tool).

### 9.3 What we explicitly do NOT do

- Build our own CVE database
- Maintain a live vulnerability feed
- Compete with Snyk / GitHub Advanced Security / Trivy on vulnerability coverage
- Replace any existing SCA tool in the user's CI

---

## 10. Recommendation

**Phase 1 (immediate): build Proposal 1 + remove `--with-sca`.** Bundled because they belong together — removing the wrong-abstraction SCA scanner and adding the right-abstraction SCA-practice check is one coherent change. Effort: 6-9h.

**Phase 2 (when ready): build Proposal 2.** Effort: 6-8h code, plus list curation as a sustained activity. Independent of Phase 1.

**Result:** the plugin stays inside the threat-modeling abstraction, no longer competes with SCA tools, and produces one coherent **patch management posture** finding per repo — combining process indicators (SCA in CI, auto-updates, lockfile hygiene) and outcome indicators (no historically-bad libraries) into a single architectural signal. Supply chain risk gets surfaced where it belongs: as a property of the team and the codebase, not as a CVE list copied from a tool the team should already be running.

---

## 11. Open questions

- Should Proposal 1's missing-SCA finding be a `F-NNN` (architectural finding) or a `MF-NNN` (meta-finding)? Both exist in the schema; F-NNN is the more common shape but MF-NNN was introduced for cross-cutting concerns and supply-chain process gap arguably qualifies.
- Should Proposal 2 walk transitive dependencies (lockfile-aware) or only direct deps (manifest-only)? Manifest-only is cheaper and more TM-shaped (only the direct architectural choice matters); lockfile-aware would surface more hits but blurs back toward SCA-tool territory. Recommendation: manifest-only.
- Should the `known-bad-libs.yaml` file be vendored in the repo, or fetchable from a public list (similar to OWASP Dependency-Check's NVD feed)? Recommendation: vendored — curated, intentional, reviewable.
