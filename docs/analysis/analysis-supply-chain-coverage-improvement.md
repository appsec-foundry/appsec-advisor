# Analysis — Supply-Chain Coverage Improvement (package.json & friends)

**Date:** 2026-06-06
**Scope:** `scripts/assess_supply_chain_controls.py` (the 9-sub-control §7.11 scorecard) plus the
recon detection layer (`scripts/recon_patterns.py`, `agents/appsec-recon-scanner.md`).
**Question that triggered this:** does the tool actually inspect `package.json` / `.npmrc` /
lockfiles for *current* (2025/2026) supply-chain best practices — and where are the gaps?

> **Implementation status (2026-06-06, branch `fix/supply-chain-ecosystem-false-negatives`):**
> P0 bugfixes **F1** (GitLab CI image digest-pinning), **F6** (`uv.lock`/`requirements.lock`),
> **F7** (Gradle `gradle.lockfile` / `verification-metadata.xml` + Maven/Gradle deterministic
> CI-install flags) are **DONE** in `scripts/assess_supply_chain_controls.py`, covered by
> `tests/test_assess_supply_chain_controls.py` (13 tests). Remaining P0 (install-cooldown
> control) and P1+ items below are open.

---

## 1. What is inspected today (verified at code level)

The deterministic §7.11 scorecard (`assess_supply_chain_controls.py`) grades **9 sub-controls**:

| # | Sub-control | Reads | Depth | File:line |
|---|---|---|---|---|
| 1 | CVE scanning | recon text | SCA tool present + blocking? | `assess_supply_chain_controls.py` |
| 2 | Lockfile pinning | recon + repo | **existence only** of `package-lock`/`Pipfile.lock`/`poetry.lock`/`uv.lock`/… | `:81` |
| 3 | CI install integrity | recon | `npm ci`/`--frozen-lockfile`/`--require-hashes` vs mutable `npm install`/`pip install` | `:99` |
| 4 | CI/CD action pinning | `.github/workflows/*` | `uses:@<sha>` vs `@v<n>`/`@latest` — **GitHub Actions only** | `:116` |
| 5 | Container image hygiene | `Dockerfile*` | `FROM …@sha256:` digest-pin | `:155` |
| 6 | Dependency confusion | recon + `.npmrc` | scoped pkg / private registry present | `:182` |
| 7 | Postinstall scripts | `package.json` | binary: has `postinstall`/`preinstall`/`install` hook + `ignore-scripts`? | `:202` |
| 8 | Dependency management | repo | Renovate / Dependabot config present | `:231` |
| 9 | SCA tooling | recon | dedicated SCA tool vs native-audit-only | `:262` |

`package.json` is genuinely parsed (sub-control 7 + recon Cat 16/17), and the diff-relevance
filter already *knows* the security-relevant keys —
`security_relevance_filter.py:508` `_PKG_JSON_SEC_KEYS` =
`{dependencies, devDependencies, optionalDependencies, peerDependencies, bundledDependencies,
overrides, resolutions, scripts, engines, type, bin, exports, imports, workspaces, config}`.

**Key insight:** that rich key-awareness is used only to decide *"is this diff worth
re-scanning"* (incremental mode). It is **not** leveraged to *grade* any control. The scorecard
reads `package.json` for exactly one thing — the presence of install hooks.

---

## 2. Current best practices (2025/2026) and how we measure against them

Grounded in: OWASP NPM Security Cheat Sheet, lirantal/npm-security-best-practices (the
"Awesome" list), Mondoo "npm Supply Chain Security in 2026". Driving incidents: chalk/debug
(Sept 2025), Shai-Hulud worm (Nov 2025), Axios compromise (~4–5h exposure window).

| Best practice (2026) | Exact config / where it lives | Covered? | Gap |
|---|---|---|---|
| **Install cooldown** — reject versions younger than N days. *The single highest-value 2026 defense* (blocks chalk/debug, Shai-Hulud, Axios outright). | npm `.npmrc min-release-age=3`; pnpm `pnpm-workspace.yaml minimumReleaseAge`; Yarn `.yarnrc.yml npmMinimalAgeGate`; Bun `bunfig.toml minimumReleaseAge` | recon Cat 26 Step 7 (LLM layer) only | **Not in deterministic scorecard** (G1) |
| **Block git-based deps** — git URL ships its own `.npmrc` that re-enables lifecycle scripts, bypassing `ignore-scripts` entirely. | npm `.npmrc allow-git=none` (CLI 11.10+); pnpm `blockExoticSubdeps: true` (10.26+) | partially: `git+https://` flagged in recon as anti-pattern | **`allow-git`/`blockExoticSubdeps` as a positive control: not checked at all** |
| **Lifecycle scripts off + allowlist** — not just "is a hook present" but "are scripts globally off with a vetted allowlist". | `.npmrc ignore-scripts=true` + `package.json` `lavamoat.allowScripts` / pnpm `allowBuilds`+`strictDepBuilds` / `onlyBuiltDependencies` | binary hook-presence only (sub-control 7) | **Allowlist mechanism gets no credit; pnpm default-off not modeled** (G6) |
| **Pin direct deps / no floating ranges** — `^`,`~`,`*`,`latest`,`>=` widen the attack window between lockfile gen and install. | `package.json` version specifiers; `.npmrc save-exact=true`; `engine-strict` | lockfile *existence* (sub-control 2) | **Range hygiene in `package.json` never inspected** |
| **Pin transitive deps** — force a known-good version everywhere in the tree. | `package.json` `overrides` (npm) / `resolutions` (yarn) | key known to diff-filter | **Not graded as a control** |
| **Provenance / trusted publishing** — verify the package was built in CI from claimed source (SLSA L2). | `npm audit signatures`; npm provenance badge; PyPI/gh-action OIDC `id-token: write`; pnpm `trustPolicy: no-downgrade` | recon Cat 27e (publish side, LLM layer) | **Consumer-side `npm audit signatures` / `trustPolicy` not checked** (G2/G3) |
| **Pin the package manager itself** | `package.json packageManager` field + Corepack | — | **Not checked** |
| **Real SCA / per-CVE** | Snyk/Trivy/OSV-Scanner/Dependabot in CI | tool *presence* graded; tool never *run* | **By design** — plugin does posture, not CVE enumeration (`phase-group-threats.md:1435`) |

---

## 3. Findings carried over from this session (the GitLab bug + others)

These came up while answering the user's GitHub-vs-GitLab and pip questions and belong in the
same improvement backlog.

### F1 — **BUG: GitLab pipelines mis-scored on action-pinning** (sub-control 4)
`_eval_action_pinning` (`assess_supply_chain_controls.py:116-151`) globs **only**
`.github/workflows/*.yml|yaml` and matches `uses:@<sha>`. For a repo whose CI lives in
`.gitlab-ci.yml`, it returns `MISSING: "No GitHub Actions workflows detected."` **even when
every `.gitlab-ci.yml` `image:` is digest-pinned.** GitLab image-pinning *is* detected
informationally by `recon_patterns.py:381` (`_CAT14_GITLAB_IMAGE`, flags *unpinned* tags) but
that signal is never fed into the scorecard verdict. → **false-negative score** for pure-GitLab
repos. This is a concrete bug, not just a gap.

### F2 — **GitLab has zero IAC checks**
`data/config-iac-checks.yaml` distinct `iac_type`: `github_workflow` ×8, `Dockerfile` ×5,
`docker_compose` ×3, `dependabot` ×3, `renovate` ×3, `npm_config` ×2. **No `gitlab_ci`.**
The 8 GitHub-workflow checks (permissions, `pull_request_target` fork-checkout, script
injection, SHA-pin) have **no GitLab equivalent**: protected CI/CD variables, `CI_JOB_TOKEN`
scope, `include:` remote-template pinning, fork-MR-pipeline risk, runner privilege — all unchecked.

### F3 — **Detection-layer vs scorecard split**
G1 (cooldown), G2 (trusted publishing), G5 (PR dependency-review gate) live **only** in the
recon/LLM threat-detection layer — they are *not* wired into the deterministic §7.11 scorecard.
So they appear (or not) at the mercy of recon quality, and never produce a graded control row.

### F4 — **Lockfile graded on existence only**
Sub-control 2 checks the file exists and isn't `.gitignore`d. It does not inspect range
hygiene in `package.json`, nor lockfile integrity. (Reading lockfile *contents* is a deliberate
non-goal — too large — but `package.json` range hygiene is cheap and currently skipped.)

### F5 — **Python dep-confusion is LLM-only**
`pip --extra-index-url` / `PIP_INDEX_URL` confusion is caught in recon Cat 16
(`appsec-recon-scanner.md:199,310`), but the deterministic `_eval_dependency_confusion`
(`:182`) is npm-`.npmrc`-centric. Python parity is recon-dependent, not guaranteed.

### F6 — **BUG: `uv.lock` not credited as a lockfile**
`_eval_lockfile` (`assess_supply_chain_controls.py:84,90`) lists `Pipfile.lock`/`poetry.lock`
but **not `uv.lock`** — even though `emit_sca_practice.py:129` and recon both recognize it. A
uv-only Python repo with a committed `uv.lock` is scored `MISSING` lockfile. False-negative.

### F7 — **BUG: Java dependency-locking/verification not credited**
`_eval_lockfile` lists no `gradle.lockfile` and no `gradle/verification-metadata.xml`; `_eval_ci_install`
(`:99`) has no Maven/Gradle deterministic-install flag. A Gradle repo with full
`verification-metadata.xml` (sha256+pgp) scores `MISSING` on **both** lockfile and CI-install
integrity. Worst false-negative in the codebase — penalizes the *strongest* Java posture.

### F8 — **Build-wrapper validation uncovered (all ecosystems)**
`gradlew`/`gradle-wrapper.jar` and `mvnw`/`maven-wrapper.jar` are committed binaries; a swapped
wrapper jar runs arbitrary code at build time. Detected by the `gradle-wrapper-validation` action
upstream, but **not checked anywhere** in this tool (not recon, not scorecard, not IAC).

---

## 3b. Cross-ecosystem parity — Python & Java (added 2026-06-06)

Section 2 above is npm-centric. The same audit for Python and Java surfaces the **same
structural pattern**: the recon/LLM layer is ecosystem-aware, but the *deterministic* scorecard
(`assess_supply_chain_controls.py`) is hard-coded around npm/JS idioms and produces
**false-negatives** for the other two.

### Python — strong in recon, thin (and one bug) in the scorecard

| Best practice (Python 2026) | Where | Det. scorecard? | Recon/LLM? |
|---|---|---|---|
| Lockfile present (`Pipfile.lock`/`poetry.lock`/`uv.lock`/`requirements.lock`) | `.gitignore` + repo | **partial — `uv.lock` MISSING from `_eval_lockfile` list** (`:84,90`) → uv-only repo scored MISSING | yes (`appsec-recon-scanner.md:289-291`) |
| Hash-pinned install (`pip install --require-hashes`) | CI / Dockerfile | **yes** (`:108`) | yes (`:236`) |
| Pinned versions (`==`, no bare `>=`) in `requirements.txt` | manifest | no | yes (`:288`) |
| Install cooldown — uv `--exclude-newer`, pip v26+ `--uploaded-prior-to` | CI / `uv.toml` / `pyproject.toml` | no | yes (`:322-323`) |
| Dependency confusion — `--extra-index-url`, `PIP_INDEX_URL`, `.pypirc`/`pip.conf` | CI / config | **npm-`.npmrc`-centric only** (`:182`) | yes (`:199,310`) |
| `setup.py` install-time shell escape | `setup.py` | no (recon only) | yes (`recon_patterns.py:566`) |
| Trusted publishing OIDC + PEP 740 provenance | publish workflow | no | yes (`:400`, Cat 27e) |

**Net:** Python is *well covered in recon* (memory `project_supply_chain_coverage_map` confirms —
do **not** call Python the thin ecosystem). But in the deterministic scorecard, only 2 of 7
Python controls are graded, and `_eval_lockfile` has a **uv.lock false-negative** (F6 below).

### Java (Maven / Gradle) — the genuinely thin ecosystem

Java manifests *are* parsed for inventory (`_lib_manifest.py:41` Maven/Gradle dep extraction,
`_manifest_readers.py:237-309` pom/gradle metadata, `baseline_state.py:77-80` diff-relevance
incl. `gradle.lockfile`). But the **security scorecard does not understand Java at all**:

| Best practice (Java 2026) | Exact artifact | Det. scorecard? | Recon/LLM? |
|---|---|---|---|
| **Gradle dependency verification** — `gradle/verification-metadata.xml` with `sha256` checksums (integrity) + `pgp` signatures (provenance); `./gradlew --write-verification-metadata sha256,pgp` | `gradle/verification-metadata.xml` | **no — not in `_eval_lockfile` list → Gradle locking scored MISSING** | yes (`:241,295`) |
| **Gradle dependency locking** — `gradle.lockfile` via `dependencyLocking{}` | `gradle.lockfile` | **no — absent from `_eval_lockfile`** (F7) | yes (`:241,295`) |
| **Maven integrity** — `-C`/`--strict-checksums`, Enforcer plugin, BOM, no `SNAPSHOT` in releases | CI / `pom.xml` | **no — `_eval_ci_install` has no mvn/gradle flag** (`:99`) | yes (`:240,294`) |
| **Build-wrapper validation** — `gradlew`/`gradle-wrapper.jar` & `mvnw`/`maven-wrapper.jar` are committed binaries that can be swapped (real attack vector) | wrapper jars + `gradle-wrapper-validation` action | **no — not covered anywhere, not even recon** | **no** |
| Repository confusion — `<repositories>` / `repositories{}` ordering, `http://` repos, internal-before-central | `pom.xml` / `build.gradle` | no | npm/py-centric only |
| Maven Central PGP signing for publish | release workflow | no | partial (27e is npm/py) |
| Gradle build script = arbitrary Groovy/Kotlin at configuration time (postinstall-analog) | `build.gradle(.kts)` | no | no |

**Net:** a Gradle repo with **best-in-class** dependency verification (`verification-metadata.xml`
with sha256+pgp) is currently scored `MISSING` on lockfile **and** `MISSING` on CI-install
integrity — a double false-negative. Java is the weakest ecosystem and the only one with a
**completely uncovered** high-value control (wrapper-jar validation).

### North-star reference

[OSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md) is the industry
baseline for an automated supply-chain assessor and is explicitly **ecosystem-parametric** — its
`Pinned-Dependencies` check resolves `package.json` / `requirements.txt` / `packages.config` /
Gradle / Dockerfile uniformly. Our scorecard should adopt the same shape: one control, an
ecosystem-detection front-end, per-ecosystem evidence. The npm-hard-coding is the root cause of
every false-negative in F1/F6/F7.

---

## 4. Prioritized improvement backlog

Effort = rough; all are additive to `assess_supply_chain_controls.py` unless noted. "Det." =
moves a control from the soft LLM layer into the deterministic scorecard.

| Pri | Item | Why now | Effort | Type |
|---|---|---|---|---|
| **P0** | **Fix F1** — make sub-control 4 ecosystem-aware: also read `.gitlab-ci.yml` `image:`/`include:` refs; grade digest-pin there. Rename verdict "CI step pinning" not "GitHub Actions". | Active false-negative; misleads users with a *worse* score than reality | S | bugfix |
| **P0** | **Install cooldown as a graded sub-control (G1 → Det.)** — parse `.npmrc min-release-age`, `pnpm-workspace.yaml minimumReleaseAge`, `.yarnrc.yml npmMinimalAgeGate`, `bunfig.toml minimumReleaseAge`. | Highest-leverage 2026 defense; already half-built in recon | M | new control |
| **P1** | **`package.json` range-hygiene check** — flag direct deps on `*`/`latest`/wide `^`ranges without a committed lockfile; credit `save-exact`/`overrides`/`resolutions`. | Cheap parse, leverages existing `_PKG_JSON_SEC_KEYS`; closes F4 | M | new control |
| **P1** | **`allow-git=none` / `blockExoticSubdeps` as positive controls** — `.npmrc allow-git`, `pnpm-workspace.yaml blockExoticSubdeps`. | New 2026 vector (git-dep re-enables scripts); pairs with existing `git+https` flag | S | enrich |
| **P1** | **Consumer-side provenance (G2/G3 → Det.)** — detect `npm audit signatures` in CI, pnpm `trustPolicy: no-downgrade`, publish-side OIDC `id-token: write`. | Decouples from recon; SLSA-L2 signal | M | new control |
| **P2** | **Lifecycle-allowlist credit (G6)** — recognize `lavamoat.allowScripts`, pnpm `allowBuilds`+`strictDepBuilds`/`onlyBuiltDependencies`; model pnpm scripts-off-by-default. Upgrade sub-control 7 from binary→graded. | Removes false "PARTIAL" for build-only hooks | M | enrich |
| **P2** | **GitLab IAC checks (F2)** — add `iac_type: gitlab_ci` checks: protected variables, `CI_JOB_TOKEN` scope, `include:` pinning, fork-MR pipeline. | Whole-ecosystem blind spot | L | new checks |
| **P3** | **Python dep-confusion parity (F5)** — port `--extra-index-url`/`PIP_INDEX_URL` into deterministic `_eval_dependency_confusion`. | Removes recon dependency | S | enrich |
| **P3** | **`packageManager`/Corepack pin** + `engines` strictness as a minor hardening signal. | Low incidence, completeness | S | enrich |

| **P0** | **Fix F6+F7** — extend `_eval_lockfile` with `uv.lock`, `gradle.lockfile`, `gradle/verification-metadata.xml`; extend `_eval_ci_install` with Gradle (`--write-verification-metadata`, `dependencyLocking`/`--write-locks`, offline+locks) and Maven (`-C`/`--strict-checksums`, Enforcer) flags. | Active false-negatives that penalize *good* Python/Java posture; trivial list additions | S | bugfix |
| **P1** | **Make the scorecard ecosystem-parametric (OSSF-Scorecard shape)** — detect ecosystem(s) once, dispatch per-ecosystem evidence inside each sub-control instead of npm-hard-coded regex. | Root cause of F1/F6/F7; future-proofs every control | L | refactor |
| **P2** | **Gradle dependency verification as a graded control** — credit `verification-metadata.xml` (`verify-metadata`/`verify-signatures`), distinguish checksum-only vs sha256+pgp. | Java's `--require-hashes` equivalent + provenance; strongest Java signal | M | new control |
| **P2** | **Build-wrapper validation (F8)** — flag presence of `gradlew`/`gradle-wrapper.jar`/`mvnw` without a `gradle-wrapper-validation` (or checksum) CI step. | Uncovered real attack vector, all ecosystems | M | new check |
| **P3** | **Maven/Gradle repository-confusion** — `http://` repos, internal-before-central ordering in `pom.xml`/`build.gradle`. | Java dep-confusion parity with npm/python | M | enrich |

**Recommended first slice (one PR):** the three P0 bugfixes — F1 (GitLab pinning), F6 (uv.lock),
F7 (Java locking/verification). All three are the same class (npm-hard-coded evidence lists
producing false-negatives), all are small list/regex additions, and all *lower* scores for
teams who did the right thing — so they actively mislead today. Pair with the P0 cooldown
control (logic already in recon). The P1 ecosystem-parametric refactor is the durable fix that
prevents the next false-negative.

---

## 5. Design note — keep the layer boundary honest

Several gaps (G1/G2/G5) exist because detection was added to the **recon/LLM layer** for speed,
then never promoted to the **deterministic scorecard**. The recurring lesson: a control the
user can *act on* belongs in `assess_supply_chain_controls.py` so it renders as a graded §7.11
row with a stable verdict — not as prose that depends on recon attention. Each "→ Det."
item above is exactly that promotion.

The hard non-goal stays: **no package manager is ever executed** (`phase-group-threats.md:1435`).
All of the above is static inspection of `package.json` / `.npmrc` / `pnpm-workspace.yaml` /
`.yarnrc.yml` / `bunfig.toml` / lockfile *existence* / CI YAML — no `npm audit` / `pip-audit`
network calls. Per-CVE reporting remains the user's SCA tool's job.

---

## Sources
- [OWASP NPM Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)
- [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices)
- [Mondoo — npm Supply Chain Security in 2026](https://mondoo.com/blog/npm-supply-chain-security-package-manager-defenses-2026)
- [Gradle — Verifying Dependencies (verification-metadata.xml)](https://docs.gradle.org/current/userguide/dependency_verification.html)
- [OSSF Scorecard — Check Documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
