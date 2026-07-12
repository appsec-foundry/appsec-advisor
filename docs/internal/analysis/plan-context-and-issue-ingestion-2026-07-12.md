# Implementation Plan: Context Hardening + Issue Ingestion (combined, shared-seam first)

**Status:** Plan only — no code yet. 2026-07-12.
**Combines:** `proposal-context-resolver-hardening-2026-07-12.md` + `proposal-issue-tracker-ingestion-2026-07-12.md` (Option 1 MVP) + a **business-context enrichment** phase (Phase 2b) that emerged in analysis (no standalone proposal — spec lives here).
**Phases:** Phase 1 clean-room · Phase 2 seam+hardening · Phase 2b business-context enrichment · Phase 3 issue ingestion.
**Strategy:** clean-room first (integrity), then the shared seam + hardening, then business-context enrichment and the issue source on top. Test-first; every contract change is bidirectional (AGENTS.md §4). See **Scope & sequencing** for the measure-vs-deliver start-phase fork.

---

## 🔒 Non-negotiable: context informs the search, code proves the finding

Deliberately-vulnerable test apps (OWASP Juice Shop et al.) ship their own answer keys — a `data/static/challenges.yml` catalog, a companion "Pwning" book, README walkthroughs, and GitHub issues full of challenge spoilers. Ingesting any of that as *evidence* would make findings (and any benchmark against them) worthless.

**Invariant every task below must preserve:** no context source (issue, README, known-threats, related-repo) may itself be the evidence for a `threats[]` finding. Context may only *hint the search*; a finding stands only when the STRIDE analyzer independently anchors a real `evidence.file:line` that passes `evidence_integrity` (`qa_checks.py:3059`) + `validate_evidence_lines.py`.

**Honest scope of the existing spine (verified — do not overstate):** it is *advisory, not a hard delete.* `check_evidence_integrity` "NEVER auto-repairs" and only surfaces `evidence_integrity.issues` to the LLM QA reviewer (`qa_checks.py:3076-3080`); `_is_inferred` (`validate_evidence_lines.py:150`) blocks *auto-verification* and CVSS/SARIF eligibility but does not remove the threat from `threats[]`. The T-065 patch closes only the naive "anchor points at `challenges.yml`" case. Critically, **no evidence gate can catch the deep cheat**: an LLM that reads a spoiler, then locates the *real* vulnerable code line and anchors legitimate `evidence.file:line`, passes every gate — the evidence is genuine; "found independently" vs "found because told where to look" is indistinguishable once the anchor is real. The ONLY real guarantee is not ingesting the spoiler = the clean-room switch (Phase 1). The tasks here must inherit the spine and add that switch, not rely on the gate alone. Four concrete consequences are baked into the phases:
- **Issue Option 1 (this plan)** is soft context only — it creates no finding, so it cannot cheat a code-level finding into existence; issues are provenance-tagged as search hints.
- **Issue Option 2 (out of this plan)** — its "evidence-less branch" MUST be redesigned as: search the component, anchor a real code line, and **drop the item if no code sink is found** (never raise from issue prose). See the issue proposal §4.
- **Benchmark clean-room mode (Phase 1 — ships first)** — a hard switch that disables ALL spoiler-prone context channels for evaluation runs. Issue-feature default-off is not sufficient because recon reads `README.md` + `docs/**/*.md` on every run (`recon-scanner.md:73-79`), gated only by a soft untrusted-content instruction. Sequenced first because it is the only real integrity guarantee and is independently valuable for every eval run.
- **No URL dereferencing (Phase 2b)** — business-context enrichment may extract and classify URLs/domains but MUST NOT fetch their content. Fetching a repo-linked page is simultaneously an SSRF vector, a prompt-injection surface, and a spoiler channel (a product's linked security/docs page can list known vulns). The *presence and domain* is the signal; the page body is never read.

---

## ⚠ Correction to both proposals (verified 2026-07-12)

The proposals said "create/extract a shared secret-scan module." **It already exists** — do NOT build a new one:

- `scripts/secret_scan.py` = documented *"single source of truth"* for pattern-based secret detection. Public API `scan_text(text) -> list[SecretHit]`, `scan_file`, `mask_file`, `_value_is_masked`. Masking-aware + false-positive suppression (code refs, prose, SCREAMING-KEBAB suffixes). Already imported by `qa_checks.py:93`, `publish_threat_model.py:20`, `postscan_secret_check.py:37`, `redact_known_secrets.py:35`, `compose_threat_model.py:12104`.
- `scripts/load_org_context.py:70 _SECRET_PATTERNS` is a **weaker duplicate** (5 patterns, no FP suppression) → a latent drift bug. Replacing it with `secret_scan.scan_text` is a real fix, folded into Phase 2 (task 2.4).
- `scripts/_url_guard.py` already provides `validate_target_url(url, strict=)` + `same_host` + `_SameHostRedirectHandler` (via `load_related_repos`). Reuse — do not reimplement.

So the only genuinely *new* shared piece is a tiny **untrusted-fence helper** (convention convergence, Phase 0).

---

## Phase 0 (prep) — Shared seam

**Not a sequenced phase before clean-room.** This is the tiny shared prep that Phase 2 executes as task 2.0 (and Phase 3 reuses). Clean-room (Phase 1) does not depend on it. Listed separately only to specify the seam once.

**Goal:** one secret-scan, one URL guard, one untrusted-fence convention, reused by every context loader.

| Task | Verify |
|------|--------|
| 0.1 Choose the canonical untrusted fence = `<untrusted-data source="…">…</untrusted-data>` (Step 5 already parses it; `context-resolver.md:613,634`). Add a small `wrap_untrusted(source, body) -> str` helper (new `scripts/_context_wrap.py`, or a function in `secret_scan`/a shared util). | unit test: wrapping + round-trip; fence literal matches Step-5 expectation |
| 0.2 Confirm `secret_scan.scan_text` + `_url_guard.validate_target_url` are the reuse targets (no new module). | grep imports; no new secret regex added anywhere |

**No behavior change — establishes the imports/helper; executed inside Phase 2.**

---

## Phase 1 — Benchmark clean-room mode (ships first)

**Goal:** a single hard, auditable switch that removes *every* spoiler-prone context channel, so eval/benchmark runs against deliberately-vulnerable apps measure **independent discovery**. This is the only real integrity guarantee (the evidence gate is advisory, not a hard delete — see the non-negotiable above). **No dependency on Phase 0** — can ship standalone and first.

Test-first order:

| Task | Verify (write test first) |
|------|---------------------------|
| 1.1 `tests/test_cleanroom_mode.py` — a fixture repo with a spoiler `README.md` + `docs/known-threats.yaml` + `docs/related-repos.yaml`: with the switch ON, the resolved context + recon state have **all** those channels empty and `meta.cleanroom=true`; with it OFF, unchanged. | red → green |
| 1.2 Define the switch: env `APPSEC_CLEANROOM=1` (+ `--cleanroom` on `run-headless.sh`) → resolves to one propagated flag `CLEANROOM=true` reaching both context-resolver and recon-scanner dispatch (mirror how existing toggles propagate). | flag reaches both agents in a dispatch trace |
| 1.3 **Context-resolver hard-disables** (the deliberate spoiler channels): under `CLEANROOM`, force to "not loaded (cleanroom)" — Step 2 External-REST, Step 3 `business-context.md`, Step 4i `known-threats.yaml`, Step 4j `related-repos.yaml`. | those sections render as `cleanroom — suppressed`, not their content |
| 1.4 **Recon prose hard-disable** (the always-on leak — the critical one): under `CLEANROOM`, recon Step 1 must NOT read `README.md` / `CLAUDE.md` / `docs/**/*.md|.adoc` as project context (`recon-scanner.md:73-79`). Code/pattern scanning is unaffected. | test: recon summary contains none of the planted spoiler prose |
| 1.5 **Auditable provenance:** emit a `CLEANROOM` banner line and stamp `meta.cleanroom=true` in `threat-model.yaml` + report meta, so a benchmark result is provably clean. | banner present; meta field set; non-cleanroom run byte-identical |
| 1.6 **Forward-guard for the not-yet-built issue feature:** add a *pending/xfail* assertion that `CLEANROOM` also forces `issue_context` off — so Phase 3 cannot ship without honoring it. | test exists, marked xfail until Phase 3 |
| 1.7 `AGENTS.md` + a "Benchmarking / eval integrity" doc note. | — |

`required-permissions.yaml`: no change.

**Phase-1 exit criterion:** a Juice-Shop-style repo (spoiler `README` + `challenges.yml` present) run with `APPSEC_CLEANROOM=1` yields a context file with every spoiler channel empty, a cleanroom banner/meta stamp, and findings that can only originate from code.

**Honest caveat (must be documented, not silently assumed):** clean-room removes *ingested* spoilers. It cannot un-bias a model whose **training data** already contains public Juice-Shop write-ups. That residual prior is out of scope for this switch — state it in the doc note (1.7) so benchmark results are not over-claimed.

---

## Phase 2 — Context-resolver hardening (Phase 0 seam folded in)

**Goal:** Steps 3–4 become deterministic; every ingested body is secret-scanned + wrapped; External-REST is URL-guarded; the org-context duplicate is removed. Composes with Phase 1: the loader must honor the `CLEANROOM` flag when deciding which categories to scan.

Test-first order:

| Task | Verify (write test first) |
|------|---------------------------|
| 2.0 Phase-0 seam (fence helper + confirm `secret_scan`/`_url_guard` reuse). | seam unit test |
| 2.1 `tests/test_load_repo_context.py` — fixtures per category (SECURITY.md, ARCHITECTURE, ADR dir, OpenAPI, docker-compose/Dockerfile/k8s/tf, schema, `.env.example`, CHANGELOG) + **one secret-redaction case** (a `.env` with an AKIA key → masked) + **one cleanroom case** (spoiler channels suppressed). | red → green |
| 2.2 `scripts/load_repo_context.py` (NEW) — walk categories with the line-limits in `context-resolver.md:218-317`; run `secret_scan.scan_text` (mask hits) on every body; wrap via 2.0; honor `CLEANROOM`; emit `$OUTPUT_DIR/.repo-context.json` + manifest. | 2.1 passes |
| 2.3 `schemas/repo-context.schema.json` (NEW) + wire into `validate_intermediate.py`. | schema-violation test fails loudly |
| 2.4 `load_org_context.py` — delete `_SECRET_PATTERNS`, call `secret_scan.scan_text`; converge onto the 2.0 fence. | existing org-context tests green; a planted secret is now caught |
| 2.5 Route External-REST (Step 2) fetch through `_url_guard.validate_target_url`. | test: SSRF/localhost URL rejected |
| 2.6 `agents/appsec-context-resolver.md` — replace Steps 3–4 prose with a `load_repo_context.py` call + a **render-only** Step 5; keep the header table; `.gitignore` block (`:588`) += `.repo-context.json`. | live smoke: `.threat-modeling-context.md` content-equivalent to pre-change on a fixture |
| 2.7 `AGENTS.md` editing-guidance row + `schemas/README.md` table. | — |

`required-permissions.yaml`: no change (`Bash(*)` + `Write(OUTPUT_DIR/.*)`, verified `:81,133`).

**Phase-2 exit criterion:** a fixture repo with a secret in `config/*.yaml` produces a `.threat-modeling-context.md` where the secret is masked (today it is not — the real bug this phase fixes).

---

## Phase 2b — Business-context enrichment

**Goal:** when `docs/business-context.md` is absent (the common case), still derive real business context deterministically from repo signals, rendered as a `Derived signals` subsection **under** the verbatim file (which stays primary/unchanged). Sits on the Phase-2 `load_repo_context.py`. **Non-negotiable: extract + classify only, never dereference a URL** (see non-negotiable §, bullet 4).

Test-first order:

| Task | Verify (test first) |
|------|---------------------|
| 2b.0 Refactor `_manifest_readers.read_project_manifest` to accept a `repo_root` (decouple from `RenderContext`) so it is callable at context time, not only at render/Phase-11. | existing infobox callers still green |
| 2b.1 `tests/test_business_context.py` — fixtures: package.json+pyproject identity; homepage `stripe.com` + internal `*.corp` URL → classified; `CODEOWNERS` → teams; `LICENSE` → SPDX; docs with `PCI-DSS` → compliance marker; a secret in a manifest field → masked; **a URL present → asserts ZERO network call (no-fetch)**; `CLEANROOM` → whole section suppressed. | red → green |
| 2b.2 **Manifest identity** extractor → `name/description/keywords/homepage/repository/author/license` via the refactored reader. | 2b.1 |
| 2b.3 **URL/domain extractor + classifier** — hosts from manifest urls / `.env.example` / OpenAPI `servers[]`,`contact` / README links; classify via new `data/service-domains.yaml` (domain→category: payment/auth/error/comms/cloud/analytics…); internal-domain heuristic (RFC1918, `.internal`/`.corp`/`.local`/`.svc`, non-ICANN TLD). **No dereference.** Provenance-tag `url-derived` (secondary to recon Cat 25b). | 2b.1 |
| 2b.4 **Ownership/identity** — `CODEOWNERS` (`.github/`,root,`docs/`) → teams; `LICENSE`+manifest license → SPDX / proprietary-vs-OSS posture; OCI labels `org.opencontainers.image.*` (Dockerfile/compose); Helm `Chart.yaml` (description/maintainers/home/sources); git remote. | 2b.1 |
| 2b.5 **Compliance-marker scan** over `docs/**`, README, `.env.example`, ADRs, config: `HIPAA|PCI(-DSS)|GDPR|CCPA|SOC ?2|ISO ?27001|FedRAMP|HITRUST|SOX|PSD2`. Complements Step-4f data-sensitivity, does not replace it. | 2b.1 |
| 2b.6 **Render** `Derived signals` subsection under the verbatim `business-context.md`; each value `secret_scan.scan_text`-masked + wrapped; honor `CLEANROOM`; emit into `.repo-context.json` under `business_context.derived[]`. | live run: signals present on a repo with no `business-context.md`, secrets masked, zero network |
| 2b.7 `schemas/repo-context.schema.json` `business_context` block + `AGENTS.md` note. | schema test |

**Phase-2b exit criterion:** a repo **without** `business-context.md` still yields a `## Business Context` section carrying product identity, external services (by domain), ownership, and compliance markers — secrets masked, **zero network calls** — and under `APPSEC_CLEANROOM=1` the whole section is suppressed.

**Out of Phase-2b MVP:** cross-referencing recon Cat 25b (SaaS via SDK) — it is only available post-Phase-2, so a corroboration merge would need a post-recon refresh (like the cross-repo register rebuild). Deferred.

---

## Phase 3 — Issue ingestion (Option 1 MVP)

**Goal:** optional, config-gated issue source rendered as a separate untrusted-data section. Soft effect (no known-threats coupling — see issue proposal §2). Must honor `CLEANROOM` (satisfies the Phase-1 forward-guard).

| Task | Verify (test first) |
|------|---------------------|
| 3.1 `tests/test_load_issues.py` — fixture gh-api / gitlab JSON → normalized records; author-association filter; label filter; cap; secret-in-body redaction; `gh` absent → graceful empty; **`CLEANROOM` → feature forced off**. | red → green |
| 3.2 `scripts/load_issues.py` (NEW) — provider adapter (`github` via `gh api repos/:o/:r/issues` — NOT `gh issue list --json`, verified; `gitlab` via REST + `GITLAB_TOKEN` + `_url_guard`). Reuse `secret_scan` + 2.0 wrap. `shutil.which` guard like `emit_dep_update_activity.py:172`. Emit `$OUTPUT_DIR/.issues.json`. | 3.1 passes |
| 3.3 `schemas/issues.schema.json` (NEW) + `validate_intermediate` wiring. | schema test |
| 3.4 `config.json` — `issue_context: {enabled:false, provider, labels, states:[open], max_issues:20, author_associations:[OWNER,MEMBER,COLLABORATOR]}` (default OFF). | default run unchanged |
| 3.5 `context-resolver.md` — new Step reads `.issues.json`, renders `## Known Issues (Tracker)` wrapped section + header-table row; `CLEANROOM` suppresses it; `.gitignore` += `.issues.json`. Provenance-tag issues as **search hints, not evidence**. | live run (feature on): fenced section, secrets masked; cleanroom run: absent |
| 3.6 **Flip the Phase-1 forward-guard test from xfail → pass.** | 1.6 now green |
| 3.7 `AGENTS.md` + README file-format + config docs. | — |

**Phase-3 exit criterion:** with `issue_context.enabled=true`, member-authored security-labeled open issues appear fenced + secret-masked; a `--enabled=false` run is byte-identical to today; an `APPSEC_CLEANROOM=1` run suppresses the section regardless of config.

---

## Scope & sequencing (measure vs deliver)

The four phases split into two value classes — be explicit about which goal you are serving before picking a start phase:

- **Phase 1 (clean-room) is an evaluation/integrity feature, not an end-user feature.** It adds zero value to a real customer run (there you *want* the context). Its entire worth is making benchmarks against test apps *trustworthy* (know the tool got no hints), producing an auditable `meta.cleanroom=true` claim, and acting as a regression guard so each new context channel (2b, 3) can't silently widen the cheating surface. It does **not** fix model training-data priors, and the evidence gate stays advisory regardless.
- **Phases 2 / 2b / 3 are capability features** — they make normal runs richer (hardened + secret-scanned context, deterministic business context, optional issue hints).

**Start-phase guidance:**
- Near-term goal = *trustworthy measurement* (e.g. comparing model versions, claiming Juice-Shop recall) → do **Phase 1 first** (prerequisite; otherwise you measure noise).
- Near-term goal = *capability* (richer context, issues) → **Phase 2 → 2b** deliver the most; pull Phase 1 in exactly when the first serious benchmark is due.

Phase 1 was placed first in this plan because it answers the integrity concern that motivated the whole document — not because it has the highest feature value.

---

## What is explicitly OUT of this plan

- **Issue Option 2** (deterministic finding integration via `appsec-issue-classifier` sub-agent + STRIDE evidence-less branch) — separate future plan; gated on it becoming a product goal.
- Any change that makes context deterministically create a `threats[]` row — no input does this today by design (verified; see both proposals §1).

---

## Suggested commit grouping (GitFlow dev)

1. Phase 1 (clean-room) — group: switch plumbing (`run-headless` + env), resolver/recon hard-disables, banner+meta stamp, forward-guard xfail test, doc note. Ships first, standalone.
2. Phase 2 (seam + hardening) — group: fence helper, loader+schema+test, resolver-prompt, org-context-dedup, external-rest-guard.
3. Phase 2b (business-context enrichment) — group: `read_project_manifest` refactor, extractors + `service-domains.yaml`, render subsection, tests (incl. no-fetch + cleanroom).
4. Phase 3 (issues) — group: loader+schema+test, config+resolver-render (+cleanroom suppression, flip forward-guard), docs.

Run targeted tests per phase (CONTRIBUTING.md → "Targeted tests"); `make test` / `make lint` before finishing each phase. Separate pre-existing baseline failures from new ones.

---

## Verified evidence index

- Canonical secret-scan: `scripts/secret_scan.py:2-16` (single source of truth) + importers `qa_checks.py:93`, `publish_threat_model.py:20`, `postscan_secret_check.py:37`, `redact_known_secrets.py:35`, `compose_threat_model.py:12104`
- Duplicate to remove: `load_org_context.py:70`
- URL guard: `_url_guard.py:87,145` (`validate_target_url`, `same_host`)
- Resolver Steps 3–4 categories + limits: `context-resolver.md:199-317`; fence `:613,634`; External-REST `:82-88`; .gitignore `:588`
- gh soft-dep blueprint: `emit_dep_update_activity.py:172`; `gh api` needed (authorAssociation not in `gh issue list --json`, verified gh 2.4.0)
- Permissions cover it: `required-permissions.yaml:81,133`
