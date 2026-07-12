# Proposal: Context-Resolver Hardening (deterministic repo-doc extraction)

**Status:** Analysis only — no implementation. 2026-07-12.
**Scope:** Harden the *existing* context sources in `appsec-context-resolver`. Distinct from — but shares the deterministic-loader pattern with — `proposal-issue-tracker-ingestion-2026-07-12.md` (which adds a *new* source). This proposal can ship independently and is valuable without the issue feature.

---

## TL;DR

`agents/appsec-context-resolver.md` is a ~750-line LLM prompt that mostly does deterministic work — finding repo docs and reproducing them verbatim. Only the cross-repo sub-step (A/B) was ever extracted to Python (`load_related_repos.py`). This violates the plugin's own non-negotiable *"prefer deterministic Python over LLM for final artifacts."*

**Headline:** extract **Steps 3–4 (4a–4i)** into a deterministic `scripts/load_repo_context.py`, mirroring `load_related_repos.py` / `load_org_context.py`. This fixes 5 verified weaknesses at once, is testable, cheaper (haiku/no-LLM), and collapses `maxTurns: 25` to a few script calls.

---

## Verified weaknesses (by priority)

| # | Problem | Evidence | Impact |
|---|---------|----------|--------|
| 1 | Steps 3–4 (4a–4i) are LLM-driven — the model reproduces up to 200 lines × ~10 file categories **verbatim** | `context-resolver.md:205,226,315,323` | truncation/paraphrase drift, expensive (sonnet), untestable |
| 2 | **No secret-scan on any ingested content** — resolver only notes secret *names* in data-model/deploy summaries; env/config templates (`.env.example`, `config/*.yaml`, `appsettings.json`) go in verbatim | verified grep: only `:280,296` (names); `load_org_context._SECRET_PATTERNS:70-76` exists but is not applied here; External-REST content (`:82-90`) also unscanned | secrets in config templates land unredacted in `.threat-modeling-context.md` |
| 3 | Untrusted-data wrapping is **LLM-dependent** — model must emit `<untrusted-data>` tags "literally" | `:613,634` | fence can slip; a deterministic loader would guarantee it (`load_org_context.WRAPPER_PREAMBLE:57-66`) |
| 4 | **Two divergent untrusted conventions** coexist: XML-ish tag (`<untrusted-data source=…>`) vs HTML-comment preamble | resolver `:613,634` vs `load_org_context.py:57-66` | downstream agents must recognize both forms |
| 5 | **External REST (Step 2) has no `_url_guard`** — bare `curl` in the prompt, no SSRF allow-list / redirect handling | `:82-88` vs `load_related_repos._fetch_url` (`validate_target_url` + `_SameHostRedirectHandler`, `:179-209`) | config-controlled → lower risk, but inconsistent hardening |

---

## Proposed design

**`scripts/load_repo_context.py`** — deterministic scanner for Steps 4a–4i (and optionally Step 3 business-context). Mirrors the two existing loaders:

- Walk the documented file categories (security policy, arch docs, ADRs, OpenAPI, deploy/IaC, data model, env templates, changelog) with the same line-limits already specified in `context-resolver.md:218-317`.
- Apply the **existing** canonical secret scanner `secret_scan.scan_text` (`scripts/secret_scan.py` — single source of truth, masking-aware, FP-suppressed) to **every** ingested body → redact-or-skip with a manifest reason (fixes #2). NOTE: `load_org_context.py:70 _SECRET_PATTERNS` is a weaker duplicate — replace it with `secret_scan`, do not extend it.
- Emit each block already wrapped in the canonical untrusted fence — pick **one** convention and converge (fixes #3, #4). Recommend keeping the `<untrusted-data source="…">` XML form (downstream consumers already parse it in Step 5) and porting `load_org_context` to it.
- Output a structured JSON (`$OUTPUT_DIR/.repo-context.json`) + a manifest; the resolver prompt then only **renders** it into `.threat-modeling-context.md` (same split as the cross-repo helpers: "helpers do the work, prompt renders").
- Validate output against a new `schemas/repo-context.schema.json` (drift guard).

**Step 2 (External REST):** route the `curl` through the same `_url_guard.validate_target_url` used by `load_related_repos` (fixes #5). Either call the loader for it too, or add a tiny guarded-fetch helper.

**What stays LLM:** nothing in Steps 3–4 needs judgment — it is find-file + extract-known-fields + wrap. The threat *reasoning* over this context remains with the STRIDE analyzer / threat-analyst, unchanged.

---

## Files touched (bidirectional contract, AGENTS.md §4)

| File | Change |
|------|--------|
| `scripts/load_repo_context.py` | NEW — deterministic scanner + secret-scan + wrap |
| `schemas/repo-context.schema.json` | NEW — validates loader output |
| `agents/appsec-context-resolver.md` | EDIT — replace Steps 3–4 prose with a helper call + render-only Step 5; route Step 2 through `_url_guard` |
| `scripts/load_org_context.py` | EDIT — converge on the single untrusted-fence convention (#4) |
| `scripts/secret_scan.py` / `scripts/_url_guard.py` | reuse as-is (both already single-source); EDIT `load_org_context.py` to drop its duplicate `_SECRET_PATTERNS` and call `secret_scan.scan_text` |
| `tests/test_load_repo_context.py` | NEW — drift guard (fixtures per category + a secret-redaction case) |
| `AGENTS.md` / `schemas/README.md` | EDIT — editing-guidance row + schema table |

`required-permissions.yaml`: **no change** (blanket `Bash(*)` + `Write(OUTPUT_DIR/.*)` already cover it — verified `:81,133`).

---

## Sequencing vs the issue-ingestion proposal

Both want the same pattern. Order-independent, but note the synergy:
- Building `load_repo_context.py` first establishes the shared secret-scan + wrap + url_guard module that `load_issues.py` then reuses verbatim.
- Neither blocks the other. This hardening is worth doing on its own (it removes a verbatim-reproduction drift risk and an unredacted-secret path that exist today).

**Recommendation:** ship this hardening independently; treat the shared secret-scan/wrap module as the deliberate seam both features lean on.

---

## Verified evidence index

- LLM-verbatim Steps 3–4: `appsec-context-resolver.md:205,226,315,323`
- No secret-scan (only names): `appsec-context-resolver.md:280,296`; External-REST unscanned `:82-90`
- Secret-scan + wrapper precedent: `load_org_context.py:57-66,70-76`
- Untrusted-fence conventions: `appsec-context-resolver.md:613,634` vs `load_org_context.py:57-66`
- External-REST no url_guard: `appsec-context-resolver.md:82-88` vs `load_related_repos.py:179-209,191`
- Deterministic-loader precedent: `load_related_repos.py` (schema-validated, url_guard, JSON out)
- Permissions cover it: `data/required-permissions.yaml:81,133`
