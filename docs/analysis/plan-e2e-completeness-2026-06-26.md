# Plan: E2E Completeness — "green ⇒ result correct"

**Date:** 2026-06-26
**Goal:** When all E2E tests are green, it should be proven that (a) the deterministic
tail — generator, contracts, renderer, exports — works correctly **and** (b) the
LLM-generated threat model is factually grounded, complete enough, and above a
quality threshold.

---

## 1. The honest boundary

Proving deterministically that the LLM finds *all* real threats is undecidable
(you'd need the ground truth of all threats — which is exactly the result). What is
achievable instead is a layered, precise "green ⇒ correct":

| Layer | Guarantee when green |
|---|---|
| **A** | Generator/contracts/renderer/exports deterministically correct |
| **B** | LLM output structurally grounded — cites real code, no hallucinated evidence |
| **C** | Known, *planted* vulnerabilities are found (recall against oracle) |
| **D** | Semantic quality above threshold (judge: plausibility, coverage, severity) |

**Completeness = all four layers airtight + breadth of the oracle corpus.**
Recall completeness is a *growing corpus* (vuln classes × languages ×
architectures), not a single green checkmark.

---

## 2. Inventory: the machinery exists but is unwired

| Layer | Checks | Exists | Automatic? | Gap |
|---|---|---|---|---|
| **A** | Structure, determinism, schema, completeness contract | `tests/test_e2e_pipeline.py` (frozen-run), `compose_threat_model.render()` against `data/sections-contract.yaml`, `scripts/validate_intermediate.py`, completeness contract (commit `5b8a9db`) | ✅ `make test` | Export chain + byte-golden + fixture diversity missing |
| **B** | every `file:line` exists, absence-grep-replay | `check_evidence_integrity` (`scripts/qa_checks.py:2929–3051`) | ✅ in the manual `e2e-full` via `qa_checks.py all` | Language/architecture breadth stays limited to the external fixture suite |
| **C** | "these N vulns MUST appear" | `scripts/e2e_fixture.sh` + `<oracle>/verify_threat_model.py` + `expected-signals.json` | ✅ in-tree for `e2e-full`; external suite still manual | Nightly matrix across all language fixtures missing |
| **D** | Plausibility/coverage/severity/actionability/missed-surface | `skills/eval-threat-model/`, `scripts/eval_threat_model.py`, `agents/appsec-eval-judge.md` (5 dims, refute-by-default, exit 0/1) | ❌ purely manual/dev | No gate — exit-1 could ship |

**Key finding:** For C and D everything is built (oracle patterns, judge loop, exit codes) —
it just runs in no automatic run. B is built **and deliberately disabled**, because
the tiny `synthetic-repo` produces noise citations.

### Deterministic "green but broken" holes verified today (layer A)

1. **Export chain in no CI E2E.** `test_e2e_pipeline.py` runs compose → annotate →
   pentest, but **not** `export_sarif.py` / `export_pdf.py` / `export_html.py` /
   `render_review_report.py`. These have only isolated unit tests with **their own**
   hand-built YAML fixtures (`tests/test_export_sarif.py` etc.) — decoupled from the real
   generator output. Otherwise SARIF is only checked structurally in the manual LLM
   `make e2e-full`. ⇒ Schema break in the generator → export contract breaks → `make test` green.
2. **No content/byte golden in CI.** `test_e2e_pipeline.py` only checks structural invariants
   (MS heading, zero-warning, idempotent), not golden equality. The byte-golden diff
   exists (`scripts/threat_fixture.py replay`, scrubbing included), **but skips in CI**
   (`tests/test_threat_fixture.py:184` — needs git-ignored `_last-run` or an external repo).
3. **Fixture monoculture.** The in-tree form stays a Node app, but now contains
   real code paths for injection/SSRF/AuthZ, LLM, multi-tenancy/B2B, secrets and CI.
   Language/framework breadth remains the job of the external fixture suite.

---

## 3. Measures — two tiers

LLM layers cost budget, therefore not per-PR.

### Tier 1 — per-PR, deterministic, CI (no LLM)

- **M1 — Export-chain test on frozen-run. ✅ DONE 2026-06-26.** Implemented in
  `tests/test_e2e_pipeline.py` (not a new file — it already has `rendered_run`/`_run_script`
  and replicates the same frozen-run; docstring "every script a real assessment would
  invoke"). `export_sarif` (pure Python, always runs; validated via `validate_sarif`, one
  result per threat → no silent drop), `export_html`/`export_pdf` conditionally via their
  own `--check-only` preflight. `render_review_report` deliberately NOT in the chain —
  it consumes `.requirements-verification.json`, not `threat-model.yaml`. Closes hole A.1.
- **M2 — In-tree golden master + completeness/integrity assertions. ✅ DONE
  2026-06-26.** Instead of `threat_fixture replay` directly: committed golden
  `tests/fixtures/e2e/golden/{threat-model.md,threat-model.sarif.json}` + byte-diff tests
  (regen via `APPSEC_UPDATE_GOLDEN=1`). Additionally (user requirement "all elements present +
  error-free"): `report_integrity_ok`/100%/0-degraded/0-empty from `.render-integrity.json`,
  curated CORE_SECTIONS (incl. Mitigation Register) + literal CORE_HEADINGS, Mitigation-
  Register-not-empty, placeholder-leak check. Closes hole A.2 + the completeness gap.
- **M3 — reactivate evidence_integrity in E2E. ✅ DONE 2026-06-27.**
  `synthetic-repo` contains real source files; `test_full_run_e2e.py` runs the
  full `qa_checks.py all` battery against the retained `_last-repo/`
  and requires idempotency.

### Tier 2 — Nightly / release gate, with LLM budget

- **M4 — In-tree oracle for the synthetic-repo. ✅ DONE 2026-06-27.**
  Planted vulns + external `expected-signals.json` + recall, secret and
  prompt-injection assertions are wired into `make e2e-full`.
- **M5 — `e2e_fixture.sh` suite as nightly. 🟡 DRIVER DONE 2026-06-27.**
  `make e2e-fixture-suite` runs all 6 language fixtures (Spring, Python, Rust,
  Go, Node/TypeScript, Python/LangChain) with their external recall oracles.
  The scheduled execution still needs CI credentials and the
  separate fixture checkout.
- **M6 — `eval_threat_model.py` as release soft-gate. ✅ DONE 2026-06-27.**
  `make e2e-full-eval` runs the five-part judge/verify loop after a fresh
  quick E2E and fails on confirmed High/Critical model defects.

---

## 4. Coverage matrix (layer C — grows over time)

Recall completeness = filled cells. Each cell = at least one oracle signal that must
appear in at least one fixture.

| STRIDE / class | node-ts | spring-boot | python | go | rust | langchain-llm |
|---|---|---|---|---|---|---|
| Spoofing / AuthN | | | | | | |
| Tampering | | | | | | |
| Repudiation | | | | | | |
| Info Disclosure | | | | | | |
| DoS | | | | | | |
| Elevation / AuthZ (BOLA/IDOR) | | | | | | |
| Injection (SQLi/cmd) | | | | | | |
| SSRF / Deserialization | | | | | | |
| Secret-Exposure | | | | | | |
| LLM (LLM01/07/10) | n/a | n/a | n/a | n/a | n/a | |

> Filling cells = extend `expected-signals.json` per fixture. The matrix is the
> measurable definition of "complete" for recall.

---

## 5. End state

Once Tier 1 + Tier 2 are in place, "green" means:

> Generator/contracts/exports deterministically correct **and** the LLM cites real code
> **and** finds the known (planted) vulns **and** passes the quality judge.

That is the complete definition of correctness, as far as it is achievable at all for an
LLM pipeline.

---

## 6. Order / risk

1. **M1, M2** first — free, CI, closes deterministic "green but broken" immediately.
2. **M3, M4** — done: first real LLM-correctness slice.
3. **M5** — the suite driver is in place; only the credential-bound nightly scheduling remains open externally.

## 7. Housekeeping (on the side)

- Remove the stray directory `tests/fixtures/e2e/_last-run-req\`` (backtick artifact).
- Either activate the unused fixture directories (`b2b-api/`, `multi-tenancy/`, `ci-pipeline/`)
  as oracle fixtures in M4/M5, or delete them.
