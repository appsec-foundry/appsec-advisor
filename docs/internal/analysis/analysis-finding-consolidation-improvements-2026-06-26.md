# Finding Consolidation — Improvements & Verified Findings (2026-06-26)

Investigation triggered by the observation that a `--standard` scan of
OWASP Juice Shop produced 94 findings (Sonnet merger) versus 78 with
`--thorough` (Opus merger) — suspected insufficient consolidation. The goal was
to derive **general** consolidation rules, not to overfit to a specific scan.

All numbers below were measured against the **correct merge-time artifact**
(`.threats-merged.json`, dict-shaped `evidence`, `component_id` populated),
not against the final composed YAML.

## Structural cause of the duplication

The scan fans out **per-component × per-STRIDE**. A shared code object
(e.g. the RSA key in `lib/insecurity.ts:21`) is thereby analyzed under multiple
STRIDE lenses and shows up as N findings with different CWEs. The
dedup layer previously keyed on `(CWE, STRIDE)` and `(/api-endpoint, cwe_family)` —
neither catches "same object, different lens".

## Implemented (verified, tested)

### 1. Catalog rules (`data/consolidation-groups.yaml`)
Four new groups, 6 → 10:
- `missing-audit-logging` (CWE-778/223, cross-component) — 5 → 1
- `absent-dependency-tooling` (CWE-1104/937 + tooling keywords, cross-component) — 4 → 1
- `ci-workflow-supply-chain` (CWE-829/1357 + pin keywords, per-component) — 2 → 1
- `xss-per-component` (CWE-79/80, per-component) — deliberately reverses the earlier
  "all XSS separate" policy: same-component XSS shares a root cause; each
  sink stays as `instances[]`. Cross-component XSS stays separate.

Effect on thorough scan: 78 → 71. Larger under standard (Sonnet consolidates less
up front). **Not** consolidated: CWE-798 hardcoded secrets (RSA/HMAC/CI creds =
different fix owners, Critical not buried under something lower).

### 2. Family-keyed evidence dedup (`model/merge_threats.py`)
`_evidence_identity_key` now keys on the **exploitation family** (`_cwe_family`)
instead of the exact CWE, with an `other`→CWE fallback. This reunifies the same
object under sibling CWEs:
- RSA key: CWE-321 (Spoofing) + CWE-798 (Information Disclosure) → 1 finding
- MD5: CWE-327 + CWE-328 (CWE-328 added to the crypto family) → 1 finding

The `other` family keeps the conservative exact-CWE guard, so `Dockerfile:1`-
/`ci.yml:1` placeholders stay separate (verified against **all** same-line
pairs of the scan: 0 false merges). The dropped CWE is retained in `merged_cwes` for
traceability.

Effect: 78 → 76 before catalog consolidation; **Criticals 10 → 9** (RSA double
count removed).

### 3. Fix: GE- apply bug (`model/merge_threats.py`)
`_apply_decisions` reconstructed groups only via `(CWE,STRIDE)` → `G-` IDs.
Merge decisions from the secondary pass (`GE-` endpoint groups, RC.G.2) ran
into `gid_to_key.get("GE-…") → None → continue` and were **silently
discarded** — the entire secondary pass was dead in the apply path.

Proven with a synthetic GE- group: merge decision 2→2 (discarded) vs.
G- control 2→1 (works). On the juice-shop scan **dormant** (0 GE-
groups generated), but real once the endpoint pass fires.

Fix: new helper `_reconstruct_group_member_indices` rebuilds the
`{group_id: member_indices}` map for **both** passes (`G-` and `GE-`) —
exactly mirrored from `_group_candidates`. Also carries a future `LC-` pass.

## Verification corrections (findings that turned out to be wrong)

Recorded because they save future analyses from the same mistakes:

- **"component_id is unreliable/empty" → WRONG.** `component_id` is fully
  populated at merge time (78/78 in `.threats-merged.json`, 9 components).
  It is empty only in the *final composed* YAML — after consolidation,
  irrelevant for merging. **Lesson:** always measure consolidation behavior against
  `.threats-merged.json`, never against `threat-model.yaml`.
- **"evidence is a list, file_glob rules are dead" → WRONG.** `evidence`
  is a dict at merge time; only composition turns it into a list.
- **"second defect: /user/login pair wrongly forms no GE- group" →
  WRONG.** Correct behavior: the two threats have different
  families (other vs authn) and different `eps[0]`.

## Open (proposed, NOT implemented)

- **Rule 2 — allowlist→default flip.** Instead of consolidating only on a hit in
  a hand-listed CWE group: default = ≥2 findings with the same
  (CWE, component) → systemic, with a small exclusion denylist for classes where
  each sink is individually exploitable (injection: 89/79/94/78/22/611). Generalizes
  to CWEs the catalog never anticipated — the biggest lever against
  standard-mode bloat. Untested, larger design change.
- **Rule 4 — severity-spread guard.** A consolidation group spanning Critical +
  something lower must not let the Critical disappear as an instance.
  Precautionary; not triggered in the scans studied.
- **Full agent-adjudicated `LC-` location pass.** The deterministic
  family dedup (#2) covers the high-confidence case. An additive `LC-` candidate
  pass (file:line, line>1, distinct CWE/STRIDE → to the merger agent) would also cover
  uncertain co-location pairs. The apply path is now prepared for it
  (see #3).
