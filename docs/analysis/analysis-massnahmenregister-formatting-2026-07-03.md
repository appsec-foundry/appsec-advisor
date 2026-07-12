# §9 Mitigation Register — formatting analysis

**Date:** 2026-07-03 · **Scope:** analysis only, no changes applied.
**Reference run:** `/home/user/juice-shop/docs/security-thin/threat-model.md` (§9 = lines 3169–4540).
**Single renderer:** `scripts/compose_threat_model.py` (per-mitigation card loop starts at `:14869`).

Three defects were reported. All three reproduce in §9. Root causes and every producer
site are below. Per AGENTS.md §4, each fix is bidirectional (producer + schema + consumer +
validator + tests) — noted per issue.

---

## Issue 1 — Code refs with line *ranges* break their backtick formatting

### Symptom
Single line refs wrap correctly (`` `insecurity.ts:55` ``), but **ranges split**: the backtick
closes before the `-NN` suffix. Confirmed in §9 (verbatim user example included):

| md line | rendered |
|---|---|
| 3381 | `` `chat.ts:123`-131 `` |
| 3562 | `` `request.interceptor.ts:13`-16 `` |
| 3759 | `` `oauth.component.ts:70`-78 `` |
| 4402 | `` `request.interceptor.ts:20`-25 `` ← the reported case |
| 4499 | `` `pr-compliance.yml:433`-465 `` |

Separate, unrelated variant: `Dockerfile:22-41` (line 2338, §6) has **no backticks at all** —
because `Dockerfile` has no dotted extension, so it matches none of the wrappers.

### Root cause (systemic)
Every locator regex in the codebase uses `(?::\d+)?` — a single `:line`, **no range branch**.
Input `file.ts:20-25` matches only `file.ts:20`; the trailing boundary lets `-25` fall outside
the wrapped span. The fix everywhere is `(?::\d+)?` → `(?::\d+(?:-\d+)?)?`.

### Producers that PRODUCE the split (backtick-wrappers)
- **`scripts/compose_threat_model.py:14530` — `_INLINE_CODE_RE` (via `_wrap_inline_code`:14560) —
  this is the PRIMARY producer of the §9 mitigation-register breaks.** The §9 "How" steps are
  wrapped by compose's own inline-code pass, not by `apply_prose_fixes`. Its `(?::\d+)?\b` matches
  `request.interceptor.ts:20`, the `\b` sits between `0` and `-`, so `-25` is left outside.
  **Verified 2026-07-03** against the real string: CUR `` (`request.interceptor.ts:20`-25) `` →
  widened `` (`request.interceptor.ts:20-25`) ``.
- `scripts/apply_prose_fixes.py:126-136` — `_PATH_RE` (same bug in general prose, e.g. §6/§7 path form).
- `scripts/apply_prose_fixes.py:183` — `_BARE_FILENAME_RE` (same bug, bare-filename form).
- `scripts/walkthrough_renderer.py:602` — `_STEP_FILELINE_RE` (§3 attack-step prose, same bug).

All four share the identical `(?::\d+)?` defect and the same `(?::\d+(?:-\d+)?)?` fix. The two
`apply_prose_fixes` producers were **verified** (import + real strings): broken → fixed, single-line
unchanged (no regression), and `file.ts:5-abc` correctly leaves the non-numeric `-abc` outside.

### Also-affected (truncate/mis-normalize ranges — secondary breakage)
- `scripts/compose_threat_model.py:1711` — `_mitigation_locator`: captures only `foo.ts:186`,
  silently **dropping** the range before it is backticked.
- `scripts/compose_threat_model.py:1735` — `_TRAILING_LOC_TOKEN` and `:1613` legacy stripper:
  fail to recognise a range-bearing trailing locator → can append a duplicate `` (`file:line`) ``.

### Validator is blind to the bug (false pass)
- `scripts/check_reference_format.py:32` — `_LOC` also ends in `(?::\d+)?`, so a broken
  `(server.ts:186-188)` is not even detected. Fixing producers requires teaching this range too.

### An existing repair proves the fix, but is scoped to one place
- `scripts/walkthrough_renderer.py:648` — `_STEP_RANGE_MERGE_RE = re.compile(r"`([^`\n]+:\d+)`-(\d+)\b")`
  re-merges `` `file:186`-188 `` → `` `file:186-188` `` — **but only inside `_format_step_code`**.
  Nothing equivalent runs in `apply_prose_fixes.py`, so the artifact survives everywhere else.

### Fix direction (not applied)
1. Widen the three producer regexes (`apply_prose_fixes.py:126,183`, `walkthrough_renderer.py:602`)
   to `(?::\d+(?:-\d+)?)?`, and the extractor at `compose:1711`.
2. Widen `check_reference_format.py:32` `_LOC` to the same, so ranges are validated not ignored.
3. Handle extension-less known filenames (`Dockerfile`, `Makefile`, `Jenkinsfile`, …) so
   `Dockerfile:22-41` gets wrapped — this is a distinct sub-issue from the range bug.
4. Tests: add range + Dockerfile cases to the prose-fix / reference-format test suites.

---

## Issue 2 — Example code block has no explanatory sentence, scope, or file target

### Symptom
§9 contains ~46 fenced code blocks. Only **9** lead with a `// filename` comment; **none** carry
a lead-in sentence. The reader cannot tell whether the snippet is the *complete* fix or an
illustrative fragment, nor which file it belongs in. Inconsistent: some snippets embed
`// lib/insecurity.ts` (M-035, M-037), most don't.

### Producer
`scripts/compose_threat_model.py:15228-15247` emits the fence **bare** — no preceding or trailing
prose:
```python
if how_code:
    lines.append(f"```{how_lang}"); lines.append(how_code.rstrip()); lines.append("```")
elif code_example:
    ...
    lines.append(f"```{how_lang}"); lines.append(ce); lines.append("```")
```
`**Verification:**` is rendered separately at `:15276-15279` (not as an explanation of the code).
The only labelled case is the *extra* multi-CWE blocks at `:15252-15261` (`_Additional pattern for
[CWE-…]:_`); the primary block gets nothing.

### Where the code comes from (three sources, priority order)
1. `m.get("how_code")` (yaml field) — `:15057`, rendered `:15228`.
2. `m.get("code_example")` (yaml, or harvested from the addressed threat's
   `remediation.code_example` / top-level `code_example` at `:15117-15132`) — rendered `:15233`.
3. CWE fallback table `_MITIGATION_CWE_SNIPPETS` (`:3405+`, e.g. CWE-798 at `:3486-3497`), used
   when neither field exists (harvest `:15156-15185`). These entries carry only `code`/`lang`/
   `verification` keys — **no description, no file target**.

### Fix direction (not applied)
- Emit a deterministic lead-in line before the fence, e.g.
  ``> Illustrative fix for **`lib/insecurity.ts:55`** — apply alongside the steps above.``
  driven by the already-resolved `**File:**` value (resolution chain `compose:15010-15034`) plus a
  fixed "complete vs illustrative" qualifier.
- Drive the in-snippet `// filename` uniformly (or drop it) rather than depending on whether the
  LLM/author happened to include it.
- Bidirectional: the qualifier needs a source of truth — either a new schema field
  (`code_caption` / `code_scope` on `mitigation-overrides.additions[]`, threaded through
  `emit_finding_fix_mitigations.py` + `build_threat_model_yaml.py`), or purely deterministic
  synthesis in compose from `File` + a constant. `_MITIGATION_CWE_SNIPPETS` entries would each
  need a caption/scope. Add render + schema tests.

---

## Issue 3 — References are plain and inconsistent (CWEs unlinked, URLs untitled)

### Symptom
Across §9's 51 references:
- **27× bare `CWE-NNN`** — not linked at all (e.g. `**Reference:** CWE-798`).
- **24× bare URLs** — linked-by-raw-URL but **untitled** (owasp cheatsheets ×17, genai.owasp ×3,
  docs.github ×2, owasp.org ×1, docs.sigstore ×1).

Confirmed: **all 27 bare CWEs are the §9 Reference lines**; the only other bare CWEs (6) sit inside
§3 mermaid fences (correctly skipped). So the §9 reference render is demonstrably not linkified.

### Producer
`scripts/compose_threat_model.py:15284-15286` emits the value **verbatim**:
```python
ref = (m.get("reference") or mitigation_reference or "").strip()
if ref:
    lines.append(f"**Reference:** {ref}")
```
No linkifier, no `_wrap_inline_code`, no title lookup.

### Data source
- Primary: LLM sidecar `mitigation-overrides.additions[].reference`, merged in
  `scripts/build_threat_model_yaml.py:1169` (collision) / `:1219` (new). Whatever raw string the
  analyst wrote is printed.
- Fallback: addressed threat's `remediation.reference`, harvested at `compose:15102-15116`
  (`mitigation_reference`), with a guard that suppresses requirement-IDs.

### Assets that already exist but are NOT wired to this render path
- `scripts/compose_threat_model.py:10681` — `_linkify_bare_cwes()` turns `CWE-NNN` → linked, but
  **untitled** (`[CWE-798](…)`, never `[CWE-798: Use of Hard-coded Credentials](…)`), and (per the
  27/27 evidence) **does not reach the §9 Reference lines** — its global passes at `:9468`/`:9753`
  run before/outside the §9 fragment assembly.
- `data/cwe-taxonomy.yaml` — CWEs under the `cwes:` key, each with `title` + canonical
  `https://cwe.mitre.org/…` URL, plus `owasp_top10_2021_titles`/`_urls` and `owasp_llm_top10` maps.
  **Not loaded by `compose_threat_model.py`.**
  **Coverage caveat (verified 2026-07-03):** the taxonomy covers **18 of the 22** distinct CWEs
  cited in §9 references — **4 are missing: CWE-20, CWE-330, CWE-602, CWE-620.** So
  `normalize_reference()` MUST NOT assume full coverage: derive the URL from the number always
  (`https://cwe.mitre.org/data/definitions/<n>.html`) and add the `: <title>` only when the
  taxonomy has it — OR extend `cwe-taxonomy.yaml` additively with the 4 (and treat "cited-CWE-not-
  in-taxonomy" as a lint the pipeline surfaces).
- `data/appsec-bestpractices-baseline.yaml` — class → OWASP CheatSheet URL map (feeds baseline
  mitigations, not the reference formatter).

### Missing
- No titled-CWE-link helper anywhere (`CWE_TITLES` / `cwe_link` grep is empty in compose).
- No routine to turn a bare owasp/genai URL into a titled markdown link.
- `check_reference_format.py` validates only inline `[F/T/M-NNN](#…)` anchor formatting (3 rules);
  it does **nothing** about the `**Reference:**` value — no link-required, no CWE/URL consistency.

### Fix direction (not applied)
- Add `normalize_reference(ref)` invoked at the emission point (`compose:15286`) that produces a
  **consistent titled markdown link** for every reference:
  - `CWE-NNN` → `[CWE-NNN: <title>](<mitre url>)` via `data/cwe-taxonomy.yaml`.
  - bare URL → `[<title>](url)`, title derived from the taxonomy's OWASP map / a slug of the path.
  - optionally attach both a CWE link and a cheatsheet link where the class map has one.
- Load `cwe-taxonomy.yaml` in compose (currently unread there).
- Extend `check_reference_format.py` to require §9 `**Reference:**` be a titled link (guard against
  regressions to bare strings).
- Bidirectional: compose loader + new helper + validator + tests; no schema change needed if the
  raw `reference` string stays free-form and normalisation is deterministic at render.

---

## Issue 4 — §3 Attack Steps: not attacker-POV, over-detailed

### Symptom
§3 "Attack Steps" read as passive code-review notes, not attacker actions, and carry excessive
implementation detail. From §3.1 (F-002):
- Step 1 (padding): *"Send the crafted payload to the endpoint backed by `lib/insecurity.ts:55`."*
  — generic, code-location framed, no attacker action.
- Step 2 (LLM): *"`verify()` at `lib/insecurity.ts:55` calls `jws.verify(token, publicKey)` without a
  third argument or an `algorithms:` allowlist…"* — the **code is the subject**; dense internals.

### Two producers
1. **LLM `threat.scenario`** (authored by the STRIDE analyzer). `walkthrough_renderer.render_attack_steps`
   (`:680`) only sentence-splits it — it cannot change POV. Governing guidance
   `agents/shared/prose-style.md` **Rule 1 was already updated** (2026-07-03) to require
   "attacker as the subject", but **this run's scenarios were authored 2026-07-02, before the
   update** → they predate the fix. Remaining gap: Rule 1 addresses POV but not the *volume* /
   over-detail ("far too much unnecessary detail"). Fix: (a) re-run to pick up Rule 1; (b) add an
   explicit detail cap to the scenario guidance (attacker action as main clause; ≤1 `file:line` per
   step; code mechanism as a subordinate "because…" clause, not the sentence).
   **Caveat: verifiable only after a live re-scan — not deterministically reproducible on the
   existing juice-shop output.**
2. **Deterministic padding steps** (used to top up short scenarios, PREPENDED at `:769-772`):
   - Hardcoded fallback `walkthrough_renderer.py:737-739`:
     *"Send the crafted payload to the endpoint backed by `{file}:{line}`."*
   - Per-CWE `data/walkthrough-templates/*.yaml` → `attack_steps_template`, e.g. cwe-89:
     *"Identify the vulnerable input parameter — `{component}` interpolates it directly into a SQL
     string at `{file}:{line}`"*.
   Both are code-location framed, not attacker-action voice. **These are deterministic and can be
   rewritten + verified now** (rewrite templates + the fallback to attacker-action voice; test in
   `tests/test_walkthrough_renderer.py`).

---

## Issue 5 — §3 walkthrough titles are unwieldy / unclear

### Symptom
Headings read `### 3.X {finding-weakness} Attack against {broad component zone}`:
- `3.1 Insecure JWT Verification Attack against Authentication & Identity`
- `3.2 SQL Injection Attack against Authentication & Identity`
- `3.3 SQL Injection Attack against Backend REST API`

User wants concise, feature-scoped, e.g. **`SQL Injection against Login`** — drop the clunky
"Attack", and target the concrete *feature/function*, not the broad zone.

### Producers
- `scripts/walkthrough_renderer.py:1074-1077` — heading assembly; `_connector = " Attack against "`
  (`:1075`).
- `scripts/walkthrough_renderer.py:236` — `_attack_target_label`: **prefers the broad component
  curated name** ("Authentication & Identity") over the more specific file/feature label; only
  falls back to a prettified file basename when no component name exists. This preference is the
  reason the target reads as a zone, not a feature.
- `scripts/walkthrough_renderer.py:215` — `_weakness_class` (the `{Weakness}` half; fine as-is).
- Contract doc: `agents/phases/phase-group-finalization.md:464` (documents `{Weakness} Attack
  against {Target}` and the target-derivation precedence — **must change with the code**).
- Tests: `tests/test_walkthrough_renderer.py:557,576,598-617` assert the current `"… Attack against …"`
  format and `_attack_target_label(...) == "Authentication & Identity"` — **must change with the code**.

### Design note (why it currently prefers the zone)
The component name was deliberately preferred to (a) differentiate two Critical findings that share a
weakness class and (b) keep GitHub-anchor-stable headings (no em-dash / file:line). A feature-scoped
label still satisfies both *if* it stays unique per finding — need a deterministic tiebreak when two
findings share weakness+feature (e.g. keep the file stem). Bidirectional: renderer + contract doc +
tests.

---

## Summary of producer sites (single source: `scripts/compose_threat_model.py` unless noted)

| Issue | Root cause | Primary fix site |
|---|---|---|
| 1 range refs | `(?::\d+)?` never allows `-NN` | **§9 primary: `compose:14530` `_INLINE_CODE_RE`** (via `_wrap_inline_code:14560`); also `apply_prose_fixes.py:126,183`; `walkthrough_renderer.py:602`; `compose:1711`; validator `check_reference_format.py:32` |
| 1 Dockerfile | no dotted extension → matched by nothing | same three prose wrappers (add extension-less filename set) |
| 2 code block | fence emitted bare, no caption/scope/file | `compose:15228-15247` (+ `_MITIGATION_CWE_SNIPPETS` @3405) |
| 3 references | raw string, no linkify/title, taxonomy unwired | `compose:15284-15286`; wire `data/cwe-taxonomy.yaml` (4 CWEs missing); extend validator |
| 4 attack steps | LLM code-as-subject + generic template padding | prompt `agents/shared/prose-style.md` Rule 1 (+detail cap); `walkthrough_renderer.py:737-739`; `data/walkthrough-templates/*.yaml` |
| 5 §3 titles | "Attack against" + broad zone target | `walkthrough_renderer.py:1075,236`; doc `phase-group-finalization.md:464`; `tests/test_walkthrough_renderer.py` |
