# Fixplan — coverage-threat `scenario` + dot-directory path backticking

Date: 2026-07-27 · Base commit: `8d66de0b` (branch `feature/trust-boundaries-first-class`)
Status: implemented, UNCOMMITTED · full suite GREEN (10341 passed, 93 skipped)
Companion patch: `fixplan-scenario-and-dotpath-2026-07-27.patch`

Two real plugin defects found while running `/appsec-advisor:create-threat-model`
against juice-shop on 2026-07-27. Both are deterministic and reproduce on any repo
that hits the same code path — neither is a model/flake issue.

## Re-applying after a branch reset

Fast path — the patch is verified to apply cleanly onto `8d66de0b`:

```bash
cd <appsec-advisor-repository>
git apply --check docs/internal/analysis/fixplan-scenario-and-dotpath-2026-07-27.patch  # dry run
git apply         docs/internal/analysis/fixplan-scenario-and-dotpath-2026-07-27.patch
python3 -m pytest tests/test_arch_coverage_bridge.py tests/test_apply_prose_fixes.py \
                  tests/test_apply_prose_fixes_coverage.py -q
```

If the patch no longer applies (the base moved), re-implement from §Bug 1 / §Bug 2
below — each carries the exact edit. **Note:** this `.md` and the `.patch` live inside
the repo. A `git reset --hard` keeps them (untracked), but `git clean -fd` removes them —
copy both out of the tree before doing that.

---

## Bug 1 — every architecture-coverage threat was missing the required `scenario`

**Symptom.** Mid-run hard abort at the post-Stage-1 gate:

```
INVALID: threats[66]: 'scenario' is a required property
```

`validate_intermediate.py` exited 1 against `threat-model.yaml`, `RUN_ABORTED`. In the
juice-shop run this was T-070 (`ARCH-TLS-001`, "Data disclosure through cleartext
transport"). Only one coverage threat existed, hence exactly one failure — with more
rules firing it fails just as hard.

**Root cause.** `scripts/arch_coverage_to_threats.py::_build_threat` never set
`scenario`, and nothing backfills it downstream (`merge_threats.py:1598/1724` only
rewrite an existing value). Meanwhile `schemas/threat-model.output.schema.yaml` lists it
in `required` for `threats[]`:

```
required@/properties/threats/items: ['id','component','stride','title','scenario','likelihood','impact','risk']
```

So **any** promoted coverage/hypothesis threat fails the gate. Verify the root cause is
still present with:

```bash
grep -c scenario scripts/arch_coverage_to_threats.py   # 0 == bug present
```

**Fix.** New helper `_scenario_for_threat()` synthesises the prose deterministically from
fields the record already carries, and `_build_threat` sets `"scenario"` right after
`"title"`. This copies the pattern of the sibling coverage emitter
`coverage_checks.py` (`suggested_threat.scenario`, lines ~149 and ~413) — an f-string
over existing fields. No LLM, and no new YAML field to keep in sync across the 15
shipped rules.

Two deliberate design points, both load-bearing:

- **The matched `signal` text is NOT interpolated.** `ARCH-SECRET-001` matches on literal
  key/credential material, and `scenario` renders user-visible in the §8 story card,
  downstream of the secret masker. Location (`file:line`) only.
- **Must clear two constraints, not one:** presence (schema) *and*
  `validate_intermediate._check_scenario_stripped_length` (≥ 10 non-whitespace chars).
  The no-evidence branch still has to produce a sentence.

Inserted above `_build_threat` in `scripts/arch_coverage_to_threats.py`:

```python
def _scenario_for_threat(
    *,
    source: str,
    rule_id: str,
    title: str,
    cwe: str,
    spaced_stride: str,
    evidence: list[dict],
    hypothesis_id: str | None,
) -> str:
    loc = ""
    first = _evidence_for_threat(evidence)
    if first:
        loc = f"`{first['file']}:{first['line']}`" if first.get("line") else f"`{first['file']}`"
    n = len([e for e in evidence or [] if (e.get("file") or "").strip()])
    extra = f" and {n - 1} further site(s)" if n > 1 else ""

    if source == "threat-hypothesis":
        origin = f"Architecture-coverage hypothesis {hypothesis_id or rule_id}"
        verb = "was confirmed against the codebase"
    else:
        origin = f"Architecture-coverage rule {rule_id}"
        verb = "matched this anti-pattern"

    where = f" at {loc}{extra}" if loc else " in this repository"
    return (
        f"{origin} {verb}{where}. {title}: the condition is observable in the "
        f"code as cited, weakening the control this rule checks and exposing the "
        f"affected surface to {spaced_stride} ({cwe})."
    )
```

and in the `threat` dict of `_build_threat`, between `"title"` and `"cwe"`:

```python
        "scenario": _scenario_for_threat(
            source=source,
            rule_id=rule_id,
            title=title,
            cwe=cwe,
            spaced_stride=spaced_stride,
            evidence=evidence,
            hypothesis_id=hypothesis_id,
        ),
```

(The full docstring with the rationale is in the patch — keep it, it is the only place
the secret-leak reasoning is written down.)

**Tests** — 4 appended to `tests/test_arch_coverage_bridge.py`:
`test_anti_pattern_threat_carries_scenario`,
`test_confirmed_hypothesis_threat_carries_scenario`,
`test_scenario_present_even_without_evidence_location`, and
`test_every_bridged_threat_has_scenario_for_all_shipped_rules` — a contract sweep that
drives one candidate per rule in `data/architecture-coverage-rules.yaml`, so a newly
added rule cannot silently reintroduce a scenario-less threat.

---

## Bug 2 — dot-directory paths never backticked (had TWO causes)

**Symptom.** The run ends `QA: repair required` instead of `pass`. `.qa-repair-plan.json`
holds one item that the repair loop structurally cannot clear
(`actionable: false`, `fragments_to_rewrite: []`):

```
reference-format: F-010: un-backticked locator '(.github/workflows/image_actions.yml:33)'
  — must be (`.github/workflows/image_actions.yml:33`)
```

It is non-actionable because the string is *composed*, not authored in any fragment —
`ms-verdict.json` only carries `refs: ["T-010"]`; the composer expands it into the title.

> **This is the important part for a re-implementation.** Fixing only the regex looks
> right (the isolated unit test goes green) but changes **nothing** in the real report.
> Both causes must be fixed together. Verify against the actual document, not just
> `_wrap_line`.

### Cause 2a — `_PATH_RE` cannot match a leading dot segment

`scripts/apply_prose_fixes.py`, the pattern began `[A-Za-z]`, so on
`.github/workflows/image_actions.yml:33` the match started one char late at `github`.
The adjacency guard further down (`if before in "._": continue`, ~line 735) then
*correctly* discarded it — wrapping would have produced a half-formatted
``.`github/...` ``. Net effect: 0 changes, path stays bare.

Reproduce:

```python
# routes/fileUpload.ts:83  -> 1 change  (wrapped)
# .github/workflows/x.yml  -> 0 changes (bare)  == bug present
```

Fix — add `\.?` to the front of the `path` group:

```python
    r"(?P<path>\.?[A-Za-z][\w.-]*/[\w./-]+\.(?:"
```

Safe because greedy `[\w.-]*` still claims the whole token when the dot is interior:
`v1.github/x.yml` matches from `v`, so this only fires on a real dot-root.

### Cause 2b — the whole `<blockquote>` body was skipped

Both `apply_fixes` (~line 1269) and `apply_code_formatting` (~line 1359) did
`out.append(raw); continue` for **every** line between `<blockquote` and `</blockquote>`,
so those lines never reached `_wrap_line` at all. The §1 Management-Summary
critical-gaps list is the only styled blockquote the report emits — and it is exactly
where the offending locator lives.

Fix — new helper next to the mask regexes:

```python
def _html_block_body_wrappable(stripped: str) -> bool:
    return "<" not in stripped
```

and in **both** loops, replacing the unconditional `out.append(raw)`:

```python
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            if _html_block_body_wrappable(stripped):
                new_line, n_bq = _wrap_line(line)
                inline_fixes += n_bq        # `total += n_bq` in apply_code_formatting
                out.append(new_line + nl)
            else:
                out.append(raw)
            continue
```

Conservative boundary: any line carrying markup (the wrapper tags, `<br/>`, inline HTML)
is still left byte-identical. Fence tracking keeps priority — it is checked earlier in
the loop — so a snippet inside the quote stays code.

### Two pre-existing tests had to change

`tests/test_apply_prose_fixes_coverage.py` pinned "the whole blockquote block is
skipped". That file's own docstring says *"Pins current behavior (test-files-only
campaign). No producer edits."* — i.e. characterization tests that captured the bug, not
a design decision. Renamed and re-pointed at the corrected behaviour, keeping the
genuinely useful assertions (wrapper tags and fences stay untouched):

- `test_apply_fixes_blockquote_block_left_untouched`
  → `test_apply_fixes_blockquote_wrapper_untouched_body_wrapped`
- `test_apply_code_formatting_skips_fence_and_blockquote_and_heading`
  → `test_apply_code_formatting_skips_fence_and_heading_but_wraps_blockquote_body`

If a future session sees these two fail, that is the signal one of the two causes was
reverted — not that the tests are wrong.

**Tests** — 10 appended to `tests/test_apply_prose_fixes.py`: dot-root wrapping in plain
prose and in the linked-title tail, `.circleci`/`.claude` variants, an interior-dot
over-reach guard, idempotency, blockquote body wrapping via both entry points,
wrapper-attribute safety, and fence-inside-blockquote precedence.

---

## Verification performed

Red-green — the fixes were reverted (`git stash`) to confirm the new tests actually
catch the defects, then restored:

| | without fix | with fix |
|---|---|---|
| Bug 1 tests | 4 failed | 4 passed |
| Bug 2 regex tests | 3 failed, 2 passed (guards) | 5 passed |
| Bug 2 blockquote tests | 2 failed, 3 passed (guards) | 5 passed |

End-to-end on a **copy** of the real report (original untouched):

```bash
cp docs/security/threat-model.md /tmp/tm.md
python3 scripts/check_reference_format.py /tmp/tm.md   # 1 violation
python3 scripts/apply_prose_fixes.py      /tmp/tm.md
python3 scripts/check_reference_format.py /tmp/tm.md   # reference-format: clean
diff docs/security/threat-model.md /tmp/tm.md          # exactly 2 lines
```

The diff touches only line 102 (the reported F-010 locator) and line 98
(`routes/search.ts:23`) — a second latent bare path the same blockquote skip had been
hiding, which `check_reference_format.py` does not flag because it only inspects
parenthesised locators. No collateral rewrites.

Full suite after both fixes: **10341 passed, 93 skipped, 0 failed** (~8m38s).

## Effect on a subsequent run

- Bug 2 takes effect on any recompose, including `--rerender`.
- Bug 1 only takes effect on a run that re-executes Stage 1 — the field is written when
  the bridge builds the threat.

## Out of scope (noted, deliberately not fixed)

`ARCH-TLS-001` produced 8 matches in the juice-shop run that are all `http://` inside JS
author comments (`frontend/src/assets/private/ShaderPass.js:2` etc.), making T-070 a
false positive. That is a rule-precision problem in
`data/architecture-coverage-rules.yaml` (the `(?<![a-z])http://…` positive signal does
not exclude comment context), not a code defect — separate change.
