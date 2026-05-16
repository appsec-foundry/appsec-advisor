# Adding a new section to `threat-model.md`

Step-by-step walkthrough for adding a new section to the generated threat model. Use this when adding entirely new content (e.g. a §X "Cloud Posture" section), not when adjusting an existing section's body. The mechanical points where drift can creep in are flagged with **Drift hazard** notes.

Five files must be touched in sequence. Skipping any one of them either (a) silently strips the new section out of the rendered Markdown or (b) breaks a downstream validator. The same five files own the registry maps documented in [`schema-invariants.md` §4f](./schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth).

## 1. Declare the section in the contract

Edit `data/sections-contract.yaml`:

```yaml
document:
  order:
    - id: cloud_posture          # snake_case, used everywhere as section_id
      heading: "Cloud Posture"   # human-readable § heading
      fragment_type: data         # one of: data | hybrid | markdown | computed
      fragment: cloud-posture.json
      schema: cloud-posture.schema.json
      condition: "render_cloud_posture"   # optional — see _safe_cond.py grammar
```

Choose `fragment_type` consciously:

- **`data`** — the LLM authors a JSON file; composer renders it via Jinja. Use when the section is tabular or structured.
- **`hybrid`** — JSON data plus a small prose block. Both are LLM-authored, both are validated.
- **`markdown`** — pure prose, LLM writes a `.md` fragment. No schema. Used for §1 Verdict, §2 System Overview etc.
- **`computed`** — derived deterministically from `threat-model.yaml` and `.triage-flags.json`. No fragment file.

**Drift hazard:** the `condition` field is parsed by `scripts/_safe_cond.py` and only supports `name`, `not name`, `name [not] in [a, b, …]`. Numeric or `and`/`or` conditions belong in `compose_threat_model.py:_build_eval_context` as a pre-computed bool.

## 2. (For `data` / `hybrid`) Author the schema

Create `schemas/fragments/cloud-posture.schema.json` — JSON Schema draft 2020-12. Use a sibling schema as the template; keep field names lowercase snake_case to match the rest of the codebase.

## 3. Wire the five registry maps

Add an entry to each of these (paths and current line numbers in [`schema-invariants.md` §4f](./schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth)):

| Map | What to add |
|---|---|
| `_SECTION_FRAGMENT_MAP` in `compose_threat_model.py` | `"cloud_posture": ["cloud-posture"],` — section_id → fragment ids in render order |
| `_KNOWN_JSON_FRAGMENT_SCHEMAS` in `compose_threat_model.py` | `"cloud-posture.json": ("CloudPosture", "cloud-posture.schema.json")` — for composer-side validation |
| `FRAGMENT_SCHEMAS` in `validate_fragment.py` | `"cloud-posture": "cloud-posture.schema.json"` — for the producer-facing `validate_fragment.py` CLI the LLM is told to run |
| `_FRAGMENT_FILENAMES` in `validate_fragment.py` | `"cloud-posture": "cloud-posture.json"` — fragment id → on-disk filename |
| `CONTRACT_SECTION_FRAGMENTS` in `qa_checks.py` | `"cloud_posture": ["cloud-posture"],` — section_id → repairable fragment ids |

**Drift hazard:** these five maps overlap because each consumer reads only the slice it needs. Adding to four of the five is the classic silent breakage — the composer renders nothing for the section, or the QA repair plan can't ask the LLM to regenerate it. `scripts/check_fragment_registry.py` is the automated gate (see Phase A1 of `docs/refactoring-plan.md`); if present, it MUST stay green.

## 4. Render the section

Add a render function in `scripts/compose_threat_model.py`. For `fragment_type: data` the function is usually a small Jinja2 template call:

```python
def _render_cloud_posture(ctx: RenderContext) -> str:
    data = ctx.load_json_fragment("cloud-posture.json")
    if not data.get("rows"):
        return ""
    return _render_template("cloud_posture.j2", ctx=ctx, data=data)
```

Register it in the dispatcher (around L5836 — see the module map in `compose_threat_model.py`'s docstring).

For `fragment_type: markdown` use `ctx.load_md_fragment("cloud-posture")` and return the body directly.

## 5. Test it

Add a focused test in `tests/test_compose_threat_model.py` that:

1. Builds a minimal `RenderContext` (use the existing fixtures).
2. Drops a fragment file with both happy-path and edge-case payloads.
3. Asserts the section header and one stable invariant of the rendered body.

If the section introduces a new ID class (e.g. `CP-NN`), also extend `scripts/qa_checks.py:linkify_anchors` per [`schema-invariants.md` §4a](./schema-invariants.md#4a-cross-reference-labelling-invariant): the linkifier is the only legal producer of titled cross-references, so a new ID class needs a new substitution function or it will render as a bare `[CP-01](#cp-01)` reference everywhere.

## Quick verification

```bash
ruff check scripts/ tests/ hooks/
pytest tests/test_compose_threat_model.py tests/test_qa_checks.py tests/test_validate_fragment.py -q
python3 scripts/check_fragment_registry.py   # if present (Phase A1)
```

If all three pass and the rendered `threat-model.md` shows your new section in a smoke run, the registry is consistent.
