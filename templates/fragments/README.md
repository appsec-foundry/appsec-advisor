# Section Fragments

This directory contains the Jinja templates used by the current production
composer, `scripts/compose_threat_model.py`. Runtime LLM-authored fragments
are written under `$OUTPUT_DIR/.fragments/` and are never written into this
plugin directory.

## Fragment contract

Markdown fragments under `$OUTPUT_DIR/.fragments/` are still section-scoped,
but the composer now validates them against `data/sections-contract.yaml`
before inlining. Data fragments are JSON files validated against
`schemas/fragments/*.schema.json` and rendered through the templates in this
directory.

Rules the orchestrator must follow when writing a fragment:

1. Start the fragment with its top-level section heading
   (`## 8. Threat Register`, `## 4. Assets`, …).
2. Do not write a trailing separator (`---`); the template owns the
   separators between sections.
3. Do not include legacy `{{include: …}}` markers. Those belong only to
   `scripts/render_threat_model.py`, the compatibility renderer retained for
   old tests.
4. Cross-reference labels are produced by the deterministic linkifier in
   `scripts/qa_checks.py`; fragments should provide canonical IDs and titles,
   not hand-authored alternate labels.
