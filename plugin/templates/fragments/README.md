# Section Fragments

This directory is intentionally empty at rest. During an assessment the
orchestrator writes section fragments to `$OUTPUT_DIR/fragments/` — never
into this plugin directory. `render_threat_model.py` resolves the template
in `../threat-model.template.md` against the runtime fragments directory
and writes the final `threat-model.md`.

## Fragment contract

Each fragment is a self-contained Markdown snippet for one section of the
final report. Fragments are inlined verbatim: the resolver does not
rewrite headings, inject anchors, or adjust list nesting. Whatever the
orchestrator writes is what appears in the rendered output.

Rules the orchestrator must follow when writing a fragment:

1. Start the fragment with its top-level section heading
   (`## 8. Threat Register`, `## 4. Assets`, …).
2. Do not write a trailing separator (`---`); the template owns the
   separators between sections.
3. Do not include nested `{{include: …}}` markers. The resolver only
   performs a single substitution pass and will warn on nested markers.
4. Clickable internal anchors for `T-NNN` / `M-NNN` IDs must already be
   present in the fragment — the resolver does not linkify.

## Template markers

The template in `../threat-model.template.md` supports exactly two
marker forms:

    {{include: <relative-path>}}      required — abort if missing
    {{include?: <relative-path>}}     optional — dropped if missing

Paths are resolved relative to the runtime fragments directory passed
via `--fragments-dir`. Nested includes are not supported.

## Migration status

Step 1 (MVP): the template contains a single passthrough marker
`{{include: 99-full-body.md}}` that the orchestrator fills with the
complete report body. This preserves today's behaviour while proving
the template + resolver pipeline. Subsequent migration steps split the
body into per-section fragments (`00-*.md` through `11-*.md`) and
eventually remove `99-full-body.md` from `REQUIRED_FRAGMENTS` in
`../../scripts/render_threat_model_schema.py`.
