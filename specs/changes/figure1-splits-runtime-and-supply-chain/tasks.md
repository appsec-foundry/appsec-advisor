# Tasks

## Slice 1 — Build placement and Figure 1a

- [x] One build-placement predicate used by `figure1_dfd`, Figure 1b and the §2.2 Mermaid diagram; attribution rules unchanged (`RA-28`).
- [x] Build placement derived from zones and CI-only paths where it is used, without rewriting `deployment_zones` (`scripts/model/build_plane.py`, `RA-28`; see Revision 2026-10-03).
- [x] Figure 1a filters build components, flows, boundaries and build-time scenarios with full-model component numbers (`scripts/renderers/figure1_dfd.py`, `scripts/renderers/compose_threat_model.py`, `RA-29`).
- [x] Figure 1a renders without runtime scenarios; the empty-`attack_paths` guard in `_render_figure1_svg` no longer skips it (`RA-29`).
- [x] Tier-stack, Mermaid and saved-fragment fallbacks receive the filtered input; a fragment with a build-plane component is rejected (`RA-29`).
- [x] Header keeps the model-wide tally, labelled; Figure 1b states its own count (`RA-29`).
- [x] People list is the union of both figures, deduplicated by actor slug (`figure1_dfd.overview_people`, `compose._overview_people`).
- [x] Build strip under the Figure 1a heading, driven by `has_build_evidence`.
- [x] Figure 1a caption and alt text; `export_pdf._FIGURE1_REGION_RE` matches `Figure 1a`.

## Slice 2 — Producers required for this change

- [x] Job association for GitHub workflow inputs and outputs, and container output destinations (`scripts/analyzers/supply_chain_facts.py`, `schemas/config-scan-findings.schema.yaml`).
- [x] Ecosystem install steps per job (`scripts/analyzers/supply_chain_facts.py`).

## Slice 3 — Supply-chain view artifact

- [x] Schema for `.supply-chain-view.json` with element sources, edge status and finding attachments (`schemas/`, `RA-30`).
- [x] Builder after merge and attribution, with input fingerprint, and a matching `tests/test_*.py` (`RA-30`).
- [x] Display and entry mapping as a data file, with a drift test against `data/config-iac-checks.yaml` (`RA-30`).
- [x] Highlighted-path selection over evidenced edges only (`RA-30`).
- [x] Rebuild-or-omit rule in composition for missing, invalid or outdated artifacts (`RA-30`).
- [x] Artifact kept for re-render (`docs/internal/contracts/audit-artifacts.md`, `scripts/runtime/runtime_cleanup.py`).

## Slice 4 — Figure 1b renderer, gates and report wiring

- [x] Renderer contract: supported widths, minimum effective font size, clearances, agreed before acceptance (`RA-31`).
- [x] Grid renderer with text measurement, content-sized columns, fan-in and fan-out ports (`RA-31`).
- [x] Geometry gate and legibility gate; table form on failure with warning and run issue (`RA-31`).
- [x] Shared anchor `figure-1b` for SVG and table; links from strip, Top Threats, §1 actor row and §2.2 (`RA-31`).
- [x] `<stem>.figure1b.svg` naming, stale cleanup, publish set (`publish_threat_model.py` TIER2, also adding the missing figure2 entries).
- [x] Section contract and QA scope for the new figure (`data/sections-contract.yaml`, `scripts/validators/qa_checks.py`).
- [x] HTML and PDF export of the figure, the table form and the anchor (`scripts/exporters/export_html.py`, `scripts/exporters/export_pdf.py`).

## Slice 5 — Verification and examples

- [ ] Fixtures 1–18 from the proposal, plus a juice-shop replay with `scripts/threat_fixture.py`.
- [ ] Inspection of representative SVG, HTML and PDF output at display size.
- [ ] README examples for Figure 1a and Figure 1b (`docs/images/`, legibility guards in `tests/`).
- [x] Decision rows `RA-28` to `RA-31` (`docs/internal/decisions.md`), after operator confirmation of the wording.
- [x] `REQ-RPT-007` rewording and `REQ-RPT-008` in `specs/requirements.md`, added by the operator.
- [x] Bindings for `REQ-RPT-007` and `REQ-RPT-008` (`data/requirement-bindings.yaml`).
- [x] Test routes for new modules and the change directory (`scripts/run_tests.py`).

## Deferred

- Facts and checks for GitLab CI, Jenkins and other CI systems.
- Deploy targets beyond registries, Kubernetes and GitLab auto deploy.
- Workflow trigger extraction, including inline `on:` forms.
- Per-ecosystem lockfile pairs as structured fields.
- Secret names per workflow.
- §6.11 split into runtime operations and supply chain, with anchor migration (`REQ-EVO-003`).
