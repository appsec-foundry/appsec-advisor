# Check threat hypotheses against selected source

Status: approved by the operator on 2026-10-07 in the implementation request following the analysis of the Threat Analyst.

The Threat Analyst currently accepts designs and code changes. Add an explicit hypothesis mode for a concrete threat and caller-selected files or directories at a Git revision. REQ-ANA-009 defines the source boundary, evidence-backed conclusions, and incomplete outcomes. Existing design and change-review promises remain in force.

The same change corrects REQ-ANA-002 completion handling for unfulfilled evidence and missing questions, and REQ-ANA-008 change attribution for removed controls. The controller, source capture, schemas, host prompt, validator, report, CLI, skill, and their routed tests change together. No new model tools, automatic activation, or assessment mutations are introduced.

Deterministic tests cover scope containment, excluded source, reference and quotation validation, question consistency, removed controls, completion and resumption. They do not establish live-model detection quality or host retention; the existing experimental qualification remains.
