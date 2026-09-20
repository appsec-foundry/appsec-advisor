# RAG, MCP, and agentic analysis implementation plan

Status: implementation delivered in the working tree on 2026-09-20; live model acceptance remains outstanding. The operator approved implementation after reviewing the analysis and implementation risks. Stable product requirements remain unchanged.

## Objective and scope

Make evidenced RAG, MCP, and agentic capabilities survive discovery, component ownership, STRIDE dispatch, finding classification, and report rendering. Use the same validated architecture facts for the report and Figure 1. Preserve complete STRIDE coverage, evidence requirements, existing model compatibility, and bounded context.

RAG describes retrieval and knowledge ingestion. MCP describes a protocol integration that can exist without an LLM. Agentic behavior describes model-directed actions and delegation. Detect these independently and connect them only when source evidence establishes the relationship. Distinguish developer-workstation MCP configuration from the target application's runtime MCP implementation.

This is an existing-application change. Extend existing capabilities, service roles, flows, and evidence contracts rather than introduce a parallel AI architecture model. The affected assets are target source, analysis context, finding integrity, and published architecture claims. Repository content and model-authored artifacts remain untrusted across discovery, dispatch, and publication boundaries.

## Verified observations

These observations describe the pre-change implementation inspected on 2026-09-20. The implementation record below distinguishes subsequent deterministic verification from outstanding live model evidence.

| ID | Observation and producer | Affected invariant and consequence |
|---|---|---|
| V1 | `scripts/build_stride_dispatch_manifest.py::_cat13_supplement` retains one category-13 signal per file and at most ten files. | A file containing SDK calls and agent tools or memory can lose capability distinctions in the supplemental context. Preserve capabilities independently from bounded source excerpts. |
| V2 | The manifest builder appends supplemental patterns to `comp`, then selects `lens_ids` through `_stride_lens_ids(c, ctx)`. The controller copies those IDs into the component plan. | Supplemental agentic evidence cannot affect this selection. An analyzer is instructed not to read unselected lenses. This can omit specialized questions without omitting generic STRIDE. |
| V3 | `_cat13_supplement` reads repository-wide findings without a component ownership filter. | Merely switching lens selection to the enriched context can activate an unrelated component's agentic lens. Ownership must be resolved before the supplement controls selection. |
| V4 | `scripts/pregenerate_fragments.py::gen_ai_exposure` computes one `agentic_surface` from all threats and components before applying the LLM-to-ASI fallback. | An independent agent can affect the classification of ordinary LLM findings elsewhere. Explicit ASI IDs already exist and must remain authoritative. |
| V5 | Recon category 28 classifies remote MCP and public-registry launch configurations as High signals. Category 13 and `has_llm_surface` use different evidence thresholds. | Detection, executable capability, and confirmed weakness must not be conflated. Final severity inflation is a downstream risk to reproduce, not an established outcome of every scan. |
| V6 | Existing lenses cover RAG poisoning, tool misuse, agent identities, memory, communication, and bounded execution, but do not explicitly require all proposed lifecycle checks. | Retrieval revocation, approval parameter binding, and uncertain side-effect retries need precise inspection questions. Generic STRIDE may already find them; missing dedicated guidance does not prove total absence of coverage. |
| V7 | `data/security-capabilities.yaml` already defines `llm-calls`, `llm-tools`, and external `llm-inference`. Figure 1 accepts arbitrary protocols, including tested MCP labels. | The initial gap is evidence and capability semantics, not protocol rendering. Do not replace the renderer or invent components to display functions. |

Primary sources are `scripts/build_stride_dispatch_manifest.py`, `scripts/orchestration_controller.py`, `agents/appsec-stride-analyzer-v2.md`, `agents/shared/owasp-llm-top10.md`, `agents/shared/owasp-asi-top10.md`, `scripts/recon_patterns.py`, `scripts/pregenerate_fragments.py`, and `docs/internal/contracts/schema-invariants.md`.

## Delivery sequence

Each delivery needs an independently reviewable diff and its own completion evidence. A later presentation improvement must not be used to declare an earlier analysis defect fixed.

### 1. Repair signal ownership and dispatch

Resolve category-13 evidence against finalized component paths before using it to select a lens. Preserve distinct capability categories within each owned file while keeping source excerpts bounded. Define handling for legitimately shared source and unresolved ownership. Unknown ownership must remain explicit and must not make every component agentic.

Select lenses from the finalized component context after normalization and enrichment. Preserve component identity and all existing non-AI lens behavior. Do not pass a dispatch-shaped object to a component predicate without checking its expected fields. Replace the text-length heuristic only after establishing which current callers rely on it.

Acceptance evidence:

- A neutral SDK-and-tool example in one file retains both capabilities and selects the agentic lens; a renamed and relocated variant has the same result.
- Two independent components do not gain each other's lens from repository-wide signals. Shared implementation ownership remains supported.
- A plain model call, a dependency-only declaration, and developer-only MCP configuration do not establish runtime agent autonomy.
- The selected IDs survive the controller's plan and bundle checks. Existing six-category STRIDE behavior remains intact.
- Each defect regression demonstrably fails against the pre-fix implementation and passes after the change, following repository test policy without a pre-change baseline suite.

### 2. Repair finding-specific report classification

Handle the global ASI fallback separately from dispatch repair. Scope inferred classification to the finding's evidenced execution path. Reuse explicit `owasp_llm_ids` and `owasp_asi_ids`; do not require a fabricated OWASP category for a valid STRIDE finding. Check grouping and representative-reference selection so independent findings are not lost merely because their ASI category already appears elsewhere.

Acceptance evidence includes a mixed plain-LLM and agentic application, ASI-only findings, findings with multiple supported tags, and ordinary unbounded consumption without an evidenced cascade. Renaming titles must not change explicit classifications. Keep the underlying finding counts and severity unchanged.

### 3. Extend existing evidence contracts and inspection questions

Before schema edits, document the smallest missing fields and their producers, validators, consumers, legacy behavior, and cleanup ownership. Reuse component capabilities, external service roles, canonical data flows, authentication evidence, and boundary references. Authentication and action authorization remain distinct facts.

| Area | Evidence to preserve | Required inspection questions |
|---|---|---|
| RAG | Source and ingestion ownership, retrieval and memory operations, source-resource permissions, relevant caches and flows | Can unauthorized content enter model context? Do same-tenant document ACLs, cross-tenant isolation, revocation, cache reuse, provenance, and memory mutations preserve permissions? |
| MCP | Runtime versus developer scope, client/server/proxy role, actual transport, operations and identities | For HTTP, inspect resource-bound tokens, downstream token handling, consent, handle ownership, Origin and discovery destinations as applicable. For stdio, inspect executable selection, credential inheritance and process restrictions. |
| Agentic | Model-selected operations, execution identity, target resources, approvals, delegation and execution bounds | Does code authorize each action? Is approval bound to concrete parameters? Can delegation widen authority? Do cancellation, revocation, limits and uncertain retries prevent unauthorized or duplicate effects? |

Each new check must state its inspected signal, applicability, false-positive exclusions, required evidence, STRIDE/CWE mapping, and severity basis. A lexical match or cited line establishes neither exploitability nor control effectiveness. External or deployment-owned controls that cannot be verified remain unverified rather than automatically vulnerable or effective.

The aiscb LLM, agent, retrieval, and MCP modules inform these boundary questions. Their controls do not authorize executing target tools, starting MCP servers, or fetching target-selected destinations. The analyzer remains static for this work.

### 4. Publish bounded coverage and architecture views

Derive report content from the validated facts and inspection results. Distinguish a confirmed weakness, an evidenced control within a stated inspection scope, an unverified question, and a non-applicable check. Do not call a capability absent because an old model lacks the new field. Do not claim full security from a successful static check.

Use existing report sections where they satisfy the need. If section structure changes, update the section registry, templates, schemas, producers, composer, QA, and tests atomically. Keep the executive summary concise; detailed coverage belongs with the relevant technical analysis.

Figure 1 should show evidenced retrieval, tool, memory, and delegation functions through existing capability labels and flows where possible. Keep the overview compact and put operation-level chains in the detail views. An authorization check inside one process does not automatically create a deployable component or a trust boundary. The renderer must not infer privileges, topology, vulnerabilities, or mitigations from labels.

Acceptance evidence includes unchanged legacy rerender behavior, valid Markdown and structured exports, agreement between report and figure identities, and complete geometry and semantic checks for dense and cyclic diagrams. New labels must respect the existing bounded capability display rather than make every AI capability highest priority.

## Implementation risks and controls

| Risk introduced by the change | Required control or release evidence |
|---|---|
| Foreign component signals trigger broader analysis and obscure relevant evidence. | Enforce ownership before routing; test isolated and shared components. |
| Extra lens content crowds out existing STRIDE work or causes repeated incomplete runs. | Measure admitted context, completion, calls and cost on comparable fixtures; retain six-category coverage and report omissions. Do not raise budgets without evidence. |
| Untrusted metadata becomes an authorization claim or controls tool execution. | Validate closed schemas and contained evidence references; keep lens IDs plugin-owned and capability facts separate from permissions. Never execute analyzed configuration. |
| New classifications inflate severity or create duplicate findings. | Separate surface detection from weakness confirmation; reuse finding IDs and evidence-based severity; test negative cases and mixed architectures. |
| A coverage status implies assurance beyond the inspected code. | Store and display the inspected control scope and evidence limits; preserve unknown state. |
| New fields break old artifacts, resumes, rerenders or exports. | Define optional-field and version behavior before implementation; exercise old and new fixtures through relevant consumers. |
| New diagrams invent boundaries or conceal meaningful paths through grouping. | Preserve canonical topology; require evidence for labels and pass overview/detail coverage and geometry gates. |
| New artifacts persist sensitive excerpts or escape normal cleanup. | Prefer references and minimal redacted evidence; review permissions, artifact lifecycle, preserved state and cleanup before adding a sidecar. |

## Contracts and validation map

This map identifies review entry points, not permission to edit them all. Run `scripts/check_specs.py --for <path>` before each affected file and read all returned requirements, decisions, and contracts. Re-evaluate policy module selection when implementation scope changes.

| Work | Contract and producer/consumer entry points | Initial test entry points |
|---|---|---|
| Ownership and lens routing | Dispatch builder; controller; context-routing contract; STRIDE analyzer; REQ-FLW-002 and DT-1/DT-6 | `tests/test_dispatch_manifest.py`, `tests/test_stride_quick_profile.py`, affected controller/context-plan tests |
| AI signal and MCP classification | Recon scanner; architecture analyst; recon schemas; evidence/severity contracts | `tests/test_recon_patterns.py`, recon dispatch and signal tests |
| Structured architecture facts | Capability catalog; component/data-flow/boundary/output schemas; fragment validator; schema invariants | Schema integrity, fragment validation, architecture context and canonical YAML tests |
| Report classification and coverage | Pre-generator; renderer; AI-exposure schema; composer; REQ-RPT-003 | `tests/test_pregenerate_fragments.py`, affected compose and QA tests |
| Figure 1 | Capability catalog; `figure1_dfd.py`; `figure1_detail.py`; authentication projection; export contracts | Figure 1 security, DFD, detail, layout and HTML/PDF export tests as selected by reviewed routes |

Review `scripts/run_tests.py` producer/consumer routes and exact requirement guards after each bounded change. Inspect the applicable `make test-plan`; use the worktree-only plan when unrelated commits or changes require scope separation. Run the prescribed validation and selected tests, Python lint when applicable, and route audit when routes change. Use `make check` when the coupled change cannot be bounded by reviewed routes. Reuse unchanged successful checks.

Use the threat-fixture runbook for scanner or deterministic-tail replay. Live model runs are necessary before claiming improved model-analysis outcomes from changed prompts or dispatch behavior; deterministic tests alone establish routing and artifact behavior. Record the fixture, revision, results, omissions, and measured cost. Do not replace missing live evidence with a claim of complete coverage.

## Regression matrix

Every mechanism needs a neutral vulnerable reproduction, a variant with different incidental names or paths, and an effective-control negative case. Keep fixtures synthetic and free of real credentials or personal data.

| Scenario | Required distinction |
|---|---|
| SDK and tool use in one source file | Preserve both capabilities without increasing evidence excerpts indiscriminately. |
| Plain LLM and independent agent in one repository | No cross-component lens or ASI contamination. |
| Retrieval with document ACLs and cached results | Denied content never enters context; revocation and same-tenant ACLs are distinct from tenant namespaces. |
| RAG without model-directed actions | Inspect retrieval security without claiming autonomy or multi-agent communication. |
| HTTP MCP and local stdio MCP | Apply transport-specific questions; MCP alone does not prove an agent. |
| Changed action parameters after approval | Check the executed operation against the approved target and parameters. |
| Delegation, cancellation and uncertain action outcome | Detect widened rights, further effects after revocation, and unsafe duplicate execution separately. |
| Old model and dense agentic architecture | Preserve unknown values, compatibility, complete flow identities and readable detail views. |

## Non-goals and completion criteria

This plan does not authorize production changes, live target probing, MCP installation or startup, additional credentials, or an autonomous exploit workflow. It does not introduce a new score, blanket High ratings for AI integrations, automatic component splitting, or a replacement Figure 1 renderer. Taxonomy version migration is separate work; retain version-qualified mappings and do not silently substitute categories.

Implementation can proceed in the delivery sequence above without treating routine implementation decisions as approval gates. A change to a stable product promise still requires explicit operator approval before editing its normative requirement. Resolve schema and consumer decisions in the corresponding bounded delivery.

Completion requires passing regression evidence for each repaired producer, validated compatibility through affected consumers, fixture replay where required, and explicit disclosure of any missing live-analysis evidence. Report permanent plugin fixes separately from run recovery or rerendering.

## Implementation record

The dispatch builder now preserves owned signal kinds independently of the ten-location excerpt cap and selects lenses from the enriched component context. Canonical, segment-aware path matching excludes foreign components and unsafe paths. Shared source can belong to multiple components. Dependency declarations and developer configuration do not establish runtime agency. Supplemental evidence filenames cannot select a lens by containing a capability keyword.

AI exposure now groups findings by their own LLM and ASI classifications. Explicit ASI tags remain authoritative, ASI-only findings survive another finding's use of the same category, and ordinary consumption does not imply a cascade. The existing ten-group limit remains in place and reports omitted groups without removing findings from the register.

The existing capability catalog adds retrieval, ingestion, memory, delegation and MCP client/server roles. Existing evidence-bearing component and external-service fields carry these values through their schemas. No new artifact, permission, section, required field or cleanup exception is introduced. Missing optional values in legacy models remain unknown. Report component labels and Figure 1 use the same catalog; the existing renderer retains canonical topology, label priorities and bounded displays.

Dedicated RAG and MCP lenses cover resource authorization, revocation, cache reuse, memory writes and transport-specific MCP boundaries. Agentic guidance covers executable action authorization, approval parameter binding, delegated authority, cancellation and uncertain retries. Existing control assessments and report prose record inspection scope and unresolved evidence. Discovery priority remains separate from finding severity. Analysis remains static and does not execute target configuration.

### Verification and outstanding acceptance

Neutral regression tests exercise SDK/tool signals in one file, renamed and relocated variants, isolated and shared owners, dependency/configuration exclusions, location caps, unsafe paths, finding-local classification, multiple ASI tags and ordinary consumption. Representative new regression tests fail against the prior producer code. Controller tests preserve all new lens IDs through the component plan and bundle checks. Schema tests enforce the fixed lens vocabulary across all consumers. Figure 1 tests cover each new capability in overview and detail views, geometry, unchanged topology and suppression without evidence.

A render-only golden replay through `scripts/threat_fixture.py` reports no Markdown or SARIF drift for the historical frozen model. Its expected outputs were produced by the prior implementation. Full YAML reconstruction was not available because the historical fixture lacks the original builder sidecars and skill configuration; the replay does not substitute for that evidence.

The complete test run recorded 17,044 passed, 77 skipped and three failures. Two introduced failures concerned the specialist renderer's pinned line slice and prompt byte limits; both were corrected and the affected agent-definition and prompt-budget suites subsequently passed all 241 tests. Existing prompt ceilings remain unchanged; the two new optional lenses have explicit byte guards. Targeted dispatch, classification, controller, schema and Figure 1 checks passed. Configuration, fragment-registry, specification and test-inventory validation passed.

The remaining full-suite failure, `test_named_tests_exist[RA-22]`, also failed against the unchanged starting HEAD because the decision named an outdated scenario-number test. The global lint target reported an existing formatting defect in `tests/test_render_editorial_receipt.py`; the starting HEAD reproduced it. Both checks passed at the development merge base. The final verification corrects the reference to the existing test and formats the docstring without changing test behavior.

The final rerun passed 1,561 tests covering prompt budgets, agent contracts, dispatch, classification, schemas and Figure 1, plus 807 consumer tests covering decisions, editorial receipts, context measurement/routing and controller plans. `make lint validate` passed globally. All three failures from the earlier complete run are resolved; unaffected successful checks from that run are reused rather than claiming a second complete run.

Measured prompt bytes are 12,993/13,000 for architecture, 14,419/14,500 for STRIDE, 6,995/7,000 for the LLM lens, 7,973/8,000 for the agentic lens, 2,427/2,600 for RAG and 3,044/3,300 for MCP. The four AI lenses total 20,439 bytes when selected together. Existing ceilings are unchanged. Several surfaces have little growth margin and future additions need replacement or compression. These byte checks do not measure provider tokenization or cumulative resident context; the existing aggregate startup-token gate remains disabled pending its separately required measurement record.

Live model acceptance remains open because the Claude CLI is unavailable in this environment. The synthetic retrieval ACL/revocation, changed approval parameters, delegation and retry scenarios still need live analysis runs to measure detection, false positives, context admission, completion and cost. Deterministic routing and artifact tests do not establish improved model recall or security coverage.
