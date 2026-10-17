# AppSec Analyzer extraction plan

Status: implementation plan, 2026-10-17. Target: [appsec-foundry/appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer). Build the independent engine in that repository while the existing AppSec Advisor implementation remains operational. Switch the plugin to a qualified Analyzer release and remove duplicated implementation in a second phase.

The plan combines the [provider-neutral engine design](design-provider-neutral-engine-2026-10-17.md) and [product architecture](../../proposals/appsec-product-architecture-concept.md), with relevant Git history preserved through `git filter-repo`. It changes their proposed sequencing: import the development history first, qualify providers in the destination repository, and package the engine there. Provider qualification still precedes a supported standalone release and plugin cutover. The existing Advisor runtime does not need an intermediate provider refactor.

This is planning work. Requirements and registered decisions remain unchanged. Before implementation changes a product promise or needs a qualifying long-lived decision, propose its exact wording and plain-language summary through the existing confirmation workflow. Creating this plan does not publish a repository, push history, release packages, or authorize paid provider runs.

## Outcome and scope

AppSec Analyzer becomes an installable Python package and CLI named `appsec-analyzer`, with two explicit execution modes:

| Mode | Behavior | Evidence needed |
| --- | --- | --- |
| Deterministic scan | Run applicable source and configuration scanners on admitted snapshots without model calls, provider credentials, or a Claude installation. Report scanner coverage and limitations. | Installed execution with model transports unavailable, validated findings, and scanner regression evidence. |
| Full assessment | Run the existing deterministic controller, semantic roles, evidence validation, reports, and exports through a selected qualified host. | Complete Claude compatibility evidence, a direct API assessment, and qualification of the planned gateway route. |

Model independence means the engine does not hardcode one provider into orchestration or configuration. It does not establish that arbitrary models produce acceptable assessments. Support is declared per host, protocol, model configuration, and analysis depth. A deterministic scan does not claim the semantic coverage or completion status of a full assessment.

Preserve the existing analysis capabilities, evidence and severity rules, source provenance, budget semantics, and supported consumers. The repository split does not introduce incremental analysis, automatic model fallback, a new scanner framework, or a report/storage rename. Coordinate any independently approved assessment migration at the selected source revision; do not repeat or undo it here.

Extracting `appsec-skills`, moving baseline lifecycle tooling, and deploying an AI gateway are separate projects. The Analyzer supplies its own thin entry skill; AppSec Advisor retains its plugin identity, marketplace address, common help, and Claude integration.

## Starting point

The source checkout was inspected at `c8b8a0ec38cf325e29f1f3cdef5c2a04c6317d3f`. It also contains unrelated uncommitted changes. Choose a committed source revision during implementation; neither the current index nor untracked files form an implicit extraction input.

The operator's sibling checkout `../appsec-analyzer` is locally clean, has an unborn `main` branch, and has `origin` set to `git@github.com:appsec-foundry/appsec-analyzer.git`. No local commits or tracked files need reconciliation at this point. Remote branch state and publication access still need verification before import or push; the local empty checkout does not establish that the remote is empty.

Several historical statements in the concepts have already been overtaken by the [assessment transition](handoff-appsec-analyzer-transition-2026-10-17.md). The current skill is `appsec-analyzer`; the assessment launcher dispatches directly to the controller. Do not recreate the retired `create-threat-model` runtime or its removed agents.

The following code paths define the initial extraction work. Line references describe the inspected revision and must be rechecked at the chosen extraction commit.

| Current producer or consumer | Coupling and consequence | Work package |
| --- | --- | --- |
| [`_assessment_cli_host_factory`](../../../scripts/orchestrator/orchestration_controller.py#L3506) | Constructs `ClaudeCliTransport` directly, so controller selection remains Claude-specific despite the injected factory seam. | A3 |
| [`Transport.invoke`](../../../scripts/runtime/analyst_host.py#L137) and [`response_schema` / `host_schema`](../../../scripts/runtime/assessment_host.py#L89) | A transport protocol exists, but wire projection targets the current host; other dialects need deliberate projection and decoding. | A3–A5 |
| [`resolve_assessment`](../../../scripts/runtime/resolve_config.py#L1872) and [`_assessment_session`](../../../scripts/orchestrator/orchestration_controller.py#L866) | Effective defaults include controller-specific model corrections; actor discovery still has a fallback outside resolution. Copying only generic model defaults changes behavior. | A3 |
| [`run-headless.sh`](../../../scripts/run-headless.sh#L238) | Checks Claude availability and authentication before controller dispatch. An API-only installation cannot use this launcher unchanged. | A3, A6 |
| [`_assessment_runtime_fingerprint`](../../../scripts/orchestrator/orchestration_controller.py#L833) | Reads plugin directories and `.claude-plugin/plugin.json`; merely moving resources cannot make installed runs independent. | A6 |
| [`read_requirements_config`](../../../scripts/runtime/resolve_config.py#L1227) | Reads functional configuration from `skills/audit-security-requirements/config.json`. Move the engine-owned setting with its consumers. | A1, A6 |
| [`assessment_scanner_findings.py`](../../../scripts/model/assessment_scanner_findings.py#L1) | Scans frozen snapshots but integrates with component ownership and subsequent evidence verification. A standalone scanner entry needs an explicit output contract. | A6 |
| [`AssessmentBudget`](../../../scripts/runtime/assessment_jobs.py#L47) and [`DiscoveryBudget`](../../../scripts/runtime/multi_repo_discovery.py#L165) | Admission and completion reserves depend on bounded host spending and validated accounting. Preserve these across adapters. | A3–A5 |
| [`skills/appsec-analyzer/SKILL.md`](../../../skills/appsec-analyzer/SKILL.md#L25) | Invokes checkout-relative scripts and reads private progress/state files. The final plugin entry must use the Analyzer's supported public boundary. | A6, B1 |

These are extraction dependencies, not assertions that the existing runtime is defective. The standalone target must eliminate them before claiming independence.

## Phase A build the independent engine

All engine changes in this phase occur in the Analyzer repository. AppSec Advisor keeps its current implementation, entry points, dependencies, and release path. No user is silently redirected to the new engine.

### A1 inventory ownership and freeze the source

1. Select a reviewed, committed Advisor revision on the development lineage. Record its full SHA, source URL, relevant release ancestry, and the current supported command/artifact surface. Resolve which ongoing assessment migration changes belong in this snapshot before choosing it.
2. Trace each retained capability from its producer through schemas, resources, consumers, permissions, tests, and cleanup. Produce a path manifest with owner, current path, historical paths, destination path, and reason for inclusion. Use explicit paths where directories contain both plugin and engine code.
3. Include controller/runtime modules, scanners, semantic roles and shared prompts, source/retrieval controls, schemas, catalogs, templates/assets, renderers, exports, requirements resolution, organization-policy enforcement, and their required tests and fixtures. Include license/attribution files and the applicable technical contracts and development tooling.
4. Classify every existing skill as Analyzer-owned, an Advisor adapter, or a retained independent consumer. Keep Analyzer-backed workflows such as focused threat analysis and assessment consumers with their actual dependencies; do not omit them because the main CLI can already run.
5. Identify host-only hooks, marketplace/manifests, baseline lifecycle integration, and plugin packaging that remain in Advisor. Any safety check needed by standalone execution must have an engine owner, even if a hook also invokes it today.
6. Record the fully resolved Claude role matrix for each supported depth, explicit override precedence, artifact shapes, exit/status behavior, and existing replay evidence. Use static inspection and existing evidence here; execute regression checks when the implementation they exercise changes.

Deliverables: ownership/path manifest, source revision, interface inventory, and named acceptance cases. Do not start a broad cleanup or alter fixture expectations to simplify extraction.

### A2 import the relevant development history

Use a disposable full clone of the selected source history. Run `git filter-repo` there, never in either working checkout. A path filter can retain multiple directories; historical renames need explicit inclusion because filtering does not follow them automatically. See the [GitHub extraction guide](https://docs.github.com/en/get-started/using-git/splitting-a-subfolder-out-into-a-new-repository) and [filter-repo manual](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt).

1. Review and pin the filter tool version and its upstream provenance before installing or executing it. Verify the destination's local and remote refs again. If new content has appeared, reconcile it before importing; do not overwrite it or force-push.
2. Build the filter selection from A1, including old locations of moved scripts, prompts, tests, and contracts. Retain selected source paths initially. Perform package-layout moves in ordinary later commits so the import and runtime refactor remain independently reviewable.
3. Filter the selected development lineage and required ancestors, retaining relevant authorship and dates. Preserve commit messages where practical; document tool normalization, such as rewritten embedded commit references. Commits affecting only excluded files can disappear; mixed commits retain only their selected changes. Do not squash the import into an initial commit.
4. Review the resulting reachable history for accidentally included credentials, private target data, local artifacts, or unrelated code before publication. Use redacted findings rather than printing sensitive values. Include applicable licenses and attribution from the original project.
5. Preserve the exact source SHA, tool version, filter arguments/path manifest, resulting tip, and old-to-new commit/ref maps in an extraction record. Keep a recoverable source backup outside the destination's published refs. Store reviewed provenance records in the new repository so they survive cloning.
6. Verify that selected tip files match the source snapshot, historical samples survive before and after known renames, and original author/committer dates remain represented. Explain pruned commits and changed hashes. Commit signatures do not survive rewriting; retain links to original signed history rather than presenting filtered commits as originally verified.
7. Import the reviewed result into the existing destination checkout as the development lineage. For the currently unborn repository, establish `dev` from the filtered tip. Integrate through the destination's agreed release branch policy; do not label an import snapshot as a released independent engine. Before pushing, replace or disable inherited publication workflows in a separate bootstrap commit so an import cannot trigger an Advisor release. Push only explicit reviewed refs during the later authorized publication step, never `--mirror` or all source tags.

Historical Advisor release tags are not Analyzer releases. Keep their relationship in provenance metadata, or use clearly namespaced historical tags only if needed and reviewed. GitHub stars, issues, pull requests, release assets, and the repository creation date are outside Git history and require separate treatment.

Acceptance: a fresh clone of the imported development branch exposes the real retained development history, has the intended source tree and licenses, and has no dependence on an unpublished local Git object. Advisor's refs and working files remain unchanged.

### A3 isolate providers and centralize configuration

Keep the imported resource layout while establishing the provider boundary. Preserve Claude CLI as the default adapter and preserve its effective depth/model behavior.

1. Define a registered adapter interface for preflight, capabilities, schema projection/decoding, invocation, usage accounting, error mapping, cancellation, and bounded response receipt. Keep orchestration, source grants, canonical validation, retries, and budgets in the core.
2. Resolve trusted host profiles, role models, tiers, organization restrictions, and dated pricing policies once. Include actor discovery. Preserve existing CLI/environment precedence and depth-driven work volume; use a single documented operator configuration location with deliberate handling of any existing location.
3. Move authentication and executable preflight behind host selection. API-only runs must start without Claude installed or logged in. Host configuration selects registered adapters and data, not arbitrary import paths, shell commands, or authentication programs.
4. Inventory every selected role/exchange schema, including retrieval requests, corrections, synthesis, and rendering. Keep canonical schemas separate from wire schemas and deterministic decoders. Preserve absent/null semantics and reject malformed output without silently deleting fields.
5. Include the non-secret host endpoint, dialect, resolved role mapping, adapter/schema version, pricing revision, and gateway route revision in run identity. A changed identity must not reuse incompatible cached work.

Acceptance: Claude replay retains canonical outcomes and model resolution; injected malformed output, unauthorized read proposals, invalid configuration, and cancellation retain their rejection behavior. Models receive bounded text and may propose reads through the existing validated exchange; they receive no executable tools or direct filesystem authority.

### A4 complete the first direct API path

Implement the direct OpenAI adapter proposed by the engine design. Select and document the concrete API dialect, supported model/depth combinations, schema capabilities, pricing revision, and usage interpretation against current official provider documentation at implementation time.

Exercise the complete assessment, including discovery, source retrieval, STRIDE, evidence verification, corrections, synthesis, report generation, interruption, and resume. Disable SDK retries; controller admission owns retry decisions. Distinguish authentication errors, refusals, truncation, malformed replies, timeouts, and cancellation.

Before each call, establish an enforceable spending bound covering input and all billable output, including reasoning, cache effects, and applicable fees. Retain the reservation for unknown failure costs. Stop further calls when pricing, usage, or the bound cannot be established. Record measured/estimated spend separately from conservative budget charges; preserve required-completion reserves.

Acceptance: offline contract and failure cases pass, then an authorized complete live run satisfies declared quality thresholds for every supported depth. Passing HTTP or schema tests alone is insufficient. Keep unqualified models/depths outside the supported matrix.

### A5 qualify a fixed gateway route

Add an explicit OpenAI-compatible dialect for an existing gateway, with LiteLLM as the planned qualification target. Use fixed versioned aliases, including a Claude backend, with an operator-provided route revision and approved upstream destination set.

Gateway qualification covers wire schemas, usage and price bounds, cancellation, route identity, and behavior under failure. Hidden gateway retries, fallback providers, and dynamic routing remain disabled unless their full destination and spending bounds are established. A cost response header is not a pre-call ceiling. Record retention/logging and upstream-routing evidence from the gateway operator; a successful request cannot prove those controls.

Acceptance: a complete authorized assessment and the gateway-specific failure cases pass for the declared route, dialect, model, and depth. Without gateway access, report A5 as pending rather than claiming completion. Direct Anthropic and additional Claude/Bedrock profiles remain later additions unless separately scoped.

### A6 package the engine and expose deterministic scanning

After A4 and A5 qualify the provider boundary, move implementation into an installable package with package-owned resource loading and supported module/API entry points. The target CLI is `appsec-analyzer`; exact subcommand names and JSON contracts are specified before implementation.

| Public operation | Required boundary |
| --- | --- |
| Version and capabilities | Engine version, interface/schema compatibility, available scanner and qualified provider capabilities. |
| Deterministic scan | Explicit source/output scope, bounded scanner execution, typed findings and coverage; no model preflight or calls. |
| Full assessment | Validated request/configuration, business context, source grants, budget and depth, canonical results. |
| Progress, status and cancellation | Versioned machine-readable events/results and bounded stop behavior; consumers do not parse private files. |
| Artifact lookup and exports | Validated artifact kind/version/identity and explicit destination; clear errors for absent optional export tools. |

Remove dependency on `CLAUDE_PLUGIN_ROOT`, `.claude-plugin/plugin.json`, sibling checkouts, and functional settings stored under another skill. Bind fingerprints to the installed engine, its resources, adapters, contracts, and resolved configuration. Keep one versioned source for semantic prompts and decoders. Define machine-readable outcomes and exit semantics that distinguish findings, completion, incomplete work, cancellation, invalid input, and execution failure.

The deterministic scan needs its own schema and coverage semantics because the current scanner bridge relies on assessment components and later verification. Reuse scanner producers and evidence rules without fabricating component IDs, semantic verification, or a completed assessment. Missing provider configuration must not block this mode. Provider-free scanning also must not introduce hidden downloads or execute target repository code.

Build wheel and source distribution with declared Python/platform support, locked build/test dependencies, license notices, and explicit optional export dependencies. Add the thin Analyzer entry skill to the release artifacts. Retained assessment consumers use public APIs or declared packaged interfaces rather than a second checkout.

Acceptance: install the built artifact into an isolated environment outside both repositories, then exercise scanning, qualified assessment, status, cancellation, resume, rendering, and supported exports. Test missing resources, incompatible artifacts, absent optional tools, and provider-free operation. Compare controlled replays with admitted inputs and recorded responses; evaluate live model quality without requiring identical prose.

### A7 release and end the temporary development overlap

Prepare an independent Analyzer release with exact revision, artifact digests, dependency inventory, supported interface versions, provider qualification evidence, and extraction provenance. Review publication permissions and protect credentials from untrusted pull-request code. The new repository's age alone does not justify labeling the inherited engine immature; describe the existing lineage and separately identify interfaces/providers whose qualification is still limited.

During Phase A, Advisor remains the source for fixes needed by its current users. Apply relevant fixes there first and port the reviewed change into Analyzer, recording the original commit and its destination counterpart. New provider and packaging work belongs only in Analyzer. Avoid blanket merges across the filtered histories and do not repeatedly rewrite published Analyzer history to catch up.

Before declaring A complete, reconcile the source delta since A1 against the ownership manifest. Every relevant fix is ported or explicitly shown to be inapplicable. Both implementations keep separate output directories and run locks; development comparisons must not overwrite the same report or reuse private state across engines.

Phase A ends with a qualified standalone release and a closed reconciliation ledger. Advisor still invokes its embedded implementation. If qualification fails, continue work in Analyzer; no plugin rollback or source deletion is needed.

## Phase B integrate and clean up AppSec Advisor

Start this phase only after A7. Integration and deletion remain separate commits so each can be reviewed and reverted independently. Use the existing Advisor development and release workflow.

### B1 build a pinned integration

1. Assemble Advisor from an exact Analyzer release with verified digest/provenance and declared interface compatibility. Bundle the Analyzer entry skill and distribution; select one implementation of each command.
2. Route `/appsec-advisor:appsec-analyzer` and its supported consumers through the public Analyzer boundary. Retain the plugin namespace and marketplace installation identity. Engine status comes from the engine; the plugin may combine component versions for display.
3. Move remaining runtime checks into the engine before removing any hook dependency. Preserve equivalent source/output authorization, organization restrictions, secret exclusion, budget enforcement, and cleanup in direct CLI use.
4. Define explicit dependency setup and preflight. A marketplace install is not assumed to install Python dependencies. The plugin uses its tested component, not an arbitrary executable found on `PATH`, a mutable branch, or a model-triggered download.
5. Build a staging plugin artifact while keeping the old implementation in the source tree. The staged composition invokes only the new engine; public users stay on the existing release until cutover. Validate component mismatch and command collision rejection.

Acceptance: standalone and staged plugin runs agree on canonical outcomes in controlled replay; configuration, business context, organization policy, status, cancellation, and affected consumers reach the intended engine. Build/install from artifacts outside all source checkouts.

### B2 cut over with compatible rollback

Publish the reviewed composition through the existing release process. If adopting the product concept's archive distribution, build and verify the exact ZIP, publish those bytes, test staging installation, then update the existing marketplace catalog URL and digest together. Test upgrade from the currently installed plugin, preservation of settings and retained data, and compatible rollback before public catalog cutover.

Do not combine this step implicitly with new report names, storage defaults, or unrelated skill extraction. Preserve the artifact contracts chosen in A1 or apply a separately approved migration. Finish or cancel active old-engine runs before switching their workspace. Old and new private state are not assumed compatible; resume across versions needs explicit evidence or a clear refusal that preserves existing results.

Keep the previous tested plugin artifact and exact component composition available. Rollback reinstalls that composition and uses compatible state or a new output location; it must not reinterpret newer state or erase findings, provenance, or retained user decisions.

Acceptance: the installed plugin invokes the pinned Analyzer release, users can upgrade through the unchanged marketplace registration, and rollback has been demonstrated within its declared compatibility limits.

### B3 remove transferred implementation

After B2 passes, use the ownership manifest to delete only code whose supported consumers now use Analyzer. Remove transferred scanners, controller code, provider logic, engine resources, and duplicate semantic instructions from Advisor as appropriate. Retain host integration, marketplace/packaging code, baseline lifecycle adapters, and integration tests.

Update references, permissions, configuration, build inputs, documentation, requirement bindings, and test routing with each removal. Keep engine regression tests in Analyzer and integration tests in Advisor. A retained skill with unresolved dependencies blocks deletion of those dependencies, not unrelated cleanup. Do not delete tests merely because the corresponding filename moved; verify their replacement coverage.

Acceptance: no supported plugin path calls deleted checkout scripts, reads private engine state, or depends on a sibling repository. Plugin packages contain only the pinned engine distribution and host integration. Analyzer is now the single source for engine changes; Advisor fixes use a new pinned release. Historical commits remain in both repositories where applicable.

## Security and acceptance boundaries

Apply the AI Secure Coding Baseline aiscb to the existing code paths changed by extraction and to newly introduced package/provider boundaries. Protected assets are admitted source code, business context, credentials, canonical results, retained decisions, and run state. Untrusted repositories, model output, catalogs, and imported history cannot select executable code, credentials, destinations, or permissions.

| Boundary | Intended behavior and representative failure evidence |
| --- | --- |
| Source and retrieval | Existing source grants and frozen snapshots remain authoritative. Reject out-of-scope reads, escaping links/paths, forged provenance, and cached access after revocation. |
| Host selection and egress | Only explicit trusted operator/organization settings choose destinations. Enforce TLS and connection-time host/address policy, reject redirects and credential forwarding, and admit private gateways only under explicit permitted ranges. |
| Model output | Validate canonical schemas and authorized read proposals outside the model. Reject unknown actions/fields, prompt-injected authority, and invalid wire decoding before downstream use. Preserve safe rendering. |
| Budget and lifecycle | Bound calls, response bytes, retries, deadlines, and cancellation; preserve completion reserves. Test unknown costs and concurrent reservations without treating an incomplete run as complete. |
| Artifacts and cleanup | Enforce output ownership and kind/version checks, exclusive run locks, safe exports, and cleanup boundaries. Preserve retained reports and decisions on failure or rollback. |
| Build and distribution | Verify immutable dependencies/components, use locked CI installs and dependency scanning, keep CI tokens read-only by default, and isolate publication credentials from untrusted jobs. Test tampered/mismatched artifacts. |

Review the affected design against the [OWASP LLM risks](https://genai.owasp.org/llm-top-10/) and [OWASP agentic application risks](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), especially prompt injection, excessive agency, output handling, tool misuse, and supply-chain trust. This review stays within the extracted and newly introduced boundaries.

Select checks per changed behavior and affected consumer. Use exact test nodes from the current code and add missing coverage in the destination repository; do not prescribe a full suite for every work package. Each producer fix needs a neutral reproduction, a variant with different incidental names, and a negative case. Deterministic-tail or scanner changes require the [golden fixture replay](../runbooks/threat-fixture.md). Relevant release gates run when preparing the corresponding release.

The import check establishes source/history fidelity. Offline tests establish deterministic boundaries. Installed-artifact tests establish packaging independence. Live provider runs establish the declared model/depth qualification. None substitutes for the others.

## Implementation model and reasoning effort

Use GPT-6.1 Sol with `high` reasoning effort as the default coding assistant for this plan. This recommendation concerns the assistant implementing the extraction; the Analyzer's runtime model selection remains governed by A3–A5. If using one model and effort throughout, choose GPT-6.1 Sol / High.

| Work package or activity | Recommended model and effort | Purpose |
| --- | --- | --- |
| A1–A2 inventory and history import | GPT-6.1 Sol / `high` | Trace dependencies, prepare the path selection, preserve history, and verify the import. |
| A3–A5 adapter implementation and tests | GPT-6.1 Sol / `high` | Implement the agreed boundaries and focused regression cases. |
| Difficult A3–A5 design decisions | GPT-6 Astra / `high` | Resolve provider abstraction, canonical schema projection/decoding, spending bounds, and resume compatibility. |
| A6–A7 packaging and B1 integration | GPT-6.1 Sol / `high` | Build the standalone package, public interfaces, pinned composition, and affected tests. |
| Review before B2 cutover and B3 deletion | GPT-6 Astra / `high`, with fresh context | Review the proposed diff, ownership manifest, relevant contracts, acceptance evidence, and rollback limits before applying the transition. |
| B3 approved cleanup implementation | GPT-6.1 Sol / `high` | Remove transferred implementation and reconcile its remaining consumers. |

Use `xhigh` selectively when a concrete complex problem remains unresolved at `high`, with a bounded question and evidence to inspect. Do not make Max or Ultra the default. A review with fresh context should receive the current plan, relevant source and diff, and verification results so it can assess the implementation without relying on the implementing session's conclusions. It can run as a separate session and does not require parallel agents.

The [official OpenAI model guidance](https://learn.chatgpt.com/docs/models), checked on 2026-10-17, recommends GPT-6.1 Sol for complex coding workflows, Astra for the most demanding work, and High or Extra High for difficult multistep tasks. The allocation above is an engineering recommendation for this extraction, not a measured comparison on this repository. Model availability depends on the account and client; model choice does not replace any milestone's acceptance evidence.

## Milestones and remaining inputs

| Milestone | Completion evidence | Advisor state |
| --- | --- | --- |
| A1–A2 history import | Reviewed source/path manifests, preserved historical samples, reproducible mapping, destination development branch. | Existing implementation retained. |
| A3–A5 provider independence | Claude compatibility, complete direct API run, qualified fixed gateway route, boundary failure cases. | Existing implementation retained. |
| A6–A7 standalone delivery | Installed package and scanner mode, supported consumers, reconciled fixes, qualified release artifacts. | Existing implementation retained. |
| B1–B2 plugin integration | Pinned composition, installed upgrade, state compatibility and rollback evidence. | New release invokes Analyzer; old implementation awaits scoped removal. |
| B3 cleanup | Transferred code removed with consumers, permissions, bindings, and test ownership reconciled. | Plugin integration and packaging only for the migrated engine capabilities. |

Before A1, choose the committed source snapshot and identify any assessment-transition work that must land first. Before live qualification, supply authorized provider/gateway access, concrete models, route evidence, dated prices, spending allowance, and per-depth quality thresholds. Before A6, settle supported platforms and the public command/artifact schemas. Before publication, verify remote state, release permissions, and package-name availability if using a registry; a GitHub release does not imply PyPI publication.

Estimate remaining implementation effort after the first complete direct API assessment and the packaging dependency inventory. Do not compensate for schema, budget, or dependency failures by increasing limits or dropping controls without diagnosing their cause.
