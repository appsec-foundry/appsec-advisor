# AppSec Advisor component packaging plan

Status: partial offline implementation committed on Advisor `dev` as `3cd82cd4`; portable skill preparation is committed on AppSec Skills `dev` as `557f16fa07beead21267a3b220f7e4d608e11b2c`. The [implementation evidence](composition-offline-evidence-2026-10-18.md) records the scope and checks. P2 source preparation and P3 staging builder/bootstrap foundations exist; the plan's acceptance criteria remain open. P4.1 now provides integrated organization configuration dispatch and external profile handoff for the declared score staging surface; remaining P4 consumer/configuration migration, native platform qualification, release qualification, public cutover, and removal are not complete. The operator approved offline P2–P4 work before A7; A7 still gates release and cutover. AppSec Advisor is intended to become a thin Claude Code integration assembled from independently maintained components. Its installed package must include the skills and Analyzer distribution required by supported workflows. A thin source repository does not imply a small installation archive.

This document extends the [product architecture](../../proposals/appsec-product-architecture-concept.md) and details Phase B of the [Analyzer extraction plan](plan-appsec-analyzer-extraction-2026-10-17.md). The [assessment transition handoff](handoff-appsec-analyzer-transition-2026-10-17.md) remains relevant to compatibility. The current inventory below replaces the extraction plan's historical starting-point description, not its acceptance gates. Do not repeat the history import or rebuild capabilities that already exist in Analyzer.

Requirements and registered decisions remain unchanged by this plan. Propose and confirm their exact wording before implementation changes a product promise or introduces a decision that meets the register's admission rule. This document does not authorize publication, deletion of existing capabilities, or paid model runs.

## Agreed outcome

The operator selected Linux, macOS, and Windows for the first new plugin version, with an existing Python installation as a prerequisite. Bundling Python itself is outside this delivery. Choose and document the supported Python versions and operating-system/architecture matrix during package qualification; an operating-system name alone is insufficient evidence of support. Native Windows is in scope; WSL-only execution does not fulfill that choice.

Keep the existing marketplace identity and `/appsec-advisor:appsec-analyzer` entry point. Users continue to start assessments in Claude Code and use Claude models. The installed plugin includes the matching entry skill and Analyzer package; Analyzer owns orchestration and invokes the selected model adapter. Standalone execution is an additional way to use the same engine.

The first delivery assembles existing capabilities, makes the selected skills independently usable, and qualifies installation and upgrades on all three platforms. It does not introduce new scoring algorithms, model fallback, scanner frameworks, report names, or storage defaults. Preserve all supported plugin workflows through migration or an explicitly approved replacement. A limited staging package is useful for integration, but is not a complete public replacement.

## Verified starting point

The inventory was inspected locally on 2026-10-18. It establishes code availability, not release readiness or executed cross-platform qualification.

| Component | Inspected committed revision | Current state and implication |
| --- | --- | --- |
| AppSec Advisor | `62f9810262b2a5647ff22143877041a903c6b9d0` on `dev` | Still owns embedded implementation, host hooks, marketplace configuration, and organization packaging. Existing users remain on this runtime until cutover. |
| [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer/tree/6743d172e03115c1f453b80e3aac807a635aebcf) | `6743d172e03115c1f453b80e3aac807a635aebcf` | Public assessment, deterministic scanning, scoring, authorization review, focused threat analysis, and requirements-audit commands exist. The inspected checkout also contains ongoing uncommitted module restructuring; it is not a release input. |
| [AppSec Skills](https://github.com/appsec-foundry/appsec-skills/tree/db437fa31b80832ef32216329d9003b1b396af31) | `db437fa31b80832ef32216329d9003b1b396af31` | Contains the independent `create-threat-model` skill for design-oriented modeling. It currently requires no Analyzer. |

Analyzer's [CLI and capability declaration](https://github.com/appsec-foundry/appsec-analyzer/blob/6743d172e03115c1f453b80e3aac807a635aebcf/appsec_analyzer/cli.py) expose interface version 1 and distinguish available commands from model adapters marked `qualified: false`. Its [package definition](https://github.com/appsec-foundry/appsec-analyzer/blob/6743d172e03115c1f453b80e3aac807a635aebcf/setup.py) already includes runtime resources and selected skills. The alpha version label alone cannot identify a tested composition; record the exact revision and artifact digest.

Advisor's [`copy_source`](../../../scripts/package_internal_plugin.py#L168) copies the existing plugin tree. Its root validation expects the current implementation layout. This is organization packaging, not yet an assembler of independent components. Reuse the applicable branding and surface-selection behavior after separating it from whole-checkout copying. The [release workflow](../../../.github/workflows/release.yml) also needs an explicit build-and-upload stage for composed plugin assets.

## Ownership and interfaces

Each implementation and runtime instruction has one authoritative owner. Distribution through several products must not create several maintained copies.

| Owner | Responsibilities | Consumers |
| --- | --- | --- |
| `appsec-analyzer` | Scanners, scoring, assessment and focused-analysis orchestration, model adapters, source admission, budgets, schemas, semantic prompts, validation, rendering, exports, run state, cancellation, and engine policy enforcement. | CLI users, CI integrations, standalone skills, and the plugin. |
| `appsec-skills` | Portable user-facing workflows, questions, command guidance, and presentation instructions for skills transferred to this collection. | Supported agent hosts, including the composed Claude plugin. |
| `appsec-advisor` | Claude manifests, namespace and help, host hooks and permission adapters, component assembly, installation/preflight, release integration, and plugin integration tests. | Claude Code users. |
| AISCB | Secure-coding baseline content and, where its supported interface permits, baseline lifecycle implementation. | Standalone installations and Advisor's baseline adapter. |

Keep the primary `appsec-analyzer` entry skill authoritative in the Analyzer repository, as the extraction plan already proposes. Package that skill into Advisor under the existing command name, alongside the exact engine it was released with. If the skill collection also offers it, use a documented reference or mechanically generated distribution from the same source. Do not maintain a separate copy there. Claude model usage remains supported through Analyzer's Claude adapter; relocating the implementation does not remove the plugin workflow.

Move general-purpose user skills to AppSec Skills incrementally. Internal model instructions, analysis contracts, schemas, and deterministic checks stay with Analyzer even when a user-facing skill moves. For `analyze-threats`, explicitly separate its currently packaged entry instructions from the engine-owned analysis contract before changing ownership.

### Skill migration map

The table defines migration direction. A command existing in Analyzer does not establish compatibility with every current plugin option or artifact.

| Current or intended skill | Authoritative source | Runtime boundary and acceptance condition |
| --- | --- | --- |
| `appsec-analyzer` | Analyzer | Use public assessment and lifecycle operations. Preserve the plugin command and supported result consumers. |
| `create-threat-model` | AppSec Skills | Remain usable without Analyzer for design-oriented modeling. Do not conflate its `threat-model.md` workflow with assessment execution. |
| `security-score` | AppSec Skills | Invoke Analyzer `score`; consume structured results and declare the scoring version. Document differences from the older plugin scanner and avoid implying numerical comparability across versions. |
| `authnz-review` | AppSec Skills | Invoke Analyzer `authnz-review`, which already owns scanning, model analysis, validation, and exports. Map old options explicitly; do not reimplement the review in the calling assistant. |
| `analyze-threats` | AppSec Skills after ownership transfer | Invoke Analyzer's question-first analysis and public answer/cancel operations. Preserve clarification, preview, bounded execution, and incomplete outcomes. |
| Requirements auditing and verification | AppSec Skills when compatible | Map the current workflow against `audit-requirements`; resolve catalog, remote-source, resume, and export differences before replacing existing behavior. |
| Result questions, triage, repair, re-export, diagnosis, and cleanup | Assign per workflow during inventory | `results` is not a general replacement for these operations. Add missing supported engine operations before removing their existing producers. |

Every transferred skill declares required commands, compatible interface versions, optional tools, and model prerequisites. Update the collection's current blanket statement that its skills need no Analyzer into per-skill dependencies. A user can install the standalone skill with a compatible Analyzer package; plugin execution must select the bundled, tested engine instead of whichever executable happens to be on `PATH`.

Portable instructions must not refer to a sibling checkout, `CLAUDE_PLUGIN_ROOT`, or private engine scripts. Provide a small explicit plugin invocation binding for host-specific paths. Validate the installed skill and its references in both distributions; avoid broad text substitution across engine prompts or resources.

### Hooks and organization policy

Trace each [current hook](../../../hooks/hooks.json) before changing it. Banner and logging code consume run details and include lifecycle behavior; moving entire files or deleting them because they look host-specific would be unsafe. Keep Claude event handling and display in Advisor. Move or retain source admission, organization restrictions, budget limits, cancellation, and cleanup guarantees in Analyzer so direct CLI execution enforces them too.

The plugin should obtain status through public operations. If the banner needs a repository-to-run lookup that the current API does not provide, add a narrow supported query rather than parsing private state. Remove a hook dependency only after its required enforcement and consumers have replacement coverage.

Separate engine configuration from plugin configuration. Analyzer's [organization configuration](https://github.com/appsec-foundry/appsec-analyzer/blob/6743d172e03115c1f453b80e3aac807a635aebcf/appsec_analyzer/organization.py) rejects Advisor-specific hook, skill, banner, and related settings. Dispatch each setting to its owner and preserve the difference between overridable defaults and mandatory policy. Reuse applicable [organization profile contracts](../contracts/org-profile-invariants.md); do not forward the entire existing profile into the engine or silently discard unsupported restrictions.

Baseline lifecycle extraction can follow independently. Keep the existing integration working until AISCB exposes the needed supported operations. A thin adapter is an acceptable intermediate state; moving baseline code into Analyzer merely to reduce Advisor's file count is not the target.

## Package assembly and installation

Introduce a versioned composition lock, provisionally `components.lock.json`, validated against a schema. It records each component's source, immutable revision, package version, artifact digest, interface compatibility, selected skills/resources, licenses, and supported runtime matrix. Record required capabilities separately from qualification evidence. Pin transitive Python dependencies and build tools as well as top-level components.

The builder takes reviewed artifacts from committed revisions and an explicit inclusion manifest. It verifies provenance and digests, rejects incompatible interfaces and duplicate command names, and assembles a clean plugin directory. Local sibling checkouts, untracked files, active run output, credentials, and unrestricted directory copies are not build inputs. Organization overlays cannot replace pinned engine code through namespace rewriting.

Produce a plugin archive, checksums, license notices, and a generated component manifest. Keep the lock as the selected inputs and the manifest as the record of delivered contents. Normalize ordering, timestamps, and permissions so repeat builds with identical inputs can be compared. Build once, qualify the archive, and publish those exact bytes.

### Python and platform setup

Use the existing supported Python interpreter to create an isolated runtime for the selected composition. Store it in an appropriate user-owned application directory, outside analyzed repositories and the possibly read-only plugin installation. Bind its identity to the component/dependency digests, Python compatibility, and platform. Never distribute a relocated virtual environment.

Prefer bundling the locked dependency wheels needed by the supported matrix so setup can install them without runtime dependency resolution or network access. Establish that all selected dependencies have supported artifacts; do not silently compile source packages on the user's machine. If archive size requires platform-specific assets, make their explicit verified acquisition part of setup and qualification, not an undocumented hook behavior.

Provide an explicit setup action and a read-only preflight. Missing or incompatible Python produces actionable instructions. Setup verifies artifacts, uses locked installation, and activates a completed environment atomically; failed setup must not leave a partially usable runtime. Hooks and model-selected actions must not silently run package managers or fetch a newer engine.

The plugin launcher invokes the exact interpreter and engine from that environment, with structured arguments and bounded process handling. Replace Bash-only launch dependencies on supported paths, handle Windows executable discovery and paths with spaces, and verify cancellation, locking, permissions, and cleanup on native Windows. Do not assume that Unix process groups, signals, executable bits, or file locking translate unchanged. Verify model-host prerequisites separately from Python setup.

### Marketplace delivery

Preserve `appsec-advisor@appsec-foundry` and its existing registration path. The proposed release changes the marketplace entry's component source to the qualified archive and digest. The [Claude marketplace reference](https://code.claude.com/docs/en/plugins/marketplace-reference), checked on 2026-10-18, documents HTTPS ZIP archive sources with SHA-256 verification and a Claude Code minimum version for that source type. Recheck the exact syntax and supported host version during implementation and encode that minimum in installation guidance and tests.

Retain the prior tested archive and composition for rollback. Publishing an archive and switching the public catalog are separate release steps. Follow the [release runbook](../../releasing.md), with staging installation and upgrade evidence before catalog cutover.

## Work packages and sequencing

The first [offline implementation evidence](composition-offline-evidence-2026-10-18.md) records portable skill sources, the staging builder/bootstrap, and a real installed-engine deterministic replay. It does not close the package, host integration, platform, or release acceptance gates below.

The operator approved this sequencing change on 2026-10-18: P2–P4 may be implemented and checked offline before A7 completes. Live qualification remains a prerequisite for release, public runtime cutover, and removal of the existing implementation. Linux, macOS, and native Windows remain in scope. A qualified standalone Analyzer release and a reconciled record of relevant Advisor fixes are still required for that gate. This changes work ordering only; it does not waive direct-API or gateway qualification, authorize paid runs, or declare the observed `qualified: false` providers qualified.

### P1 establish the migration inventory

Record every supported skill, hook responsibility, command, artifact consumer, configuration field, permission, and cleanup operation with its current owner and destination. For each, record the public replacement, compatibility gaps, tests, and deletion prerequisite. Choose clean committed component inputs after the ongoing Analyzer restructuring lands. Reconcile applicable Advisor fixes against the extraction ledger.

Acceptance: every existing public workflow has an explicit destination or an unresolved item that blocks its replacement. The primary plugin command and Claude execution path are included. No private-state consumer is assumed covered by `results` alone.

### P2 prepare portable skill distributions

Transfer `security-score`, `authnz-review`, and `analyze-threats` user instructions with their help and required references. Preserve the independent design-modeling skill. Retain the Analyzer-owned primary entry skill and define how it is included in the plugin. Complete the invocation binding and compatibility declaration for each transferred skill. Address requirements skills only when their interface gaps are closed.

Acceptance: each transferred skill works from an installed distribution outside all three repositories. Deterministic skills require no model calls. Model-backed skills preserve their actual host prerequisites, budgets, questions, cancellation, and outcome semantics. Missing or incompatible capabilities fail with useful guidance, without falling back to private scripts.

### P3 build the composed staging plugin

Implement the composition schema and lock, artifact verification, explicit assembly, runtime setup, and launcher. Adapt organization packaging to consume the assembled tree. Keep the old Advisor implementation in the repository during this stage; the staging artifact selects exactly one implementation per command. Establish the platform matrix and reproducible asset outputs.

Acceptance: install the archive outside source checkouts on Linux, macOS, and native Windows using existing Python. Verify read-only plugin locations, paths with spaces, missing prerequisites, failed setup recovery, component mismatch, tampering, command collisions, and use of the pinned engine even when another version exists on `PATH`.

### P4 migrate hooks and remaining consumers

Implement missing public lifecycle, artifact, and consumer operations in Analyzer. Adapt Advisor hooks and result workflows to those operations. Split organization settings by ownership, preserve mandatory restrictions, and update host permissions to match the installed invocation paths. Keep the existing baseline adapter until its separate migration is ready.

Acceptance: assessment launch, progress, status, cancellation, supported result workflows, organization configuration, and cleanup reach the intended component. Direct Analyzer use retains the controls previously enforced through hooks. No migrated consumer relies on private files or an undeclared checkout dependency.

### P5 qualify upgrade and rollback

Exercise controlled standalone and plugin replays against the selected artifacts. Compare canonical outcomes, coverage, provenance, and completion semantics; do not require identical model prose or conceal intentional versioned scoring differences. Record the command/platform/model combinations actually qualified.

Finish or cancel active old-engine runs before switching their workspace. Preserve settings, reports, provenance, and retained user decisions. Treat old and new private run state as incompatible unless an explicit migration or compatibility reader proves otherwise. Rollback restores the prior composition and uses compatible state or a fresh output location; it must not reinterpret newer state or delete results.

Acceptance: an installed previous release upgrades through the existing marketplace registration, the new primary skill performs the supported Claude assessment workflow, and rollback works within documented state limits on all supported platforms. Existing provider qualification and release gates are satisfied.

### P6 release and remove transferred implementation

Publish the tested composition through the normal release process, then perform scoped cleanup in separately reviewable commits. Delete transferred producers only after their supported consumers have switched and replacement coverage exists. Update permissions, configuration, bindings, test routes, and documentation with each removal. Unresolved dependencies block the affected deletion, not unrelated completed transfers.

Acceptance: Advisor maintains host integration and packaging; Analyzer owns engine fixes; AppSec Skills owns the transferred workflows. A plugin engine update is a reviewed component-pin update with relevant integration evidence. No supported command calls removed scripts or depends on a sibling checkout. The component manifest identifies exactly what users installed.

## Security boundaries and verification

Apply the AI Secure Coding Baseline aiscb to the affected package, process, and agent boundaries. Protected assets include admitted source, business context, credentials, results, retained decisions, and run state. Trusted release configuration selects executable components; target repositories, catalogs, scanner output, and model output remain untrusted data and cannot choose installation sources, executable paths, permissions, or write destinations.

Verify locked dependencies and artifact integrity before installation or execution. Confine archive extraction, reject escaping paths and links, and bound expanded size and entry counts. Keep publication credentials out of untrusted build jobs and use least-privilege CI permissions. Preserve authorization, source grants, deterministic output validation, budget limits, cancellation, and output ownership independently of Claude hooks. Reject missing or incompatible security context rather than using an uncontrolled fallback.

Verification follows ownership: Analyzer tests engine behavior and contracts, AppSec Skills tests dependency declarations and installed references/workflows, and Advisor tests composition and host integration. For each implementation change, select only checks that exercise the changed behavior or its consumers. Add neutral reproductions, variants, and negative cases for producer fixes; scanner or deterministic-tail changes also require the [golden fixture replay](../runbooks/threat-fixture.md). Run full release gates when the corresponding release requires them, not for every migration edit.

Installed-artifact checks establish independence from source trees. Cross-platform checks establish the declared runtime support. Controlled replays establish deterministic compatibility. Authorized live assessments establish model qualification. Keep their evidence separate; passing one does not substitute for another.

## Decisions still needed during implementation

The platform family and Python prerequisite are settled. The remaining technical selections are the exact Python/OS/architecture matrix, initial immutable component versions, complete capability compatibility declarations, and the resulting asset layout. Resolve these from the package inventory and platform evidence. Ask the operator before reducing the agreed platform or workflow scope, changing a product promise, or revising the existing provider qualification gate.

The [P1 inventory](appsec-advisor-composition-inventory-2026-10-18.md) records all existing skills, hook consumers, configuration fields, permissions, cleanup boundaries, and relevant Advisor fixes against committed component revisions. No workflow has switched. Offline P2–P4 work proceeds under the approved sequence above; qualification and reconciliation gaps still block release, public cutover, and removal. The inventory distinguishes available commands from compatible replacements and records the evidence required for each transfer.
