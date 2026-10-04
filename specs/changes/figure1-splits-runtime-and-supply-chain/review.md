# Review of the runtime and supply-chain figure split

This review records proposed corrections to [proposal.md](proposal.md) and [tasks.md](tasks.md) for coordination between sessions. It does not approve requirement changes or modify the proposed design. The findings below distinguish implementation evidence from recommendations and decisions still needed.

## Scope and conclusion

The review compared the proposal with the current producers, rendering code, actor attribution, configuration checks, requirements, and schema invariants on 2026-10-03. It was a static review. No tests or fixture replays were executed. The cited Juice-Shop run and mockup were not independently inspected, so their exact appearance and component inventory remain unverified.

The split addresses a confirmed inconsistency, but the proposal is not ready for implementation. The initial six issues concern evidence for connecting the supply-chain elements, non-GitHub producer coverage, entry-point eligibility, count partitioning, display conditions, and agreement between the proposal and task scope. A subsequent interface review added three issues concerning runtime views without attack scenarios, shared identities in the saved artifact, and navigation during table fallback.

The proposed `REQ-RPT-008` is not an existing requirement. The current `REQ-RPT-007` concerns Figure 1 readability. Accepted wording must receive explicit operator approval before changing [specs/requirements.md](../../requirements.md).

## Confirmed basis for the change

The three cited consumers use different build-zone checks:

- [`figure1_dfd._zone_key`](../../../scripts/renderers/figure1_dfd.py) accepts any deployment-zone string containing `ci`, `build`, or `pipeline`, then falls back to the component tier.
- [`figure_deployment.py`](../../../scripts/renderers/figure_deployment.py) selects build components by the exact zone `build-pipeline`.
- [`actor_attribution._valid`](../../../scripts/analyzers/actor_attribution.py) uses the canonical zones from [`actor-attribution-rules.yaml`](../../../data/actor-attribution-rules.yaml), but also accepts independent CWE and evidence-path matches.

A component with `tier: application` and no deployment zone therefore takes the application placement in `_zone_key`, as the proposal describes. A shared component predicate would remove that placement inconsistency. It must not inadvertently replace the separate finding-attribution rules: component placement and evidence that an actor can exploit a finding are different decisions.

## Findings and proposed corrections

The first two findings affect whether the promised attack path can be produced from evidence. The remaining findings affect consistency and acceptance criteria.

### R1: Existing facts do not establish an end-to-end delivery path

**Affected proposal:** “Figure 1b content,” “Entry points and the highlighted path,” and decision 4.

**Evidence:** [`supply_chain_facts._workflows`](../../../scripts/analyzers/supply_chain_facts.py) records workflow file locations for inputs and outputs. Container outputs contain a kind, file, line, and pushed flag, but no registry or artifact identity. The [`supplyChainFacts` schema](../../../schemas/config-scan-findings.schema.yaml) confirms this shape. [`deployment_inventory.scan_ci`](../../../scripts/analyzers/deployment_inventory.py) aggregates GitHub workflows into one CI-system row and a list of publish destinations. `scan_dependencies` emits aggregate counts and a global lockfile flag under `dependencies`, with selected package entries returned separately. These structures do not establish the complete relation between a dependency, the job that consumes it, the produced artifact, and the deployment that executes that artifact. Shared workflow-file evidence can support some associations, but does not resolve independent jobs within that file.

**Consequence:** A repository can contain a vulnerable dependency used only by a test workflow and a separate production image workflow. Joining facts merely because they belong to the same repository or CI system could draw a production compromise path that the evidence does not support. A registry push also does not prove that production executes the image.

**Proposed correction:** Specify evidence-bearing relationships in `.supply-chain-view.json`, not only evidence-bearing elements. Each highlighted step must connect the actual evidenced input, build, artifact, and delivery relationship. Define what happens when a relationship is unknown. Do not complete an unknown chain by choosing an arbitrary CI system, artifact, or execution row. A conceptual execution endpoint may remain visible, but its unproven connection must be distinguishable from an evidenced delivery flow.

**Decision needed:** Either extend producers to capture the required relationships in this change, or narrow the promise to showing the evidenced portion of a potential attack path. The unconditional statement that every delivery channel ends in production needs to reflect that choice.

**Acceptance cases:** Two independent workflows must not be joined into one attack path. A publish-only repository must not assert production execution. A complete evidenced chain must still highlight end to end. Re-rendering the view artifact without repository access must preserve the same relationships and evidence status.

### R2: Extending the scan gate does not provide GitLab or Jenkins supply-chain facts

**Affected proposal:** The producer-gap discussion and verification cases 2 and 3. **Affected tasks:** Slice 4.

**Evidence:** `WORKFLOW_GLOBS` in [`supply_chain_facts.py`](../../../scripts/analyzers/supply_chain_facts.py) includes only GitHub workflow files. `collect` passes those files to `_workflows`; its capability searches also use Dockerfiles, package manifests, and Makefiles, but not GitLab or Jenkins definitions. `precondition_holds` derives `publishes_container_image` from collected outputs. [`IAC-040`](../../../data/config-iac-checks.yaml) requires that precondition. `deployment_inventory.scan_ci` can report a Jenkins registry destination, but that destination is not the fact source used by this check.

**Consequence:** Opening `_has_iac_surface` for a Jenkins-only repository does not make its image push visible to `IAC-040`. The proposed Jenkins/Maven test cannot obtain its required unsigned-artifact entry through the specified gate change alone. GitLab inventory visibility likewise does not imply equivalent supply-chain check coverage.

[`config_iac_scanner.py`](../../../scripts/analyzers/config_iac_scanner.py) evaluates `expect: repository` checks directly through `capability_gap`, before per-file evaluation. The check's `github_workflow` label is therefore not itself the immediate blocker. The missing push facts and resulting false precondition are the blocker identified here; changing a label or file pattern alone would not fix it.

**Proposed correction:** Separate CI-system discovery, scan eligibility, fact extraction, and check applicability in the task list. Add the non-GitHub input/output and capability producers required by the promised fixtures, with corresponding schema and check changes where necessary. Alternatively, explicitly limit these systems to inventory display until their finding producers exist and change the acceptance promise accordingly.

**Decision needed:** Choose full finding support or inventory-only support for each CI system in this change. Do not describe inventory-only support as a complete supply-chain analysis.

**Acceptance cases:** A Jenkins-only image push without signing must produce the expected facts and finding before testing the renderer. A signed variant must suppress that finding. GitLab-only input must exercise its real producer path. Merely supplying hand-authored renderer facts does not verify the producer gap.

### R3: Element attachment does not define attack-entry eligibility

**Affected proposal:** The check-to-element mapping and entry-point table.

**Evidence:** The mapping attaches `IAC-012` and `IAC-013` to a CI-system element, while “Change in the repository” expects workflow injection and privileged fork checkout among findings attached to the repository. The mapping also attaches both `IAC-040` and `IAC-041` to release artifacts. In [`config-iac-checks.yaml`](../../../data/config-iac-checks.yaml), `IAC-041` reports missing SBOM generation; it does not establish that an artifact can be replaced. The proposal does not explicitly define how attachment and attack eligibility interact.

**Consequence:** An implementation based only on element kind could omit the workflow entry or turn a visibility/control-assessment gap into an unsupported artifact-replacement attack. The fallback “attaches to its CI system” is also undefined when no CI system is evidenced or several systems are present.

This is a specification ambiguity, not an observed renderer defect. The entry table already qualifies replacement with “pushed and not signed,” which can correctly exclude an SBOM-only finding. The correction should make that eligibility test explicit and independent of element attachment, rather than assert that the current proposal necessarily creates a false entry.

**Proposed correction:** Define separate fields or rules for display attachment and entry eligibility. Eligibility must identify the attack mechanism and its prerequisites, using the reported finding rather than the presence of any finding on an element. Preserve missing-SBOM findings as annotations without treating them alone as an artifact-replacement entry. Define an unresolved association explicitly rather than guessing a CI owner.

**Decision needed:** Resolve the coding-agent configuration question using evidence of the relevant mechanism and build relationship. Do not let every finding in a numeric check range automatically assert a release-compromise path.

**Acceptance cases:** `IAC-012/013` remain eligible for their intended entry even when displayed on CI. A missing-SBOM-only repository has no replacement entry. An unsigned pushed image can qualify under the chosen prerequisites. Findings with missing or ambiguous CI ownership remain visible without an invented association.

### R4: Actor filtering does not guarantee additive header totals

**Affected proposal:** “Figure 1a” and proposed decision `RA-29`.

**Evidence:** [`actor_attribution.reconcile_attribution`](../../../scripts/analyzers/actor_attribution.py) permits multiple actor IDs and findings without an attacker. [`compose_threat_model._attributed_only_to`](../../../scripts/renderers/compose_threat_model.py) explicitly distinguishes exclusive attribution. [`risk_distribution_counts`](../../../scripts/renderers/_severity_rollup.py) counts the Management Summary basis, including design-risk weaknesses under practice folding; that basis is not simply the number of findings reachable through displayed attack scenarios.

**Consequence:** Removing build-time scenarios from Figure 1a does not partition all summary-counted items. A finding attributed to both runtime and build actors could be counted twice, and an attackerless finding or design-risk weakness could be omitted. The promised equation is therefore underspecified.

**Proposed correction:** Define count ownership separately from scenario visibility. Every item counted by the existing summary tally must have exactly one count owner if additive totals remain the requirement. An item may be referenced in both figures without being counted twice. Cover actorless items, mixed attribution, folded practices, and design-risk weaknesses explicitly. Table fallback and an omitted Figure 1b must preserve the chosen counting semantics.

**Decision needed:** Retain additive totals with a complete ownership rule, or use non-additive view counts with an explicit explanation and revise `RA-29` accordingly.

**Acceptance cases:** Assert the chosen invariant with a mixed-actor finding, a build-only finding, a runtime-only finding, an attackerless finding, and a design-risk weakness. Include a mixed runtime/build component and fallback rendering.

### R5: Display and geometry promises have conflicting scopes

**Affected proposal:** Goal, non-goals, proposed `REQ-RPT-008`, and verification cases 4 and 5.

**Evidence:** The requirement applies when a repository “builds or publishes software,” but case 4 excludes every repository without a CI definition. A local Makefile or Dockerfile can provide build evidence without CI. The requirement also promises a path from an attacked input whenever the figure applies, while case 5 correctly expects no entry points when no finding supports an attack. Finally, the generic prohibition on crossing lines includes Figure 1a in ordinary reading, but the non-goals explicitly retain its existing crossings.

**Consequence:** An implementation cannot satisfy all these statements under one interpretation. The acceptance cases do not determine which promise takes precedence.

**Proposed correction:** Define one explicit `has_build_evidence` condition and use it consistently in the requirement, renderer, strip, cleanup, and tests. Distinguish whether the view exists from whether an attack entry exists. Scope the new geometry gate and table fallback explicitly to Figure 1b unless changes to Figure 1a are intentionally added.

**Candidate wording for discussion, assuming local builds remain in scope:** “When repository evidence establishes a build or publication process, the Management Summary includes a supply-chain view of the evidenced inputs, build systems, and release artifacts. A reported finding adds an attack entry only when it establishes the relevant mechanism. Highlighted paths follow evidenced relationships; unknown delivery relationships remain explicit. The runtime figure excludes build-plane elements. Figure 1b is replaced by a table when its geometry self-check fails.”

This wording is a proposal, not an approved requirement change. The final wording must also settle the actor-display behavior when no active build-time actor exists and retain the operator's intended execution-endpoint behavior without asserting unsupported delivery.

If the operator instead chooses CI-only scope, narrow the opening condition to evidenced CI build or publication and retain a no-CI exclusion test. Neither scope choice is established by this review.

**Acceptance cases:** No build evidence, local build without CI, CI without findings, build findings without a complete delivery chain, and a Figure 1b geometry failure. Existing Figure 1a crossings must not accidentally activate a newly scoped Figure 1b rule.

### R6: The task list includes producer work that the proposal defers

**Affected proposal:** “What the mockup showed that the producers cannot deliver today.” **Affected tasks:** Slice 4.

**Evidence:** The proposal says the design omits unavailable facts until producers exist, including additional deploy targets, inline trigger handling, and per-ecosystem lockfile pairs. Slice 4 schedules producer changes for these areas. The proposal does not identify which omissions become deliverables in this change.

**Consequence:** Sessions could implement different scopes and disagree on completion. Additional deploy-target extraction could expand the work without being necessary for the split, while the non-GitHub facts needed by R2 remain unspecified.

**Proposed correction:** Mark each producer gap as required for this change or deferred. Make `tasks.md` reflect exactly that classification. Prioritize producers needed for accepted end-to-end cases. Keep additional deployment platforms and trigger analysis out of this change unless explicitly selected.

**Decision needed:** Agree on the bounded producer scope before implementation. Synchronize the proposal, task list, and fixture expectations in the same revision.

**Acceptance criterion:** Every producer task supports an accepted behavior or fixture, and every fixture has a producer capable of emitting its required facts and findings.

### R7: A build-only attack model can empty the runtime renderer's input

**Affected proposal:** Figure 1a filtering and the requirement that Figure 1b links to the runtime view. **Affected tasks:** Slice 1 fallback handling.

**Evidence:** [`compose_threat_model._render_figure1_svg`](../../../scripts/renderers/compose_threat_model.py) returns an empty string when `attack_paths` is empty, even if runtime components exist. Its caller attempts a Mermaid fallback and then reads `.fragments/top-threats-architecture.md` if the deterministic builders yield nothing. The task list addresses filtered tier-stack and Mermaid inputs but does not address this last fragment fallback or the empty-scenario guard.

**Consequence:** In a repository whose only reported attack scenarios are build-time scenarios, the proposed filtering can leave Figure 1a with components but no attack paths. Retaining the existing guard would skip the DFD. An unfiltered saved fragment could then reintroduce build elements, and an empty fallback could leave Figure 1b linking to a runtime view that is absent. This is a conditional integration failure identified from the current call path, not a reproduced failure of an implemented split.

**Proposed correction:** Render the runtime architecture independently of whether runtime attack scenarios exist. Define what to show when no runtime components exist at all. Cover every fallback, including the saved fragment, with the same build-plane exclusion invariant. Do not use an unvalidated legacy fragment to bypass that invariant.

**Acceptance cases:** A model with runtime components and only build-time findings retains a runtime DFD without attack arrows. A stale fragment containing CI components cannot reintroduce them after filtering. A build-tool repository without an evidenced running application has an explicit endpoint policy and no dangling runtime-view link.

### R8: The artifact needs resolved actor and scenario identities plus a freshness rule

**Affected proposal:** The exclusive `.supply-chain-view.json` renderer input, people-list union, shared scenario numbers, and highlighted step numbering. **Affected tasks:** Slice 2 builder and retained artifact.

**Evidence:** [`compose_threat_model._overview_people`](../../../scripts/renderers/compose_threat_model.py) loads resolved attack paths, actor labels, and model display data. [`figure1_dfd.overview_people`](../../../scripts/renderers/figure1_dfd.py) returns names, subtitles, actor codes, and scenario numbers. Actor codes are assigned from the actor order during node construction. The proposal lists inventories and merged threats as builder inputs, while its actor table additionally refers to active actors and posture labels. It does not specify how the resolved shared presentation identities reach the artifact, or when they are refreshed.

**Consequence:** Independently reconstructing actors and paths from a filtered threat set can change actor codes or scenario numbers. Retaining a view artifact is necessary for offline rendering, but does not by itself prevent outdated severity, selected paths, or labels after a model rebuild. Local step numbers `1..n` can also be confused with the existing shared scenario numbers unless their meanings remain distinct.

**Proposed correction:** Build or reconcile the artifact after canonical actor and scenario resolution, and persist the shared identities and display fields it needs. Distinguish scenario references from local path-step numbers in the schema and legend. Specify when the artifact is regenerated and how composition handles an absent, invalid, or outdated artifact. Retain the inputs needed by the chosen offline rebuild policy. Deduplicate the people-list union by stable identity, not by independently assigned display codes.

**Acceptance cases:** Both views and Figure 2 retain the same actor and scenario references after filtering. A repository-free re-render preserves them. A changed finding severity or membership either regenerates the dependent view or produces an explicit incompatibility result; it must not silently combine a new report with stale supply-chain claims. An older report directory without the new artifact follows a defined compatibility path.

### R9: Table fallback needs a stable navigation target and content contract

**Affected proposal:** Layout fallback and report placement. **Affected tasks:** Slice 3 links, publication, and exports.

**Evidence:** The proposal removes the Figure 1b SVG when it is not written, while the runtime strip, Top Threats table, actor row, and §2.2 refer readers to Figure 1b. It does not define whether these references target the SVG file or a report anchor that survives table fallback. [`REQ-RPT-003`](../../requirements.md) requires references to locations that exist, and `REQ-EVO-003` governs incompatible published-anchor changes.

**Consequence:** File-target links can become dangling when geometry fails, even though the table renders successfully. A fallback table that preserves only inventory rows could also discard the finding references, highlighted path, or evidence needed to interpret the same content.

**Proposed correction:** Give the supply-chain view a stable report anchor shared by its image and table forms. Define the table's required information, including findings, evidence, unknown relationships, path order when available, and overflow details. Specify separate behavior when the view is not applicable and when its artifact is invalid; neither is automatically a geometry failure with trustworthy table content. Carry the navigation target through Markdown, HTML, and PDF.

**Acceptance cases:** Force geometry failure after a successful SVG render. The old SVG is removed, all report references resolve to the table, and findings and path evidence remain available. When build evidence disappears, remove the stale artifact or invalidate it according to R8 and omit all obsolete links. Check a custom report stem and exported HTML/PDF targets.

### R10: Clean geometry and legibility at delivery size are mandatory

**Operator clarification:** Figure 1b must consistently scale and draw cleanly. This is a central acceptance condition, not a cosmetic follow-up. The clarification applies to the new Figure 1b; it does not expand the change to redesign Figure 1a.

**Affected proposal:** Goal, fixed columns and slots, content caps, layout self-check, proposed `REQ-RPT-007`, and verification cases 6 and 7. **Affected tasks:** Renderer, exports, examples, and regression fixtures.

**Evidence:** The proposed self-check covers intersections, overlaps, and text overflow, but not the effective text size after fitting the SVG to a report page. Fixed element counts do not bound label length or legend height. Fixed vertical slots do not alone establish valid routing for multiple inputs feeding one build or one build feeding multiple artifacts. The existing [`test_readme_example_is_legible_at_page_width_and_names_the_scanned_project`](../../../tests/test_figure1_dfd.py) checks Figure 1's scaled font size against an explicit target width and minimum font size; Figure 1b needs its own coverage.

**Consequence:** A diagram can pass geometric checks in SVG coordinates yet become unreadable when reduced to page width. Long repository-controlled labels, uneven column populations, and large legends can also make a nominally bounded diagram clip, overlap, or shrink excessively. A single attractive mockup does not establish this behavior for arbitrary repositories.

**Proposed correction:** Treat geometry validity and legibility at the delivered size as separate publication gates. Measure text and wrapped lines before routing edges. Size columns from their content within a defined width budget, and allocate vertical space for the actual rows, labels, badges, and legend. Keep arrowheads, line weights, and badges visually consistent at the target size. Do not satisfy the width budget by silently dropping evidence labels or shrinking text below the accepted minimum. Preserve required content through explicit aggregation and complete overflow details, or use the table fallback when the diagram cannot meet both gates.

The renderer contract must name supported display widths, the PDF content area, minimum effective font sizes, and spacing tolerances. Set numeric thresholds before implementation acceptance, using the existing Figure 1 readability guard as a reference rather than assuming its constants suit five columns. Keep the thresholds and layout algorithm in their authoritative technical sources; requirement prose should state the observable readability and clean-drawing promise.

For a uniformly scaled SVG, check effective font size as `source_font_size × displayed_width / viewBox_width`; account for any additional height constraint or export scaling. Check all required text roles, including legend and evidence references, rather than only the heading. Validate the final bounds including arrowheads and strokes. Check text against other text, boxes, badges, lines, and zone headings with a positive clearance. Define legitimate shared endpoints separately from forbidden intersections, and prevent overlapping routes from obscuring distinct flows. Wrapping must handle long unbroken paths or artifact references and preserve access to the full value.

**Required acceptance matrix:**

- Sparse input, no findings, one complete path, and every supported entry kind.
- Each content cap at its limit and beyond it, with uneven column populations and the highest-severity entry among overflow candidates.
- Multiple inputs feeding one build, one build producing several artifacts, multiple CI systems, and delivery channels with different evidenced associations.
- Long names, unbroken references, wrapped evidence labels, supported non-ASCII characters, and a large overflow legend.
- Standalone SVG and embedded report/README at the declared widths, plus final HTML and PDF output at their declared sizes.
- Forced geometry failure and forced readability failure; both must produce a complete usable table, preserve R9 navigation, remove stale SVG output, and record the render warning and run issue.

Use deterministic geometry and scaled-size assertions as regression gates. Inspect representative rendered SVG, HTML, and PDF examples at actual display size to catch font-metric and export differences that the geometry model misses. Normal inputs within the supported envelope must render as diagrams; always falling back to a table is not an acceptable way to pass the quality gate. For inputs outside that envelope, never publish a broken or unreadably scaled Figure 1b merely to keep an image present. The fallback table must also wrap long values and remain readable in exports.

**Proposed requirement addition for approval:** “Figure 1b remains readable at the supported report and README widths and in exported HTML and PDF. Its labels, connections, arrowheads, and badges remain distinct and unclipped. When the renderer cannot satisfy the geometry and readability checks, the report presents the same information as a readable table and records the fallback.”

This records the operator's quality requirement and proposes measurable implementation obligations. It does not claim the current mockup or any future renderer has passed them.

## Coordination and verification follow-up

Resolve R1 and R2 first because they determine the scope of the artifact and producer work. Then settle entry eligibility, tally semantics, and the display condition. Apply accepted corrections to the proposal and task list together. Update normative requirements only after explicit operator approval.

Include R10 in the initial renderer design and acceptance plan. Do not postpone scaling, routing, or export readability until after report wiring or example generation.

The verification plan should include a neutral reproduction of the existing misplacement, a variant with different incidental CI paths or names, and a negative case where mixed application/CI evidence retains runtime placement. These cases complement the seven proposed renderer fixtures; the original Juice-Shop replay remains additional evidence.

Inspect the actual fixture inputs before treating case 6 as a cap test. Three ecosystems and two CI systems do not by themselves exceed the stated limits. Exercise each cap beyond its limit and check that overflow preserves identities, evidence, and any selected attack path. The geometry suite also needs valid fan-in and fan-out cases, with an explicit distinction between legitimate shared endpoints and forbidden crossings.

Requirement bindings, producer/consumer routes, cleanup, publication, permissions for any new commands or artifact paths, and PDF/HTML behavior must be reviewed after the implementation scope is fixed. Existing tasks already cover several of these integration points; this review does not claim they are all missing. Run the repository's routed checks for the resulting implementation and report any missing producer or replay evidence before declaring the defect fixed.

## Self-review

A second static pass checked the scanner's repository-check dispatch, the supply-chain schema, dependency aggregation, actor deduplication, and the summary tally. The original six findings remain applicable. R2 now names the missing facts as the immediate blocker rather than suggesting that check metadata gates repository checks. R3 explicitly distinguishes an underspecified eligibility rule from an observed implementation failure. R5 labels local-build inclusion as an assumption of the candidate wording, not an agreed scope decision. A further pass traced the renderer's empty-input and fallback branches and the actor-presentation inputs, producing R7–R9. Those additions identify implementation obligations and missing design rules, not failures of code that has not yet been written.

`check_specs.py --for` reports no requirement binding for this review file. Both `make test-plan BASE=origin/dev` and `make test-plan BASE=HEAD` select the full suite because the new change-directory Markdown files have no reviewed route. This review changes documentation only; no runtime tests or fixture replay were run to establish its claims. The static evidence does not verify the original run, the proposed geometry, or future implementation behavior.
