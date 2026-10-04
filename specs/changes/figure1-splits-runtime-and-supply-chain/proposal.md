# Figure 1 splits into runtime and supply chain

## Problem

Figure 1 is a data-flow diagram of the running system, but it also draws the build pipeline and the build-time attacker. In the 2026-10-02 juice-shop run (`docs/security/threat-model.figure1.svg`), `C-06 · CI/CD Pipeline` sits in the Application Layer with no data flow, and the Supply-Chain / Build Attacker reaches it over a long attack line across the diagram. The reader sees an attacker hitting an isolated box and cannot see how a supply-chain attack reaches production.

The placement comes from a defect. `figure1_dfd._zone_key` puts a component in the build zone only when its `deployment_zones` contains `ci`, `build` or `pipeline`. The juice-shop pipeline component has `tier: application` and no `deployment_zones`, so it falls back to the application column. Three places decide what a build component is, with three different rules: `_zone_key` (substring match), `figure_deployment.py` (exact `build-pipeline`) and `actor_attribution._valid` (canonical zones plus independent CWE and evidence-path matches).

A supply-chain attack happens at build time and takes effect later, when the release runs. A runtime data-flow diagram cannot show that chain. Part of the data exists: `.deployment-inventory.json` lists CI systems, publish destinations and aggregate dependency facts, and `.config-scan-findings.json` → `supply_chain_facts` lists GitHub workflow inputs with their pinning, outputs and repository-wide capabilities. No renderer reads `supply_chain_facts` today. The facts do not relate an input to the job that consumes it, the artifact that job produces, or the deployment that runs that artifact.

## Goal

Figure 1a shows the runtime only. A new Figure 1b shows the build-time attacker, the inputs, build systems and release artifacts the repository evidences, and the running system they feed. Where the evidence relates them, Figure 1b draws the path from an attacked input towards production. Where it does not, Figure 1b says so instead of completing the chain. Figure 1b is drawn cleanly and stays readable at its delivered size, or it is replaced by a table.

## Decisions

The operator chose, in this session:

1. Figure 1 becomes Figure 1a, the runtime view. It draws no build component, no build-time attacker and no build-time scenario. A strip under its heading names the build systems found and points to Figure 1b.
2. Figure 1b, Supply Chain and Build, stands in the Management Summary directly after Figure 1a and before Figure 2.
3. Figure 1b draws the build-time attacker as its own element, with the name and description used in §1 Identified Actors and Figure 2.
4. Figure 1b ends in one execution element, the running system, which links to Figure 1a. A connection to it is drawn as evidenced only when the repository shows the deployment; otherwise it is drawn as not evidenced.
5. The path of the most severe eligible entry is drawn as numbered steps along evidenced relationships and stops where the evidence ends. The attack through unpinned dependencies is the reference case.
6. Figure 1b shows the evidenced part of a path. Producers add job-level relationships for GitHub workflows in this change; no chain is completed by guessing.
7. GitHub Actions, Dockerfiles and package manifests get facts and findings in this change. Other CI systems appear in Figure 1b as inventory only, marked as such.
8. Header counts are not additive. Figure 1a keeps the model-wide tally that the existing invariant ties to the Management Summary. Figure 1b states how many findings it shows.
9. Figure 1b appears when a CI definition is evidenced or at least one build-time scenario has findings. Without CI evidence, its build column states that no CI is evidenced.
10. Figure 1b must draw cleanly and stay legible at its delivered size. Geometry and legibility are separate publication gates; when either fails, the report shows the same information as a table and records the fallback. This applies to Figure 1b only.

## Design

### Build placement

One function decides whether a component belongs to the build plane. Figure 1a, Figure 1b and the §2.2 container diagram use it. It decides placement only. Actor attribution keeps its own rules in `actor-attribution-rules.yaml`, because placing a component and judging whether an actor can exploit a finding are different decisions.

The canonical zone names stay those of `actor-attribution-rules.yaml` (`build-pipeline`, `ci-cd-runtime`, `deployment-pipeline`). Component finalization derives a build zone when every evidence path of a component is a CI definition file (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.travis.yml`). A component that also cites application source keeps its runtime placement. A Dockerfile alone does not make a component a build component, because the same file defines the runtime image.

### Figure 1a

Figure 1a filters build components, their flows and boundaries, and every scenario whose actor is the build-time group. Path numbers stay shared with Figure 2 and the Top Threats table. Component numbers come from the full model, so `C-NN` does not change when a component is not drawn.

Figure 1a is drawn whenever runtime components exist, with or without runtime attack scenarios. A model whose only scenarios are build-time scenarios gets a runtime data-flow diagram without attack arrows. Every fallback (tier stack, Mermaid, saved fragment) receives the same filtered input. A saved `.fragments/top-threats-architecture.md` is used only when it contains no build-plane component; otherwise it is rejected with a render warning. A model without runtime components has no Figure 1a; Figure 1b then states "no running application evidenced" and carries no link.

The header keeps the model-wide threat tally, labelled as such, so the existing invariant between the figure header and the Management Summary holds. The people list that Figure 1 provides to §1 Identified Actors, §2 and the actor-name QA check becomes the union of both figures, deduplicated by actor slug.

The strip under the heading reads, for example: "Build pipeline, not drawn in this runtime view: GitHub Actions, GitLab CI. ⑧ Supply-Chain / Build Attacker → Figure 1b". It appears exactly when Figure 1b appears.

### When Figure 1b appears

`has_build_evidence` holds when the deployment inventory reports a CI system, or when at least one resolved build-time scenario has findings. The same condition drives the Figure 1b section, the strip, every link to Figure 1b, stale-file cleanup and the tests. Whether the view exists and whether it has an attack entry are separate questions: a view without an eligible finding shows inputs, build and artifacts without an attack arrow.

### The supply-chain view artifact

`.supply-chain-view.json`, with a schema, holds elements, relationships and finding attachments. It is built after threat merge and actor attribution from `.deployment-inventory.json`, `supply_chain_facts`, `.threats-merged.json` and the component inventory. It records a fingerprint of these inputs: finding ids, register severities and actor attributions.

Actor codes and scenario numbers are not stored in the artifact. Composition takes them from the same resolved attack paths and actor labels that drive Figure 1a, Figure 2 and the Top Threats table, so all three agree after filtering and on a repository-free re-render.

Composition compares the fingerprint with the current model. A mismatch rebuilds the artifact when its inputs are present. When the inputs are missing, Figure 1b, the strip and all links are omitted and the run records an outdated-view warning; a new report is never combined with stale supply-chain claims. An older report directory without the artifact follows the same path. The artifact and its inputs are kept for re-render (`audit-artifacts.md`).

### Elements

Figure 1b has five fixed columns. Each element carries its source (`file:line`, or an absence with the files searched, as `FE-20` defines).

| Column | Elements | Source |
|---|---|---|
| Attacker | the build-time actor; omitted with a legend note when no build-time actor is active | posture actor labels, active actors |
| Sources and inputs | repository; one upstream group with one row per input kind: package ecosystem, CI action, base image, remote installer | `supply_chain_facts.inputs`, manifests from the deployment inventory |
| Build | one element per CI system; GitHub with findings, others marked "inventory only"; "no CI evidenced" when none | `deployment_inventory.ci` |
| Release artifacts | one element per evidenced output: container image, package per ecosystem | `supply_chain_facts.outputs`, `ci[].publishes` |
| Execution | one element "running system → Figure 1a", one row per delivery channel the inventory evidences | `publishes`, `environments` |

The vocabulary is closed. An input kind, CI system or delivery channel that no producer reports is not drawn. Caps keep the figure bounded: at most four upstream rows, three CI systems, four artifacts and five delivery rows. Overflow becomes an explicit "+N more" row whose members, evidence and findings are listed in the legend and in the table form.

### Relationships

Every edge in the artifact carries `status: evidenced` or `status: unknown` and, when evidenced, its source.

- Input to build: evidenced when the input is used by a job of that CI system. For an action or base image, the job that references it. For a package ecosystem, a job that installs that ecosystem's dependencies or builds a Dockerfile that does.
- Build to artifact: evidenced when the same job pushes or publishes the artifact.
- Artifact to execution: evidenced only when a deployment step in the repository consumes that artifact. A registry push alone does not prove that production runs the image, so the edge stays unknown.

For this, `supply_chain_facts` records the workflow job of each input and output, and the destination of each container output where the push names one. Facts in two independent jobs are never joined. Unknown edges are drawn dashed and grey with the label "not evidenced"; they never carry an attack step.

### Findings and entry eligibility

A data file maps each config check to two independent properties: the element it is displayed on and the attack entry it can establish, if any. Display attachment never implies an entry.

| Check | Displayed on | Entry it can establish |
|---|---|---|
| `IAC-050`, `IAC-051`, `IAC-005` | package ecosystem | manipulated dependency |
| `IAC-011`, `IAC-001` | CI action, base image | manipulated CI input |
| `IAC-012`, `IAC-013` | CI system | change through the repository |
| `IAC-071` | repository | change through the repository |
| `IAC-060` to `IAC-075` except `IAC-071` | repository | none |
| `IAC-040` | release artifact | replaced release artifact, when the artifact is pushed |
| `IAC-041` | release artifact | none (missing SBOM is a visibility gap) |
| `IAC-010`, `IAC-014`, `IAC-015` | CI system | none (they widen the impact of an entry) |
| `IAC-030` to `IAC-035` | repository | none |

A drift test keeps the file aligned with `data/config-iac-checks.yaml`. Runtime hardening checks (`IAC-002`, `IAC-003`, `IAC-020` to `IAC-024`, `IAC-080` to `IAC-086`) stay on runtime components in Figure 1a. A dependency CVE exploited at runtime stays in Figure 1a with the internet attacker. A build-time finding whose CI owner is unknown or ambiguous is listed under "findings without an evidenced CI owner" and is not attached to a guessed element.

The highlighted path belongs to the eligible entry with the highest register severity, with ties broken by the order of the entry column above. Its steps carry local numbers 1 to n, drawn as outlined circles and distinct from the filled scenario numbers ① to ⑨; the legend names both.

### Layout, legibility and fallback

Geometry rules:

- Flows run horizontally between neighbouring columns through the gaps.
- Attack routes run only in the gap between the attacker and the sources column and in one lane above the zones. They cross only the border of their target's zone, and only once.
- Fan-in (several inputs to one build) and fan-out (one build to several artifacts) use distinct ports, so overlapping routes never hide a flow.
- Arrowheads have one fixed size, line weights one value per style, and entry and step symbols one radius, in the figure and in the legend.

Legibility rules:

- Text is measured and wrapped before routing. Long unbroken references wrap at path separators, and the full value stays available in the legend or the table.
- Columns are sized from their content within a width budget, and rows take the height their wrapped text needs.
- No evidence label is dropped and no text is shrunk to meet the budget. Aggregation is explicit, or the table is used.

The geometry gate fails on any of the following: a line crossing another line, a line through a box it does not connect, a line through any text or zone heading or through a badge of another line, a badge touching an arrowhead, text overflowing its box, an attack route crossing a foreign zone border, or content outside the final bounds including strokes and arrowheads. Legitimate shared endpoints are declared, not exempted by tolerance.

The legibility gate computes the effective size of every text role as `font size × displayed width / viewBox width` for each supported display width (report page, README, HTML, PDF content area) and fails below the minimum. The renderer contract names the widths, the minimum effective font size and the clearances. Their values are set and agreed before implementation acceptance, using the Figure 1 README guard as a reference.

When either gate fails, the SVG is not written (a stale one is removed), the report shows the table form, and the run records a render warning and a run issue. Inputs inside the supported envelope must render as a diagram; the table is not a way to pass the gates.

### Table form and navigation

Both forms share one report anchor, `figure-1b`. The strip, the Top Threats row, the §1 actor row and §2.2 link to that anchor, not to the SVG file, so the links resolve in either form and in Markdown, HTML and PDF.

The table form contains the elements with their sources, the relationships with their status, the findings per element, the eligible entries, the highlighted path in step order, the findings without an evidenced CI owner and the overflow members. It wraps long values and stays readable in exports.

When `has_build_evidence` is false, the section, the anchor and every link are absent. When the artifact is invalid or outdated, the same applies and the run records why. Neither case is a geometry failure.

### Report placement

| Place | Change |
|---|---|
| Management Summary | Figure 1a, Figure 1b, Figure 2, Top Threats table. The row of a build-time scenario links to `figure-1b` |
| §1 Identified Actors | The intro names both figures. The build-time actor row links to `figure-1b` |
| §2.2 container diagram | Build components leave the Mermaid diagram; a sentence links to `figure-1b` |
| §2.3 components | The note on threat counts names Figure 1a and Figure 1b |
| Files | `<stem>.figure1b.svg` next to the report, removed when not written, listed in the publish set |

### Producer scope

Required in this change:

1. Build-zone derivation in component finalization.
2. Job association for GitHub workflow inputs and outputs, and the destination of container outputs where the push names one (`supply_chain_facts`).
3. Ecosystem install steps per job, enough to evidence the input-to-build edge for package ecosystems.

Deferred, each a separate change:

- facts and checks for GitLab CI, Jenkins and other CI systems,
- deploy targets beyond registries, Kubernetes and GitLab auto deploy,
- workflow trigger extraction, including inline `on:` forms,
- per-ecosystem lockfile pairs as structured fields,
- secret names per workflow.

## Revision 2026-10-03 (implementation)

Implementation refined four points of the design above:

1. Build placement. A component is build-plane when a deployment zone names the build (zone token `ci`, `cicd`, `build` or `pipeline`), or when its paths cite at least one CI definition and otherwise only build-neutral files (container build files, compose files, package manifests, lockfiles, build scripts). The juice-shop pipeline component cites `Dockerfile` and `package.json` besides its workflows, so "every path is a CI file" would have missed it. Finalization does not rewrite `deployment_zones`: they enter the inventory fingerprint, STRIDE selection and actor attribution, so placement is derived where it is used (`scripts/model/build_plane.py`).
2. Freshness. Composition rebuilds `.supply-chain-view.json` on every render from the retained inputs instead of comparing a stored fingerprint, so a report can never pair with a stale view. The fingerprint stays in the artifact for audit. A view that cannot be built or fails its schema omits Figure 1b, its strip and its links, and records a warning.
3. Finding attachment. STRIDE findings carry supply-chain defects as well (the juice-shop lockfile finding has no config check). A finding without a config check attaches through an evidence location shared with a fact row (input or install step) or a package manifest, and it can establish an entry only with a supply-chain CWE from the build-time attribution list.
4. Presentation. The build strip is a Markdown line under the Figure 1a caption, not part of the SVG. The PDF export gives Figure 1b the same A3 sheet as a wide Figure 1a. The supported display widths are 880 px for report, README and HTML and 1100 px for the PDF sheet, with a minimum effective text size of 6 px.

## Non-goals

- Splitting §6.11. §6.12 and §6.13 are taken, and renumbering moves report anchors (`REQ-EVO-003`). Figure 1b links to §6.11 for the control assessment.
- Layout changes to Figure 1a beyond the removal of build elements. The new geometry and legibility gates apply to Figure 1b only.
- A second highlighted path, or one Figure 1b per CI system.
- Reviving `figure_deployment.py`.

## Proposed requirement wording

For operator approval. Nothing below is in `specs/requirements.md` yet.

`REQ-RPT-007`, title and first sentence reworded from Figure 1 to Figure 1a: "Figure 1a shows each column only as wide as its content needs, so its labels stay legible when the figure is scaled to the width of a report page or README. Making the figure more compact never removes a data-flow label from the drawing."

New `REQ-RPT-008 — The report shows how a supply-chain attack reaches production`: "When the repository evidences a CI build or the analysis reports a build-time attack, the Management Summary includes a supply-chain view of the evidenced inputs, build systems and release artifacts and of the running system they feed. A reported finding adds an attack entry only when it establishes the attack mechanism. A highlighted path follows evidenced relationships, and a relationship the evidence does not establish is shown as not evidenced. The runtime figure then shows no build element. The supply-chain view stays readable at the supported report and README widths and in HTML and PDF exports, with distinct and unclipped labels, connections, arrowheads and badges. When it cannot be drawn cleanly and legibly, the report presents the same information as a table and records the fallback."

## Proposed decisions

- `RA-28`: one build-placement predicate for Figure 1a, Figure 1b and §2.2, separate from attribution; finalization derives the build zone from CI-only evidence.
- `RA-29`: Figure 1a filters the build plane, keeps component and path numbers, renders without runtime scenarios, applies the filter to every fallback, and keeps the model-wide header tally; Figure 1b counts what it shows.
- `RA-30`: the supply-chain view artifact, its fingerprint and rebuild rule, edge status, the display and entry mapping, and the highlighted-path selection.
- `RA-31`: Figure 1b geometry and legibility gates, the table form, and the shared anchor.

## Verification

Producer and placement fixtures, each with incidental names that differ from juice-shop:

1. A neutral reproduction of the misplacement: a CI-only component without zones takes the build zone. A variant with different CI paths and names behaves the same. A component citing CI files and application source keeps its runtime placement.
2. A GitHub workflow job that installs npm dependencies with ranges and no lockfile and pushes an image: the dependency path is evidenced up to the artifact, and artifact to execution stays not evidenced.
3. A test workflow that installs dependencies and a separate release workflow that pushes an image: no path joins them.
4. A workflow that only publishes an npm package: no execution claim.
5. A pushed image without signing yields the replaced-artifact entry; a signed variant does not. A missing SBOM alone yields no entry.

View and report fixtures:

6. No CI and no build-time scenario: no Figure 1b, no strip, no link, no anchor.
7. No CI with a build-time lockfile finding: Figure 1b with "no CI evidenced".
8. GitLab CI only: an "inventory only" build element and no entry.
9. CI without supply-chain findings: Figure 1b without an attack arrow.
10. Only build-time scenarios: Figure 1a renders the runtime without attack arrows; a stale fragment containing a CI component is rejected.
11. Count invariant: Figure 1a header equals the Management Summary tally with mixed-actor, build-only, attackerless and design-risk items present; Figure 1b states its own count.
12. Repository-free re-render keeps actor codes and scenario numbers equal across Figure 1a, Figure 1b and Figure 2. A changed severity or attribution with missing inputs omits Figure 1b with a warning. A report directory without the artifact follows the same path.

Geometry and legibility matrix:

13. Sparse input, one complete path, and every entry kind.
14. Each cap at its limit and beyond it, with uneven columns and the highest-severity entry among overflow members.
15. Fan-in, fan-out, several CI systems, and delivery rows with different edge status.
16. Long names, unbroken references, non-ASCII text and a large overflow legend.
17. Standalone SVG and embedded report and README at the declared widths, and final HTML and PDF.
18. Forced geometry failure and forced legibility failure: the table renders, every link resolves to `figure-1b`, the stale SVG is removed, and the warning and run issue are recorded. A custom report stem behaves the same.

Representative SVG, HTML and PDF outputs are also inspected at display size, because font metrics and export scaling can differ from the geometry model. The juice-shop run is replayed with `scripts/threat_fixture.py` as additional evidence. The README example is regenerated as Figure 1a, with a Figure 1b example beside it.

## Review resolution

| Review item | Resolution |
|---|---|
| R1 relationships | Decision 6; "Relationships": edge status, job association, unknown edges never carry steps |
| R2 non-GitHub CI | Decision 7; inventory only, producers deferred, fixture 8 |
| R3 entry eligibility | "Findings and entry eligibility": separate display and entry columns, `IAC-041` and coding-agent checks without entry except `IAC-071`, unowned findings listed |
| R4 counts | Decision 8; fixture 11 |
| R5 display condition | Decision 9; `has_build_evidence`; gates scoped to Figure 1b |
| R6 producer scope | "Producer scope": required and deferred lists match `tasks.md` |
| R7 empty runtime input | "Figure 1a": renders without scenarios, filtered fallbacks, fragment rejection, no-runtime policy |
| R8 identities and freshness | "The supply-chain view artifact": identities from resolved paths, fingerprint, rebuild or omit |
| R9 navigation and table | "Table form and navigation": shared anchor, table contract, not-applicable and invalid cases |
| R10 legibility | Decision 10; "Layout, legibility and fallback"; fixtures 13–18 |
