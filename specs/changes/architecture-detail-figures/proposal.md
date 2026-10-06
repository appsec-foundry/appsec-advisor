# §2 architecture diagrams become detail views of Figure 1

## Problem

A 2026-09-20 VulnerableApp run showed that the four §2 Mermaid diagrams add little next to Figure 1:

- §2.3 Components folded nine application components into one node and drew two nodes in total, while its own takeaway named the CI/CD pipeline as the hotspot it did not draw.
- §2.2 Container Architecture capped at eight containers, left the pipeline without edges and said "0 client" next to a drawn browser node.
- Figure 1, §2.2 and §2.3 showed the same model with 10, 8 and 2 components, which a reader takes for a contradiction.
- None of the diagrams showed what Figure 1 leaves out: where each component runs, what it is built on, which settings of the deployment weaken a control, and where controls are weak per component.

The same run also showed that `_lib_manifest` read 5 of 22 Gradle dependencies, because map notation (`group: 'g', name: 'n', version: 'v'`) was not recognized.

## Decisions

The operator chose, in this session:

1. Figure 1 stays the overview. §2 carries detail views of single aspects of it, in its visual language: palette, `C-NN`, severity colours, authentication hexagon.
2. A §2 subsection shows an SVG figure when its inputs exist and keeps its Mermaid diagram otherwise. No report loses a diagram. Figures are numbered consecutively from 3.
3. Two figures ship: Deployment and Technology in §2.2 and component control coverage in §2.3. The earlier drafts for context (§2.1) and technology hygiene (§2.4) are dropped: the context repeated Figure 1, and the technology inventory belongs in an SBOM.
4. The deployment figure is a nested deployment diagram: cloud account or cluster, network, service, workload, container, process, framework, embedded store. Each box names its technology and version and at most three facts that change the threat assessment; findings stay in Figure 1 and §8, details in §6. Lines run only in corridors, and no line crosses a box that holds neither of its ends.
5. The figure reads the environment the repository declares: the Dockerfile, the compose file `docker compose` resolves without `-f`, Kubernetes and OpenShift manifests, Helm chart values, a GitLab Auto Deploy values file and AWS Terraform. It draws the first environment and names the others. Azure and GCP Terraform follow as rule extensions.
6. A deterministic scanner writes `.deployment-inventory.json` during the scan; the composer renders both figures from it and the model and never reads the repository, so a re-render shows the state of the scan.

## Revision 2026-09-24

A juice-shop run showed that the two figures were hard to read in a Markdown viewer: the page scales a 1286-pixel canvas to the column width, so 8- to 10-point text becomes unreadable. Figure 4 was a table drawn as an image, and Figure 3 drew nine boxes nested in one box for an application that runs as a single container. §2.4 repeated Figure 3 from a keyword heuristic and contradicted it. The operator chose, in that session, and these decisions replace decisions 2 and 3 where they differ:

7. §2.2 shows the deployment figure only when the environment deploys several units (workloads, managed services, services with their own image). With one unit, or only a Dockerfile, §2.2 shows the same content as a Markdown table, one row per layer.
8. §2.3 shows the component × control-effectiveness view as a Markdown table above the component table, with the worst effectiveness per control domain, instead of Figure 4.
9. §2.4 Technology Architecture is removed. §2.2 already names every runtime, framework and version the scan found.
10. §2.1 System Context becomes a real C4 Level 1 view from the model: the report's actors and the external systems of `external_entities`. That change is delivered separately.
11. The detail tables carry the `<!-- detail-table -->` marker. QA accepts a marked table in place of a subsection's diagram, and the §2.3 component-table injector keeps it.

## Non-goals

- Azure and GCP Terraform, CloudFormation, Bicep and Kustomize overlays in this change.
- Known-vulnerability status of libraries; that needs an SCA scan.
- Changing Figure 1 or Figure 2.
- Publishing `figure2.svg`: `publish_threat_model.TIER2` does not list it. That gap predates this change and stays open.
