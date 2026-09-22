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

## Non-goals

- Azure and GCP Terraform, CloudFormation, Bicep and Kustomize overlays in this change.
- Known-vulnerability status of libraries; that needs an SCA scan.
- Changing Figure 1 or Figure 2.
- Publishing `figure2.svg`: `publish_threat_model.TIER2` does not list it. That gap predates this change and stays open.
