# Tasks

- [x] Bounded docker-compose reader: services, ports with bind address, expose, volumes, networks, `depends_on`, privileged flag, line spans; environment values only as boolean-like switches (`scripts/compose_services.py`).
- [x] Deterministic deployment inventory with schema: Dockerfile runtime, compose, Kubernetes and OpenShift manifests, Helm values, GitLab Auto Deploy, AWS Terraform, CI systems and their publish targets, dependency ranges and lockfile, framework and library roles; bounded, symlink-safe, never an environment value or file content (`scripts/deployment_inventory.py`, `schemas/deployment-inventory.schema.json`, `data/deployment-technology.yaml`).
- [x] Controller runs the scanner after the config scan; a failure writes nothing and surfaces as a Run Issue (`scripts/orchestration_controller.py`); the inventory is an audit artifact that survives cleanup for re-render.
- [x] Deployment and Technology figure: nested renderer, components placed in the workload that runs the repository image, client and third-party columns, build lane, corridor-only lines (`scripts/figure_deployment.py`).
- [x] Controls figure reads compose services from the inventory instead of the repository; context, old deployment and technology figures removed (`scripts/figure_details.py`).
- [x] Composer writes `<stem>.figure3.svg` and `<stem>.figure4.svg` from the inventory, ignores an inventory that breaks its schema, removes stale figures 3–6 and falls back to Mermaid with a RENDER_WARN on a builder failure (`scripts/compose_threat_model.py`).
- [x] §2 generator replaces only the §2.2 and §2.3 Mermaid diagrams and captions; the §2.3 component table stays (`scripts/pregenerate_fragments.py`).
- [x] Contract accepts a Mermaid block or a detail figure in §2; QA accepts a figure only when its file exists (`data/sections-contract.yaml`, `scripts/qa_checks.py`).
- [x] Publish list, permission reasons, audit-artifact contract, cleanup list and test routes name the new files.
- [x] Gradle map notation in `_lib_manifest` (`scripts/_lib_manifest.py`).
- [x] Tests: neutral and renamed variants per environment, negative cases, secrets and symlinks, schema failure, composer independence from the checkout, and a drawing check that no line crosses a foreign box and no text leaves its box (`tests/test_deployment_inventory.py`, `tests/test_figure_deployment.py`, `tests/test_figure_details.py`, `tests/test_compose_services.py`, `tests/test_lib_manifest.py`).

## Open

- [ ] Confirm the figures on fresh runs: a repository with only a Dockerfile, one with compose, one with Kubernetes manifests and one with AWS Terraform.
- [ ] Azure (`azurerm_*`) and GCP (`google_*`) Terraform rules.
- [ ] Components of a compose environment without a service that builds the repository are placed by name only; placement by build context and image needs the compose `build.context`.
- [ ] `analysis-model.md` figures are named `analysis-model.figure<N>.svg`; `stamp_threat_model.py` only stamps `threat-model.figure*.svg`, the same as for Figure 1.
- [ ] A configuration file matched by several components (for example a shared `application.properties`) places its controls on each of them.
