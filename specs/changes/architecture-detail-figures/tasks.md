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

## Revision 2026-09-24

- [x] §2.2 renders a Markdown table when the environment deploys one unit or only a Dockerfile; the figure stays for several units (`scripts/figure_deployment.py`).
- [x] Embedded stores are recognized by package or artifact name (`sqlite3`, `better-sqlite3`, `h2database`, `com.h2database:h2`) through the technology vocabulary, so they sit in the process that embeds them (`scripts/figure_deployment.py`).
- [x] §2.3 control coverage becomes a Markdown table; the Figure 4 SVG is no longer written, and a stale one is removed (`scripts/figure_details.py`, `scripts/compose_threat_model.py`).
- [x] §2.4 Technology Architecture and its generator, layer tables and filesystem-prefix data are removed; the contract forbids the heading; the §2 legend explains borders only while a diagram draws them (`scripts/pregenerate_fragments.py`, `data/sections-contract.yaml`).
- [x] QA accepts a table under the `<!-- detail-table -->` marker in place of a diagram; the §2.3 table injector keeps that table and now also ends §2.3 at an H2 or the §2 legend (`scripts/qa_checks.py`, `scripts/compose_threat_model.py`).
- [ ] §2.1 as a C4 Level 1 view from `external_entities` and the report's actor set (separate change).

## Open

- [ ] Confirm the figures on fresh runs: a repository with only a Dockerfile, one with compose, one with Kubernetes manifests and one with AWS Terraform.
- [ ] Azure (`azurerm_*`) and GCP (`google_*`) Terraform rules.
- [ ] Components of a compose environment without a service that builds the repository are placed by name only; placement by build context and image needs the compose `build.context`.
- [ ] `analysis-model.md` figures are named `analysis-model.figure<N>.svg`; `stamp_threat_model.py` only stamps `threat-model.figure*.svg`, the same as for Figure 1.
- [ ] A configuration file matched by several components (for example a shared `application.properties`) places its controls on each of them.
