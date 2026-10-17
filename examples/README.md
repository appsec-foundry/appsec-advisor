# Examples

This directory holds example inputs to copy into your own setup and a sample report from the requirements audit.

## Security assessment report

The companion repository [appsec-advisor-examples](https://github.com/appsec-foundry/appsec-advisor-examples) contains one complete [standard assessment of OWASP Juice Shop](https://github.com/appsec-foundry/appsec-advisor-examples/blob/main/threat-modeler/security-assessment-juice-shop-standard-v0.6.0b5.md), with its diagrams and exports. Use it to see the report structure and export formats before you run an assessment. The [Security Assessment guide](../docs/security-assessment.md#assessment-depth--cost-control) compares assessment depths.

## Threat model inputs

Copy these files into the repository you assess and adapt them.

- [`known-threats.yaml`](known-threats.yaml) records prior pentest findings, accepted risks, and known issues for OWASP Juice Shop. Place your version at `docs/known-threats.yaml`, as described in [Known threats](../docs/security-assessment.md#known-threats--docsknown-threatsyaml).
- [`abuse-cases.yaml`](abuse-cases.yaml) is a commented abuse case that documents every field and the values it accepts. Place your version under `docs/security/abuse-cases/`, as described in [Abuse cases](../docs/org-profiles.md#abuse-cases).

## Requirements catalog

These files form a demonstration catalog informed by OWASP ASVS 5.0.0, the OWASP Top 10:2025, and the OWASP Cheat Sheets. The catalog is not an official OWASP standard.

- [`appsec-requirements-example.yaml`](appsec-requirements-example.yaml) is the combined catalog with requirements and blueprints. The requirements audit loads it for `--demo`, and the bundled mock server serves it.
- [`appsec-requirements-example.requirements.yaml`](appsec-requirements-example.requirements.yaml) carries only the requirements.
- [`blueprints/`](blueprints/) holds two blueprints of the combined catalog, one file per blueprint, in the shape the harvester writes.
- [`appsec-requirements-example.openspec.md`](appsec-requirements-example.openspec.md) and [`appsec-requirements-example.sdd`](appsec-requirements-example.sdd) express the observable, mandatory behavior of the combined catalog as an OpenSpec and a SpecDD specification.

Each YAML file is accepted by `--requirements` on its own. The [Requirements Harvester](../docs/harvester.md#output-format--validation) guide describes the catalog format and the OpenSpec and SpecDD exports.

## Requirements audit report

The `requirements-auditor/` directory holds a `--demo` requirements audit of OWASP Juice Shop as [Markdown](requirements-auditor/appsec-requirements-report.md), [JSON](requirements-auditor/appsec-requirements-report.json), and [PDF](requirements-auditor/appsec-requirements-report.pdf). The [Requirements Audit](../docs/security-requirements-audit-skill.md) guide explains the statuses and flags.
