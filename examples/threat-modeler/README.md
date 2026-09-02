# Threat-Modeler — Example Reports

Sample outputs from the **threat-modeler** plugin, run against public test
applications. Use them to see the report structure, depth levels and artifact
formats before running a scan of your own.

> For more examples (additional targets, depths and historical runs), see the
> companion repo: **<https://github.com/matthiasrohr/appsec-advisor-examples>**

## What's here

Each run produces a set of files that share a common slug
`threat-model-<target>-<depth>-v<version>`:

| Report formats | Data and integration formats |
|----------------|------------------------------|
| `.md` — human-readable report | `.yaml` — structured model |
| `.html` — browser-readable report | `.sarif.json` — SARIF v2.1 code-scanning results |
| `.pdf` — printable report with cover and TOC | `.threatdragon.json` — Threat Dragon and ThreatAtlas export |
| | `pentest-tasks-*.yaml` — endpoint catalog and pentest plan |

Optional outputs are linked for each run below when they were generated.

The `-vX.Y` suffix is the plugin version that produced the run, so outputs from
different releases stay side by side and comparable.

## Examples in this directory

**[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — deliberately
insecure web shop:

- **Tech stack:** Angular, Node.js, Express, Socket.IO, Sequelize, SQLite, Docker.
- **[Quick](threat-model-juice-shop-quick-v0.5.2.md)** — Model: Claude Sonnet
  4.6 · 🔴 7 Critical · 🟠 15 High · 🟡 12 Medium · 🟢 0 Low · 34 total.
  Artifacts: [YAML](threat-model-juice-shop-quick-v0.5.2.yaml).
- **[Standard](threat-model-juice-shop-standard-v0.5.2.md)** — Model: Claude
  Sonnet 4.6 · 🔴 9 Critical · 🟠 29 High · 🟡 12 Medium · 🟢 0 Low · 50 total.
  Artifacts: [YAML](threat-model-juice-shop-standard-v0.5.2.yaml) ·
  [Threat Dragon](threat-model-juice-shop-standard-v0.5.2.threatdragon.json).
- **[Thorough](threat-model-juice-shop-thorough-v0.6.0b2.md)** — Model: Claude Opus · 🔴 8 Critical · 🟠 24 High · 🟡 20 Medium · 52 total, reporting threshold medium. Artifacts: [YAML](threat-model-juice-shop-thorough-v0.6.0b2.yaml) · [HTML](threat-model-juice-shop-thorough-v0.6.0b2.html) · [PDF](threat-model-juice-shop-thorough-v0.6.0b2.pdf) · [SARIF](threat-model-juice-shop-thorough-v0.6.0b2.sarif.json) · [Threat Dragon](threat-model-juice-shop-thorough-v0.6.0b2.threatdragon.json) · [pentest tasks](pentest-tasks-juice-shop-thorough-v0.6.0b2.yaml).
- **[Standard with requirements](threat-model-juice-shop-standard-req-v0.6.0b2.md)** — standard run invoked with `--requirements` against the bundled [example baseline](../appsec-requirements-example.yaml), which carries 73 requirements in 11 categories plus 12 blueprint guidance entries. Model: Claude Sonnet 4.6, triage and merge on Claude Sonnet 5 · 🔴 10 Critical · 🟠 27 High · 🟡 15 Medium · 52 total, reporting threshold medium. The run adds section 7b with a per-requirement verdict: 2 PASS · 40 FAIL · 10 PARTIAL · 5 N/A · 16 UNVERIFIABLE, and a traceability table linking each violated requirement to its findings and mitigations. Artifacts: [YAML](threat-model-juice-shop-standard-req-v0.6.0b2.yaml).

**[Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)**
— deliberately vulnerable PHP/MariaDB web application:

- **Tech stack:** PHP, MariaDB, Docker.
- **[Report](threat-model-dvwa-standard-v0.5.2.md)** — Depth: standard · Model:
  Claude Sonnet 4.6 · 🔴 6 Critical · 🟠 16 High · 🟡 13 Medium · 🟢 0 Low ·
  35 total. Artifact: [YAML](threat-model-dvwa-standard-v0.5.2.yaml).

**[Insecure Spring App](https://github.com/matthiasrohr/insecure-spring-app)** —
local-only application-security verification fixture:

- **Tech stack:** Java 17, Spring Boot, Spring Security, JPA, Thymeleaf, H2,
  Docker.
- **[Standard](threat-model-insecure-webapp-standard-v0.5.2.md)** — Model:
  Claude Sonnet 4.6 · 🔴 10 Critical · 🟠 29 High · 🟡 4 Medium · 🟢 0 Low ·
  43 total. Artifact: [YAML](threat-model-insecure-webapp-standard-v0.5.2.yaml).

**[OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp)** —
vulnerable application for demonstrating and testing security issues:

- **Tech stack:** Java, Spring Boot, JSP, PHP.
- **[Standard](threat-model-owasp-vulnerableapp-standard-v0.5.2.md)** — Model:
  Claude Sonnet 4.6 · 🔴 6 Critical · 🟠 31 High · 🟡 23 Medium · 🟢 0 Low ·
  60 total. Artifact:
  [YAML](threat-model-owasp-vulnerableapp-standard-v0.5.2.yaml).

## Assessment depths

For component coverage criteria, cost, and runtime guidance, see
[Assessment depth & cost control](../../docs/threat-modeler.md#assessment-depth--cost-control).

- **quick** — early feedback and low-risk changes; reduced analysis that skips
  abuse-case validation and final model-based QA.
- **standard** *(default)* — normal threat models and security reviews; full
  analysis, abuse-case validation, and QA.
- **thorough** — high-risk services and major releases; deeper component
  analysis and architecture review.

## Large-component-count test fixture

Files matching `threat-model-insecure-large-spring-app-v0.5.2*` were generated
from the custom-built
[Insecure Large Spring App](https://github.com/matthiasrohr/insecure-large-spring-app)
repository. The fixture was built to test how the threat-modeling process handles
applications with a large number of components.

The repository defines 42 Docker Compose services across 7 network zones. The
standard run represents the system as 11 logical components, identifies 122
entry points and performs full STRIDE analysis on 8 components. The other 3
remain in the inventory but are not analyzed individually at standard depth.

Artifacts: [report](threat-model-insecure-large-spring-app-v0.5.2.md) ·
[YAML](threat-model-insecure-large-spring-app-v0.5.2.yaml) ·
[architecture figure 1](threat-model-insecure-large-spring-app-v0.5.2.figure1.svg) ·
[architecture figure 2](threat-model-insecure-large-spring-app-v0.5.2.figure2.svg).
