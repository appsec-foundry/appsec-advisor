# Threat-Modeler — Example Reports

Sample outputs from the **threat-modeler** plugin, run against public test
applications. Use them to see the report structure, depth levels and artifact
formats before running a scan of your own.

> For more examples (additional targets, depths and historical runs), see the
> companion repo: **<https://github.com/matthiasrohr/appsec-advisor-examples>**

## What's here

Each run produces a set of files that share a common slug
`threat-model-<target>-<depth>-v<version>`:

| Extension | Contents |
|-----------|----------|
| `.md` | Human-readable threat-model report (Management Summary → Threat Register). |
| `.yaml` | Machine-readable model — findings, STRIDE mapping, mitigations, abuse cases. |
| `.pdf` | Rendered report with cover and TOC (where included). |
| `.html` | Browser-readable report (where included). |
| `.sarif.json` | SARIF v2.1 results for code-scanning integrations (where included). |
| `.threatdragon.json` | Alpha, opt-in OWASP Threat Dragon v2 export for Threat Dragon and ThreatAtlas (where included). |
| `.figure1.svg` | Figure 1 — Architecture & Top Threats. |
| `.figure2.svg` | Figure 2 — Risk Flow (Actor → Tier → Impact). |

The `-vX.Y` suffix is the plugin version that produced the run, so outputs from
different releases stay side by side and comparable.

## Examples in this directory

**[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — deliberately
insecure web shop:

- **Tech stack:** Angular, Node.js, Express, Socket.IO, Sequelize, SQLite, Docker.
- [Quick report](threat-model-juice-shop-quick-v0.5.2.md) — quick depth.
- [Standard report](threat-model-juice-shop-standard-v0.5.2.md) — standard
  depth.
- [Thorough report](threat-model-juice-shop-thorough-v0.5.2.md) — thorough
  depth.

**[Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)**
— deliberately vulnerable PHP/MariaDB web application:

- **Tech stack:** PHP, MariaDB, Docker.
- [Standard report](threat-model-dvwa-standard-v0.5.2.md) and its
  [unversioned copy](threat-model-dvwa.md) — standard depth.

**[OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp)** —
vulnerable application for demonstrating and testing security issues:

- **Tech stack:** Java, Spring Boot, JSP, PHP.
- [Standard report](threat-model-owasp-vulnerableapp-standard-v0.5.2.md) —
  standard depth.

## Assessment depths

For component coverage criteria, cost, and runtime guidance, see
[Assessment depth & cost control](../../docs/threat-modeler.md#assessment-depth--cost-control).

- **quick** — early feedback and low-risk changes; reduced analysis that skips
  abuse-case validation and final model-based QA.
- **standard** *(default)* — normal threat models and security reviews; full
  analysis, abuse-case validation, and QA.
- **thorough** — high-risk services and major releases; deeper component
  analysis and architecture review.
