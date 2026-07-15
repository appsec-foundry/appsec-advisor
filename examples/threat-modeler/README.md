# Threat-Modeler — Example Reports

Sample outputs from the **threat-modeler** plugin, run against public target
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
| `.figure1.svg` | Figure 1 — Architecture & Top Threats. |
| `.figure2.svg` | Figure 2 — Risk Flow (Actor → Tier → Impact). |

The `-vX.Y` suffix is the plugin version that produced the run, so outputs from
different releases stay side by side and comparable.

## Examples in this directory

**[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — deliberately
insecure web shop:

- `threat-model-juice-shop-quick-v0.4.*` — quick depth.
- `threat-model-juice-shop-requirements-quick-v0.4.md` — quick depth with a
  requirements-compliance section (findings mapped to security requirements).
- `threat-model-juice-shop-standard-v0.5.*` — standard depth (broader STRIDE
  coverage, abuse cases).

**[OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp)** — vulnerable
Java application:

- `threat-model-owasp-vulnarableapp-v0.4.*` — standard depth.

## Scan depths

- **quick** — fast pass; top components and highest-severity threats.
- **standard** — full STRIDE fan-out, abuse-case chains, richer mitigations.
- **thorough** — deepest analysis (`threat-model-juice-shop-thorough-v0.5.*`, a
  fresh run to be added here).
