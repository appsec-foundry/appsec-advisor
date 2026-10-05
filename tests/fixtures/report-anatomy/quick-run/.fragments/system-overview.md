## 1. System Overview

**Repository:** git@github.com:appsec-foundry/appsec-advisor.git

### Scope

_last-repo comprises **4** modeled components. This threat model applied full STRIDE threat analysis to **2 of 4** — the components on the externally-reachable, authentication-bearing, and business-critical surface: **Express Web API**, **Authentication & Session Middleware**. Selection criteria: AI/LLM surface; internet-exposed; auth.

The remaining **2** component(s) were **not individually analyzed** at this assessment depth (lower-priority / internal surface): Relational Datastore, CI/CD Pipeline. Re-run at a higher `--assessment-depth` to extend STRIDE coverage to them.

**Out of scope:** third-party hosted dependencies, browser runtime, operating-system kernel, and the underlying network infrastructure.

**Basis:** a code-derived threat model at implementation level, built from source, configuration and git history. It describes the system as built, not as designed.
