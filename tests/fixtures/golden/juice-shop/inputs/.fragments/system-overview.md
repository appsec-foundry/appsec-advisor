## 1. System Overview

Probably the most modern and sophisticated insecure web application

**Repository:** https://github.com/juice-shop/juice-shop.git
**Runtime:** Node.js 22 - 26

### Scope

This threat model covers 9 components of juice-shop: 

- Juice Shop Express server
- Sequelize application data access
- CI/CD Pipeline
- Web3 / Wallet / NFT Surface
- Angular frontend
- MarsDB embedded store
- Real-time WebSocket Channel
- SQLite embedded store
- Authentication & Session Surface

**Not individually examined:** 124 source files in 3 components had no route, lead or security signal (Sequelize application data access 11, CI/CD Pipeline 4, Angular frontend 109).

**Not assessed:** 2 security-relevant code locations were read but could not be judged (Web3 / Wallet / NFT Surface 1, Authentication & Session Surface 1); `threat-model.yaml` records each with its reason under `meta.undecided_targets`.

**Not assigned to any component:** 134 program files belong to no component and were not analysed (`data/` 97, `lib/` 21, `frontend/` 5, `(repository root)` 4, `rsn/` 4, `models/` 1, `routes/` 1, `views/` 1).

**Out of scope:** third-party hosted dependencies, browser runtime, operating-system kernel, and the underlying network infrastructure.

**Basis:** An automated, AI-assisted threat model built from the repository's source code and configuration — static analysis only, no dynamic or penetration testing. It describes the system as built, not as designed.
