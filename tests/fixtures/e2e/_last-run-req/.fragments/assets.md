## 4. Assets

Information assets and the classification level that drives the Confidentiality / Integrity / Availability targets used in [§8 Findings Register](#8-findings-register) risk scoring.

| Asset | ID | Classification | Description |
|------------------|------|--------------|----------------------------------------|
| Application Data (Database) | A-003 | Confidential | Application data managed via Sequelize ORM. Classification assumed Confidential as typical web application data store. |
| Application Container (Docker) | A-001 | Internal | Docker container running the Node.js application as root user. Compromise gives root-level container access. |
| npm Dependencies | A-002 | Internal | Third-party packages: express@4.19.2, lodash@4.17.10 (CVE-2019-10744), sequelize@6.37.1. No lockfile means versions may drift. Lodash has known prototype pollution CVEs. |
| Container Image | A-004 | Internal | node:20-alpine base image (mutable tag, no digest pinning). Supply chain integrity depends on Docker Hub trust. |
