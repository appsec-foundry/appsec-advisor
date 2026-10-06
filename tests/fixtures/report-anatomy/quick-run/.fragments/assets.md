## 4. Assets

Information assets and the classification level that drives the Confidentiality / Integrity / Availability targets used in [§8 Findings Register](#8-findings-register) risk scoring.

| Asset | Classification | Description | Linked Threats |
|----------------------|-------------|-------------------------------------------|----------------------|
| JWT Signing Secret | Restricted | Hardcoded JWT signing secret stored in server.js source. Any party with repository read access can forge valid JWT tokens for any user identity, bypassing all authentication. | [F-005](#f-005) |
| Database Credentials | Restricted | Database password hardcoded in config/insecure-settings.ini committed to the repository. Grants full database access to anyone with repository read permissions. | [F-001](#f-001) · [F-003](#f-003) |
| Partner API Keys | Restricted | API keys issued to partner systems and validated by partnerAuth middleware against the database. Compromise of any key grants access to the corresponding partner's order data. | — |
| Runtime Environment Variables | Restricted | Full process.env contents returned as JSON by the unauthenticated GET /debug/environment endpoint. Likely contains runtime secrets, API keys, and connection strings injected at deployment time. | — |
| User Account Records | Confidential | Relational records storing user email, role enum (admin/member), and tenant_id. Queried by raw SQL in server.js; email and password submitted at login are passed unsanitized into a string-interpolated query. | [F-001](#f-001) · [F-003](#f-003) |
| Partner Order Records | Confidential | Order data scoped to a partner identity and returned by GET /orders. Accessible to any caller presenting a valid partner API key; no row-level isolation beyond partner ownership is visible in the route handler. | — |
