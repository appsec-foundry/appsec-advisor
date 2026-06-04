## 5. Attack Surface

Network-reachable entry points classified by authentication requirement. Each row links to the threat(s) referenced in its **Notes** column. The **Risk** column reflects the highest-severity linked finding.

### 5.1 Unauthenticated Entry Points (16)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| POST | `/file-upload` | 🔴 Critical | [F-010](#f-010)<br/>[F-026](#f-026)<br/>[F-031](#f-031)<br/>ZIP directory traversal; XML XXE via libxmljs2 noent:true; YAML upload |
| GET | `/ftp (and files)` | 🔴 Critical | [F-006](#f-006)<br/>Directory listing exposing confidential files: acquisitions.md, incident-support.kdbx, coupons |
| POST | `/profile/image/url` | 🔴 Critical | [F-026](#f-026)<br/>[F-012](#f-012)<br/>[F-015](#f-015)<br/>SSRF via URL-based profile image upload; fetches arbitrary URLs server-side |
| GET | `/rest/products/search` | 🔴 Critical | [F-005](#f-005)<br/>SQL injection via q parameter; raw Sequelize query with string interpolation |
| GET | `/rest/track-order/:id` | 🔴 Critical | [F-011](#f-011)<br/>[F-029](#f-029)<br/>[F-040](#f-040)<br/>SQL injection via order ID parameter |
| POST | `/rest/user/login` | 🔴 Critical | [F-030](#f-030)<br/>[F-001](#f-001)<br/>SQL injection via email/password fields; no rate limiting on this endpoint |
| PUT | `/api/Products/:id` | 🟠 High | [F-013](#f-013)<br/>[F-018](#f-018)<br/>Authorization intentionally commented out — unauthenticated product modification |
| POST | `/api/Users (registration)` | 🟠 High | [F-019](#f-019)<br/>[F-030](#f-030)<br/>User registration; allows setting role field (mass assignment if validation bypassed) |
| GET | `/encryptionkeys/:file` | 🟠 High | [F-021](#f-021)<br/>Exposes JWT public key (jwt.pub) and premium.key; directory listing enabled |
| GET | `/metrics` | 🟠 High | [F-026](#f-026)<br/>[F-041](#f-041)<br/>Prometheus metrics endpoint; reveals application internals and request statistics |
| GET | `/rest/products/:id/reviews` | 🟠 High | [F-025](#f-025)<br/>[F-017](#f-017)<br/>NoSQL injection via $where clause in MarsDB query; sleep injection DoS possible |
| GET | `/support/logs/:file` | 🟠 High | [F-020](#f-020)<br/>Access log directory listing; reveals user activity and IP addresses |
| GET | `/redirect` | 🟡 Medium | [F-039](#f-039)<br/>Open redirect via ?to= parameter; allowlist bypassable |
| GET | `/api-docs` | — | Swagger UI exposing full API documentation including B2B endpoints |
| GET | `/rest/user/change-password` | — | Password change via GET with no CSRF; current password can be omitted in some flows |
| ? | `WebSocket / Socket.IO` | — | Challenge notification socket; no authentication required to connect |

### 5.2 Authenticated Entry Points (4)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| GET | `/profile (POST /profile)` | 🔴 Critical | [F-026](#f-026)<br/>[F-012](#f-012)<br/>[F-015](#f-015)<br/>SSTI + eval() in username field; pug template injection |
| GET | `/api/Users` | 🟠 High | [F-019](#f-019)<br/>[F-030](#f-030)<br/>Lists all users; IDOR possible on /api/Users/:id; finale-rest auto-generated |
| POST | `/b2b/v2/orders` | 🟠 High | [F-033](#f-033)<br/>[F-040](#f-040)<br/>RCE via vm.runInContext + notevil on orderLinesData field |
| PATCH | `/rest/products/reviews` | 🟠 High | [F-025](#f-025)<br/>[F-017](#f-017)<br/>NoSQL injection in review update; multi:true allows updating all reviews |
