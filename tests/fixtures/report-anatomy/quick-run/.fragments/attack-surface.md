## 5. Attack Surface

Network-reachable entry points classified by authentication requirement. Each row links to the threat(s) referenced in its **Notes** column. The **Risk** column reflects the highest-severity linked finding. Entry points with no linked finding are still listed when they sit on a sensitive surface (authentication, registration, management) or look like a missing-auth/authz suspect — marked **⚑ Review** in Notes.

### 5.1 Unauthenticated Entry Points (8)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| POST | `/admin/export` | 🔴 Critical | [F-002](#f-002)<br/>Unauthenticated admin endpoint; exec() with unsanitized user-supplied path enables command injection and arbitrary file read. |
| POST | `/assistant` | 🔴 Critical | [F-004](#f-004)<br/>[F-008](#f-008)<br/>Unauthenticated LLM endpoint; user input concatenated directly into prompt enabling prompt injection against gpt-4o-mini. |
| GET | `/debug/environment` | 🔴 Critical | [F-004](#f-004)<br/>[F-006](#f-006)<br/>Unauthenticated debug endpoint exposing full process.env; discloses runtime secrets and deployment configuration. |
| POST | `/login` | 🔴 Critical | [F-001](#f-001)<br/>[F-012](#f-012)<br/>Login endpoint performs authentication via SQL string interpolation at server.js:12 enabling SQL injection to bypass credential check. |
| GET | `/users/:id` | 🟠 High | [F-011](#f-011)<br/>Unauthenticated user lookup; raw SQL with string interpolation at server.js:18 is a SQL injection sink. |
| POST | `/webhooks/preview` | 🟡 Medium | [F-013](#f-013)<br/>Unauthenticated webhook preview; fetch(req.body.url) enables SSRF to internal network and cloud metadata endpoints. |
| GET | `/orders` | — | Partner API authenticated via x-partner-api-key header; only authenticated route in the application. |
| GET | `/redirect` | — | Unauthenticated open redirect; res.redirect(req.query.next) with no validation enables phishing redirection. |

### 5.2 Authenticated Entry Points (0)

_None enumerated._
