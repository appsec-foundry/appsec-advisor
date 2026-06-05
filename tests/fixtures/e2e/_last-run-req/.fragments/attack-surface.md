## 5. Attack Surface

Network-reachable entry points classified by authentication requirement. Each row links to the threat(s) referenced in its **Notes** column. The **Risk** column reflects the highest-severity linked finding.

### 5.1 Unauthenticated Entry Points (2)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| ? | `Docker container entrypoint` | — | Container runs as root. If container escape occurs, attacker has host-level root access. |
| ? | `HTTP API (port 3000)` | — | Express app listening on port 3000. No TLS configured. Route inventory returned 0 routes (server.js absent from repo). Assumed unauthenticated HTTP by default. |

### 5.2 Authenticated Entry Points (0)

_None enumerated._
