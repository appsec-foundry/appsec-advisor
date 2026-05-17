---
id: acme-platform
type: platform_context
owner: platform-team
last_reviewed: 2026-04-20
---

# Acme Platform

Acme product services share these platform building blocks:

- Central API gateway terminates TLS and enforces tenant routing.
- Secrets are read from a managed secrets service at boot time.
- All service-to-service calls are mutually authenticated.
- Audit logs go to a write-once log sink.
- Background jobs run on a shared worker pool with per-tenant
  isolation.
