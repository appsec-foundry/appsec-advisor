---
id: acme-sso
type: ecosystem_context
owner: identity-platform-team
last_reviewed: 2026-04-20
---

# Acme SSO

Acme uses a centralized OIDC provider for workforce applications.

Common issuer patterns:

- `https://login.example.test/oauth2/default`
- `https://login.example.test/oauth2/admin`

The SSO platform authenticates users and emits group claims. It does
not provide object-level authorization.
