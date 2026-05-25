# B2B API E2E Fixture

Synthetic repository for testing Actor Layer Done-Criterion #4:
LLM-Discovery should propose a B2B-partner-org actor.

Discovery trigger signals:
  has_external_apis = true   →  routes/partner-api/ with API-key auth
  has_auth_surface = true    →  partner authentication middleware

Expected: .actors-discovered.json contains a proposed_additional entry with
  label containing "b2b" or "partner" and confidence "high"
