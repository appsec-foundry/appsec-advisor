# Multi-Tenancy E2E Fixture

Synthetic repository for testing Actor Layer Done-Criterion #2:
ACT-D-09 (tenant-from-adjacent-tenancy) must be activated.

Activation requires BOTH signals:
  (a) tenant_id column in schema  →  models/User.js
  (b) tenant scoping middleware   →  middleware/tenantContext.js

Expected: .actors-resolved.json contains ACT-D-09 with _provenance.active=true
