# CI Pipeline E2E Fixture

Synthetic repository for testing Actor Layer Done-Criterion #3:
ACT-D-04 (malicious-insider-dev) and/or ACT-D-06 (supply-chain-attacker)
must be activated.

Activation signals:
  has_secrets_in_repo = true  →  .env file with secrets
  has_ci_pipeline = true      →  .github/workflows/ci.yml

Expected: .actors-resolved.json contains ACT-D-04 and ACT-D-06 with _provenance.active=true
