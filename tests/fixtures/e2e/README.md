# E2E fixture suite

A frozen run-directory that exercises the plugin pipeline without invoking an LLM.

`frozen-run/` is the canonical output of a (synthetic) Juice-Shop-style scan:

```
frozen-run/
├── threat-model.yaml          # structured output (5 threats, 3 mitigations)
├── .threats-merged.json       # canonical threat register consumed downstream
├── .dep-scan.json             # SCA output (heuristic + native shape)
├── .stride-C-01.json          # per-component STRIDE analyzer output
├── .stride-C-02.json
├── .triage-flags.json         # Phase 10b flags
├── .recon-summary.md          # Phase 2 recon summary
├── .appsec-cache/baseline.json  # baseline state (for incremental tests)
└── .fragments/                  # Jinja2 fragments for compose_threat_model.py
```

`synthetic-repo/` is a minimal repo whose manifests (`package.json`, `Dockerfile`)
the baseline fingerprint tests operate against.

## Refreshing the fixture

To regenerate from a real run (future work), do:

```bash
./scripts/run-headless.sh \
    --repo examples/juice-shop \
    --output /tmp/juice-run \
    --assessment-depth quick --with-sca
cp -r /tmp/juice-run/* tests/fixtures/e2e/frozen-run/
```

Then re-run `pytest tests/test_e2e_pipeline.py` to confirm the suite still passes.
