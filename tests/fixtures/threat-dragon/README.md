# Threat Dragon fixtures

`owasp.threat-dragon-v2.schema.json` is an unmodified copy of OWASP Threat
Dragon's own model schema, taken from
`td.vue/src/assets/schema/threat-dragon-v2.schema.json`
(<https://github.com/OWASP/threat-dragon>, Apache-2.0). Threat Dragon compiles
it with ajv and validates every opened model against it, so validating our
export against this file is the check that it opens cleanly there —
`tests/test_export_threat_dragon.py` does that offline.

`threat-model.threatdragon.golden.json` is the export of
`tests/fixtures/schema/threat-model.valid.yaml` at `--tool-version 0.0.0-test`.
It pins the whole mapping byte for byte. Regenerate it deliberately, never to
make a test pass:

```bash
python3 scripts/export_threat_dragon.py \
  --threat-model tests/fixtures/schema/threat-model.valid.yaml \
  --output       tests/fixtures/threat-dragon/threat-model.threatdragon.golden.json \
  --tool-version 0.0.0-test
```

Refresh the schema copy when Threat Dragon releases a schema change; note the
upstream version in the commit message.
