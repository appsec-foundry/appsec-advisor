# Shared Validation Routine for Intermediate Files

Use this routine to validate `.stride-*.json` and `.dep-scan.json` files immediately after writing them.

## Step 1 — Locate the validation script

```bash
VALIDATE_SCRIPT=""
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  VALIDATE_SCRIPT="$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py"
else
  VALIDATE_SCRIPT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-plugin/plugin/scripts/validate_intermediate.py" \
    2>/dev/null | head -1)
fi
```

## Step 2 — Run validation

```bash
python3 "$VALIDATE_SCRIPT" <schema_type> "<output_file>"
```

Where `<schema_type>` is `stride` for `.stride-*.json` or `dep_scan` for `.dep-scan.json`.

## Step 3 — Handle result

- **Output starts with `VALID`** — proceed normally.
- **Output starts with `INVALID` or script not found** — print each error line, then overwrite the file with a minimal error stub containing `parse_error` set to the first validation error message, and an empty results array. Print: `[<agent>] ✗ Schema validation failed — error stub written`

### Error stub format for STRIDE:
```json
{
  "component_id": "<COMPONENT_ID>",
  "component_name": "<COMPONENT_NAME>",
  "analyzed_at": "<ISO 8601 timestamp>",
  "parse_error": "<first validation error message>",
  "threats": []
}
```

### Error stub format for dep-scan:
```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_root": "<REPO_ROOT>",
  "parse_error": "<first validation error message>",
  "summary": {"vulnerable_dependencies": 0},
  "vulnerable_dependencies": []
}
```
