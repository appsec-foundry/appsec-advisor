# Shared Validation Routine for Intermediate Files

Use this routine to validate `.stride-*.json` files immediately after writing them. (The `.dep-scan.json` validation pathway was removed in 2026-05 alongside the in-tree SCA producer.)

## Step 1 — Locate the validation script

```bash
VALIDATE_SCRIPT=""
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  VALIDATE_SCRIPT="$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py"
else
  VALIDATE_SCRIPT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/scripts/validate_intermediate.py" \
    2>/dev/null | head -1)
fi
```

## Step 2 — Run validation

```bash
python3 "$VALIDATE_SCRIPT" <schema_type> "<output_file>"
```

Where `<schema_type>` is `stride` for `.stride-*.json`.

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

