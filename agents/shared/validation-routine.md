# Shared Validation Routine for Intermediate Files

Use this routine to validate `.stride-*.json` files immediately after writing them. (The `.dep-scan.json` validation pathway was removed in 2026-05 alongside the in-tree SCA producer.)

## Step 1 — Run validation

Resolve the script and run it in **one** Bash call. Shell variables do not survive between Bash calls, so a path assigned in an earlier call is empty in a later one.

```bash
VALIDATE_SCRIPT="${CLAUDE_PLUGIN_ROOT:+$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py}"
[ -f "$VALIDATE_SCRIPT" ] || VALIDATE_SCRIPT=$(find /root /home /opt -maxdepth 6 \
  -path "*/appsec-advisor/scripts/validate_intermediate.py" 2>/dev/null | head -1)
python3 "$VALIDATE_SCRIPT" <schema_type> "<output_file>"
```

`<schema_type>` is `stride` for `.stride-*.json`. Substitute `<output_file>` as a **literal absolute path**. `$OUTPUT_DIR` is an invocation-prompt variable, not an environment variable — used inside the command it expands to the empty string and the validator reports a missing file for a file that exists.

## Step 2 — Handle result

- **`VALID`** — proceed normally.
- **`INVALID`** — each line names the offending field path, e.g. `threats[2].attack_steps[1]: … is too long`. Edit that field in the file you just wrote and re-run Step 1. Two fix rounds; if it still fails, print `[<agent>] ✗ Schema validation failed — <first error>` and finish the turn with the file left as it is.
- **Script not found** — print `[<agent>] ⚠ Validator not found — skipped self-check` and proceed.

**Never overwrite the file with an empty or stub result in response to a validation failure.** One over-long sentence or one off-enum label would discard a complete component analysis; the orchestrator's own gate re-validates and re-dispatches, and it can only recover from a file that still holds the findings.
