# Promote accepted risks

Loaded by SKILL.md Step 6b after an accept-risk decision.

## Step 6b — Promote accepted risks to `docs/known-threats.yaml` (opt-in)

Reached right after an **accept-risk** decision — the *Decide* action in Mode 5A,
or *Accept instead* in the Mode 5B fix loop — and only on the user's explicit
**yes**, never automatically. This is the one time the skill writes outside
`.appsec-triage/`. Ask once with `AskUserQuestion`:

> Also record these as accepted in `docs/known-threats.yaml`? On the next
> `create-threat-model` scan they'll be treated as accepted — skipped (not
> re-raised as open findings) and shown as accepted risks — instead of
> reappearing. (Your triage sidecar is unaffected either way.)

Options: **Yes, record as accepted** / **No, keep in triage only**. On **No**, do
nothing and return to the menu. On **Yes**, run the deterministic promoter — it
reads *every* `accept-risk` decision from the sidecar, synthesizes a schema-valid
`status: accepted` entry per finding (id = the finding's stable `local_id`; title,
STRIDE, component from the model; severity derived; `accepted_risk` = the
rationale; evidence = the finding's `file:line`), and **merges** into the file,
preserving any team-authored entries and deduping by id:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/review_threat_model.py" promote-accepted \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" \
    --known-threats "$REPO_ROOT/docs/known-threats.yaml"
```

It prints a JSON summary (`added` / `updated` / `skipped` / `total`). Report the
counts in one line and point the user at `docs/known-threats.yaml`. `skipped`
lists accepted findings that are stale (gone from the model) or lack a STRIDE
category — mention it only if non-empty. The command validates against
`known-threats.schema.yaml` before writing and fails loudly on invalid output; it
never touches `threat-model.yaml`. Do not commit the file — leave that to the user.
