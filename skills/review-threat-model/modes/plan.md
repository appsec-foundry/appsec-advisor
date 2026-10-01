# Mode: Build a remediation plan

Loaded by SKILL.md Step 5A when the user picks this mode. SKILL.md's Navigation, Selecting findings, Step 6 and Step 6b still apply.

## Step 5A — Mode: Build a remediation plan (decide → plan, no code)

A menu loop that records decisions. On entry and after each action, first print
the recommendation (`screens.fix_start`, see **Selecting findings**), then ask with
`AskUserQuestion` — put `Decided: X/<total>` in the prompt:

1. **Decide these first** — the fix-first set just shown (highest-value, low-risk;
   a starting point, not the only findings that need deciding) — act on the
   `recommended[]` fixes
2. **Browse & select** — by severity / type / requirement / unmitigated (see **Look around**)
3. **Security posture** — control ratings *(only when `control_posture` is non-empty)*
4. **Done — write plan & exit**

After a selection (from 1 or 2), run the **Decide** action (below): **Mark to fix**
or **Accept risk**. On **Done**, render the plan (Step 7), then offer the **bridge**
with one `AskUserQuestion`: *"Fix the To-Fix findings now directly?"* — **Yes**
switches to Mode 5B with that set preselected; **No** finishes.

### Decide action (Mode 5A terminal)
Applies to the named selection — record the decision only, never touch code:
- **Mark to fix** — write `fix` to the sidecar (Step 6); it lands in the plan's
  *To Fix* bucket with the model's remediation steps. Optional owner + target
  sprint — offer once, capture only if volunteered.
- **Accept risk** — requires a rationale; ask once for one shared reason and write
  it to every selected key (never an empty rationale). Persist `accept-risk`
  (Step 6), then offer the opt-in promotion to `docs/known-threats.yaml` (Step 6b).

## Step 7 — Write the plan (menu "Done — write plan & exit" / when the user is done)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/review_threat_model.py" render \
    --output-dir "$OUTPUT_DIR" --triage "$TRIAGE" --plan "$PLAN"
```

The script writes `remediation-plan.md` deterministically: **every** finding is
grouped by its current triage decision — **To Fix** (with the model's remediation
steps), **Accepted Risk** (with the rationale), and **Untriaged — decision still
needed** (anything not yet decided is listed here, never dropped) — severity-ranked
within each bucket, plus a Stale section for decisions whose finding left the
model, and a **Deferred** bucket when the sidecar carries `defer` decisions. It is a snapshot of the sidecar at this
moment (decisions from this and prior sessions). When you describe this option to
the user, say concretely what the plan contains — not a vague "from current
decisions". Print the plan path and a one-line triage summary (counts per
decision). Do not paste the whole plan; point the user to the file.

If `stale[]` was non-empty, mention it once: some prior decisions reference
findings no longer in the model (fixed, merged, or renumbered) and are listed at
the bottom of the plan for review.
