# Mode: Fix or accept findings now

Loaded by SKILL.md Step 5B when the user picks this mode or bridges into it. SKILL.md's Navigation, Selecting findings, Step 6 and Step 6b still apply.

## Step 5B — Mode: Fix or accept findings now (change code, one at a time)

A menu loop that changes code. **On entry, if `freshness.verdict` is `STALE`,
say so once** — this mode edits source against a model the code has already moved
past, so its `location`s and remediation steps may no longer match the file. Name
the reason and offer to re-scan first (`/appsec-advisor:create-threat-model`); if
the user wants to continue anyway, continue. Do not block, do not repeat it per
finding, and do not raise it in the read-only modes.

On entry and after each fix, first print
`screens.fix_start`, then ask — put `Fixed: X` in the prompt:

1. **Fix these first** — implement the fix-first set shown (highest-value, low-risk;
   the place to start, not the only findings worth fixing) — the `recommended[]` fixes
2. **Browse & pick** — by severity / type / requirement / unmitigated
3. **Done — finish** — point the user at `git diff`
4. **← Back** — return to the mode picker (Step 4b); fixes already applied stay,
   nothing new is written

After a selection, run the **Fix loop** (Step 5b) on the named findings — one at a
time, for review. There is no plan step; the output is the code diff. A finding the
user would rather not fix can be accepted inline via the loop's **Accept instead**.
(Entered from the Mode-5A bridge with a set preselected, skip the menu and go
straight to the Fix loop on that set.)

## Step 5b — Fix loop (Mode 5B terminal — code changes)

The terminal action of **Fix or accept findings now** (also reached from the Mode-5A
bridge). This is the one place the skill edits the target repo's source. Work
through the selected findings **one at a time**, never as a blind bulk apply:

1. For each selected finding (resolve mitigations to their `covered_keys`), read
   its remediation detail from `threat-model.yaml` — the `remediation.steps` and
   `affected_files` on the threat (and the covering mitigation). These are the
   **only** basis for the change; do not invent unrelated edits or touch files
   the finding does not name.
2. Show the user what you will change (file + intended edit), then per finding
   offer **Apply** / **Skip** / **Accept instead** / **Stop**:
   - **Apply** — make the edit (minimal, scoped to the finding). If the remediation
     is ambiguous or needs a decision, ask rather than guess.
   - **Skip** — move to the next finding, unchanged.
   - **Accept instead** — the user would rather accept this finding's risk than
     fix it: ask for a rationale and record `accept-risk` in the sidecar (Step 6),
     then continue. (Offer the Step 6b known-threats promotion once at loop end for
     any accepted findings.)
   - **Stop** — end the loop, return to the Mode 5B menu.
3. After each **applied** finding, record its decision as `fix` in the sidecar
   (Step 6) so triage state stays consistent. Note which findings you implemented,
   skipped, or accepted.
4. When done, suggest verifying — run the project's tests or the `verify` flow if
   present — and point the user at `git diff` to review. Do **not** commit; leave
   that to the user. Then return to the Mode 5B menu.

Guardrails: only findings the user selected; one at a time with review; changes
traceable to the finding's own remediation; the threat model itself is never
edited (Consumer guarantee holds — you change source, not `threat-model.yaml`).
