# Business Context Capture (interactive full / rebuild runs)

> **Lazy-loaded mode file.** Read at the "Business context" anchor of
> `SKILL-full-runtime.md` §2b, before the run plan, on the default full/rebuild
> path, after the controller pre-flight wipes. The run plan is computed before the
> answer and does not change with it; the answer feeds the analysis.
>
> This file is the interactive question only. A source supplied with `--context`
> is captured by the controller during pre-flight, before this file is read, and
> a failed capture stops the run there. So this file is read only when
> `ACTION.business_context_prompt_needed` is `true` and `MODE` is `full` or
> `rebuild`. That one field already carries the empty-source, skip-flag and
> operator-present conditions, so none of them is re-derived here.

Business context is what the repository cannot show: what the system is for, which
flows carry money or personal data, which obligations apply. It weights the impact
rating and the order of findings that repository evidence already supports, so it is
worth one question at the start of a fresh analysis. It never creates a finding.

It stays optional. Declining is a complete answer, the analysis runs on repository
evidence either way, and nothing later in the run treats a missing context as a defect.
Ask once, take the first answer, never press.

## Step 1 — What is already there

```bash
BC_FILE="$REPO_ROOT/docs/business-context.md"
if [ -f "$BC_FILE" ]; then
  BC_WORDS=$(wc -w < "$BC_FILE" | tr -d ' ')
  BC_DATE=$(date -r "$BC_FILE" +%Y-%m-%d 2>/dev/null || echo unknown)
  BC_DIRTY=$(cd "$REPO_ROOT" && git status --porcelain -- docs/business-context.md 2>/dev/null | head -1)
  printf 'Business context: docs/business-context.md — %s words, last changed %s%s\n' \
      "$BC_WORDS" "$BC_DATE" "${BC_DIRTY:+ (uncommitted changes)}"
else
  printf 'Business context: none stored\n'
fi
```

## Step 2 — Ask

One `AskUserQuestion`, header `Context`.

**No file present** — question: whether to add business context for this and future
analyses. Options, recommended first:

- `Continue without` — the analysis runs on repository evidence alone.
- `Paste text` — you type or paste the context in the next question.
- `Fetch from URL` — a raw Markdown or plain-text URL.

**File present (only reachable on `--rebuild`)** — question: state the word count,
date, and whether it has uncommitted changes, then ask whether to keep or replace it.
Replacing overwrites the file; say so when it carries uncommitted changes, because git
cannot restore those. Options, recommended first:

- `Keep stored context` — the existing file is used unchanged.
- `Replace — paste text`
- `Replace — fetch from URL`

On `Continue without` or `Keep stored context`: print one line saying which applies and
return to the compact full runtime. Do not ask again.

## Step 3 — Collect the value

A second `AskUserQuestion`, header `Context`: ask the user to enter the text (or the
URL) through the **Other** option, since that is the only free-text field available
mid-run. Offer one option, `Cancel — continue without context`, as the way out.

Name what to write, because the analysis projects exactly these five per component
and free-form prose maps onto them unevenly: the business purpose, the concrete harm
if the component is compromised, the sensitive assets it handles, applicable
obligations, and the security assumptions being made. Partial answers are fine.

Cancelled or empty answer → print one line and return.

## Step 4 — Capture it

A pasted text goes to a buffer file first, so no shell quoting can mangle it. Write
`$OUTPUT_DIR/.business-context-raw.md` with the **Write** tool, verbatim, then:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/load_business_context.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" \
    --source "$OUTPUT_DIR/.business-context-raw.md" --consume-source \
    --persist ${BC_REPLACE:+--replace}
```

For a URL, pass it as `--source` unchanged and drop `--consume-source`. Set
`BC_REPLACE=1` only when the user chose one of the `Replace` options.

The script validates the URL against the SSRF policy, rejects an HTML page, refuses a
source carrying a credential, and writes `docs/business-context.md` with a provenance
header. Report what it printed.

**When it exits non-zero**, the run continues without the new context — it is an
optional input, not a gate. Two cases are worth a retry rather than a shrug:

- The repository is not writable (a scanned repository you do not own): re-run the same
  command with `--run-only` instead of `--persist`. The context then applies to this run
  and is cleaned up afterwards.
- A credential was found: nothing was written. Report the reported line and continue;
  the user can capture a cleaned version on the next run.

Then return to the compact full runtime.
