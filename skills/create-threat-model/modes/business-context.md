# Business Context Capture (interactive full / rebuild runs)

> **Lazy-loaded mode file.** Read at the "Business context" anchor of the runtime in
> use — `SKILL-full-runtime.md` §3a on the default full/rebuild path,
> `SKILL-impl.md` on the legacy path — after the pre-flight wipes, before Stage 1.
> `SKILL-impl.md` reads it only for the question (`BUSINESS_CONTEXT_SOURCE` empty,
> `APPSEC_HEADLESS` not `1`, `DRY_RUN=false`, `MODE` `full` or `rebuild`) because it
> captures a supplied source itself; the compact runtime reads it for both.

Business context is what the repository cannot show: what the system is for, which
flows carry money or personal data, which obligations apply. It changes severity and
priority, so it is worth one question at the start of a fresh analysis.

It stays optional. Declining is a complete answer, the analysis runs on repository
evidence either way, and nothing later in the run treats a missing context as a defect.
Ask once, take the first answer, never press.

## Step 0 — A source was supplied

When `BUSINESS_CONTEXT_SOURCE` is non-empty, capture it for this run and return
without asking — `--context` is the user's answer already:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/load_business_context.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" \
    --source "$BUSINESS_CONTEXT_SOURCE" --run-only \
  || printf 'Continuing without the supplied business context.\n' >&2
```

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
return to `SKILL-impl.md`. Do not ask again.

## Step 3 — Collect the value

A second `AskUserQuestion`, header `Context`: ask the user to enter the text (or the
URL) through the **Other** option, since that is the only free-text field available
mid-run. Offer one option, `Cancel — continue without context`, as the way out.

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

Then return to `SKILL-impl.md`.
