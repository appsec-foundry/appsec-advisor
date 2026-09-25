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
> `rebuild`. That one field already carries the empty-source, stored-file,
> skip-flag and operator-present conditions, so none of them is re-derived here.

Business context is what the repository cannot show: which data is sensitive, what a
compromise would cost, and which obligations apply. It weights the impact rating and
the order of findings that repository evidence already supports. It never creates a
finding.

It stays optional. Every question can be skipped, declining is a complete answer, and
nothing later in the run treats a missing context as a defect. Ask once, take the
first answer, never press, and never ask a follow-up question.

## Step 1 — Ask

One `AskUserQuestion` call with exactly these three questions, all `multiSelect: true`.
Translate the wording into the language the user writes in; keep the meaning.

1. Header `Data` — "Which sensitive data does this system handle?"
   Options: `Personal data`, `Payment or financial data`,
   `Health or other special-category data`, `None of these`.
2. Header `Impact` — "What would hurt most if an attacker succeeded?"
   Options: `Leak of confidential data`, `Fraud or direct financial loss`,
   `Outage of business-critical operations`, `Tampered data or decisions`.
3. Header `Obligations` — "Which obligations apply?"
   Options: `GDPR or other data-protection law`, `PCI DSS`,
   `Sector regulation (e.g. HIPAA, KRITIS, DORA)`, `None known`.

State in the first question's text that every question may be skipped and that the
answers are stored in `docs/business-context.md`, so later runs do not ask again. The
user can name a component or add detail through **Other**.

When the call is dismissed, or every question is skipped or answered only with
`None of these` / `None known`, print one line saying the analysis continues on
repository evidence alone and return to the compact full runtime.

## Step 2 — Capture the answers

Write `$OUTPUT_DIR/.business-context-raw.md` with the **Write** tool. Use these
headings and include a heading only when its question has a substantive answer; put
the selected labels and any **Other** text verbatim as bullets:

```markdown
# Business context

## Sensitive assets

## Compromise impact

## Obligations
```

Then:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/load_business_context.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" \
    --source "$OUTPUT_DIR/.business-context-raw.md" --consume-source --persist
```

The script refuses a source carrying a credential and writes `docs/business-context.md`
with a provenance header. Report what it printed.

**When it exits non-zero**, the run continues without the new context — it is an
optional input, not a gate. If the repository is not writable (a scanned repository
you do not own), re-run the same command with `--run-only` instead of `--persist`; the
context then applies to this run and is cleaned up afterwards. If a credential was
found, nothing was written; report the reported line and continue.

Then return to the compact full runtime.
