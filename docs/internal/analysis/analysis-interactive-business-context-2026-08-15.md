# Interactive business-context capture — analysis

Date: 2026-08-15. Analysis only, nothing implemented.

Request: ask the user, on a new analysis and on `--rebuild`, whether extra context
should be added; accept pasted text or a URL; use it as business context for this run
and for future runs. Headless gets one parameter that takes the same two forms.

## What already exists

The context channel is built. What is missing is a way to fill it without hand-writing
a file.

| Piece | Where |
|---|---|
| Business-context input file `docs/business-context.md`, first 200 lines, untrusted-fenced | `scripts/build_threat_modeling_context.py:381` (context-v2), `agents/appsec-context-resolver.md:220` (legacy) |
| URL-sourced context over a POST endpoint, SSRF-guarded, 64 KiB cap, redirect re-validation | `build_threat_modeling_context.py:122` `_external_context`, config key `external_context.rest_url` |
| URL policy incl. org-profile `policy.url_allowlist` | `scripts/_url_guard.py:123` `validate_target_url` |
| Canonical secret scanner for ingested text | `scripts/secret_scan.py` (`load_org_context.py:70` is a weaker duplicate) |
| Untrusted-data wrapper for org markdown | `scripts/load_org_context.py:57` |
| Per-component projection of business context into STRIDE bundles, schema- and fingerprint-validated | `scripts/build_stride_evidence_bundles.py:625,673`, `schemas/stride-component-business-context.schema.json` |
| Pre-flight `AskUserQuestion` with a headless guard | `skills/create-threat-model/SKILL-impl.md:1025-1055` (session-model prompt) |
| Opt-in write into a target-repo input file | `data/required-permissions.yaml:113` (`docs/known-threats.yaml`, review-threat-model) |
| Documented contract for the file | `docs/threat-modeler.md:437` |

Consequence for the design: the feature is a capture-and-persist front end for
`docs/business-context.md`. It must not add a second injection path into the analysis.

## Where the prompt goes

`SKILL-impl.md` pre-flight, after the Configuration Summary and before the Stage 1
handoff banner — the same anchor as the rebuild wipe
(`skills/create-threat-model/modes/rebuild-wipe.md`) and the session-model prompt.

Trigger matrix:

| Mode | Behaviour |
|---|---|
| New analysis, no `docs/business-context.md` | Ask whether to add context |
| New analysis, file present | Do not ask; the file is already the answer |
| `--rebuild`, file present | Ask whether to refresh it (keep / replace / add a URL) |
| `--rebuild`, file absent | Same as a new analysis |
| `--incremental`, `--resume`, `--rerender`, `--dry-run` | Never ask |
| `APPSEC_HEADLESS=1` | Never ask; the CLI parameter is the only input |

The rebuild wipe clears `.threat-modeling-context.md` in `OUTPUT_DIR` but not the
repo-side input file, so on `--rebuild` the file survives and "refresh?" is the right
question.

## Write order matters

`repository_fingerprint` (`build_stride_evidence_bundles.py:163`) hashes HEAD plus the
bytes of every modified or untracked file, excluding only `OUTPUT_DIR`. Writing
`docs/business-context.md` sits inside that hash. It must therefore be written before
Stage 1 starts, i.e. in the same pre-flight window as the prompt. A write after a
fingerprint has been taken produces `business-context source fingerprint is stale`
from the bundle validator.

## Persistence

Default target `<repo>/docs/business-context.md`, which is what both context producers
read and what survives every run without extra plumbing.

Two things this needs:

- `Write(${REPO_ROOT}/docs/business-context.md)` in `data/required-permissions.yaml`
  plus its permission test, modelled on the `docs/known-threats.yaml` entry: explicit,
  opt-in, user-confirmed.
- A decision for AppSec-team operation (`--repo <foreign> --output <elsewhere>`), where
  the target repo may be read-only or not the right place for a written file. Options:
  fall back to a persisted copy next to the output (must then be added to
  `docs/internal/contracts/cleanup-whitelist.md`, since everything runtime in
  `OUTPUT_DIR` is wiped), or skip persistence and use the context for this run only.
  Open question, see below.

The written file should carry a short provenance header (source: interactive paste /
URL / file, date) as a Markdown comment, so a later reader knows where the text came
from.

## Ingestion rules for the captured text

Both input forms are untrusted data and must go through the same treatment the org
context already gets:

1. URL validated with `_url_guard.validate_target_url`. Unlike `_external_context`,
   which passes `check_ip_safety=False` for an operator-configured endpoint, a URL
   typed at the prompt or passed on the command line is user input and should keep IP
   safety on. The org-profile allowlist applies automatically.
2. Size cap on fetch and on paste; the reader caps at 200 lines anyway.
3. `secret_scan.scan_text` over the body before it is written — a pasted deployment
   note with a token in it would otherwise land in a tracked repo file. Do not extend
   `load_org_context._SECRET_PATTERNS`; it is the weaker duplicate.
4. Content type: accept Markdown/plain text; reject HTML pages rather than storing
   markup (a wiki URL usually needs an export/raw link).
5. The stored file keeps the untrusted framing that the producers already apply
   (`_fenced` / `_escape_untrusted`); nothing in it may act as instruction. Same rule
   as `docs/threat-modeler.md:437` states today: no file-selection rules, no severity
   claims, no agent instructions.

## Headless parameter

One flag, two forms, as requested — for example `--context <value>`, resolved
deterministically in `resolve_config.py`: `http(s)://` prefix → URL, otherwise a file
path.

Inline free text as a third form is possible but fragile in this pipeline:
`run-headless.sh:610-623` assembles the skill invocation as a single prompt string
(`PROMPT="$PROMPT --repo $REPO_PATH"`), and the skill layer parses its arguments out of
that string before `resolve_config.py` sees them. Multi-line text, quotes and newlines
do not survive that reliably. A file path covers the same use case without the quoting
risk, which is why the recommendation is URL-or-path, and inline text only at the
interactive prompt.

The flag has to be threaded through `run-headless.sh` argument parsing, the prompt
assembly, `resolve_config.py` (argparse, resolved JSON, conflict rules) and
`orchestration_controller.py` if the value needs to reach a stage beyond pre-flight.

## Incremental behaviour

Changing the business context changes the analysis inputs, not the code. Today nothing
maps a business-context change onto the incremental dirty set — the criteria in
`docs/internal/decisions.md` and `scripts/baseline_state.py` key off source changes.
A refreshed context in an incremental run would therefore be picked up by the context
producers but would not by itself re-open components whose code did not change. Whether
that is acceptable, or whether a changed context hash should recommend a full run (the
pattern `--requirements` uses, per the requirements-toggle gate), is a decision to
take before implementing, not an implementation detail.

## Files a later implementation would touch

- `skills/create-threat-model/SKILL-impl.md` — prompt block at the pre-flight anchor,
  headless guard, write step; possibly a lazy-loaded mode file to keep the prompt
  budget flat (`tests/test_context_prompt_budgets.py`).
- `skills/create-threat-model/SKILL.md` — flag row.
- `scripts/resolve_config.py` — `--context` parsing, form detection, resolved JSON key.
- New `scripts/load_business_context.py` — fetch/validate/secret-scan/write, mirroring
  `load_org_context.py`, with `tests/test_load_business_context.py`.
- `scripts/run-headless.sh` — flag parsing and prompt assembly.
- `data/required-permissions.yaml` + `tests/test_check_permissions.py`.
- `docs/threat-modeler.md` §Business context, `docs/internal/decisions.md` if the
  incremental question gets a registered answer, `CHANGELOG.md`.

## Decisions and recommendations

### 1. Where captured context is persisted

Options: write `<repo>/docs/business-context.md`, keep a persisted copy beside the
output, or use the context for the current run only.

Recommendation: one persistent location, `<repo>/docs/business-context.md`, written
only on explicit confirmation. When the repo is not writable, or the user declines to
persist, fall back to a transient `<output>/.business-context-input.md` that
`build_threat_modeling_context.py` reads in addition to the repo file, and that
`runtime_cleanup.py` removes as an always-cleanup artifact.

Reason: a second *persistent* location would become a second place the analysis loads
context from, which is the one property this feature should not add. The transient
file is a run input, not a store — it is a dotfile (covered by the gitignore template
pattern), it disappears at the end of the run, and it cannot silently shape the next
scan. Writing a durable file into a foreign repository during AppSec-team operation is
a change to someone else's repository and should not happen as a side effect.

### 2. Refresh semantics on `--rebuild`

Options: replace the file, or append a dated section.

Recommendation: replace, with the current state shown in the question (file date, word
count, first line) and "keep" as the default answer. Say so explicitly when the file
has uncommitted changes, since replacing then loses content git cannot restore.

Reason: business context describes the system as it is now, not a history. Appended
layers accumulate contradictory statements and push the oldest ones past the 200-line
read limit, where they drop out unannounced.

### 3. Incremental runs with a changed context

Options: recommend a full run, force one, or use the changed context silently.

Recommendation: recommend, do not force — the same shape the incremental criteria
already use for security-critical changes, where a hard force would multiply CI cost.
Store a hash of the context text in the baseline and compare it at pre-flight; on a
mismatch print the recommendation and continue. The interactive prompt never fires in
incremental mode, so this only triggers when someone edits the file directly or passes
`--context` headless.

Reason: context shapes severity and priority across all components. An incremental run
re-rates only the dirty ones, producing a model whose findings were rated against two
different context versions.

### 4. Inline text as a headless value

Options: allow `--context "<text>"`, or restrict headless to URL and file path.

Recommendation: restrict to URL and file path. In CI the text comes from a file or a
variable anyway, and writing it to a file is one heredoc.

Reason: the invocation is assembled as a single prompt string
(`run-headless.sh:610-623`) and parsed back out of it before argparse sees it.
Multi-line text with quotes does not survive that reliably, and a flag that silently
does the wrong thing on realistic input is worse than one that does not accept it.
