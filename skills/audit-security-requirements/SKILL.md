---
name: audit-security-requirements
description: Audit the current repository against a security requirements catalog and verify whether each requirement is implemented. Requirement IDs follow your catalog's own naming scheme (e.g. SEC-CSP-1, SCG-HARDENXML, or anything your YAML defines); tagging code with those IDs is optional and not required. Prints open requirements to the conversation with color-coded status and concise evidence. When you save an artifact (Markdown, PDF, JSON) or use --gate, it also persists a deterministic structured verdict (.requirements-audit.json) and can act as a CI gate.
---

You are auditing whether security requirements are implemented in the current repository. Follow the steps below exactly.

## Output discipline (professional, quiet)

This skill produces an audit report — present it like a tool, not a chat. The
user-visible output is, in order: the `AppSec Requirements Audit` title +
**Requirements Source** banner (Step 1b), then the **Results** block and open
requirements (Step 3), and the saved-file lines (Step 4). Between those, scan
the repository **silently**.

Do **not** narrate reasoning or step transitions. Forbidden filler includes
lines like "Now load threat model context…", "Banner first, then I'll grade",
"Let me scan systematically", "Now gathering codebase evidence". Tool calls run
without a running commentary. The only progress line permitted between the
banner and the results is a single, optional `Auditing <n> requirements against
the codebase…`. Internal caveats (e.g. an empty `violated_requirements` map)
are not surfaced as prose — they simply produce empty cross-links.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, **do not scan the repository**. Print the block below verbatim to the conversation and exit with status 0.

```
/appsec-advisor:audit-security-requirements — Audit a repo against your security requirements.

USAGE
  /appsec-advisor:audit-security-requirements [CATEGORY_FILTER] [FLAGS]

  CATEGORY_FILTER is an optional substring matched against requirement IDs and
  category IDs (e.g. "SEC-AUTH" or "AUTH"). When given, ONLY matching
  requirements are graded — the filter narrows scope for a focused review of
  one area. (It no longer force-includes every MUST; an unfiltered run grades
  the whole catalog.)

WHERE REQUIREMENTS COME FROM (highest priority first)
  1. --requirements <src>      explicit source for this run (no cache fallback)
  2. --demo                    packaged example catalog (clearly stamped DEMO)
  3. docs/security/requirements.yaml   a local repo catalog, if present
                               (beats the org profile; surfaced in the banner)
  4. the active org profile's configured source
  5. the legacy configured source
  6. the remembered source     the URL the catalog was last fetched from,
                               served from the plugin cache
  On first use with none of the above, the audit explains what to pass and
  offers to run against --demo.

SOURCE FLAGS
  --requirements <src>     http(s):// URL or local file path (abs/rel/~).
  --update                 force a fresh re-fetch from the remembered/configured
                           source and refresh the cache.
  --cache-only             use the plugin cache only; never touch the network.
  --demo                   audit against the packaged example catalog (DEMO).
  --status                 show which requirements WOULD be used (source, date,
                           count, freshness) and exit — no audit, no fetch.
  --clear-requirements     forget the remembered source + cached catalog, exit.
  --org-profile <path>     use this org profile for source resolution.
  --preset <name>          use a specific preset from the active org profile.
  --no-org-profile         ignore packaged/env-pointed org profiles.

OUTPUT FLAGS
  --md                     save the rendered report as
                           docs/security/appsec-requirements-report.md
  --pdf                    save a PDF (docs/security/appsec-requirements-report.pdf);
                           also writes the Markdown it is converted from
  --json                   copy the structured verdict to
                           docs/security/appsec-requirements-report.json
  --save                   --md, --pdf and --json

GATE FLAGS (CI / merge gate — advisory by default)
  --gate                   exit non-zero when a gating requirement fails.
  --gate-on <fail|partial> what gates: fail (default) or fail+partial.
  --priority-floor <MUST|SHOULD|MAY>
                           lowest priority that may gate (default MUST).

DEFAULT BEHAVIOUR
  A plain run prints a banner (catalog, source, fetch date, count, freshness),
  grades the catalog, and prints the open requirements — fast and quiet, no
  files written. Saving an artifact (--md/--pdf/--json/--save) or gating
  (--gate) additionally builds a deterministic structured verdict
  (docs/security/.requirements-audit.json, schema-validated, counts recomputed)
  and runs the gate. A fresh cache (< 30 days) is reused without a network
  round-trip; a stale cache triggers a refresh that falls back to the cache.

See `/appsec-advisor:status` for plugin & configuration status, and
`docs/security-requirements-audit-skill.md` for the full source-resolution rules.
```

After printing, exit. Do not read any files or perform any other action.

## Step 1 — Parse arguments and load requirements

### 1a — Parse arguments

The user may pass arguments after the skill name. Parse them now:

- **Category filter** — any word that does not start with `--` (e.g. `AUTH`, `SQL`) — grade ONLY requirements whose ID or category contains this string. It narrows scope; it does not force-include other priorities. An unfiltered run grades the whole catalog.
- `--md` — save results as `docs/security/appsec-requirements-report.md` after rendering
- `--pdf` — save `docs/security/appsec-requirements-report.pdf` (converted from the Markdown report, which is written too)
- `--json` — save results as `docs/security/appsec-requirements-report.json` after rendering
- `--save` — save all formats (`--md`, `--pdf`, `--json`)
- `--requirements <src>` — override the configured `requirements_yaml_url` for this run. `<src>` is an http(s):// URL (fetched remotely) or a local file path (absolute or relative). The source must load; there is no cache fallback when an explicit source is provided.
- `--update` — force a fresh re-fetch from the remembered/configured source and refresh the plugin cache before auditing.
- `--cache-only` — use the plugin cache only; never touch the network.
- `--demo` — audit against the packaged example catalog. The report is stamped **DEMO**.
- `--status` — **mode flag**: print the resolution banner (source, date, count, freshness) and exit. Do not scan the repository.
- `--clear-requirements` — **mode flag**: forget the remembered source and delete the cached catalog, then exit. Do not scan the repository.
- `--gate` — enforce a CI gate: exit non-zero when a gating requirement fails (default advisory, always exit 0). Decided deterministically by `scripts/requirements_gate.py`, not by the model.
- `--gate-on <fail|partial>` — what gates: `fail` (default) or `fail`+`partial`.
- `--priority-floor <MUST|SHOULD|MAY>` — lowest priority eligible to gate (default `MUST`).
- `--org-profile <path>` — use this org profile for source resolution instead of the packaged default.
- `--preset <name>` — use a specific preset when resolving the active org profile.
- `--no-org-profile` — ignore any packaged or env-pointed org profile for this run.

Store the resolved flags: `save_md`, `save_pdf`, `save_json`, `category_filter`,
`requirements_url_override`, `update`, `cache_only`, `demo`, `status_mode`,
`clear_requirements`, `gate_mode`, `gate_on` (default `fail`),
`priority_floor` (default `MUST`), `org_profile_override`, `preset_override`,
`no_org_profile`.

`--save` sets `save_md`, `save_pdf` and `save_json`. `--pdf` implies `save_md`
(the PDF is converted from the Markdown report). `--gate-on` and
`--priority-floor` each consume the following token as their value.

#### Reject unknown flags (hard fail)

Non-flag words (tokens that do not start with `--`) are always valid — they
are treated as the `category_filter`. But any token starting with `--` that
is not one of the recognized flags above — or is not the value consumed by
`--requirements` — is a hard error. DO NOT proceed. Do not read any files,
do not fetch requirements, do not scan the repository. Print the following
block verbatim to stderr, substituting `<TOKEN>` with the first unknown
flag, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:audit-security-requirements accepts only:
  [CATEGORY_FILTER]        Optional substring (e.g. AUTH, SQL) — no -- prefix
  --md                     Save the rendered report as Markdown
  --pdf                    Save the report as PDF (also writes the Markdown)
  --json                   Copy the structured verdict to JSON
  --save                   --md, --pdf and --json
  --requirements <url>     Override the configured requirements YAML source
  --update                 Force a fresh re-fetch and refresh the cache
  --cache-only             Use the plugin cache only; never touch the network
  --demo                   Audit against the packaged example catalog (DEMO)
  --status                 Show which requirements would be used, then exit
  --clear-requirements     Forget the remembered source + cache, then exit
  --gate                   Enforce a CI gate (non-zero exit on a gating failure)
  --gate-on <fail|partial> What gates (default fail)
  --priority-floor <MUST|SHOULD|MAY>  Lowest priority that may gate (default MUST)
  --org-profile <path>     Override the packaged org profile
  --preset <name>          Select an org-profile preset
  --no-org-profile         Ignore org-profile defaults
  --help, -h               Show full help and exit

Run `/appsec-advisor:audit-security-requirements --help` for details.
```

`--requirements`, `--org-profile`, `--preset`, `--gate-on`, and
`--priority-floor` count as unknown when their value is missing — treat the flag
itself as the offending token in that case.

### 1b — Resolve the org profile and requirements YAML

Find the plugin root:

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_MD_PATH=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/audit-security-requirements/SKILL.md" \
    2>/dev/null | head -1)
  if [ -n "$SKILL_MD_PATH" ]; then
    CLAUDE_PLUGIN_ROOT=$(dirname "$(dirname "$(dirname "$SKILL_MD_PATH")")")
  fi
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved — install appsec-advisor or set the variable manually." >&2
  exit 2
fi
```

Resolve the active org profile before resolving the requirements source. The
audit report output directory is the current repository's `docs/security/`;
the resolver writes `.org-profile-effective.json` there so the shared
requirements resolver and fetch gate see the same profile state as
`create-threat-model`.

```bash
AUDIT_OUTPUT_DIR="${PWD}/docs/security"
mkdir -p "$AUDIT_OUTPUT_DIR"

ORG_ARGS=()
[ -n "$ORG_PROFILE_OVERRIDE" ] && ORG_ARGS+=(--org-profile "$ORG_PROFILE_OVERRIDE")
[ -n "$PRESET_OVERRIDE" ] && ORG_ARGS+=(--preset "$PRESET_OVERRIDE")
[ "$NO_ORG_PROFILE" = "true" ] && ORG_ARGS+=(--no-org-profile)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_org_profile.py" \
  --output-dir "$AUDIT_OUTPUT_DIR" \
  --emit-file \
  "${ORG_ARGS[@]}" >/dev/null
ORG_RESOLVE_EXIT=$?
if [ "$ORG_RESOLVE_EXIT" -ne 0 ]; then
  exit "$ORG_RESOLVE_EXIT"
fi
```

#### Mode flags — `--clear-requirements` and `--status` exit early

These two flags are maintenance/inspection modes. Handle them **before** any
repository scan. If `CLEAR_REQUIREMENTS` is set, run the gate's clear mode and
exit; the skill does not audit on this invocation:

```bash
if [ "$CLEAR_REQUIREMENTS" = "true" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" \
    --caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" \
    --plugin-root "$CLAUDE_PLUGIN_ROOT" --clear-requirements
  exit 0
fi
```

#### Honour an org profile that disables the standalone audit (governance-first)

Resolve the source first. When the active org profile configures a requirements
source but sets `requirements.standalone_audit.enabled: false`, that governance
decision wins — **even if a local `docs/security/requirements.yaml` is present**.
A passive in-repo catalog must not silently defeat the org policy. Only an
explicit per-run override — `--requirements <src>` or `--demo` (which resolve to
source `cli` / `demo`) — bypasses the block.

```bash
REQ_SOURCE_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT")
[ -n "$REQUIREMENTS_URL_OVERRIDE" ] && REQ_SOURCE_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
[ "$DEMO" = "true" ] && REQ_SOURCE_ARGS+=(--demo)

REQ_SOURCE_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_requirements_source.py" "${REQ_SOURCE_ARGS[@]}")
REQ_SOURCE_KIND=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('source') or '')")
ORG_AUDIT_DISABLED=$(printf '%s' "$REQ_SOURCE_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('org_audit_disabled',False)).lower())")

# Block when the org disabled the standalone audit, unless an explicit per-run
# source (--requirements / --demo → source cli/demo) overrides it.
if [ "$ORG_AUDIT_DISABLED" = "true" ] && [ "$REQ_SOURCE_KIND" != "cli" ] && [ "$REQ_SOURCE_KIND" != "demo" ]; then
  echo "✗ Requirements audit is disabled by the active org profile (standalone_audit.enabled: false)." >&2
  if [ "$REQ_SOURCE_KIND" = "local" ]; then
    echo "  A local docs/security/requirements.yaml does not override this org policy." >&2
  fi
  echo "  Override for this run with --requirements <src> or --demo, or set" >&2
  echo "  requirements.standalone_audit.enabled: true in the org profile." >&2
  exit 2
fi
```

#### Fetch or inspect through the shared deterministic gate

Resolution precedence (highest first): explicit `--requirements <src>` >
`--demo` > local `docs/security/requirements.yaml` > active org-profile source
(honouring `standalone_audit.enabled`) > legacy config > remembered source via
the plugin cache. A **local repo catalog overrides the org profile** and is
surfaced in the banner. The gate also writes a `.requirements-resolution.json`
sidecar describing the chosen source — render it as the startup banner.

Pass the user's source flags straight through to the gate. `--status` is a
no-fetch inspection mode; every other invocation loads the catalog:

```bash
FETCH_ARGS=(--caller audit-security-requirements --output-dir "$AUDIT_OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT")
if [ -n "$REQUIREMENTS_URL_OVERRIDE" ]; then
  FETCH_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
else
  FETCH_ARGS+=(--require)
fi
[ "$DEMO" = "true" ]       && FETCH_ARGS+=(--demo)
[ "$UPDATE" = "true" ]     && FETCH_ARGS+=(--update)
[ "$CACHE_ONLY" = "true" ] && FETCH_ARGS+=(--cache-only)
[ "$STATUS_MODE" = "true" ] && FETCH_ARGS+=(--status)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" "${FETCH_ARGS[@]}"
REQ_FETCH_EXIT=$?

REQ_RESOLUTION="$AUDIT_OUTPUT_DIR/.requirements-resolution.json"
REQUIREMENTS_YAML="$AUDIT_OUTPUT_DIR/.requirements.yaml"
```

**First-run / no-source handling (`REQ_FETCH_EXIT` == 2).** The gate aborts with
exit 2 only when requirements were requested but nothing loaded — no configured
source, and an empty cache. This is the genuine first-run case. Do not proceed
to scan. Print the guidance below, then **offer to run against the packaged demo
catalog** (decision A). When running interactively you may ask the user with
`AskUserQuestion` whether to re-run with `--demo`; otherwise just print the hint
and exit 2:

```
No security requirements are configured yet, and the plugin cache is empty.

Tell the audit where your requirements live, one of:
  • --requirements https://your-org/appsec-requirements.yaml   (fetch + remember)
  • drop a catalog at docs/security/requirements.yaml          (local repo file)
  • configure an org profile (see docs/org-profiles.md)

Or try it now against the bundled example catalog:
  /appsec-advisor:audit-security-requirements --demo
```

For any other non-zero, non-2 exit, propagate it:

```bash
if [ "$REQ_FETCH_EXIT" = "2" ]; then
  exit 2   # after printing the first-run guidance above
fi
if [ "$REQ_FETCH_EXIT" -ne 0 ]; then
  exit "$REQ_FETCH_EXIT"
fi
```

#### Render the startup banner (always, before scanning)

Read `REQ_RESOLUTION` and print a banner so the user always knows **which
requirements are in effect and how current they are** before any findings.
This banner — led by the title rule — is the **first user-visible output of the
skill**; nothing precedes it (no preamble, no "loading…" narration). Derive a
human "fetched N days ago" from `freshness.age_days`. Example:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AppSec Requirements Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requirements Source
  Catalog  : Acme Application Security Requirements
  Source   : remembered · https://security.example.com/appsec-requirements.yaml
  Loaded   : plugin cache /home/you/appsec-advisor/.cache/requirements.yaml
  Fetched  : 2026-06-05 (7 days ago) · catalog generated 2026-04-09
  Count    : 63 requirements
  Freshness: 🟢 fresh (cache < 30 days)
  Override : --update (refresh) · --cache-only · --demo · --requirements <url> · --status · --clear-requirements
```

After the banner, scan silently. The only line permitted before the Step 3
results is a single optional `Auditing <n> requirements against the codebase…`.

Banner rules:
- **Always print a `Loaded   :` line** naming the concrete on-disk path the catalog bytes were actually read from **this run** — so it is never ambiguous that the `Source` URL was not necessarily contacted. Derive it from `disposition` + `cache_path` + `url`:
  - `cache` / `cache_only` / `cache_after_fetch_fail` → `Loaded   : plugin cache <cache_path>`
  - `fetched` → `Loaded   : freshly fetched from <url> → cached at <cache_path>`
  - `local` → `Loaded   : local file <url>`
  - `demo` → `Loaded   : packaged example <url>`
  When the bytes came from the cache, the `Source` line still shows the remembered/configured URL (where the cache came from) and the `Loaded` line shows the cache file that was actually read.
- If `demo` is `true`, title the catalog line `Catalog  : <desc>  ⚠ DEMO — not your organization's requirements` and colour it yellow. The audit still runs, but every report it writes must carry the DEMO stamp (Steps 3a/4a).
- If `surfaced` is `true` (a local `docs/security/requirements.yaml` is in effect), add a line `Note     : using local repo catalog (overrides org profile)`.
- If `freshness.stale` is `true`, render `Freshness: 🟡 STALE (cache ≥ 30 days) — refresh with --update`, and note that an `--update` attempt was already made this run if the disposition is `cache_after_fetch_fail`.
- If `disposition` is `cache_after_fetch_fail`, add `Source    : unreachable this run — served the cached copy` so the user knows the network refresh failed.
- If `STATUS_MODE` is set, print the banner and **stop here** — do not scan the repository, do not render findings, exit 0.

Use `REQUIREMENTS_YAML` as the loaded catalog in Step 1c. The skill cannot
produce meaningful results without this file.

### 1c — Parse the YAML

From the loaded YAML, extract all requirements by iterating `categories[].requirements[]`. For each requirement record:

- **ID** — `requirements[].id` (e.g. `SEC-SQL`)
- **Category** — parent `categories[].id`
- **Category title** — parent `categories[].title`
- **Description** — `requirements[].text`
- **Requirement URL** — `requirements[].url` (may be null in fallback mode)
- **Priority** — `requirements[].priority` (`MUST` / `SHOULD` / `MAY`)

Apply the category filter from Step 1a if set.

### 1c-ii — Load blueprints (if present)

If the YAML contains a top-level `blueprints[]` section, build a blueprint index:

For each blueprint in `blueprints[]`, iterate its `sections[]`. For each section that has a `references[]` list, map every referenced requirement ID to the blueprint section:

```
blueprint_map[ref.id] → { bp_id, bp_title, section_title, section_url }
```

This map is used in Step 3b to show relevant blueprint guidance alongside violations.

### 1d — Scan for inline requirement references (optional, non-essential)

Some teams annotate code with their requirement IDs; one common convention is
the bracket form `[<ID>]` (e.g. `[SEC-CSP-1]`). Many teams use a **different
convention or none at all** — that is expected. This scan is a convenience that
surfaces such references when they exist; the audit does **not** depend on it,
and finding zero references is normal and fine. Requirement IDs come from the
loaded catalog (Step 1c) and may use any naming scheme.

```bash
# Optional — only meaningful if this repo uses the [<ID>] tag convention.
grep -rn "\[<ID>\]" --include="*.{ts,js,py,go,java,kt,rb,cs,php,md,yaml,yml}"
```

Run for every known requirement ID (or a combined regex) if you scan at all.
Grading in Step 2 searches for actual implementation evidence per requirement
and is independent of any inline tag.

---

## Step 1.5 — Load threat model context (non-fatal)

Try to read `docs/security/threat-model.yaml` relative to the current working directory (the repo root). This step is always non-fatal — if the file is absent or unreadable, skip silently and continue to Step 2 with an empty `req_to_threats` map.

If the file exists and is valid YAML:

1. Extract `meta.generated` and store as `model_generated` (ISO 8601 string, for display).
2. Build a `req_to_threats` map by iterating `threats[]`:
   - For each threat that has a non-empty `violated_requirements` array, add an entry for each requirement ID in that array:
     ```
     req_to_threats[req_id] → [{ f_id, risk, title }, ...]
     ```
   - Use the threat's `id` field as `f_id`, `risk` as the severity label, and `title` as the short label. Current threat-model.yaml exports use final `F-NNN` IDs; do not convert them back to internal `T-NNN` IDs.
3. If `threats[]` is missing or empty, `req_to_threats` remains empty — no error.

This map is used in Step 3b to annotate violations with Threat Register links.

---

## Step 2 — Verify implementation for each requirement

For each requirement, search the codebase for evidence using `Grep` and `Read`.

Assign one of four statuses:

| Status | Icon | Meaning |
|--------|------|---------|
| PASS | ✅ | Implementation found; code demonstrably satisfies the requirement |
| PARTIAL | ⚠️ | Some implementation exists but incomplete, inconsistent, or only partial |
| FAIL | ❌ | No implementation found, or existing code contradicts the requirement |
| UNVERIFIABLE | ❓ | Cannot be verified from static analysis alone |
| NOT_APPLICABLE | ➖ | The requirement does not apply to this repo (e.g. XML-parser hardening in a repo that parses no XML). Set `in_scope: false`; never gates. |

Collect for each requirement:
- Status
- **Requirement statement**: the requirement's verbatim `text` from the catalog (Step 1c). Carry it through to the outputs unchanged — never replace it with the derived title or a paraphrase.
- Evidence: file path(s) and line number(s) — formatted as VS Code deep links `[path:line](vscode://file/ABSOLUTE_REPO_ROOT/path:line)`
- One-line finding
- For **FAIL**, **PARTIAL**, and **UNVERIFIABLE** additionally collect:
  - **Fix**: the control **prescribed by the requirement**, made concrete for this repository — anchored to the catalog, not invented. Ground it in (a) the requirement's own `text` (what it demands) and (b) the matched blueprint section from `blueprint_map[<id>]` (Step 1c-ii), the catalog's prescribed "how". The model's contribution is to map that prescribed control onto the exact file / function / config key in the repo (which call to change, which setting to set) — **not** to introduce a mechanism or requirement the catalog does not call for, and not generic best-practice padding. Reference exact file and function names; when a blueprint matched, name it and let the blueprint link carry the detail. For console output keep it to one to three concise lines; for Markdown output, include a short before/after code block when meaningful code evidence exists. If neither the requirement nor a blueprint prescribes a specific mechanism, state the minimal concrete change that satisfies the demand here and say so — do not over-specify.
  - **Effort**: `S` (< 1 hour, isolated change), `M` (half day, several files), or `L` (multi-day, architectural change)

### 2.5 — Persist the structured verdict (ONLY when an artifact or gate is requested)

**Skip this whole step for a plain console run.** Serialising a full
per-requirement verdict is only worth its cost when the user asked for a
machine-readable artifact or a gate — i.e. when **any** of `save_json`,
`save_pdf`, `save_md`, or `gate_mode` is set. When none are set, do NOT build a
verdict file and do NOT write helper scripts; go straight to Step 3 and render
the console from your grading (a plain run stays fast and quiet).

When the verdict IS needed, it is the canonical output the saved reports and the
gate derive from. Build it directly with the `Write` tool — you already produced
these fields while grading; keep it quiet (no narration). A short one-off
serialisation script is acceptable here since an artifact was explicitly
requested, but the plain run must never reach this step.

**Assemble** one object per `schemas/requirements-audit.schema.json`:

```json
{
  "version": 1,
  "generated_at": "<ISO 8601 UTC>",
  "repository": "<git remote URL or directory name>",
  "requirements_source": "<remote|cached|local|demo>",
  "catalog": { "description": "<…>", "generated": "<…>", "url": "<…>", "count": <n> },
  "filter": "<category_filter or null>",
  "demo": <true|false>,
  "priority_floor": "<priority_floor>",
  "summary": { "total": 0, "pass": 0, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0 },
  "results": [
    {
      "id": "SEC-SQL", "category": "...", "priority": "MUST",
      "status": "FAIL", "in_scope": true,
      "requirement_text": "<verbatim catalog text>", "title": "Parameterized SQL Queries",
      "evidence": [ { "file": "routes/search.ts", "line": 23 } ],
      "finding": "...", "risk": "...", "fix": "...", "effort": "M",
      "url": "<requirements[].url or null>",
      "blueprint": { "id": "...", "section": "...", "url": "..." },
      "threats": [ { "f_id": "F-014", "risk": "High", "title": "..." } ]
    }
  ]
}
```

- One `results[]` entry **per graded requirement** — every status, not only the open ones. `in_scope` is `true` except for `NOT_APPLICABLE` (then `false`).
- Leave `summary` as zeros; the script recomputes it. Pull `blueprint` from `blueprint_map[<id>]` and `threats` from `req_to_threats[<id>]` when present.

**Write** it to `$AUDIT_OUTPUT_DIR/.requirements-audit.json`, then validate +
recompute the summary deterministically:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/requirements_report.py" \
  --audit "$AUDIT_OUTPUT_DIR/.requirements-audit.json" --write
REPORT_EXIT=$?
```

- Exit `0`: the printed `total=… pass=… partial=… fail=… unverifiable=… not_applicable=…` line is **authoritative** — use exactly these numbers for the Result block in Step 3a (do not re-count).
- Exit `2`: the verdict is schema-invalid (a grading-output bug). Fix the offending `results[]` entry and re-write, then re-run — do not render counts you cannot validate.

---

## Step 3 — Render console output

Print a concise console summary plus only open requirements. "Open" means
`FAIL` or `PARTIAL`. Do not print `PASS` or `UNVERIFIABLE` items anywhere in
the console output. Keep `PASS` and `UNVERIFIABLE` in internal stats and JSON
output only.

**Colour primitive.** This report is shown in the conversation as rendered
Markdown, where raw ANSI escapes do **not** colourise. The reliable, real-colour
indicator is the **coloured-circle emoji**, so each stats row and each open
finding leads with a criticality circle:

| Status | Circle |
|--------|--------|
| FAIL | 🔴 |
| PARTIAL | 🟡 |
| PASS (stats only) | 🟢 |
| UNVERIFIABLE (stats only) | ⚪ |

This is the **same house palette as the Markdown report** (Step 4a), so console
and report read identically. Use exactly one circle per line — it carries the
colour; do not add box drawing or background fills. Render the finding **title
in `**bold**`** (Markdown bold renders in the conversation). Requirement and
blueprint references are real Markdown links (see Links rule in 3b).

The ANSI escape table below is a **fallback for genuine ANSI-terminal / CLI
embedding only** (where emoji may be undesirable); in the conversation the
coloured circles + Markdown bold/links carry the colour. When `NO_COLOR` is set
or colour is unavailable, the circles still render as distinct glyphs.

ANSI color rules:

| Field | Color |
|-------|-------|
| `●` dot / `[FAIL]` | bold red (`\033[1;31m`) |
| `●` dot / `[PARTIAL]` | bold yellow (`\033[1;33m`) |
| `●` dot / `PASS` (stats only) | green (`\033[32m`) |
| `○` dot / `UNVERIFIABLE` (stats only) | dim gray (`\033[2m`) |
| `MUST` | red (`\033[31m`) |
| `SHOULD` | yellow (`\033[33m`) |
| `MAY` | cyan (`\033[36m`) |
| Requirement ID | cyan (`\033[36m`) |
| Short title (first line) | bold (`\033[1m`) |
| Effort `S` | green (`\033[32m`) |
| Effort `M` | yellow (`\033[33m`) |
| Effort `L` | red (`\033[31m`) |
| Links (catalog URLs, `F-NNN` reference) | cyan (`\033[36m`) |
| Field labels (`Finding`, `Risk`, etc.) | dim gray (`\033[2m`) |
| Paths / line references | dim gray (`\033[2m`) |

Keep the colour budget restrained: the dot + status + priority + ID anchor the
line, the bold title carries the eye, and the Effort badge mirrors the
red/yellow/green risk scale. Do not add box drawing, accent stripes, or
background colours — the report must stay clean and copy-paste friendly. When
colour is unavailable (`NO_COLOR` or unknown terminal) render the identical
text and glyphs without escapes.

### 3a — Results header

The catalog source/provenance was already shown in the Step 1b banner, so the
results header does **not** repeat the title or the `Source` line — it opens the
verdict. **Counts:** if Step 2.5 ran (an artifact/gate was requested), use the
`requirements_report.py` stats line verbatim. Otherwise (plain run) tally them
directly from your grading. Print a compact header and stats block:

```
Results · <Project Name> · <total> requirements<, filter: <filter> if set>

  🔴 FAIL          <fail>
  🟡 PARTIAL       <partial>
  🟢 PASS          <pass>
  ⚪ UNVERIFIABLE  <unverifiable>
  ➖ NOT_APPLICABLE <not_applicable>   (omit this row when not_applicable is 0)
```

Color each leading circle per its status. Use the canonical status token `UNVERIFIABLE` here — the same label used in
the Step 2 status table and the JSON `unverifiable` stat. Do not invent
synonyms such as "ignored" or "untestable". Right-align the counts in a single
column as shown.

If the resolution banner reported `demo: true`, print a yellow line directly
under the results header: `⚠ DEMO catalog — results do not reflect your
organization's requirements.`

### 3b — Findings

Print all open requirements (`FAIL` and `PARTIAL`) sorted in this order:

1. `FAIL` before `PARTIAL`
2. within each status: `MUST`, then `SHOULD`, then `MAY`
3. within each priority: requirement ID ascending

If there are zero open requirements, print:

```
Open Requirements

  None. All verifiable requirements passed.
```

Otherwise print `Open Requirements`, a one-line legend, then one block per open
requirement:

```
Open Requirements
🔴 failed · 🟡 partial — worst-first (FAIL before PARTIAL, MUST before SHOULD)
```

Per-finding block:

```
🔴 MUST · `SEC-SQL` — **Parameterized SQL Queries**
> Use parameterized SQL/HQL queries or ORM methods for database queries to prevent SQL injection.
Finding : raw request input reaches sequelize.query() in routes/search.ts:23
Risk    : attacker-controlled search terms can alter the SQL predicate
Evidence: routes/search.ts:23
Fix     : replace string interpolation with bound parameters.
          Use `sequelize.query(sql, { replacements: { term } })` or the ORM query builder.
Effort  : M
Links   : https://reqs.example/sec-sql · [F-014](docs/security/threat-model.md#f-014)
```

Rules:

- **Requirement statement:** directly under the title, quote the requirement's
  **verbatim `text`** from the catalog (parsed in Step 1c) as a Markdown
  blockquote `> …`. This is the actual demand being graded — never the derived
  title and never a paraphrase. If the catalog text is very long (> ~240 chars),
  trim to its first sentence and append `…` for the console only; the Markdown
  and JSON outputs keep the full text. If a catalog entry has no `text`, omit the
  blockquote.
- **First line:** `<CIRCLE> <PRIORITY> · `<ID>` — **<Short Title>**`. The two
  axes are kept distinct and non-redundant: the **circle is the audit verdict**
  (status) and the **priority is the requirement's obligation** — an orthogonal
  pair, exactly like InSpec (result + impact) or Prowler (status + severity).
  - `<CIRCLE>` is the status: 🔴 for `FAIL`, 🟡 for `PARTIAL`. Do **not** also
    print the word `FAIL`/`PARTIAL` on the line — it would duplicate the circle
    (the list is already failures-only). The one-line legend above explains the
    circles, so colour is never the sole signal.
  - `<PRIORITY>` is `MUST` / `SHOULD` / `MAY`, followed by a middle dot ` · `.
  - Render `<ID>` as an inline `code` span, then an em dash ` — ` before the
    title.
  - Keep the title to 3-8 words in Title Case and render it in `**bold**` — it is
    the visual anchor of the block.
  - Do not use Markdown headings.
- **Finding:** one concrete sentence naming the file/function/config key and the failing mechanism.
- **Risk:** one concrete sentence fragment describing what the attacker or misuse path can do. No hype.
- **Evidence:** one line with up to three `path:line` entries. If there is no direct file evidence, use a concise process/config evidence phrase such as `no .github/workflows SAST job found`.
- **Fix:** one to three concise lines that make the **control prescribed by the requirement** concrete for this repository — it is anchored to the catalog, not free-form best practice the model prefers. Specifically:
  - The fix must satisfy the requirement's own `text` (the demand quoted above) and, when `blueprint_map[<id>]` matched (Step 1c-ii), follow that **blueprint section's prescribed approach** — name it and rely on the blueprint link for the "how". Do not substitute an unrelated or contradicting remedy.
  - The model's job is to map that prescribed control onto the actual file / API / config key in the repo (e.g. *which* call to change, *which* setting to set) — not to invent a requirement or a mechanism the catalog does not call for.
  - If the catalog/blueprint does not prescribe a specific mechanism, say what the requirement demands and the minimal concrete change here; do not pad with generic advice.
  - It may include 1-2 short code fragments inline. Do not render a full before/after code block in the console.
- **Effort:** `S`, `M`, or `L` (in an ANSI terminal, colour it green / yellow / red).
- **Links:** print the **bare URL(s) from the loaded catalog** — no `requirement` /
  `blueprint` label word in front (the URL is the link; a label plus URL just reads
  doubled in most renderers). Order and sources:
  - the requirement URL → `requirements[].url` (parsed in Step 1c). Omit the whole Links line when the catalog entry has no `url` and there is nothing else to link.
  - the blueprint URL → the `section_url` from `blueprint_map[<id>]` (Step 1c-ii), when one matched — appended as a second bare URL.
  - threat model → `[F-NNN](docs/security/threat-model.md#f-nnn)`, only when `req_to_threats[<id>]` is non-empty (Step 1.5). Keep the `F-NNN` label here — it is an identifier pointing at a local anchor, not a web URL.
  Separate the present links with ` · `.
- Separate finding blocks with one blank line. Do not use `---` separators, box drawing, or accent stripes — keep it copy-paste clean.

### 3c — Footer

Always print one footer block after open requirements:

```
Output
  Save Markdown: /appsec-advisor:audit-security-requirements --md
  Save PDF     : /appsec-advisor:audit-security-requirements --pdf
  Save JSON    : /appsec-advisor:audit-security-requirements --json
  Save all     : /appsec-advisor:audit-security-requirements --save
```

If one or more reports were saved in Step 4, print the written file paths
instead of the save-command reminder.

---

## Step 4 — Save output (conditional)

### 4a — If `save_md` is true

Write the full report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if needed).

The Markdown report is more detailed than the console, but still includes
only open requirements (`FAIL` and `PARTIAL`). Do not include `PASS` or
`UNVERIFIABLE` requirement entries. Prefix with a metadata table:

````markdown
# AppSec Requirements — <Project Name>

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Repository | <git remote URL or directory name> |
| Source | <remote \| cached> |
| Open Requirements | <n> |
| 🔴 Failed | <n> |
| 🟡 Partial | <n> |
| 🟢 Passed | <n> |
| ⚪ Unverifiable | <n> |

## Open Requirements

> 🔴 fail · 🟡 partial — open gaps detailed below. 🟢 passed and ⚪ unverifiable are counted in the summary only.

| Status | Priority | ID | Requirement | Effort |
|--------|----------|----|-------------|--------|
| 🔴 FAIL | MUST | SEC-SQL | Parameterized SQL Queries | M |
| 🟡 PARTIAL | SHOULD | SEC-CSP-1 | Content Security Policy | S |

### 🔴 FAIL · MUST · SEC-SQL — Parameterized SQL Queries

> **Requirement:** Use parameterized SQL/HQL queries or ORM methods for database queries to prevent SQL injection.

Raw request input reaches `sequelize.query()` at `routes/search.ts:23`, so the query predicate can be changed by user-controlled input.

**Evidence:** `routes/search.ts:23`

**Risk:** An attacker can submit a crafted search term that changes the SQL predicate.

**Fix:** Replace string interpolation with bound parameters in `routes/search.ts`.

```ts
// Before
sequelize.query(`select * from product where name like '%${term}%'`)

// After
sequelize.query("select * from product where name like :term", {
  replacements: { term: `%${term}%` },
})
```

**Effort:** M

**Links:**
- Requirement: <full requirement url>
- Blueprint: <full blueprint section url, if available>
- Threat model: [F-014](docs/security/threat-model.md#f-014)

---

*Effort: S = under 1 hour · M = about half a day · L = multi-day or architectural change.*

````

Markdown rules:

- If the resolution banner reported `demo: true`, insert a blockquote warning
  directly under the `#` title: `> ⚠ **DEMO catalog** — audited against the
  packaged example requirements, not your organization's. Configure a real
  source with --requirements / an org profile.` Also set the metadata
  `| Source |` cell to `packaged example (DEMO)`.
- Prefix every status — in the summary metadata table, the overview table, and
  each `###` heading — with its criticality circle, reusing the threat model's
  house palette: 🔴 FAIL · 🟡 PARTIAL · 🟢 PASS · ⚪ UNVERIFIABLE. Keep the
  one-line palette legend (the `>` blockquote) directly under the
  `## Open Requirements` heading.
- Lead the `## Open Requirements` section with an overview table
  (`Status | Priority | ID | Requirement | Effort`) listing every open
  requirement in the sort order below. The detailed `###` blocks follow
  beneath it, so a reviewer can scan the whole gap list before reading details.
- Directly under each `###` heading, quote the requirement's **verbatim `text`**
  from the catalog as `> **Requirement:** <text>` (full text, not the derived
  title, not a paraphrase) — this is the demand being audited. Omit only when
  the catalog entry has no `text`.
- Close the report with the one-line effort legend shown above
  (`*Effort: S = … · M = … · L = …*`), preceded by a `---` rule.
- Sort open requirements with the same order as console output.
- Use one `###` heading per open requirement: `### <STATUS> · <PRIORITY> · <ID> — <Title>`.
- Include full URLs for requirement and blueprint links.
- If `req_to_threats[req_id]` is non-empty (from Step 1.5), add one Threat model bullet per linked `F-NNN`, linking to `docs/security/threat-model.md#f-nnn`. Canonical link shape: `[F-NNN · Risk](docs/security/threat-model.md#f-nnn)`.
- Include a short before/after code block only when there is meaningful code evidence. Omit code blocks for missing process controls or absent configuration.
- Do not add a Passed section.
- Do not add an Unverifiable section.

Print: `✓ Markdown report written to docs/security/appsec-requirements-report.md`

### 4b — If `save_json` is true

The canonical structured verdict was **already written** in Step 2.5
(`.requirements-audit.json`, schema `requirements-audit.schema.json`, summary
recomputed). `--json` simply exposes it as a visible deliverable — do not author
a second, differently-shaped JSON:

```bash
cp "$AUDIT_OUTPUT_DIR/.requirements-audit.json" \
   "$AUDIT_OUTPUT_DIR/appsec-requirements-report.json"
```

Print: `✓ JSON report written to docs/security/appsec-requirements-report.json`

### 4c — If `save_pdf` is true

The PDF is converted from the Markdown report, so this runs **after** Step 4a
(which always runs when `save_pdf` is set, because `--pdf` implies `save_md`).
Convert it with the shared, deterministic exporter — the requirements report has
no Mermaid diagrams, so pass `--no-mermaid` (skips mmdc/Chrome; needs only
pandoc + weasyprint):

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" \
  --input "$AUDIT_OUTPUT_DIR/appsec-requirements-report.md" \
  --output "$AUDIT_OUTPUT_DIR/appsec-requirements-report.pdf" \
  --no-mermaid
PDF_EXIT=$?
```

Handle the result by exit code (the exporter is self-describing on stderr):
- `0` — print `✓ PDF report written to docs/security/appsec-requirements-report.pdf`.
- `1` — a hard dependency (pandoc or weasyprint) is missing. This is **non-fatal**: the Markdown report was still written. Print:
  `⚠ PDF skipped — install pandoc + weasyprint (the Markdown report was saved).`
- `2` / `3` — input/conversion error. Print `⚠ PDF conversion failed (see message above); the Markdown report was saved.`

Never abort the audit because the PDF step failed — the console findings and the
Markdown report are the primary deliverables.

### 4d — If no output flag is set

The save-command reminder is already covered by the Step 3 footer. Do not
print a second `Save:` line.

---

## Step 5 — Gate (deterministic; advisory by default)

**Only when the verdict was written in Step 2.5** (an artifact/gate was
requested). A plain console run has no verdict file — skip this step entirely.

The **script**, not the model, decides whether the audit blocks. Run it on the
verdict — advisory (prints the summary, exit 0) unless `--gate` enforces it:

```bash
GATE_ARGS=(--verdict "$AUDIT_OUTPUT_DIR/.requirements-audit.json"
           --priority-floor "$PRIORITY_FLOOR" --gate-on "$GATE_ON")
[ "$GATE_MODE" = "true" ] && GATE_ARGS+=(--gate)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/requirements_gate.py" "${GATE_ARGS[@]}"
GATE_EXIT=$?
```

- The script prints `requirements-gate: PASS` or `… BLOCK/WARN — <n> gating requirement(s)` with the offending IDs. Surface that line as-is.
- When `GATE_MODE` is true, **propagate the exit code**: `exit "$GATE_EXIT"` (1 ⇒ a MUST-or-above in-scope requirement failed at/above the floor). In advisory mode the script always returns 0.
- A gating requirement is recomputed authoritatively as `in_scope AND status==FAIL (or PARTIAL with --gate-on partial) AND priority >= floor` — the model's `results[]` feed it; it never trusts model-side verdict flags.

---

Note: the analyzed repository does **not** need to tag its code with requirement IDs. The `[<ID>]` bracket form (e.g. `[SEC-CSP-1]`) is just one optional convention; many teams use a different scheme or none, and finding zero inline references is fine — the loaded catalog is always graded in full from codebase evidence regardless of inline tags. The skill requires a requirements catalog to be available, resolved in this priority order: explicit `--requirements`, `--demo`, a local `docs/security/requirements.yaml`, the active org-profile source, the legacy configured source, or the remembered source served from the plugin cache. On a fresh machine with none of these, the skill prints first-run guidance and offers `--demo` instead of failing cryptically (Step 1b). A successful fetch from a configured/remembered source remembers the URL (`.cache/requirements.source.json`) and refreshes the cache; a fresh cache (< 30 days) is reused without a network round-trip, while a stale cache triggers a refresh attempt that falls back to the cache when the source is unreachable.
