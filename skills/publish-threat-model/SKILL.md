---
name: publish-threat-model
description: Publish a completed threat model to version control. Runs pre-flight security checks (repo visibility, secret scan), patches .gitignore with negation exceptions for the publishable files, and creates a signed git commit with threat-count metadata. Keeps pentest-tasks.yaml and all intermediate files permanently ignored.
---

Publish a completed threat model from `docs/security/` into git version control.
This skill is the deliberate counterpart to the secure-by-default `.gitignore` that
`/appsec-advisor:create-threat-model` sets up. Nothing is committed until this skill runs.

## What gets published

| File | When |
|------|------|
| `threat-model.md` | Always (required) |
| `threat-model.yaml` | Always (required — enables cross-repo STRIDE analysis via `docs/related-repos.yaml`) |
| `threat-model.sarif.json` | Auto, if present |
| `.architect-review.md` | Auto, if present |
| `pentest-tasks.yaml` | **Never** — contains concrete probe targets |
| `.dep-scan.json`, `.threat-modeling-context.md`, `.recon-summary.md` | **Never** |

## Step 1 — Parse arguments

Parse from the user's invocation:

| Arg | Env var | Default |
|-----|---------|---------|
| `--repo <path>` | `REPO_ROOT` | git repo root of cwd |
| `--output <path>` | `OUTPUT_DIR` | `$REPO_ROOT/docs/security` |
| `--check-only` | — | false — run checks without writing anything |
| `--no-commit` | — | false — patch .gitignore but skip the git commit |

```bash
if [ -z "$REPO_ROOT" ]; then
  REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
fi
if [ -z "$OUTPUT_DIR" ]; then
  OUTPUT_DIR="$REPO_ROOT/docs/security"
fi
```

## Step 2 — Run pre-flight checks

Delegate to the Python helper with `--check-only` first. The helper:

1. Verifies `threat-model.md` and `threat-model.yaml` exist in `$OUTPUT_DIR`
2. Calls `gh repo view --json isPrivate` — warns (non-blocking) if the repo is public
3. Scans `threat-model.md` for secret-like patterns — blocks if found

```bash
PREFLIGHT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/publish_threat_model.py" \
    --output-dir "$OUTPUT_DIR" \
    --repo-root  "$REPO_ROOT" \
    --check-only \
    --json)
```

Parse the JSON result. If `blockers` is non-empty, print each blocker and **stop**:

```
✗ Publish blocked:

  <blocker message>
```

If `warnings` is non-empty, print each warning and ask the user to confirm before proceeding:

```
⚠  <warning>

Proceed with publishing? [y/N]
```

If the user answers anything other than `y` or `yes` (case-insensitive), stop.

## Step 3 — Patch .gitignore and commit

Run the helper in commit mode:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/publish_threat_model.py" \
    --output-dir "$OUTPUT_DIR" \
    --repo-root  "$REPO_ROOT" \
    $( [ "$NO_COMMIT" = "true" ] && echo "" || echo "--commit" )
```

Print the helper's stdout verbatim.

## Step 4 — Completion message

After the helper returns successfully, print:

```
✓ Threat model published.

  threat-model.yaml is now trackable by other repos via docs/related-repos.yaml
  for cross-repo STRIDE analysis. Share the path or URL with dependent teams.

  To unpublish: remove the negation lines added to .gitignore and run:
    git rm --cached docs/security/threat-model.{md,yaml}
    git rm --cached docs/security/threat-model.sarif.json  # if present
    git rm --cached docs/security/.architect-review.md     # if present
    git commit -m "security: remove published threat model"
```

## Error Handling

- `threat-model.yaml` missing → block with message to run `--yaml` flag on `create-threat-model`
- `git commit` fails → print stderr from git and suggest `git status` investigation
- `gh` not installed → skip visibility check silently (non-blocking)
