# Threat Analyst

The Threat Analyst analyzes a planned feature, a selected code change, or a concrete threat hypothesis in existing code when you ask for it. It checks the applicable security requirements and possible attack paths, and it asks the team only for facts that the code and context do not answer. The Threat Analyst is experimental.

```text
/appsec-advisor:analyze-threats Let support staff export customer data as CSV.
/appsec-advisor:analyze-threats --worktree
```

Results are advisory. They separate evidence-backed findings from threat scenarios, protection assumptions, requirement observations, and open questions, and they state what the analysis covered. A result is never a security approval and never changes `threat-model.yaml`. For a full assessment use `/appsec-advisor:create-threat-model`; for requirement grading use `/appsec-advisor:verify-requirements`.

The analysis runs only when you invoke `/appsec-advisor:analyze-threats` or when your team configures it in its own CI. Installing the plugin, configuring an organization profile, or selecting a question package never starts an analysis.

> [!IMPORTANT]
> The model session runs `claude -p` without tools, project configuration, or session persistence. In a test on Claude Code 2.1.289, the model did not follow instructions planted in a hostile repository. Whether Claude Code retains host-side session data for these calls is not yet verified. See the [test results](proposals/security-advisor-threat-analyst-wp1-results.md).

## Analyze a design or a change

Ask a design question without any code, or pass a longer description with `--design-file <path>`:

```text
/appsec-advisor:analyze-threats Let support staff export customer data as CSV.
```

Review a change by naming exactly one scope: `--worktree` (including untracked, not ignored files), `--staged`, or `--base <commit> --head <commit>`. For a feature branch, use its fetched target branch as `--base` and the feature tip as `--head`. A commit range compares the merge base of both commits with the head; `--exact-base` compares the two commits directly. An empty change completes without a model call.

The analysis reads your requirements catalog, `docs/security/business-context.md`, and, when `scripts/appsec-analyst-cli` receives `--threat-model`, a structured `threat-model.yaml`. A missing optional source is reported and the analysis continues. A source marked as required that is missing or invalid ends the analysis as incomplete; a required catalog is never replaced by the packaged fallback. When your organization profile names a requirements catalog, the analysis needs a trusted local copy passed with `--requirements`; it does not download catalogs.

## Check a concrete threat in existing code

Supply one hypothesis, a Git revision, and the files or directories to inspect:

```text
/appsec-advisor:analyze-threats --hypothesis "Can a user export another tenant's records?" --revision HEAD --path src/export --path src/auth
```

The CLI equivalent is `scripts/appsec-analyst-cli hypothesis --repo <repo> --hypothesis <text> --revision <commit> --path <path>`. Repeat `--path` for additional areas. Paths are literal repository-relative file or directory names, without wildcards. The analysis reads committed source at the selected revision; it excludes uncommitted edits. Include the relevant middleware, callers, and configuration in the selected paths. The model cannot expand those paths. A missing path or excluded source leaves the check incomplete; narrow or correct the scope and start a new check.

The report records the resolved commit, selected paths, and hypothesis. Its conclusion is `supported` (source evidence supports the threat), `not_confirmed` (not established in the inspected scope), or `unresolved` (required evidence or facts are missing). Supported and not-confirmed conclusions cite inspected code. A not-confirmed result never means disproved or safe. Findings describe the selected revision and make no claim about which change introduced them. The analyst does not execute exploits or application code.

Required evidence requests that cannot be fulfilled, including when a limit is exhausted, leave any analysis incomplete. The report lists the requested paths and their disposition. A question marked as needing an answer must appear among the actual questions.

## Questions and feature files

The analysis asks only when a missing fact changes the assessment, and only when the code and context do not already answer it. All open questions are shown together. Required questions keep the result incomplete until you answer them; optional ones appear next to a complete result. Answers are declarations of intended behavior. They are not proof that code implements them, they cannot waive a requirement, and they are not risk acceptance.

Answers stay in the session unless you ask to save them. Saving writes a feature file of your choice, for example `docs/security/features/customer-export.yaml`, and never commits it. A save refuses to overwrite a file that changed since it was read. CI can use a reviewed and committed feature file with `--feature`. A saved answer is reused only while its question and the selected packages are unchanged and its text matches its stored fingerprint; see the [example feature file](../examples/analyst/customer-export-feature.yaml). The fingerprint detects accidental edits, not deliberate ones: anyone who can edit the file can recompute it. Review feature files like code, because their content is a declaration and never gains authority. Remove a saved answer with `scripts/appsec-analyst-cli forget --repo <repo> --feature <file> --feature-sha <sha256> --question-fingerprint <fingerprint>`.

## Question packages and the Threat Modeling Manifesto profile

The analysis always loads the core question package, adapted from the pinned aiscb release. Packages guide what the analysis investigates. They cannot establish a vulnerability or a requirement violation on their own, and they cannot carry commands, tools, write targets, or permissions.

Add a package for one analysis with `--package`, either a packaged reference such as `tmm/threat-modeling-manifesto@1.0.0` or the absolute path of your own package file. The [example package](../examples/analyst/payments-package.yaml) shows the format. Packages your organization requires always apply; you can add packages but not remove required ones.

The Threat Modeling Manifesto profile (`tmm/threat-modeling-manifesto@1.0.0`) is an attributed adaptation of the [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) under CC BY 4.0. When selected, the analysis reports methodology observations about scope, plausible failures, practical responses, adequacy of the investigation, missing perspectives, and what to revisit. The profile certifies no compliance and does not replace collaboration with the people who own the system. It applies only when you select it or your organization sets it as a default or requirement.

Organizations set defaults and requirements in the `analyst` block of the [organization profile](org-profiles.md#on-demand-threat-analysis).

## Advisory CI

Your team can run the same analysis on merge requests with `scripts/appsec-analyst-cli review --ci --repo <repo> --base <target-branch-sha> --head <feature-branch-sha>`. The plugin never installs this job. Start from the [GitHub Actions](../examples/analyst/github-actions.yml) or [GitLab CI](../examples/analyst/gitlab-ci.yml) example and pin every version they name.

In CI, packages come only from trusted pipeline configuration through `--trusted-package`, and a package file must be pinned with `#sha256=` and live outside the checkout under review. A merge request therefore cannot choose the packages that assess it. The CLI never fetches history; fetch enough history for the merge base before you call it.

| Exit code | Meaning |
|---|---|
| `0` | The analysis is complete, whatever it found. |
| `2` | Rejected input, missing required context or answers, invalid model output, a transport failure, or an exhausted limit. The report names the reason. |
| `130` | Cancelled. |

Exit code `1` is reserved for a future blocking gate. Upload the report on every outcome, and do not hide a non-zero exit code with a blanket success override.

## Limits, state, and retention

The plugin enforces the limits in [`data/analyst-limits.yaml`](../data/analyst-limits.yaml) in code, outside the model: wall-clock time, model calls, evidence rounds, question rounds, retries, files and bytes read, response size, packages, and questions. The values are provisional until measured. An exhausted limit ends the analysis as incomplete.

Each analysis gets a private job directory under `$XDG_STATE_HOME/appsec-advisor/analyst/` (default `~/.local/state/appsec-advisor/analyst/`), outside the repository and outside any assessment output. Captured source is deleted when the analysis ends; a job waiting for answers keeps it for `answer_hours` and is then closed as incomplete. Results are deleted after `result_days`. Each invocation closes abandoned jobs of the same repository. Stop a running job or close a waiting one with `scripts/appsec-analyst-cli cancel --repo <repo> --job <id>`; SIGTERM and Ctrl-C also stop the model session and record the cancellation. Assessment cleanup never touches these directories, and the analysis never touches assessment state, locks, or outputs.

Your parent Claude Code conversation and the model provider keep their own records under their own retention rules. Deleting an analysis job does not erase them.

## What the analysis cannot see

The analysis reads only the files of the selected scope and surrounding files it requests from the same snapshot of the repository. Ignored files, symlinks, submodules, nested repositories, binaries, oversized files, and files with detected secrets are excluded and listed in the coverage section. Related repositories are not read. A narrow scope is not complete feature coverage; recommend a full assessment when the result says the context is insufficient.
