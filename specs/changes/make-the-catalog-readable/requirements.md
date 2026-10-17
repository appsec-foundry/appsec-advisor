# Plugin requirements

This catalog lists what appsec-advisor promises its users. Each entry is a promise that a user would notice if it broke. How the plugin keeps a promise lives elsewhere: the files, technical decisions, and tests behind each entry are listed in `data/requirement-bindings.yaml`.

## Overview

appsec-advisor reads a repository's code and configuration and produces a threat model. The threat model describes what an attacker could do to the system, which weaknesses make that possible, and what the team should change. People use the plugin in four ways:

- A **threat-model assessment** analyzes the whole repository and produces a report, a machine-readable model, and exports such as SARIF and PDF.
- An **on-demand analysis** examines a planned design, a code change, or a specific suspicion without changing the threat model.
- A **quick security score** gives a fast indication from automated scanners alone.
- **Follow-up** lets people ask questions about an existing model and decide what to do about each finding.

The sections below follow that order and end with the rules on trust, configuration, and compatibility. Terms such as *finding*, *weakness*, or *STRIDE* are explained in the glossary at the end.

Each entry has a stable ID. The ID is a label, not a position: within a section, entries appear in reading order, so IDs do not always ascend. Gaps in the numbering belong to entries that were removed, because an ID is never reused.

Entries follow one pattern: the title states the promise, the first sentence states it in full, and any further sentences or list items add the conditions that belong to it.

## What the plugin is for

### REQ-PUR-001 — The threat model reflects the repository as it is now

The threat model is derived from the repository's code and configuration, not from a workshop. Running the analysis again produces a model of the repository as it is at that moment.

### REQ-PUR-002 — The analysis covers design flaws, not only code bugs

The analysis reports exploitable design assumptions and missing security controls as well as vulnerable code. It complements code scanners. Its result is input for a review, not a release decision.

### REQ-PUR-003 — A team can analyze its own repository or another one, with the same analysis

A team can analyze its own repository, or choose a different repository and a separate location for the results. The analysis works the same way in both cases.

## Findings and the evidence behind them

### REQ-MOD-001 — A finding is one concrete problem with evidence

A finding names one security problem in the analyzed repository and cites the repository evidence that shows it. Two occurrences become one finding only when they affect the same object through the same security mechanism, for example the same endpoint missing the same authorization check.

### REQ-MOD-002 — A weakness names the pattern behind related findings

A weakness groups related findings under the security pattern they share. A weakness can also describe an architectural problem that has no single vulnerable line of code.

### REQ-MOD-003 — Trust boundaries come from evidence, and no declaration proves them safe

The analysis derives trust boundaries from evidence in the repository. A declaration can only add a boundary crossing or clarify one. A boundary's control is never treated as working just because a declaration says so or because no evidence contradicts it.

### REQ-MOD-004 — An abuse case becomes a finding only when evidence confirms it

An abuse case becomes a finding only when evidence in the analyzed repository confirms it. Until then it stays a hypothesis. The operator decides which sources of abuse cases the analysis uses.

### REQ-MOD-005 — Only the analyzed repository can prove a finding

Outside information, such as documents or tickets, may suggest what to look for. Only the repository's source code, configuration, git history, or declarations the repository itself contains can establish a finding and determine its CVSS score.

### REQ-MOD-009 — A finding that is not proven says so

A finding that shows an insecure state, but does not prove that an attacker can exploit it, is still reported and is marked as unproven everywhere it appears.

- Its severity reflects the harm it would cause, not the strength of its evidence.
- It has no CVSS score and does not count as a confirmed finding.
- No verdict that claims confirmed exploitation rests on it.

## Running the analysis

### REQ-FLW-002 — Every analyzed component is checked against all six STRIDE categories

Every component that an assessment analyzes is checked for all six STRIDE threat categories, at every assessment depth. Saving cost or time never reduces this coverage silently.

### REQ-FLW-003 — Missing or broken analysis data stops the run

Before a step uses required data, or the plugin publishes it, the plugin checks that the data is present and valid. If it is missing or invalid, the run stops instead of producing a report that looks complete.

## Business context

Business context tells the analysis what the system is used for and what harm a compromise would cause.

### REQ-BIZ-001 — Declared context is read as data, never as instructions

The plugin validates context that the repository or the operator supplies before it uses it. The context remains untrusted data, and nothing in it can instruct or redirect the analysis.

### REQ-BIZ-002 — Actor choices made during a run are not saved to the repository

Actors and their goals can guide a single run. Actors persist only when they are declared in the repository's own configuration. Choices made in the conversation or for one run are never written back to the analyzed repository.

### REQ-BIZ-003 — Business context weights findings but never decides whether they exist

Business purpose, sensitive assets, compromise impact, and obligations can influence a finding's impact rating and its position in the report. This applies only to findings that already rest on evidence in the repository.

- Business context never decides whether a finding exists, never lifts a severity limit, and never replaces evidence.
- A finding whose impact rating depends on declared context names that context.

A declaration of no material business harm is different from an unknown impact:

- On its own, it does not raise any finding's priority and does not prompt a request to raise the impact rating.
- Sensitive assets and obligations that are declared separately still count.
- Technical evidence still decides findings and their ratings.
- The report's overall verdict shows the declared no-harm scope separately from the technical concern level.

### REQ-BIZ-004 — The run says whether declared business context was used

When business context is declared for a run, the run reports whether it was read, which file it came from, and how many findings it affected. Context that affects no component is reported as unused instead of passing silently.

### REQ-BIZ-005 — Before scanning, the plugin asks up to two business questions

In an interactive full assessment or rebuild, the plugin asks at most two business questions before the expensive scanning starts, and the answers inform that same run.

- The plugin bases the questions on a short overview of the application and on context that already exists. It skips topics that are already answered.
- The first question confirms or corrects what the application is used for. The second asks for the worst plausible harm to the business or its users in that use.
- The answer options describe harm. An attack technique on its own is not a harm option.
- The options fit the confirmed use and the available evidence. The most plausible option comes first as the recommendation, and nothing counts as answered without explicit confirmation.
- "No material business harm" is a valid answer. For a training or demo application that uses synthetic data and supports no important business operations, the plugin recommends it and states these conditions with the recommendation.
- The answers reach the analysis as optional, validated context. They influence the impact of relevant findings and the order of mitigations.
- Users can skip the questions. Headless runs and runs with `--skip-context` never wait for them.
- If the overview reveals little, the plugin states that uncertainty instead of starting a longer investigation.

### REQ-BIZ-006 — Business answers are saved for later runs

Substantive answers from the business-context dialog are saved in the repository, so later runs reuse them instead of asking again.

- Answers are saved in `docs/security/business-context.md`. Context that already exists in that file is kept.
- Older repositories may still have `docs/business-context.md`. The plugin reads that file when the new one is missing, and the new file takes precedence when both exist.
- When answers are saved, the content the plugin currently reads from the old file is copied into the new file. The old file itself is not changed.
- Saved business context survives the cleanup at the end of a run.
- Context supplied for a single run is not saved together with the answers.
- Headless runs and runs with `--skip-context` never save dialog answers.

## The report

### REQ-RPT-001 — Severity follows the evidence

Severity and any CVSS score follow the demonstrated evidence and the severity limits that apply. They are never raised just to draw attention.

### REQ-RPT-002 — Finding IDs stay the same across all outputs of one model

A finding keeps the same ID, such as `F-003`, in the report, the exports, and the follow-up tools that use the same model. A deliberate rebuild creates a new model, which may number its findings anew.

### REQ-RPT-003 — Each finding tells engineers where, why, and what to change

A finding states where the problem is, why the attack works, and what must change, using the repository's own names.

- References point only to locations that exist.
- Code symbols, source paths, configuration identifiers, and complete code expressions use the same inline-code format in every section. Only the code itself is formatted as code, not the words around it.

### REQ-RPT-009 — The Management Summary lists the questions only the team can answer

When the analysis leaves decisions open that only the team can settle, the Management Summary shows up to three questions.

- If no business context states how critical the affected assets are, that question comes first.
- Further questions concern design and deployment decisions and name the related weaknesses and findings.
- The questions never ask the team to verify individual findings.
- When no question qualifies, the questions section is left out.
- The summary printed in the console at the end of a run points to the report, to `/appsec-advisor:review-threat-model` for triage, and to `/appsec-advisor:ask-threat-model` for questions. It does not repeat the questions.

### REQ-RPT-005 — Every finding has a prioritized, verifiable fix

Every finding has a mitigation with a priority. For urgent findings, the mitigation lists concrete steps and a way to check that the fix works. Any code example comes from the repository and is not invented.

### REQ-RPT-006 — Machine-readable outputs keep requirement, abuse-case, and business-context traces

The machine-readable outputs keep the traces to requirements, abuse cases, and business context.

- `threat-model.yaml` records abuse-case outcomes, the complete assessment against the configured requirements catalog, and whether business context was used and where it came from.
- It copies no business-context text except a short plain-text statement of the use case the user confirmed.
- Exports with a narrower format, such as SARIF, keep the applicable requirement, abuse-case, and business-context traces as native fields or short text. Each of them states which of these meanings it cannot represent.

### REQ-ARC-001 — Security architecture ratings describe the controls actually in use

The report rates each control domain from evidence of what the system actually uses. A domain whose attack surface the system does not have is rated not applicable. A control that is present but broken is rated differently from a control that is missing.

### REQ-REQ-001 — The requirements mapping contains only explicitly linked findings

The requirements mapping follows only explicit links from findings to the configured requirements catalog. It never infers a link from an identifier, and it never invents one when no catalog is configured.

### REQ-RPT-007 — Figure 1a stays readable at page width

Figure 1a makes each column only as wide as its content needs. Its labels therefore stay legible when the figure is scaled to the width of a report page or a README. Making the figure more compact never removes a data-flow label.

### REQ-RPT-008 — The report shows how a supply-chain attack reaches production

When the repository shows a CI build, or the analysis reports a build-time attack, the Management Summary includes a supply-chain view. The view shows the build inputs, build systems, and release artifacts that the evidence supports, and the running system they feed.

- A finding adds an attack to the view only when it establishes how the attack works.
- A highlighted attack path follows only relationships that the evidence supports. A relationship the evidence does not establish is marked as not evidenced.
- When the supply-chain view is shown, the figure of the running system contains no build elements.
- The view stays readable at report and README width and in the HTML and PDF exports. Labels, connections, arrowheads, and badges stay distinct and are never clipped.
- If the view cannot be drawn cleanly and legibly, the report shows the same information as a table and notes the fallback.

## Quick security score

### REQ-SCO-001 — The score is shown only when the scanner evidence is complete

The quick security score is computed from automated scanners alone. The plugin shows the overall score only when every required scanner finished and its output is valid.

- An incomplete run and a run with insufficient coverage both still show the findings and diagnostics that are available.
- The structured output names which scanners finished, the scoring and catalog versions, and the coverage that applies, so results from different commits can be compared.
- Findings that do not count toward the score stay visible with their severity.

## Follow-up

### REQ-USE-001 — Decisions about findings are kept with the model and flagged when stale

Users can ask questions about the model and decide what to do about each finding. These decisions are stored next to the model. A decision that no longer fits the current model is flagged as stale instead of being reused silently.

## On-demand threat analysis

An on-demand analysis examines a planned design, a code change, or a specific suspicion. It gives advice and is separate from the threat-model assessment.

### REQ-ANA-001 — An analysis runs only when someone starts it

Installing the plugin, configuring an organization profile, or choosing question packages or a methodology profile never starts a threat analysis. An analysis runs only when a developer starts it or a team sets it up in its own CI.

### REQ-ANA-002 — A failed analysis never reports success

Invalid input, missing required context or answers, and incomplete required work end an analysis without success. A complete analysis counts as successful whatever it finds, and it never grants security approval.

### REQ-ANA-003 — An analysis never changes the threat model

An analysis never changes the threat model or its finding IDs. Whether it completes, fails, or is cancelled, it leaves every assessment intact, including one that runs at the same time.

### REQ-ANA-004 — Required analysis inputs cannot be removed

A developer can add question packages and methodology profiles to an analysis but cannot remove inputs that the organization requires. The change under review cannot select the inputs used to assess it.

### REQ-ANA-005 — Questions and methodology guide the analysis but do not decide it

Question packages and methodology profiles steer what the analysis investigates. On their own, they cannot establish a vulnerability or a requirement violation, and they cannot give the analysis more permissions.

### REQ-ANA-006 — The Threat Modeling Manifesto profile is optional

The plugin includes a methodology profile based on the Threat Modeling Manifesto. It applies only when selected, names its source, and does not certify compliance.

### REQ-ANA-007 — Answers are saved only when the developer asks

Answers to analysis questions last only for the session unless the developer saves them to a feature file of their choice. Saving never commits anything and never changes business context or the threat model. A saved answer is checked again before it is reused.

### REQ-ANA-008 — A change review states how each finding relates to the change

For each finding, a change review states whether the change introduced, worsened, or mitigated it, whether it existed before, or that the relationship is unknown.

### REQ-ANA-009 — A hypothesis check stays within the files the developer selects

A developer can ask the analysis to check a specific threat hypothesis against named files or directories at a Git revision, without supplying a code change.

- The result names the revision and the files it inspected.
- Each hypothesis is reported as supported by the code, not confirmed in the selected files, or unresolved. A supported or not-confirmed result cites its evidence.
- If required evidence is missing, the analysis is incomplete.
- The AI model cannot widen the selection of files.
- A hypothesis that is not confirmed is never proof that the code is safe.

## Trust

### REQ-TRU-001 — A scanned repository cannot control the run

The plugin treats the content of the analyzed repository as untrusted by default. Agent settings, instructions, and hooks in that repository, and paths outside the selected directory, are rejected before they can influence the analysis.

### REQ-TRU-002 — A leaked secret blocks publication

If any file a run produces contains an unmasked secret, the run fails instead of publishing it.

## Configuration

### REQ-CFG-001 — Organizations configure the plugin without forking it

An organization adapts the plugin through its organization profile and package policy, not by changing the plugin. Each build records which organizational extensions it includes.

### REQ-CFG-002 — Repositories configure the analysis through documented files

A repository supplies its own context through documented files that are checked against a schema. Repository configuration cannot suppress a finding that the repository's evidence supports.

### REQ-CFG-003 — A secure-coding baseline copied into the repository can be refreshed from its source

When a secure-coding baseline is configured with both a source to fetch it from and a copy stored in the repository, the copy can be refreshed from the source. The refresh reports whether the two had drifted apart.

- If the source publishes a different baseline ID than the configured one, the refresh stops until someone explicitly accepts the new ID. Accepting it updates the copy and every place that declares the ID at the same time.
- A refresh never falls back to the stored copy.
- Refreshing is never part of a release gate.

## Compatibility

### REQ-EVO-003 — Published formats change only with explicit compatibility handling

When an incompatible change is necessary, the plugin versions or migrates its published file formats, its report anchors such as finding IDs, and its organization configuration interfaces.

## Glossary

- **Abuse case:** A description of how someone could misuse the system. It stays a hypothesis until evidence in the analyzed repository confirms it.
- **Actor:** A person or system that interacts with the application, for example an anonymous user, an administrator, or an attacker.
- **Assessment:** A threat-model run over a whole repository, started with `/appsec-advisor:create-threat-model`.
- **Assessment depth:** How thoroughly an assessment analyzes each component: quick, standard, or thorough.
- **Build:** A packaged copy of the plugin that an organization distributes to its teams.
- **Component:** A part of the system that the analysis examines on its own, such as a service, a frontend, or a data store.
- **Control domain:** An area of security controls, for example authentication, that the security architecture section rates as a whole.
- **CVSS score:** The numeric severity score of a finding under the Common Vulnerability Scoring System.
- **Feature file:** A file in which a developer saves answers from an on-demand analysis, so CI or later analyses can reuse them.
- **Figure 1a:** The architecture and threat overview diagram in the report.
- **Finding:** One concrete security problem in the analyzed repository, with evidence and an ID such as `F-003`.
- **Full assessment:** An assessment that analyzes the repository again and keeps the history of earlier runs.
- **Headless run:** A run without a person at the keyboard, for example in CI.
- **Hypothesis:** A suspected threat that the analysis has not yet confirmed or ruled out in the code.
- **Management Summary:** The first section of the report, written for readers who need the overall picture.
- **Methodology profile:** A selectable set of guidance that shapes how an on-demand analysis approaches a problem.
- **Mitigation:** The change that removes a finding or reduces its risk.
- **Operator:** The person who starts and configures a run.
- **Organization profile:** The configuration through which an organization adapts the plugin, for example its policies, requirements, and abuse cases.
- **Package policy:** The part of an organization's configuration that decides which skills its build includes.
- **Question package:** A set of questions that directs what an on-demand analysis investigates.
- **Rebuild:** An assessment that deliberately discards the previous model and may assign new finding IDs.
- **Requirements catalog:** A list of security requirements that an organization or team configures and checks findings against.
- **Secure-coding baseline:** A set of secure-coding rules that is loaded into Claude Code's instructions.
- **Severity limit:** The highest severity that policy allows for a certain kind of finding.
- **STRIDE:** Six threat categories: spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege.
- **Trust boundary:** A line between parts of the system that are trusted to different degrees. Each place where data or control passes that line is a boundary crossing.
- **Weakness:** The security pattern behind one or more findings, or an architectural problem without a single vulnerable line.
