---
name: Bug report
about: Something isn't working correctly
labels: bug
---

**What happened?**

<!-- Describe the problem. Include the exact error message if there is one. -->

**Steps to reproduce**

1. 
2. 
3. 

**Expected behavior**

<!-- What should have happened? -->

**Plugin version / Claude Code version**

- Plugin version (from `.claude-plugin/plugin.json`): 
- Claude Code version (`claude --version`): 

**Which agent or skill was running?**

<!-- e.g. appsec-threat-analyst, create-threat-model skill, appsec-qa-reviewer, etc. -->

**Diagnostic bundle (recommended — anonymised)**

Instead of pasting raw output, attach an **anonymised** diagnostic bundle. In the
Claude Code session where the error happened, run:

```
/appsec-advisor:report-error
```

This writes an `appsec-diag-<id>.tgz` containing only tool/plugin versions, the
run shape (phases reached, timings, aggregate counts), and scrubbed logs —
**no threat-model results, findings, source, or repo paths**. The tool makes no
network calls; you choose whether to attach it. It prints a summary so you can
review it first, then drag the `.tgz` onto this issue.

If you cannot produce a bundle, paste only a **non-sensitive** error message:

```
```

**Additional context**

<!-- Any other non-sensitive details (OS, repo type, etc.) -->
