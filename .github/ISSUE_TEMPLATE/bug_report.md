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

<!-- e.g. create-threat-model runtime, appsec-stride-analyzer-v2, appsec-qa-reviewer, etc. -->

**Optional diagnostic bundle**

To investigate the error and prepare a separate issue draft with explicit publication approval, use `/appsec-advisor:report-error`. To create only a local support archive for this issue, run:

```text
/appsec-advisor:report-error --bundle-only
```

The bundle helper makes no network calls. Its log scrubbing is best effort; inspect the entire archive for confidential or identifying data before attaching it manually. Never paste raw logs or source from the scanned repository.

If you cannot produce a bundle, paste only a **non-sensitive** error message:

```
```

**Additional context**

<!-- Any other non-sensitive details (OS, repo type, etc.) -->
