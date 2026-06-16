# Coverage Agent Guide (temporary — will be deleted after campaign)

Goal: raise **line coverage to ≥90% for each assigned script**.

## Hard rules
1. **Test files ONLY.** Never edit any file under `scripts/`, `hooks/`, `agents/`,
   `data/`, skills, or producers. Footprint = `tests/` only (new or extended files).
2. **Pin current behavior.** If a script has a bug, write a test that asserts the
   *current* (possibly wrong) output. Do NOT fix producers. Several assigned
   scripts contain known dead-code/bugs — that is expected; cover the real path.
3. **Real tests, no cheating.** No `# pragma: no cover`, no importing just to bump
   counters without assertions, no monkeypatching the function under test away.
   Drive real inputs through real functions and assert real outputs.
4. **No suite regressions.** All tests you add must pass. Do not break existing tests.

## Workflow per script
1. Read the script. Find a `tests/test_<name>.py` if it exists; extend it,
   else create one matching the repo's existing test style.
2. Run focused coverage to see missing lines:
   ```
   python3 -m pytest tests/test_<name>.py -q -o addopts="" \
     --cov=scripts.<name> --cov-report=term-missing
   ```
   (module path uses the script filename without `.py`.)
3. Write tests targeting the missing lines: error branches, `argparse`/`main()`
   CLI paths (use `monkeypatch.setattr("sys.argv", [...])` + capture
   `SystemExit`), file-not-found, malformed YAML/JSON, empty inputs, the
   absent-PyYAML fallback paths, etc.
4. Iterate until `scripts.<name>` shows **≥90%**. Verify no failures.

## Conventions in this repo
- Tests use pytest, `tmp_path`, `monkeypatch`, `capsys`. Many scripts read env
  vars (`CLAUDE_PLUGIN_ROOT`, `APPSEC_*`) and files in a run dir.
- `main()` typically parses argv and returns/exits an int code.
- Use `importlib`/direct `from scripts.<name> import ...` like existing tests.
- Run the full assigned-file test at the end to confirm green + ≥90%.

## Report back (your final message = data, not prose)
For each assigned script return: `name: before% -> after% (PASS/FAIL, N tests added)`
and note any script you could NOT push to 90% with the reason.
