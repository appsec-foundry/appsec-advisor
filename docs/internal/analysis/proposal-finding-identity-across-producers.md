# Proposal: one finding identity across producers

Status: proposal, not implemented. Decision **D1** needs operator confirmation before any change to WK-7 or the `_dedupe_evidence` contract. Severity: not critical. Reports overcount by one or two findings per affected run; no finding is lost and no severity is lowered.

## Problem

The plugin has three definitions of "the same finding":

| Surface | Key |
|---|---|
| `promote_verified_abuse_cases._same_object_finding` | `_evidence_identity_key`: file, line > 0, CWE family |
| `merge_threats._dedupe_evidence` (key at ~1646) | the same key plus the primary `threat_category_id`; uncategorized records are skipped |
| `run_invariants.unique_identity` | its own key: file, line > 1, CWE family, every evidence entry |

The category guard dates from c2317491 (2026-07-20). It contradicts the docstring of `_evidence_identity_key` (889a991b, 2026-06-26), which names a hardcoded RSA key reported as CWE-321 and as CWE-798 as one finding. It also contradicts REQ-MOD-001: one object and one mechanism make one finding. WK-7 already joins categories when the titles are identical. A single defect therefore ships as two findings whenever two analyzers label its consequence differently, for example a NoSQL `$where` injection reported as Tampering and as DoS, or Redis without AUTH reported as Spoofing and as DoS. `tests/test_run_invariants.py` pins this as a strict xfail ("pending core refactor: finding identity across producers").

Evidence: the current collect pipeline was replayed on seven witness runs (juice-shop2, juice-shop3, insecure-large-spring-app, VulnerableApp, DVWA, insecure-spring-app, insecure-ai-app).

| | Today | Shared key without category |
|---|---|---|
| Identity collisions after collect | 5 | 0 |
| Newly enabled merges | n/a | 8, all true duplicates |
| Uncategorized findings | 0 | 0 |
| Merges at line 1 | n/a | 29, all true duplicates |

Under the shared key, the line-1 exemption in the invariant hides real duplicates, such as the workflow-permission pairs in juice-shop3 and VulnerableApp. Raising the merge threshold to line > 1 would split 29 true duplicates, so that direction is refuted.

## Related defects in error reporting

- `aggregate_run_issues.py` (~1761) reports `unique_identity` as an error under the premise "guards a fixed producer defect … regression". That premise holds for `confirmed_needs_verified` and `architect_refuted`. It is false for `unique_identity`, which is still open.
- `recommend_fixes.py` (~1051) adds "the producer it guards regressed" with high confidence.
- The diagnostician (`agents/appsec-run-diagnostician.md` procedure step 2) never reads the producer's docstring or `decisions.md`. It labeled the issue `plugin_bug`/high at `merge_threats.py:1646` and proposed removing category from the key, which would remove a documented guard without resolving the conflict between the two contracts.
- `report_plugin_issue.py` `_diagnosis` gates publication only on the labels the agent wrote. The human approval step stopped a wrong public issue.

## Measures

1. **Red test first.** The output of exact → evidence → title_locator must satisfy the shared identity. Parametrize the test over: different categories, a missing category, sibling CWEs, a refuted member, line 1, and different families on one line.
2. **Registry of open invariants** in `run_invariants.py`. It drives the xfail markers, the aggregator's severity and wording (known open: warning), and the recommendation's confidence (medium). A consistency test ties the registry to the xfails.
3. **Publish gate.** `report_plugin_issue.py` refuses issues on invariants listed as known open.
4. **Diagnostician.** Before choosing `plugin_bug`, read the docstring at the cited location and grep `decisions.md`. When two contracts conflict, cite both as the cause. Do not propose a one-sided fix, and do not exonerate.
5. **Shared identity (D1).**
   - `_dedupe_evidence` keys on `_evidence_identity_key` alone. Records without a category participate, and the dead `_same_primary_threat_category` check is removed.
   - Categories are folded into `additional_categories`, TH ids only. A survivor without a TH id adopts the first member TH id.
   - `unique_identity` calls `_evidence_identity_key` and drops its line-1 exemption.
   - Invert `test_same_line_family_members_with_different_categories_stay_distinct` and `test_unique_identity[file-level-line]`.
   - Extend WK-7, reword `agents/appsec-threat-merger.md` (~73) and the `_dedupe_evidence` docstring, refresh the frozen fixture, and flip the xfail.
6. **Rerun** juice-shop2 and one other witness.

A prototype of measure 5 on local dev a95c0047 passed the routed suite (`make test-changed`) except for the two tests above: 2267 passed, 2 failed.

## Decision

**D1.** At an identical `(file, line, CWE family)`, threat category is not part of finding identity, including at line 1. The higher-risk member stays primary, and the other categories are kept in `additional_categories`.

## Deferred

- `additional_categories` contract: TH ids only. Normalize at intake, state the rule in the analyzer prompt, then add a schema pattern. The STRIDE analyzer still emits STRIDE names in this field.
- Findings created by `promote_verified_abuse_cases.py` carry no `threat_category_id`.
- `unique_identity` as a blocking gate during the run, after measure 5 lands.
