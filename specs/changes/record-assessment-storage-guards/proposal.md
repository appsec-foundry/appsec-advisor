# Record the guards of the assessment storage decision

## Problem

Decision `AS-1` was recorded before its implementation, so its guard column still reads "no guard written". The storage resolver, the controller's default destination and the legacy import now have boundary tests.

## Goal

- Decision `AS-1`: the guard column names `test_without_output_the_run_writes_to_a_private_application_directory`, `test_clones_of_one_remote_share_their_directory` and `test_a_finished_docs_security_assessment_is_imported_on_request_and_its_history_continues`. The decision's wording and rationale stay unchanged.

## Non-goals

- Changing what `AS-1` decides, or the coverage of `REQ-TRU-005`.

## Approval

The operator approved filling the guard column on 2026-10-17.
