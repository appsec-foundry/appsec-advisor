# Keep decision rows to the decision

## Problem

Five rows of the decision register restate the algorithm they constrain: `FE-15`, `WK-8`, `RA-16`, `RA-17` and `AC-7` run from 104 to 234 words. They list scheme mappings, ranking order, display bounds and attribution conditions that the cited code, data files and guards already define. A reader cannot tell the decision from its implementation, and every change to the algorithm also becomes a change to a held register entry.

## Goal

Each of the five rows states what holds in a few sentences. The register's rules and `AGENTS.md` say that mappings, rankings, limits and algorithms stay in the code, data file or contract a row cites.

## Non-goals

- Changing, loosening or retiring any decision. Guard and rationale cells stay as they are.
- Shortening the remaining rows above 60 words.
- Enforcing a word limit with a test.
- Moving detail into new documents. The removed detail already lives in the cited modules, data files and named guards.

## Approval

The operator approved the wording of the five rows and of the `AGENTS.md` entry on 2026-09-27.
