# Figure 1 stays readable at page width

## Problem

GitHub and the report scale Figure 1 to the page width, so every extra pixel of canvas shrinks its text. A 2026-09-26 juice-shop overview was 1496 units wide, and its 8.5-unit payload labels rendered at about 5 px in the README. Column gaps reserved a fixed margin for boundary chips even where the overview draws none: 100 units before the boundary coordinate and 40 before the first lane, whatever the gap contained.

The README example was later replaced by a render made outside a scanned repository. It named the plugin instead of Juice Shop, and it had a fractional width. No guard noticed either defect.

## Decisions

The operator chose, in this session:

1. Figure 1 sizes each column gap from its content. Only a gap whose boundary line carries chips keeps the fixed reserve; every other gap takes its lanes and the shortest form of its widest payload label. Recorded as `RA-26`.
2. Compactness never costs a payload label. A gap whose compact layout displaces one is laid out again with the full reserve.
3. Two budgets guard the result. The overview of the neutral fixture topologies stays within 1120 units, and the README example keeps its payload font at 6 px or more when shown 880 px wide, has an integer width, and names the scanned project.
4. The whole appearance is not frozen. A byte-exact golden would fail on every deliberate renderer change and invite editing the golden instead of reviewing the change.

## Non-goals

- Figure 1 height. The external column stacks internet, client and third-party zones and sets the height; moving third-party services to the shortest column is a separate decision.
- The detail views keep the full reserve wherever boundary chips sit.
