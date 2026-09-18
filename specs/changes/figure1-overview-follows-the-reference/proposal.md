# Figure 1 overview follows the reference design

## Problem

A 2026-09-17 juice-shop run rendered a Figure 1 that differed from `docs/images/figure1-example.svg` in ways the operator flagged:

- The overview listed ten trust-boundary entries in its own legend column, five of them internal interfaces with no trust transition and four marked "no unique drawn flow", plus a single `tb-10` pill on one line. The reader could not find most entries in the picture.
- Two in-process calls inside the backend ran as long lines with a `0` hexagon through the application column.
- The generic "User" victim card stood next to "End User (Browser)", the one classified regular role of the same run.
- Scenario badges repeated numbers (`6·5·5·4·3·2·1`), the actor legend repeated "Internet Attacker" four times, and the header said 56 threats while the report said 54.
- The component inventory carried a second MarsDB store injected by reconciliation next to the analyst's own document store, which cost a separate STRIDE pass.
- The reference shows capability and service-role labels that no renderer produced.

## Decisions

The operator chose, in this session:

1. Draw a dashed trust-boundary line in a column gap only when a resolved boundary that is not an internal interface crosses it. The overview shows no boundary IDs, no boundary legend and no internal-interface count; the detail views and the report catalogue keep the full inventory. Recorded as `RA-15`.
2. Hide process-to-process calls that a canonical internal interface places inside one process from the overview; the detail views keep them.
3. Keep separate attacker cards for build-time and privileged access (`RA-10`, `RA-12` unchanged).
4. Add evidenced `components[].capabilities[]` and `external_entities[].service_roles[]` from a fixed vocabulary and show them as labels without a risk rating.
5. Widen `RA-11`: a single classified regular role, not only a merged one, may replace the generic victim. Privileged, unclassified and unnamed-flow participants keep their identities.

## Non-goals

- Changing the attack-bus geometry. Actor attribution and per-finding attack targets were later brought into scope by the operator (`RA-17`, `RA-18`).
- Inferring `protocol_group` or `access_group` in the renderer. The architecture prompt now asks for a shared `protocol_group` on the steps of one integration; the renderer still uses only explicit values.
- Adding data flows for components that reconciliation injects after the architecture analyst wrote its flows. That ordering gap is open work.
