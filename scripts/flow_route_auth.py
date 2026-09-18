"""Fill a data flow's unknown authentication from the routes it cites.

The architecture analyst cites route registrations as a flow's evidence but
cannot always tell how the handler authenticates, so it writes
``authentication.scheme: unknown``. The route inventory resolves each handler
chain (``handler_resolver.py``); when every route a flow cites has the same
resolved outcome, that outcome becomes the flow's authentication with the
handler code as evidence. Routes that authenticate differently cannot share one
flow: the analyst's self-check reports them so the flow is split, and the
controller leaves such a flow unknown. A flow whose scheme the analyst already
set is never changed, and an unresolved route never fills anything.
"""

from __future__ import annotations

import copy

from handler_resolver import HandlerSignal

_MAX_EVIDENCE = 8


def route_outcome(route: dict) -> tuple[str, str, list[dict]] | None:
    """(scheme, scope, evidence) a route's resolved handler proves, or None."""
    signal = route.get("authn_handler_signal")
    if signal == "verified" and route.get("authn_signal") == "present":
        scheme = route.get("authn_handler_scheme") or "other"
    elif signal in {"none", "decode_only"} and route.get("authn_signal") == "absent":
        scheme = "none"
    else:
        return None
    evidence = route.get("authn_handler_evidence") or [
        {"file": route.get("handler_file"), "line": route.get("handler_line")}
    ]
    return scheme, HandlerSignal(signal, scheme).scope(), evidence


def cited_routes(flow: dict, routes: list[dict]) -> list[dict]:
    """Routes whose registration line the flow or its authentication cites."""
    rows = [*(flow.get("evidence") or []), *((flow.get("authentication") or {}).get("evidence") or [])]
    cited = {(row.get("file"), row.get("line")) for row in rows if isinstance(row, dict)}
    return [r for r in routes if (r.get("handler_file"), r.get("handler_line")) in cited]


def _open(flow: dict) -> bool:
    return not flow.get("interaction") and (flow.get("authentication") or {}).get("scheme", "unknown") == "unknown"


def _outcomes(flow: dict, routes: list[dict]) -> list[tuple[dict, tuple[str, str, list[dict]] | None]]:
    return [(route, route_outcome(route)) for route in cited_routes(flow, routes)]


def mixed_route_auth_errors(flows: list, routes: list) -> list[str]:
    """Flows with unknown authentication whose cited routes resolve to different authentication."""
    errors = []
    for flow in flows or []:
        if not isinstance(flow, dict) or not _open(flow):
            continue
        resolved = [(route, outcome) for route, outcome in _outcomes(flow, routes or []) if outcome]
        kinds = {(outcome[0], outcome[1]) for _route, outcome in resolved}
        if len(kinds) > 1:
            described = "; ".join(
                f"{route.get('method')} {route.get('path')}: {outcome[0]} ({outcome[1]})" for route, outcome in resolved
            )
            errors.append(
                f"{flow.get('id')}: its routes authenticate differently ({described}); "
                "split the flow into one flow per authentication"
            )
    return errors


def reconcile(flows_doc: dict, routes: list) -> tuple[dict, list[str], list[str]]:
    """(flows with filled authentication, filled flow ids, flow ids left unknown for mixed routes)."""
    result = copy.deepcopy(flows_doc)
    filled, mixed = [], []
    for flow in result.get("data_flows") or []:
        if not isinstance(flow, dict) or not _open(flow):
            continue
        outcomes = _outcomes(flow, routes or [])
        if not outcomes or any(outcome is None for _route, outcome in outcomes):
            continue
        kinds = {(outcome[0], outcome[1]) for _route, outcome in outcomes}
        if len(kinds) > 1:
            mixed.append(flow["id"])
            continue
        scheme, scope = kinds.pop()
        evidence: list[dict] = []
        for _route, outcome in outcomes:
            evidence.extend(row for row in outcome[2] if row not in evidence)
        authentication = {"scheme": scheme, "scope": scope, "evidence": evidence[:_MAX_EVIDENCE]}
        if (flow.get("authentication") or {}).get("transport"):
            authentication["transport"] = flow["authentication"]["transport"]
        flow["authentication"] = authentication
        filled.append(flow["id"])
    return result, filled, mixed
