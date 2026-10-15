"""Client-to-API flows from the routes a client's code requests (F2).

A browser client usually calls its own API by a relative path
(`this.http.get(host + '/rest/basket/' + id)`), which outbound-call detection
excludes as same-origin, so the architecture model can miss the most
important flow of a web application. This module matches path literals in a
client component's files against the route inventory: a literal whose path,
with `${...}` and a trailing concatenation read as a parameter, equals a
route's path pattern is a request to that route. The matched routes are
grouped by their owning component and by the authentication their resolved
handlers prove (`flow_route_auth.route_outcome`); each group becomes one flow
whose authentication considers every matched route before evidence is bounded.
Existing flows cover only their evidenced requests, not an entire component pair.
Several groups between one pair are
`alternatives` of one access group; `settle_access_groups` keeps a flow in it
only when its authentication is proven, because an access group admits no
unknown member. Explicit client HTTP methods restrict path matches to that
method; a global wildcard alone is not a called interface.

False-positive exclusions: test files, templates, comment lines, literals without a
leading path segment, and routes whose path is only `/` never match. A router's
root path alone does not establish its mounted client-visible URL.
"""

from __future__ import annotations

import re

from analyzers.flow_route_auth import cited_routes, route_outcome

MAX_CALL_EVIDENCE = 4
MAX_ROUTE_EVIDENCE = 4
MAX_ROUTE_REFS = 32
MAX_AUTH_EVIDENCE = 8

_LITERAL_RE = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"|`([^`\n]*)`")
_TEMPLATE_RE = re.compile(r"\$\{[^}]*\}")
_PARAM_RE = re.compile(r"^(?::\w+|\{\w+\}|<[^>]+>|\*)$")
_COMMENT_RE = re.compile(r"^\s*(?://|#|\*|/\*|<!--)")
_METHOD_CALL_RE = re.compile(r"\.(get|post|put|patch|delete|head|options)\s*\([^()]*$", re.IGNORECASE)
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|e2e|cypress|__mocks__)(?:/|$)|\.(?:spec|test|cy)\.\w+$|(?:^|/)test_[^/]*$"
)


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("?")[0].split("#")[0].strip().split("/") if segment]


def _route_pattern(path: str) -> re.Pattern | None:
    segments = _segments(path)
    if not segments or not path.startswith("/"):
        return None
    parts = ["[^/]+" if _PARAM_RE.match(s) else re.escape(s) for s in segments]
    return re.compile("^/" + "/".join(parts) + "$")


def _request_paths(line: str) -> list[tuple[str, str | None]]:
    """Paths a line's literals request, with interpolations and a trailing `/` + value read as parameters."""
    out = []
    for match in _LITERAL_RE.finditer(line):
        text = next(group for group in match.groups() if group is not None)
        text = _TEMPLATE_RE.sub("p", text)
        start = text.find("/")
        if start < 0 or "//" in text[start : start + 2] or " " in text[start:]:
            continue
        path = text[start:]
        if path.endswith("/") and line[match.end() :].lstrip().startswith("+"):
            path += "p"
        if len(_segments(path)) >= 1:
            method = _METHOD_CALL_RE.search(line[: match.start()])
            out.append(("/" + "/".join(_segments(path)), method[1].upper() if method else None))
    return out


def client_calls(files: dict[str, bytes], routes: list[dict]) -> dict[int, list[dict]]:
    """``{route index: [{file, line}]}`` of client lines requesting each route."""
    patterns = [(index, _route_pattern(str(route.get("path") or ""))) for index, route in enumerate(routes)]
    patterns = [(index, pattern) for index, pattern in patterns if pattern is not None]
    calls: dict[int, list[dict]] = {}
    for path in sorted(files):
        # A template's paths are client routes and links, not API requests.
        if _TEST_PATH_RE.search(path) or path.endswith((".html", ".htm")):
            continue
        for number, line in enumerate(files[path].decode("utf-8", "replace").splitlines(), 1):
            if _COMMENT_RE.match(line):
                continue
            for requested, method in _request_paths(line):
                for index, pattern in patterns:
                    if method and routes[index].get("method") not in {method, "ALL"}:
                        continue
                    rows = calls.setdefault(index, [])
                    if pattern.match(requested) and {"file": path, "line": number} not in rows:
                        rows.append({"file": path, "line": number})
    return {index: rows for index, rows in calls.items() if rows}


def uncovered_calls(client_id, calls, routes, owner_of, existing):
    """Retain requests not evidenced by an existing flow to the same receiver.

    Route references alone are untrusted claims. Coverage requires a matching
    client call or registration source, and a known outcome must already be
    represented or recoverable by the route reconciler. A method/path reference
    backed by its resolved guard also retains coverage beyond the evidence cap.
    A generic pair or differently authenticated interface cannot hide a variant.
    """
    remaining = dict(calls)
    for flow in existing:
        if flow.get("from") != client_id or flow.get("interaction"):
            continue
        evidence = [*(flow.get("evidence") or []), *((flow.get("authentication") or {}).get("evidence") or [])]
        locations = {(row.get("file"), row.get("line")) for row in evidence}
        auth = flow.get("authentication") or {}
        scheme = auth.get("scheme", "unknown")
        scope = auth.get("scope")
        registrations = cited_routes(flow, routes)
        if scheme == "unknown":
            outcomes = [route_outcome(route) for route in registrations]
            if outcomes and all(outcomes) and len({outcome[:2] for outcome in outcomes}) == 1:
                scheme, scope = outcomes[0][:2]
        for index, rows in list(remaining.items()):
            route = routes[index]
            if owner_of(route) != flow.get("to"):
                continue
            sources = [*rows, {"file": route["handler_file"], "line": route["handler_line"]}]
            outcome = route_outcome(route)
            # Stable method/path references survive evidence presentation caps,
            # but only an independently resolved guard can corroborate them.
            if outcome and f"{route.get('method')} {route.get('path')}" in (flow.get("route_refs") or []):
                sources.extend(outcome[2])
            if not any((row["file"], row["line"]) in locations for row in sources):
                continue
            if outcome and (
                scheme != outcome[0]
                or not scope
                or not auth.get("evidence")
                and not registrations
                or scheme in {"none", "other"}
                and scope != outcome[1]
            ):
                continue
            del remaining[index]
    return remaining


def flows(client_id: str, calls: dict[int, list[dict]], routes: list[dict], owner_of) -> list[dict]:
    """One flow per receiving component and proven authentication outcome, without IDs.

    ``owner_of(route)`` names the component that decides a route, or None.
    """
    groups: dict[tuple[str, str, str], list[int]] = {}
    for index in sorted(calls):
        owner = owner_of(routes[index])
        if owner is None or owner == client_id:
            continue
        outcome = route_outcome(routes[index])
        scheme, scope = (
            outcome[:2] if outcome else ("unknown", "Authentication is unresolved in the route handler chain.")
        )
        groups.setdefault((owner, scheme, scope), []).append(index)
    per_owner: dict[str, int] = {}
    for owner, _scheme, _scope in groups:
        per_owner[owner] = per_owner.get(owner, 0) + 1
    out = []
    for (owner, scheme, scope), members in sorted(groups.items()):
        evidence: list[dict] = []
        for index in members:
            for row in calls[index]:
                if row not in evidence and len(evidence) < MAX_CALL_EVIDENCE:
                    evidence.append(row)
        registrations = []
        for index in members:
            row = {"file": routes[index]["handler_file"], "line": routes[index]["handler_line"]}
            if row not in registrations and len(registrations) < MAX_ROUTE_EVIDENCE:
                registrations.append(row)
        auth_evidence = []
        for index in members:
            outcome = route_outcome(routes[index])
            for row in outcome[2] if outcome else []:
                if row not in auth_evidence and len(auth_evidence) < MAX_AUTH_EVIDENCE:
                    auth_evidence.append(dict(row))
        flow = {
            "from": client_id,
            "to": owner,
            "label": f"API requests ({'unknown authentication' if scheme == 'unknown' else scheme})",
            "diagram_label": "API requests",
            "protocol": "HTTP",
            "data_classification": "Internal",
            "direction": "request-response",
            "evidence": evidence + registrations,
            "provenance": "route-extraction",
            "route_refs": sorted({f"{routes[i].get('method')} {routes[i].get('path')}"[:120] for i in members})[
                :MAX_ROUTE_REFS
            ],
        }
        if scheme != "unknown":
            flow["authentication"] = {"scheme": scheme, "scope": scope, "evidence": auth_evidence}
        if per_owner[owner] > 1:
            flow["access_group"] = {
                "id": f"api-{client_id}-{owner}"[:80],
                "mode": "alternatives",
                "label": "API access",
            }
        out.append(flow)
    return out


def settle_access_groups(data_flows: list[dict]) -> None:
    """After the route fill, drop route-extraction group members whose authentication stays unknown.

    An access group requires every member's authentication to be evidenced
    (`figure1_security.access_groups`); the unknown flow stays as its own
    flow, and a group left with fewer than two members dissolves.
    """
    from renderers.figure1_security import authentication_profile

    members: dict[str, list[dict]] = {}
    for flow in data_flows:
        if flow.get("provenance") == "route-extraction" and isinstance(flow.get("access_group"), dict):
            if authentication_profile(flow)["scheme"] == "unknown":
                del flow["access_group"]
            else:
                members.setdefault(flow["access_group"]["id"], []).append(flow)
    for group in members.values():
        if len(group) < 2:
            del group[0]["access_group"]
