"""Client-to-API flows from the routes a client's code requests (F2).

A browser client usually calls its own API by a relative path
(`this.http.get(host + '/rest/basket/' + id)`), which outbound-call detection
excludes as same-origin, so the architecture model can miss the most
important flow of a web application. This module matches URL arguments of
complete, bounded HTTP calls against the route inventory: a literal whose path,
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

False-positive exclusions: test files, templates, comments, payload strings,
unresolved methods, literals without a leading path segment, and routes whose
path is only `/` never match. A router's
root path alone does not establish its mounted client-visible URL.
"""

from __future__ import annotations

import hashlib
import re

from analyzers.flow_route_auth import cited_routes, route_outcome

MAX_CALL_EVIDENCE = 4
MAX_ROUTE_EVIDENCE = 4
MAX_ROUTE_REFS = 32
MAX_AUTH_EVIDENCE = 8

_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
_LEX_RE = re.compile(_LITERAL_RE.pattern + r"|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*")
_TEMPLATE_RE = re.compile(r"\$\{[^}]*\}")
_PARAM_RE = re.compile(r"^(?::\w+|\{\w+\}|<[^>]+>|\*)$")
_METHOD_CALL_RE = re.compile(
    r"\.(?P<method>get|post|put|patch|delete|head|options)\s*(?:<[^();\n]+>)?\s*\("
    r"|(?<![\w$.])(?:window\.)?fetch\s*\(",
    re.IGNORECASE,
)
_MAX_CALL_CHARS = 4096
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


def _request_paths(expression: str) -> list[tuple[str, int]]:
    """Relative paths in a URL argument, with their literal offsets for source evidence."""
    out = []
    if any(re.match(r"(?:[a-z][a-z0-9+.-]*:)?//", token[0][1:-1], re.I) for token in _LITERAL_RE.finditer(expression)):
        return out
    for match in _LITERAL_RE.finditer(expression):
        text = match[0][1:-1]
        text = _TEMPLATE_RE.sub("p", text)
        start = text.find("/")
        if start < 0 or "//" in text[start : start + 2] or " " in text[start:]:
            continue
        path = text[start:]
        if path.endswith("/") and expression[match.end() :].lstrip().startswith("+"):
            path += "p"
        if len(_segments(path)) >= 1:
            out.append(("/" + "/".join(_segments(path)), match.start()))
    return out


def _arguments(code: str, opening: int) -> list[tuple[int, int]]:
    """Top-level argument spans in a bounded, balanced call or object; strings are masked."""
    stack, spans, start = [code[opening]], [], opening + 1
    pairs = {")": "(", "]": "[", "}": "{"}
    for index in range(start, min(len(code), opening + _MAX_CALL_CHARS)):
        char = code[index]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                return []
            if not stack:
                return [*spans, (start, index)]
        elif char == "," and len(stack) == 1:
            spans.append((start, index))
            start = index + 1
    return []


def _fetch_method(text: str, code: str, arguments: list[tuple[int, int]]) -> str | None:
    """Fetch defaults to GET only when no dynamic options can override its method."""
    if len(arguments) == 1:
        return "GET"
    start, end = arguments[1]
    while start < end and text[start].isspace():
        start += 1
    if start == end or code[start] != "{":
        return None
    fields = _arguments(code, start)
    if not fields or text[fields[-1][1] + 1 : end].strip():
        return None
    methods = []
    for first, last in fields:
        field = text[first:last].strip()
        if (
            field.startswith("...")
            or field.startswith("[")
            or re.match(r"(?:get|set)\s+|(?:__proto__|['\"]__proto__['\"])\s*:", field)
            or (field.startswith(("'", '"')) and "\\" in field.split(":", 1)[0])
        ):
            return None
        if re.match(r"(?:method\b|['\"]method['\"])", field):
            match = re.fullmatch(
                r"(?:method|['\"]method['\"])\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", field, re.I
            )
            if not match:
                return None
            methods.append(match[1].upper())
    return methods[0] if len(methods) == 1 else "GET" if not methods else None


def _requests(text: str):
    """Read URL arguments of complete calls, never payload strings or standalone path literals."""
    code, clean = list(text), list(text)
    for token in _LEX_RE.finditer(text):
        blank = ["\n" if c == "\n" else " " for c in token[0]]
        code[token.start() : token.end()] = blank
        if token[0][0] not in "'\"`":
            clean[token.start() : token.end()] = blank
    code, clean = "".join(code), "".join(clean)
    for call in _METHOD_CALL_RE.finditer(code):
        arguments = _arguments(code, call.end() - 1)
        if not arguments:
            continue
        method = call["method"].upper() if call["method"] else _fetch_method(clean, code, arguments)
        if method is None:
            continue
        start, end = arguments[0]
        for requested, offset in _request_paths(clean[start:end]):
            yield requested, method, text.count("\n", 0, start + offset) + 1


def client_calls(files: dict[str, bytes], routes: list[dict]) -> dict[int, list[dict]]:
    """``{route index: [{file, line}]}`` of client lines requesting each route."""
    patterns = [(index, _route_pattern(str(route.get("path") or ""))) for index, route in enumerate(routes)]
    patterns = [(index, pattern) for index, pattern in patterns if pattern is not None]
    calls: dict[int, list[dict]] = {}
    for path in sorted(files):
        # A template's paths are client routes and links, not API requests.
        if _TEST_PATH_RE.search(path) or path.endswith((".html", ".htm")):
            continue
        for requested, method, number in _requests(files[path].decode("utf-8", "replace")):
            for index, pattern in patterns:
                if routes[index].get("method") not in {method, "ALL"}:
                    continue
                rows = calls.setdefault(index, [])
                if pattern.match(requested) and {"file": path, "line": number} not in rows:
                    rows.append({"file": path, "line": number})
    return {index: rows for index, rows in calls.items() if rows}


def _route_reference(route: dict) -> str:
    """Keep method/path identity within the reference contract without prefix collisions."""
    reference = f"{route.get('method')} {route.get('path')}"
    if len(reference) <= 120:
        return reference
    return reference[:40] + " [sha256:" + hashlib.sha256(reference.encode()).hexdigest() + "]"


def uncovered_calls(client_id, calls, routes, owner_of, existing):
    """Retain requests not evidenced by an existing flow to the same receiver.

    Route references alone are untrusted claims. Coverage requires a matching
    client call or registration source, and a known outcome must already be
    represented or recoverable by the route reconciler. A method/path reference
    backed by another evidenced member and rederived client/receiver matches
    retains topology coverage beyond the evidence cap, including unknown routes.
    This does not turn those references into authentication evidence.
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
        referenced = {
            index
            for index in calls
            if owner_of(routes[index]) == flow.get("to")
            and _route_reference(routes[index]) in (flow.get("route_refs") or [])
        }
        anchored = any(
            (row["file"], row["line"]) in locations
            for index in referenced
            for row in [*calls[index], {"file": routes[index]["handler_file"], "line": routes[index]["handler_line"]}]
        )
        for index, rows in list(remaining.items()):
            route = routes[index]
            if owner_of(route) != flow.get("to"):
                continue
            sources = [*rows, {"file": route["handler_file"], "line": route["handler_line"]}]
            outcome = route_outcome(route)
            # Stable method/path references survive evidence presentation caps,
            # but only an independently resolved guard can corroborate them.
            if outcome and _route_reference(route) in (flow.get("route_refs") or []):
                sources.extend(outcome[2])
            if not (anchored and index in referenced) and not any(
                (row["file"], row["line"]) in locations for row in sources
            ):
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
    # Every emitted group retains its full interface list. Only explanatory
    # evidence is sampled; a reference cap must not silently erase coverage.
    batches = [
        (key, members[start : start + MAX_ROUTE_REFS])
        for key, members in sorted(groups.items())
        for start in range(0, len(members), MAX_ROUTE_REFS)
    ]
    per_owner: dict[str, int] = {}
    for (owner, _scheme, _scope), _members in batches:
        per_owner[owner] = per_owner.get(owner, 0) + 1
    out = []
    for (owner, scheme, scope), members in batches:
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
            "route_refs": sorted({_route_reference(routes[i]) for i in members}),
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
