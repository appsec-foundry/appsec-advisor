"""Evidence-qualified authentication presentation, independent of repository names.

The architecture producer owns mechanism discovery. These functions consume its
validated flow records; labels, dependencies and findings never prove a login.
Colours describe method properties, not the effectiveness of an implementation.
"""

SCHEMES = {
    "unknown": ("Not established", "The inspected evidence does not establish authentication."),
    "none": ("No Authentication", "The recipient performs no authentication check on this connection."),
    "password": ("Password login", "The recipient checks the supplied password."),
    "basic": ("HTTP Basic", "Username and password accompany the request."),
    "bearer": ("Bearer token", "The recipient checks the token supplied with the request."),
    "cookie": ("Session cookie", "A session cookie identifies the caller."),
    "api-key": ("API key", "The caller presents a configured service credential."),
    "oauth2": ("OAuth 2.0", "Delegated access; only the evidenced protocol step is covered."),
    "oidc": ("OpenID Connect", "The relying party validates identity through the provider."),
    "saml": ("SAML", "The relying party validates the provider's assertion."),
    "mtls": ("Mutual TLS", "The peer proves possession of its certificate's private key."),
    "private-key": (
        "Private-key authentication",
        "The caller proves key possession; a key name alone is insufficient.",
    ),
    "mfa": ("Multiple factors", "Independent factors are checked for this access."),
    "other": ("Other authentication", "See the access-specific evidence and scope."),
}


def authentication_profile(flow):
    """Return a display profile; absence or incomplete evidence stays unknown."""
    auth = flow.get("authentication") or {}
    scheme = auth.get("scheme", "unknown")
    evidence = auth.get("evidence") or []
    if scheme not in SCHEMES or not auth.get("scope") or not evidence:
        scheme, auth = "unknown", {}
    factors = tuple(sorted(auth.get("factors") or []))
    if scheme == "mfa" and (len(factors) < 2 or not {"password", "biometric"}.intersection(factors)):
        return authentication_profile({})
    grant, transport = auth.get("flow", ""), auth.get("transport", "unknown")
    color = "yellow"
    if scheme == "unknown":
        color = "grey"
    elif scheme == "none" or transport == "cleartext":
        color = "red"
    elif transport == "protected" and (
        scheme in {"mtls", "private-key"}
        or scheme == "mfa"
        and len(factors) >= 2
        and not {"sms", "email"}.intersection(factors)
        or scheme in {"oidc", "oauth2"}
        and grant == "authorization-code-pkce"
    ):
        color = "green"
    title, description = SCHEMES[scheme]
    if factors:
        title += ": " + " + ".join(factors)
    if grant:
        title += " · " + grant.replace("-", " ")
    # The key holds only what the legend shows: transport enters it through the
    # colour, and the title names the transport wherever it decided that colour.
    if scheme not in {"unknown", "none"} and (transport == "cleartext" or color == "green"):
        title += " · " + ("cleartext" if transport == "cleartext" else "protected transport")
    key = (scheme, grant, factors, color) if scheme not in {"unknown", "none"} else (scheme,)
    if scheme == "other":
        # Equivalence of custom methods cannot be inferred from one generic name,
        # so each keeps its own number and its evidenced scope explains it.
        description = auth["scope"]
        key += (description,)
    return {"key": key, "scheme": scheme, "title": title, "description": description, "color": color}


def profile_catalog(flows):
    """Reuse numbers for equal methods; 0 and ? never depend on encounter order."""
    profiles = {p["key"]: p for f in flows if not f.get("interaction") for p in [authentication_profile(f)]}
    number = 0
    for key in sorted(profiles):
        profile = profiles[key]
        if profile["scheme"] in {"none", "unknown"}:
            profile["number"] = "0" if profile["scheme"] == "none" else "?"
        else:
            number += 1
            profile["number"] = str(number)
    return profiles


def flow_bundle_key(flow):
    """Only equivalent receiving interfaces share a line; identities stay intact."""
    return (
        flow.get("from"),
        flow.get("from_entity"),
        flow.get("to"),
        flow.get("to_entity"),
        flow.get("protocol"),
        str(flow.get("direction") or "").lower(),
        tuple(sorted(flow.get("interface_refs") or [])),
        authentication_profile(flow)["key"],
        bool(flow.get("interaction")),
        flow.get("protocol_group"),
        flow.get("id") if flow.get("access_group") else None,
    )


def access_groups(flows):
    """Validate explicit access relationships; never deduce them from labels.

    A group preserves one technical sender, receiver, protocol and direction.
    Separate interfaces may be alternatives or ordered checks at that receiver.
    Invalid groups are not projected, including when rendering legacy input
    outside the producer gate. The architecture validator reports the errors.
    """
    groups, accepted, errors = {}, {}, []
    for flow in flows:
        group = flow.get("access_group")
        if group is None:
            continue
        if not isinstance(group, dict) or not isinstance(group.get("id"), str):
            errors.append(f"{flow.get('id')}: invalid access_group")
            continue
        groups.setdefault(group["id"], []).append(flow)
    for gid, members in groups.items():
        first = members[0]["access_group"]
        mode = first.get("mode")

        def signature(f):
            return tuple(f.get(k) for k in ("from", "from_entity", "to", "to_entity", "protocol", "direction"))

        valid = (
            len(members) >= 2
            and isinstance(mode, str)
            and mode in {"alternatives", "sequence"}
            and isinstance(first.get("label"), str)
            and bool(first["label"].strip())
            and all(
                f["access_group"].get("mode") == mode
                and f["access_group"].get("label") == first["label"]
                and signature(f) == signature(members[0])
                and not f.get("interaction")
                and not f.get("protocol_group")
                and authentication_profile(f)["scheme"] != "unknown"
                for f in members
            )
        )
        steps = [f["access_group"].get("step") for f in members]
        if mode == "sequence":
            valid = valid and all(type(s) is int for s in steps) and sorted(steps) == list(range(1, len(members) + 1))
        else:
            valid = valid and all(s is None for s in steps)
        if not valid:
            errors.append(
                f"access_group {gid}: requires evidenced methods, consistent endpoints/protocol/direction/label and unique consecutive sequence steps"
            )
        else:
            accepted[gid] = sorted(members, key=lambda f: f["access_group"].get("step", 0) or f["id"])
    return accepted, errors


def bundle_access_groups(model, edges):
    """Project small explicit groups to one line without modifying canonical flows.

    Two methods fit one compact port. Larger groups retain individual lines;
    a partial projection must never suggest an incomplete login sequence.
    """
    groups, _errors = access_groups(model.get("data_flows", []))
    result = list(edges)
    for members in groups.values():
        ids = [f["id"] for f in members]
        selected = [e for e in result if set(e["ids"]).intersection(ids)]
        group = members[0]["access_group"]
        keys = [authentication_profile(f)["key"] for f in members]
        if group["mode"] == "alternatives":
            keys = sorted(set(keys), key=lambda k: (k[0] != "none", k))
        if len(keys) > 2 or {fid for e in selected for fid in e["ids"]} != set(ids):
            continue
        if len({(e["src"], e["dst"]) for e in selected}) != 1:
            continue
        merged = {
            **selected[0],
            "ids": ids,
            "access_group": group,
            "auth_keys": keys,
            "tb": sorted({t for e in selected for t in e["tb"]}),
        }
        ranking = {"Restricted": 0, "Confidential": 1, "Internal": 2, "Public": 3}
        merged["cls"] = min((e["cls"] for e in selected), key=lambda c: ranking.get(c, 9))
        first = min(result.index(e) for e in selected)
        result = [e for e in result if e not in selected]
        result.insert(first, merged)
    return result


def select_references(model, nodes, edges, boundary_findings):
    """Summarize explicit client integrations, never stores or finding-linked flows."""
    groups = {}
    flows = {f["id"]: f for f in model.get("data_flows", [])}
    protected_pairs = {
        (t.get("from"), t.get("to")) for t in model.get("trust_boundaries", []) if boundary_findings.get(t.get("id"))
    }
    for edge in edges:
        if edge.get("attack") or edge.get("interaction"):
            continue
        members = [flows[fid] for fid in edge["ids"]]
        names = {f.get("protocol_group") for f in members}
        if len(names) != 1 or None in names or "" in names:
            continue
        if any(f.get("threats") for f in members) or any(boundary_findings.get(t) for t in edge["tb"]):
            continue
        if any((f.get("from"), f.get("to")) in protected_pairs for f in members):
            continue
        if not all(nodes[edge[side]]["zone"] in {"client", "third-party"} for side in ("src", "dst")):
            continue
        clients = tuple(sorted(edge[side] for side in ("src", "dst") if nodes[edge[side]]["zone"] == "client"))
        if len(clients) != 1:
            continue
        groups.setdefault((next(iter(names)), clients), []).append(edge)
    references = []
    for (name, _clients), candidates in sorted(groups.items()):
        ids = [fid for e in candidates for fid in e["ids"]]
        if len(ids) < 2:
            continue
        ref = {"id": f"E{len(references) + 1}", "name": name, "ids": ids, "edges": candidates}
        references.append(ref)
        for node_id in sorted({e[side] for e in candidates for side in ("src", "dst")}):
            peers = sorted(
                {e["dst"] if e["src"] == node_id else e["src"] for e in candidates if node_id in (e["src"], e["dst"])}
            )
            for peer in peers:
                pair = [e for e in candidates if {e["src"], e["dst"]} == {node_id, peer}]
                incoming = any(e["dst"] == node_id or e.get("bidi") for e in pair)
                outgoing = any(e["src"] == node_id or e.get("bidi") for e in pair)
                nodes[node_id].setdefault("references", []).append(
                    {
                        "id": ref["id"],
                        "peer": peer,
                        "direction": "↔" if incoming and outgoing else "←" if incoming else "→",
                        "profiles": sorted({e["authentication"]["key"] for e in pair if e["dst"] == node_id}),
                        "ids": sorted(fid for e in pair for fid in e["ids"]),
                    }
                )
    removed = {id(e) for ref in references for e in ref["edges"]}
    return [e for e in edges if id(e) not in removed], references
