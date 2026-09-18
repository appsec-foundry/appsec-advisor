"""Bounded, linked SVG views for large Figure 1 models.

The existing detail SVG remains one portable asset. Native SVG view fragments
select an index, a small connection diagram, or a catalogue page without fitting
the complete model into one viewport. All references keep the global numbering.
"""

from __future__ import annotations

import collections
import copy
import re
import xml.etree.ElementTree as ET

import figure1_dfd as F

# Six outgoing flows fit at most seven component cards in one zone, below the
# renderer cap. Catalogue pages have a separate text budget, not a flow cap.
FLOWS_PER_VIEW = 6
LINES_PER_PAGE = 36
NS = "{http://www.w3.org/2000/svg}"


def needs_views(model):
    zones = collections.Counter(F._zone_key(c) for c in model.get("components", []))
    return (
        any(count > F.ZONE_CAP for count in zones.values())
        or len(model.get("external_entities", [])) > F.ZONE_CAP
        or len(model.get("data_flows", [])) > F.OVERVIEW_FLOW_CAP
        or len(F._figure_boundaries(model)) > 12
    )


def _text_pages(title, entries):
    """Pack full, escaped catalogue text; long entries continue on another page."""
    pages, lines = [], []
    for attributes, text, target in entries:
        wrapped = F._legend_wrap(text, 900, 13)
        for line in wrapped:
            if len(lines) == LINES_PER_PAGE:
                pages.append(_text_page(title, lines))
                lines = []
            lines.append((attributes, line, target))
    if lines:
        pages.append(_text_page(title, lines))
    return pages


def _text_page(title, lines):
    content = []
    for i, (attributes, line, target) in enumerate(lines):
        attrs = " ".join(f'{key}="{F._esc(value)}"' for key, value in attributes.items())
        row = f'<text x="24" y="{32 + i * 22}" font-size="13" {attrs}>{F._esc(line)}</text>'
        if target is not None:
            row = f'<a href="#{target}">{row}</a>'
        content.append(row)
    return dict(title=title, width=960, height=60 + len(lines) * 22, content="".join(content))


def _assemble(pages):
    viewport_width = max(page["width"] for page in pages)
    viewport_height = max(page["height"] for page in pages) + 64
    offsets, y = [], 0
    for page in pages:
        offsets.append(y)
        y += viewport_height + 100
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{viewport_width}" height="{viewport_height}" '
        f'viewBox="0 0 {viewport_width} {viewport_height}" data-paged-detail="true" '
        f'font-family="{F.FONT}" fill="{F.INK}">',
        "<title>Detailed architecture — select a view from the index</title>",
    ]
    for i, (page, offset) in enumerate(zip(pages, offsets)):
        ident = page.get("id", f"view-{i}")
        width, height = page["width"], page["height"] + 64
        parts.append(f'<view id="{ident}" viewBox="0 {offset} {width} {height}"/>')
        parts.append(f'<g data-detail-view="{ident}" transform="translate(0 {offset})">')
        parts.append(f'<rect width="{width}" height="{height}" fill="white"/>')
        links = [("Index", "view-0")]
        if i:
            links.append(("Previous", pages[i - 1].get("id", f"view-{i - 1}")))
        if i + 1 < len(pages):
            links.append(("Next", pages[i + 1].get("id", f"view-{i + 1}")))
        for j, (label, target) in enumerate(links):
            parts.append(
                f'<a data-detail-nav="true" href="#{target}"><text x="{24 + j * 110}" y="22" font-size="13" '
                f'fill="{F.NAVY}" text-decoration="underline">{label}</text></a>'
            )
        parts.append(f'<text x="24" y="48" font-size="14" font-weight="bold">{F._esc(page["title"])}</text>')
        content = page["content"]
        # SVG marker IDs are document-global even inside nested SVG elements.
        content = re.sub(r' id="([^"]+)"', lambda m: f' id="p{i}-{m[1]}"', content)
        content = re.sub(r"url\(#([^)]+)\)", lambda m: f"url(#p{i}-{m[1]})", content)
        parts.append(f'<g transform="translate(0 64)">{content}</g></g>')
    parts.append("</svg>")
    return "\n".join(parts)


def image_views(svg):
    """Extract inert, standalone images for HTML's collapsible detail sections.

    Images cannot navigate SVG links. Each connection/catalogue view therefore
    gets its own viewport; SVG remains an image rather than active HTML content.
    """
    root = ET.fromstring(svg)
    if root.get("data-paged-detail") != "true":
        return []
    views = {view.get("id"): view.get("viewBox") for view in root.findall(f"{NS}view")}
    result = []
    for group in root.findall(f"{NS}g[@data-detail-view]"):
        ident = group.get("data-detail-view")
        if ident.startswith("view-"):
            continue
        _, _, width, height = views[ident].split()
        page = ET.Element(
            f"{NS}svg",
            {"viewBox": views[ident], "width": width, "height": height, "font-family": F.FONT, "fill": F.INK},
        )
        group = copy.deepcopy(group)
        for nav in group.findall(f"{NS}a[@data-detail-nav]"):
            group.remove(nav)
        title = group.find(f"{NS}text").text
        page.append(group)
        result.append((title, ET.tostring(page, encoding="unicode")))
    return result


def check_views(svg, model):
    """Validate rendered coverage and local navigation before publication."""
    root = ET.fromstring(svg)
    errors = []
    views = {e.get("id") for e in root.findall(f"{NS}view")}
    for link in root.iter(f"{NS}a"):
        if link.get("href", "").removeprefix("#") not in views:
            errors.append("detail navigation points to a missing view")
    for key, rows, attr in [
        ("component", model.get("components", []), "data-component-id"),
        ("flow", model.get("data_flows", []), "data-catalogue-flow"),
        ("boundary", F._figure_boundaries(model), "data-catalogue-boundary"),
    ]:
        visible = {e.get(attr) for e in root.iter() if e.get(attr) and (e.text or len(e))}
        expected = {row["id"] for row in rows}
        if visible != expected:
            errors.append(f"detail {key} coverage differs from the canonical inventory")
    return errors


def build_views(model, scenarios, actors, actor_groups):
    numbers = {c["id"]: f"C-{i:02d}" for i, c in enumerate(model.get("components", []), 1)}
    by_number = {number: cid for cid, number in numbers.items()}
    # Resolve roles once over the complete model, so panel membership cannot
    # change whether a generic victim is ambiguous or regular roles can fold.
    projected, victim, _ = F._project_legitimate_roles(model)
    catalog = F.profile_catalog(projected.get("data_flows", []))
    outgoing = collections.defaultdict(list)
    for flow in projected.get("data_flows", []):
        outgoing[F._flow_endpoints(flow)[0]].append(flow)
    batches = [
        flows[i : i + FLOWS_PER_VIEW] for flows in outgoing.values() for i in range(0, len(flows), FLOWS_PER_VIEW)
    ]
    represented = {endpoint for batch in batches for flow in batch for endpoint in F._flow_endpoints(flow)}
    scopes = [(batch, {endpoint for flow in batch for endpoint in F._flow_endpoints(flow)}) for batch in batches]
    scopes += [([], {cid}) for cid in numbers if cid not in represented]
    pages, index, errors = [], [], []
    for i, (flows, participants) in enumerate(scopes):
        subset = copy.deepcopy(projected)
        subset["components"] = [c for c in subset.get("components", []) if c["id"] in participants]
        subset["external_entities"] = [e for e in subset.get("external_entities", []) if e["id"] in participants]
        subset["data_flows"] = flows
        subset["trust_boundaries"] = [
            b
            for b in F._figure_boundaries(projected)
            if all(b[k] == "external" or b[k] in participants for k in ("from", "to"))
        ]
        subset["assets"] = [
            a
            for a in subset.get("assets", [])
            if any(r.get("component_id") in participants for r in a.get("component_refs", []))
        ]
        local_scenarios = []
        for scenario in scenarios:
            cids = scenario.get("cids") or [by_number.get(n) for n in scenario.get("cnums", [])]
            if set(cids) & participants:
                local_scenarios.append(dict(scenario, cids=[cid for cid in cids if cid in participants]))
        if victim != F.USER_ID and any(scenario.get("victim") for scenario in local_scenarios):
            if not any(entity["id"] == victim for entity in subset["external_entities"]):
                subset["external_entities"].extend(
                    entity for entity in projected.get("external_entities", []) if entity["id"] == victim
                )
        svg, state = F._build(
            subset,
            local_scenarios,
            actors,
            actor_groups,
            detail=True,
            component_numbers=numbers,
            authentication_catalog=catalog,
            projected_victim=victim,
        )
        problems = F._check_geometry(
            state["nodes"], state["edges"], state["canvas"], state["chips"], boundaries=state["boundaries"]
        )
        problems += F._audit(
            state["d"], state["nodes"], state["edges"], state["chips"], state["boundaries"], state["canvas"]
        )
        errors.extend(f"view {i + 1}: {problem}" for problem in problems)
        root = ET.fromstring(svg)
        ident = f"connections-{i + 1}"
        labels = ", ".join(numbers[cid] for cid in numbers if cid in participants) or "External participants"
        title = f"Connections {i + 1}: {labels}"
        pages.append(
            dict(id=ident, title=title, width=float(root.get("width")), height=float(root.get("height")), content=svg)
        )
        index.append(({}, title, ident))

    def endpoint(flow, key):
        cid = flow.get(key)
        return numbers.get(cid, flow.get(f"{key}_entity") or "External")

    flow_entries = []
    for flow in model.get("data_flows", []):
        direction = "↔" if flow.get("direction") == "bidirectional" else "→"
        payload, protocol = F.flow_payload(flow)
        text = (
            f"{flow['id']} · {endpoint(flow, 'from')} {direction} {endpoint(flow, 'to')} · "
            f"{protocol} · {payload} · {flow.get('data_classification', 'Public')}"
        )
        flow_entries.append(({"data-catalogue-flow": flow["id"]}, text, None))
    boundary_entries = []
    for boundary in F._figure_boundaries(model):
        kind = (
            "internal interface · no trust transition"
            if F._internal_interface(boundary)
            else str(boundary.get("surface") or boundary.get("kind") or "type not recorded")
        )
        if boundary.get("transition") and not F._internal_interface(boundary):
            kind += " · " + " + ".join(boundary["transition"])
        text = (
            f"{boundary['id']} · {endpoint(boundary, 'from')} → {endpoint(boundary, 'to')} · "
            f"{kind} · {boundary.get('confidence', 'inferred')} · "
            f"{boundary.get('assumption_verdict', 'unconfirmed')} · {boundary.get('enforcement_point', '')}"
        )
        boundary_entries.append(({"data-catalogue-boundary": boundary["id"]}, text, None))
    for title, entries in [
        ("Complete flow catalogue", flow_entries),
        ("Complete boundary catalogue", boundary_entries),
    ]:
        for page in _text_pages(title, entries):
            page["id"] = f"catalogue-{len(pages)}"
            pages.append(page)
            index.append(({}, title + f" — {page['id']}", page["id"]))
    index_pages = _text_pages("Detailed architecture — choose a connection view or catalogue", index)
    svg = _assemble(index_pages + pages)
    return svg, errors + check_views(svg, model)
