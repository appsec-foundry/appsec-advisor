from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_architecture_analysis_context as context  # noqa: E402
import context_routing as routing  # noqa: E402


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _route(index: int, *, framework: str = "express", file: str = "routes/api.ts", risky: bool = False) -> dict:
    return {
        "route_id": f"R-{index:03d}",
        "method": "POST" if risky else "GET",
        "path": f"/items/{index}",
        "framework": framework,
        "handler_file": file,
        "handler_line": index,
        "authn_signal": "absent" if risky else "present",
        "authz_signal": "unknown",
        "management_surface": risky,
        "missing_auth_suspect": risky,
        "missing_authz_suspect": False,
        "relevance_tags": ["management"] if risky else [],
        "confidence": "high",
        "notes": [],
    }


def test_recon_projection_preserves_headings_and_discloses_truncation() -> None:
    payload = (
        "# Recon\n"
        + "\n".join(f"root {i}" for i in range(10))
        + "\n## Routes\n"
        + "\n".join(f"route {i}" for i in range(20))
    ).encode()

    projected = context.project_recon_summary(payload)

    jsonschema.validate(projected, _schema("recon-summary-context.schema.json"))
    assert [row["heading"] for row in projected["sections"]] == ["Recon", "Routes"]
    assert len(projected["sections"][0]["lines"]) == 4
    assert len(projected["sections"][1]["lines"]) == 8
    assert projected["limits"]["omitted_body_lines"] == 18
    assert projected["source"]["sha256"] == hashlib.sha256(payload).hexdigest()


def test_recon_projection_rejects_non_markdown_input() -> None:
    try:
        context.project_recon_summary(b"plain text only\n")
    except context.ContextProjectionError as exc:
        assert "no Markdown headings" in str(exc)
    else:
        raise AssertionError("missing heading must fail")


def test_recon_projection_semantic_cap_fits_serialized_routing_cap() -> None:
    payload = "\n".join(
        line
        for section in range(context.MAX_RECON_SECTIONS)
        for line in (f"## Section {section}", *(f"body {section}-{index}" for index in range(8)))
    ).encode()

    projected = context.project_recon_summary(payload)
    rendered = (json.dumps(projected, indent=2) + "\n").encode()
    bindings = json.loads((ROOT / "data" / "context-routing-bindings.json").read_text(encoding="utf-8"))
    profile = bindings["limit_profiles"]["recon_projection"]
    physical_lines = rendered.count(b"\n")

    jsonschema.validate(projected, _schema("recon-summary-context.schema.json"))
    assert projected["limits"]["retained_lines"] == context.MAX_RECON_RETAINED_LINES
    assert physical_lines > context.MAX_RECON_RETAINED_LINES
    assert physical_lines <= profile["max_lines"]
    assert len(rendered) <= profile["max_bytes"]
    routing._enforce_limits(  # noqa: SLF001
        "discovery.recon_projection",
        routing._counts(rendered, record_count=len(projected["sections"])),  # noqa: SLF001
        profile,
    )


def test_route_projection_is_bounded_risk_first_and_diverse() -> None:
    routes = [_route(i) for i in range(1, 121)]
    routes.append(_route(121, framework="fastapi", file="service/api.py"))
    routes.append(_route(122, framework="spring", file="backend/Api.java", risky=True))
    source = {
        "version": 1,
        "routes": routes,
        "coverage": {"frameworks_detected": ["spring", "express", "fastapi"], "unsupported_route_files": []},
    }
    payload = json.dumps(source).encode()

    projected = context.project_routes(payload)

    jsonschema.validate(projected, _schema("architecture-route-context.schema.json"))
    assert len(projected["routes"]) == context.MAX_ROUTES
    assert projected["routes"][0]["route_id"] == "R-122"
    assert {row["framework"] for row in projected["routes"]} == {"express", "fastapi", "spring"}
    assert projected["limits"]["omitted_routes"] == 26
    rendered = (json.dumps(projected, indent=2) + "\n").encode()
    profile = json.loads((ROOT / "data" / "context-routing-bindings.json").read_text(encoding="utf-8"))[
        "limit_profiles"
    ]["route_projection"]
    routing._enforce_limits(  # noqa: SLF001
        "architecture.route_projection",
        routing._counts(rendered, record_count=len(projected["routes"])),  # noqa: SLF001
        profile,
    )


def test_build_writes_both_projection_artifacts(tmp_path: Path) -> None:
    (tmp_path / ".recon-summary.md").write_text("# Recon\nsummary\n", encoding="utf-8")
    (tmp_path / ".route-inventory.json").write_text(
        json.dumps(
            {
                "version": 1,
                "routes": [_route(1)],
                "coverage": {"frameworks_detected": ["express"], "unsupported_route_files": []},
            }
        ),
        encoding="utf-8",
    )

    recon, routes = context.build(tmp_path)

    assert recon == tmp_path / ".dispatch-context/architecture/recon-summary-context.json"
    assert routes == tmp_path / ".dispatch-context/architecture/route-context.json"
    jsonschema.validate(json.loads(recon.read_text()), _schema("recon-summary-context.schema.json"))
    jsonschema.validate(json.loads(routes.read_text()), _schema("architecture-route-context.schema.json"))


def test_an_llm_route_survives_the_cut_that_drops_ordinary_routes() -> None:
    """The model surface must reach the architect, or the run never sees it.

    Juice Shop's single `/rest/chat` ranked 97th of 247 on 2026-08-15 and was
    omitted. The architect then produced an inventory with no LLM component,
    and every prompt-injection and excessive-agency finding was lost with it.
    """
    routes = [_route(i) for i in range(1, 200)]
    llm = _route(200)
    llm["path"] = "/rest/chat"
    llm["relevance_tags"] = ["llm"]
    routes.append(llm)
    payload = json.dumps({"version": 1, "routes": routes, "coverage": {}}).encode()

    projected = context.project_routes(payload)

    assert len(projected["routes"]) == context.MAX_ROUTES
    assert "/rest/chat" in [row["path"] for row in projected["routes"]]
    assert "llm" in projected["limits"]["ordering_key"]


def test_the_llm_rank_is_what_retains_it_not_merely_having_a_tag() -> None:
    """Without the dedicated rank the tag alone does not survive the cut."""
    routes = [_route(i) for i in range(1, 200)]
    llm = _route(200)
    llm["relevance_tags"] = ["llm"]
    routes.append(llm)
    payload = json.dumps({"version": 1, "routes": routes, "coverage": {}}).encode()

    ranked = sorted(routes, key=context._route_order_key)
    assert ranked.index(llm) < context.MAX_ROUTES // 2, "an LLM route must rank into the guaranteed half"
