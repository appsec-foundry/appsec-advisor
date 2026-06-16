"""Tests for scripts/route_inventory.py (arch.md §Route Inventory MVP)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "route_inventory.py"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "route-inventory.schema.json").read_text())


sys.path.insert(0, str(REPO_ROOT / "scripts"))
import route_inventory as ri  # noqa: E402


def _run(repo_root: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo_root), "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Per-framework extraction
# ---------------------------------------------------------------------------


def test_express_method_routes(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/users', handler);\n"
        "app.post('/users', handler);\n"
        "app.delete('/users/:id', handler);\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/users") in methods_paths
    assert ("POST", "/users") in methods_paths
    assert ("DELETE", "/users/:id") in methods_paths
    assert "express" in inv["coverage"]["frameworks_detected"]


def test_fastapi_decorator(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app/routes.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "@router.get('/items/{id}')\n"
        "def get_item(id: int):\n"
        "    return {}\n"
        "@router.post('/items')\n"
        "def create(): return {}\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/items/{id}") in methods_paths
    assert ("POST", "/items") in methods_paths
    assert "fastapi" in inv["coverage"]["frameworks_detected"]


def test_flask_methods_kwarg(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/login', methods=['POST', 'GET'])\n"
        "def login(): return 'ok'\n"
    )
    inv = _run(tmp_path)
    methods = {r["method"] for r in inv["routes"] if r["path"] == "/login"}
    assert {"GET", "POST"}.issubset(methods)


def test_spring_get_mapping(tmp_path: Path) -> None:
    (tmp_path / "src/main/java/com/example").mkdir(parents=True)
    (tmp_path / "src/main/java/com/example/Api.java").write_text(
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class Api {\n"
        '  @GetMapping("/api/users")\n'
        '  public String users() { return "[]"; }\n'
        '  @DeleteMapping("/api/users/{id}")\n'
        "  public void delete(@PathVariable Long id) {}\n"
        "}\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/api/users") in methods_paths
    assert ("DELETE", "/api/users/{id}") in methods_paths
    assert "spring" in inv["coverage"]["frameworks_detected"]


def test_aspnet_minimal_apis(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Program.cs").write_text(
        "var app = WebApplication.CreateBuilder(args).Build();\n"
        'app.MapGet("/items", () => "ok");\n'
        'app.MapPost("/items", (Item i) => i);\n'
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/items") in methods_paths
    assert ("POST", "/items") in methods_paths
    assert "aspnet-minimal" in inv["coverage"]["frameworks_detected"]


def test_javascript_framework_detection_and_nestjs_decorators() -> None:
    fastify = ri._extract_javascript(
        Path("api.ts"), ["const fastify = require('fastify')();\n", "fastify.get('/fast', h);\n"]
    )
    koa = ri._extract_javascript(Path("api.ts"), ["import Router from 'koa-router';\n", "router.get('/koa', h);\n"])
    hapi = ri._extract_javascript(
        Path("api.ts"), ["const hapi = require('@hapi/hapi');\n", "server.get('/hapi', h);\n"]
    )
    nest = ri._extract_javascript(
        Path("controller.ts"),
        [
            "@Controller('/base')\n",
            "export class C {\n",
            "  @Get()\n",
            "  list() {}\n",
            "  @Post('/items')\n",
            "  create() {}\n",
            "}\n",
        ],
    )

    assert fastify[0].framework == "fastify"
    assert koa[0].framework == "koa"
    assert hapi[0].framework == "hapi"
    assert {(r.method, r.path, r.framework) for r in nest} == {
        ("GET", "/", "nestjs"),
        ("POST", "/items", "nestjs"),
    }


def test_python_django_and_default_route_methods() -> None:
    flask = ri._extract_python(
        Path("app.py"),
        ["from flask import Flask\n", "@app.route('/default')\n", "def default(): pass\n"],
    )
    django = ri._extract_python(
        Path("urls.py"),
        [
            "from django.urls import path\n",
            "urlpatterns = [\n",
            "  path('admin/', admin_view),\n",
            "  re_path('', empty_view),\n",
            "]\n",
        ],
    )

    assert flask[0].method == "GET"
    assert flask[0].path == "/default"
    assert django[0].framework == "django"
    assert django[0].method == "ANY"
    assert django[0].path == "admin/"


def test_java_jaxrs_path_and_http_method_lookahead() -> None:
    routes = ri._extract_java(
        Path("Api.java"),
        [
            "import javax.ws.rs.Path;\n",
            '@Path("/orders")\n',
            "@POST\n",
            "public Response create() { return ok(); }\n",
            '@Path("/status")\n',
            "public Response status() { return ok(); }\n",
        ],
    )

    by_path = {r.path: r for r in routes}
    assert by_path["/orders"].framework == "jaxrs"
    assert by_path["/orders"].method == "POST"
    assert by_path["/status"].method == "ANY"


def test_aspnet_map_methods_collapses_to_any() -> None:
    routes = ri._extract_aspnet(Path("Program.cs"), ['app.MapMethods("/bulk", new[] { "GET", "POST" }, h);\n'])
    assert routes[0].method == "ANY"


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


def test_management_surface_detected(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/admin/users', h);\n"
        "app.get('/metrics', h);\n"
        "app.get('/api/items', h);\n"
        "app.get('/swagger', h);\n"
    )
    inv = _run(tmp_path)
    mgmt = {r["path"] for r in inv["routes"] if r["management_surface"]}
    not_mgmt = {r["path"] for r in inv["routes"] if not r["management_surface"]}
    assert "/admin/users" in mgmt
    assert "/metrics" in mgmt
    assert "/swagger" in mgmt
    assert "/api/items" in not_mgmt


def test_authn_signal_from_nearby_middleware(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "import express from 'express';\n"
        "const router = express.Router();\n"
        "router.use(requireAuth);\n"
        "router.get('/orders', h);\n"
    )
    inv = _run(tmp_path)
    orders = [r for r in inv["routes"] if r["path"] == "/orders"][0]
    assert orders["authn_signal"] == "middleware_present"


def test_authn_signal_defaults_to_unknown(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("import express from 'express';\nconst app = express();\napp.get('/public', h);\n")
    inv = _run(tmp_path)
    public = [r for r in inv["routes"] if r["path"] == "/public"][0]
    assert public["authn_signal"] == "unknown"
    assert public["authz_signal"] == "unknown"


def test_prefix_mounted_guard_marks_routes_protected(tmp_path: Path) -> None:
    """Express apps (e.g. Juice Shop) protect whole path prefixes via
    `app.use('/path', security.isAuthorized())` separate from the handler.
    The cross-file prefix pass must mark those routes protected (fixes the
    2026-05-31 'every route auth=unknown' miss)."""
    (tmp_path / "server.ts").write_text(
        "app.use('/api/BasketItems', security.isAuthorized());\napp.get('/api/Users', security.isAuthorized());\n"
    )
    (tmp_path / "routes.ts").write_text(
        "router.get('/api/BasketItems/:id', h);\n"  # protected by the prefix
        "router.get('/api/Products', h);\n"  # not guarded
    )
    inv = _run(tmp_path)
    by_path = {r["path"]: r for r in inv["routes"]}
    assert by_path["/api/BasketItems/:id"]["authn_signal"] == "middleware_present"
    assert by_path["/api/Users"]["authn_signal"] == "middleware_present"
    assert by_path["/api/Products"]["authn_signal"] == "unknown"


def test_missing_auth_suspect_flags_sensitive_unguarded_routes(tmp_path: Path) -> None:
    """State-changing / management routes with no detected guard are flagged as
    advisory suspects — EXCEPT auth-flow/public-by-design endpoints."""
    # Space the routes apart so the ±6-line nearby-middleware window does not
    # bleed the guarded line's `isAuthorized` onto its neighbours.
    pad = "\n" * 12
    (tmp_path / "app.ts").write_text(
        "app.put('/rest/wallet/balance', h);\n"
        + pad  # sensitive write → suspect
        + "app.get('/rest/admin/config', h);\n"
        + pad  # management → suspect
        + "app.post('/rest/user/login', h);\n"
        + pad  # auth-flow → NOT a suspect
        + "app.post('/api/Orders', security.isAuthorized());\n"
        + pad  # guarded → NOT a suspect
        + "app.get('/rest/products', h);\n"  # GET read, not mgmt → NOT a suspect
    )
    inv = _run(tmp_path)
    susp = {r["path"] for r in inv["routes"] if r["missing_auth_suspect"]}
    assert "/rest/wallet/balance" in susp
    assert "/rest/admin/config" in susp
    assert "/rest/user/login" not in susp  # public by design
    assert "/api/Orders" not in susp  # guarded
    assert "/rest/products" not in susp  # GET, non-management
    assert inv["coverage"]["missing_auth_suspect_count"] >= 2


# ---------------------------------------------------------------------------
# relevance_tags — display signal for finding-free §5 rows
# ---------------------------------------------------------------------------


def test_relevance_tags_flag_auth_registration_and_suspect_routes(tmp_path: Path) -> None:
    """A finding-free route still earns §5 visibility when it sits on the
    auth / registration / management surface or is a missing-auth/authz suspect.
    A plain authenticated read with no id and no auth-flow path carries none."""
    pad = "\n" * 12
    (tmp_path / "app.ts").write_text(
        "app.post('/rest/user/login', h);\n"  # authentication
        + pad
        + "app.post('/api/Users/register', h);\n"  # registration (+ POST, but public-by-design login/register suppresses missing-auth)
        + pad
        + "app.get('/metrics', h);\n"  # management surface
        + pad
        + "app.put('/rest/wallet/balance', h);\n"  # state-changing, unguarded → missing-auth
        + pad
        + "app.get('/rest/products', h);\n"  # plain read, no relevance
    )
    inv = _run(tmp_path)
    tags = {r["path"]: set(r.get("relevance_tags") or []) for r in inv["routes"]}
    assert "authentication" in tags["/rest/user/login"]
    assert "registration" in tags["/api/Users/register"]
    assert "management" in tags["/metrics"]
    assert "missing-auth" in tags["/rest/wallet/balance"]
    assert tags["/rest/products"] == set()  # no relevance → may be collapsed in §5


def test_relevance_tags_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("app.post('/rest/user/login', h);\napp.get('/metrics', h);\n")
    inv = _run(tmp_path)
    jsonschema.validate(inv, SCHEMA)


# ---------------------------------------------------------------------------
# Excludes
# ---------------------------------------------------------------------------


def test_excludes_node_modules(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/x', h);")
    (tmp_path / "node_modules/express/lib").mkdir(parents=True)
    (tmp_path / "node_modules/express/lib/router.js").write_text("app.get('/should-not-appear', h);")
    inv = _run(tmp_path)
    paths = {r["path"] for r in inv["routes"]}
    assert "/x" in paths
    assert "/should-not-appear" not in paths


def test_excludes_build_output(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/keep', h);")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/bundle.js").write_text("app.get('/drop', h);")
    inv = _run(tmp_path)
    paths = {r["path"] for r in inv["routes"]}
    assert "/keep" in paths
    assert "/drop" not in paths


# ---------------------------------------------------------------------------
# Schema and contract
# ---------------------------------------------------------------------------


def test_route_inventory_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/a', h);\nrouter.post('/b', h);\n")
    inv = _run(tmp_path)
    jsonschema.validate(inv, SCHEMA)


def test_route_ids_are_unique_and_sequential(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/a', h);\napp.get('/b', h);\napp.get('/c', h);\n")
    inv = _run(tmp_path)
    ids = [r["route_id"] for r in inv["routes"]]
    assert ids == sorted(set(ids))
    assert all(rid.startswith("R-") for rid in ids)


def test_empty_repo_emits_empty_routes(tmp_path: Path) -> None:
    inv = _run(tmp_path)
    assert inv["version"] == 1
    assert inv["routes"] == []
    assert inv["coverage"]["route_count"] == 0


def test_exclude_fallback_and_source_walker_filters(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ri, "_scan_is_excluded", None)
    assert ri._is_excluded("node_modules/pkg/index.js") is True
    assert ri._is_excluded("src/app.ts") is False

    def boom(_rel):
        raise RuntimeError("bad scan-excludes")

    monkeypatch.setattr(ri, "_scan_is_excluded", boom)
    assert ri._is_excluded("vendor/lib/router.js") is True

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("app.get('/x', h);\n", encoding="utf-8")
    (tmp_path / "src" / "notes.txt").write_text("app.get('/ignored', h);\n", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("app.get('/ignored', h);\n", encoding="utf-8")

    files = [p.relative_to(tmp_path).as_posix() for p in ri._walk_sources(tmp_path)]
    assert files == ["src/app.ts"]


def test_read_lines_and_extract_file_handle_empty_and_unsupported_files(tmp_path: Path) -> None:
    missing = tmp_path / "missing.ts"
    assert ri._read_lines(missing) == []

    empty = tmp_path / "empty.ts"
    empty.write_text("", encoding="utf-8")
    assert ri._extract_file(tmp_path, empty) == []

    unsupported = tmp_path / "routes.txt"
    unsupported.write_text("app.get('/ignored', h);\n", encoding="utf-8")
    assert ri._extract_file(tmp_path, unsupported) == []


def test_route_inventory_writes_to_output_dir(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/x', h);")
    out = tmp_path / "output"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output-dir", str(out)],
        capture_output=True,
        text=True,
        check=True,
    )
    target = out / ".route-inventory.json"
    assert target.is_file()
    data = json.loads(target.read_text())
    assert data["version"] == 1


def test_route_inventory_missing_repo_returns_error(tmp_path: Path, capsys) -> None:
    assert ri._main(["--repo-root", str(tmp_path / "missing"), "--stdout"]) == 1
    assert "repo-root not found" in capsys.readouterr().err


def test_build_inventory_tolerates_unreadable_source_and_dedupes_routes(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "app.ts"
    src.write_text("app.get('/x', h);\n", encoding="utf-8")

    def fake_walk(_repo_root):
        return iter([src])

    duplicate = ri.RouteCandidate(
        method="GET",
        path="/x",
        framework="express",
        handler_file="app.ts",
        handler_line=1,
    )

    monkeypatch.setattr(ri, "_walk_sources", fake_walk)
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unreadable")))
    monkeypatch.setattr(ri, "_extract_file", lambda *_args, **_kwargs: [duplicate, duplicate])

    inv = ri.build_inventory(tmp_path)

    assert inv["coverage"]["route_count"] == 1
    assert inv["routes"][0]["path"] == "/x"


# ---------------------------------------------------------------------------
# missing_authz_suspect (BOLA surface) + cross-file authZ lift
# ---------------------------------------------------------------------------


def _route(inv: dict, method: str, path: str) -> dict:
    hits = [r for r in inv["routes"] if r["method"] == method and r["path"] == path]
    assert hits, f"{method} {path} not in inventory"
    return hits[0]


def test_missing_authz_suspect_on_authenticated_object_route(tmp_path: Path) -> None:
    """Authenticated (central authN mount), object-addressing (:id), no authZ
    gate → BOLA suspect."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.get('/api/orders/:id', getOrder);\n"
        "app.put('/api/orders/:id', updateOrder);\n"
    )
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/orders/:id")["authn_signal"] == "middleware_present"
    assert _route(inv, "GET", "/api/orders/:id")["missing_authz_suspect"] is True
    assert _route(inv, "PUT", "/api/orders/:id")["missing_authz_suspect"] is True
    assert inv["coverage"]["missing_authz_suspect_count"] >= 2


def test_missing_authz_suspect_cleared_by_central_authz_mount(tmp_path: Path) -> None:
    """A centrally-mounted role guard lifts authz cross-file → not a suspect (P1b)."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.use('/api/orders', requireRole('user'));\n"
        "app.get('/api/orders/:id', getOrder);\n"
    )
    inv = _run(tmp_path)
    r = _route(inv, "GET", "/api/orders/:id")
    assert r["authz_signal"] == "middleware_present"
    assert r["missing_authz_suspect"] is False


def test_missing_authz_suspect_not_on_unauthenticated_route(tmp_path: Path) -> None:
    """Public (no authN) object route is not a BOLA suspect — precision guard."""
    (tmp_path / "app.ts").write_text("const app = express();\napp.get('/api/products/:id', getProduct);\n")
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/products/:id")["missing_authz_suspect"] is False


def test_missing_authz_suspect_not_on_collection_route(tmp_path: Path) -> None:
    """No path parameter → not object-addressing → not a suspect."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.get('/api/orders', listOrders);\n"
    )
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/orders")["missing_authz_suspect"] is False
