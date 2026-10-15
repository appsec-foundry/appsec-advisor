"""A route's handler chain decides its authentication, not only its registration line."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyzers.authz_confirm as ac  # noqa: E402
import analyzers.route_inventory as ri  # noqa: E402
from analyzers.handler_resolver import DECODE_ONLY_SCOPE, HandlerResolver, direct_imports  # noqa: E402

SCHEMA = json.loads((ROOT / "schemas/route-inventory.schema.json").read_text())


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def route(inventory: dict, path: str) -> dict:
    return next(r for r in inventory["routes"] if r["path"] == path)


def express_app(handler_file: str, handler_name: str, route_path: str, mounted: str = "") -> str:
    return (
        "import express from 'express'\n"
        "import bodyParser from 'body-parser'\n"
        f"import {{ {handler_name} }} from './{handler_file}'\n"
        "const app = express()\n"
        "app.use(bodyParser.json())\n"
        f"{mounted}"
        f"app.post('{route_path}', {handler_name}())\n"
    )


SESSION_HANDLER = (
    "export function {name} () {{\n"
    "  return async (req, res, next) => {{\n"
    "    const who = sessions.get(req.cookies.{cookie})\n"
    "    if (!who) {{\n"
    "      res.status(401).end()\n"
    "      return\n"
    "    }}\n"
    "    res.json({{ ok: true }})\n"
    "  }}\n"
    "}}\n"
)


@pytest.mark.parametrize(
    ("folder", "name", "cookie", "path"),
    [("handlers/notes", "saveNote", "session", "/notes"), ("api/v2/upload", "storeAvatar", "token", "/avatar/file")],
)
def test_imported_handler_with_a_session_check_authenticates_its_route(tmp_path, folder, name, cookie, path):
    write(
        tmp_path,
        {
            "server.ts": express_app(folder, name, path),
            f"{folder}.ts": SESSION_HANDLER.format(name=name, cookie=cookie),
        },
    )
    inventory = ri.build_inventory(tmp_path)
    jsonschema.validate(inventory, SCHEMA)
    row = route(inventory, path)
    assert row["authn_signal"] == "present" and row["authn_handler_signal"] == "verified"
    assert row["authn_handler_scheme"] == "cookie"
    assert row["authn_handler_evidence"] == [{"file": f"{folder}.ts", "line": 3}]
    assert not row["missing_auth_suspect"]


@pytest.mark.parametrize(
    ("server", "files", "path", "module"),
    [
        (
            "import express from 'express'\n"
            "import { getNoteView } from './routes/noteView'\n"
            "import { requireSession } from './lib/guard'\n"
            "import * as helpers from './lib/helpers'\n"
            "const app = express()\n"
            "app.get('/notes', requireSession(), helpers.catchErrors(getNoteView()))\n",
            {
                "routes/noteView.ts": "export function getNoteView () {\n  return (req, res) => res.json({})\n}\n",
                "lib/guard.ts": "export function requireSession () {\n  return (req, res, next) => next()\n}\n",
                "lib/helpers.ts": "export function catchErrors (fn) {\n  return (req, res, next) => fn(req, res, next)\n}\n",
            },
            "/notes",
            "routes/noteView.ts",
        ),
        (
            "const express = require('express')\n"
            "const { listLedger } = require('./api/ledger_rows')\n"
            "const app = express()\n"
            "app.post('/ledger', listLedger)\n",
            {
                "api/ledger_rows.js": "function listLedger (req, res) {\n  res.json([])\n}\nmodule.exports = { listLedger }\n"
            },
            "/ledger",
            "api/ledger_rows.js",
        ),
        (
            "import express from 'express'\n"
            "import listMembers from './routes/memberList'\n"
            "import * as helpers from './lib/helpers'\n"
            "const app = express()\n"
            "app.get('/members', helpers.catchErrors(listMembers()))\n",
            {
                "routes/memberList.ts": "async function loadMembers (req, res) {\n  res.json([])\n}\n\n"
                "export default () => loadMembers\n",
                "lib/helpers.ts": "export function catchErrors (fn) {\n  return (req, res, next) => fn(req, res, next)\n}\n",
            },
            "/members",
            "routes/memberList.ts",
        ),
        (
            "const express = require('express')\n"
            "import archiveExport from './api/archive-export'\n"
            "const app = express()\n"
            "app.post('/archive', archiveExport)\n",
            {"api/archive-export.js": "export default async function (req, res) {\n  res.json({})\n}\n"},
            "/archive",
            "api/archive-export.js",
        ),
    ],
)
def test_route_records_the_module_of_its_own_handler_but_not_its_guards(tmp_path, server, files, path, module):
    write(tmp_path, {"server.js": server, **files})
    inventory = ri.build_inventory(tmp_path)
    jsonschema.validate(inventory, SCHEMA)
    assert route(inventory, path).get("handler_module") == module


def test_default_exported_factory_follows_the_handler_it_returns(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": "import express from 'express'\n"
            "import viewInvoice from './billing/invoice'\n"
            "const app = express()\n"
            "app.get('/invoice', viewInvoice())\n",
            "billing/invoice.ts": "const showInvoice = async (req, res) => {\n"
            "  const who = sessions.get(req.cookies.sid)\n"
            "  if (!who) {\n"
            "    res.status(401).end()\n"
            "    return\n"
            "  }\n"
            "  res.json({ ok: true })\n"
            "}\n"
            "export default () => showInvoice\n",
        },
    )
    row = route(ri.build_inventory(tmp_path), "/invoice")
    assert row["handler_module"] == "billing/invoice.ts"
    assert row["authn_handler_signal"] == "verified" and row["authn_handler_scheme"] == "cookie"


def test_factories_returning_each_other_stay_unresolved(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": "import express from 'express'\n"
            "import pingRoute from './routes/ping'\n"
            "const app = express()\n"
            "app.get('/ping', pingRoute())\n",
            "routes/ping.ts": "const first = () => second\nconst second = () => first\nexport default () => first\n",
        },
    )
    assert route(ri.build_inventory(tmp_path), "/ping")["authn_handler_signal"] == "unresolved"


def test_an_unresolved_handler_records_no_module(tmp_path):
    write(tmp_path, {"server.js": "const app = express()\napp.get('/feed', loadFeedFromPlugin())\n"})
    assert "handler_module" not in route(ri.build_inventory(tmp_path), "/feed")


def test_fastapi_dependency_in_another_module_authenticates_its_route(tmp_path):
    write(
        tmp_path,
        {
            "service/main.py": (
                "from fastapi import FastAPI, Depends\n"
                "from service.security import current_account\n"
                "app = FastAPI()\n"
                "@app.post('/reports')\n"
                "def create_report(account = Depends(current_account)):\n"
                "    return {'ok': True}\n"
            ),
            "service/security.py": (
                "import jwt\n"
                "from fastapi import HTTPException, Header\n"
                "def current_account(authorization: str = Header()):\n"
                "    try:\n"
                "        return jwt.decode(authorization.split()[1], KEY, algorithms=['HS256'])\n"
                "    except jwt.PyJWTError:\n"
                "        raise HTTPException(status_code=401)\n"
            ),
        },
    )
    row = route(ri.build_inventory(tmp_path), "/reports")
    assert row["authn_signal"] == "present" and row["authn_handler_signal"] == "verified"
    assert row["authn_handler_evidence"] == [{"file": "service/security.py", "line": 5}]


def test_a_token_decoded_without_verification_is_not_authentication(tmp_path):
    write(
        tmp_path,
        {
            "server.js": express_app("routes/assistant", "ask", "/assistant"),
            "routes/assistant.js": (
                "const jwt = require('jsonwebtoken')\n"
                "export function ask () {\n"
                "  return (req, res) => {\n"
                "    const claims = jwt.decode(tokenFrom(req))\n"
                "    res.json({ user: claims && claims.sub })\n"
                "  }\n"
                "}\n"
                "function tokenFrom (req) { return req.headers.authorization }\n"
            ),
        },
    )
    row = route(ri.build_inventory(tmp_path), "/assistant")
    assert row["authn_signal"] == "absent" and row["authn_handler_signal"] == "decode_only"
    assert row["authn_handler_evidence"] == [{"file": "routes/assistant.js", "line": 4}]
    assert HandlerResolver(tmp_path).route_signal(row).scope() == DECODE_ONLY_SCOPE


def test_a_fully_resolved_chain_without_a_credential_is_absent(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": express_app("routes/feedback", "submit", "/feedback"),
            "routes/feedback.ts": "export function submit () {\n  return (req, res) => res.json(req.body)\n}\n",
        },
    )
    row = route(ri.build_inventory(tmp_path), "/feedback")
    assert row["authn_signal"] == "absent" and row["authn_handler_signal"] == "none"
    assert row["missing_auth_suspect"]


@pytest.mark.parametrize(
    "variant",
    ["neighbour-check", "commented-check", "dispatch-map", "unknown-package", "router-elsewhere", "conditional"],
)
def test_nothing_unproven_counts_as_authenticated_or_absent(tmp_path, variant):
    handler = "export function submit () {\n  return (req, res) => res.json(req.body)\n}\n"
    mounted = ""
    server = None
    if variant == "neighbour-check":
        handler += SESSION_HANDLER.format(name="other", cookie="session")
    elif variant == "commented-check":
        handler = (
            "export function submit () {\n  return (req, res) => {\n"
            "    // const who = sessions.get(req.cookies.session); if (!who) res.status(401)\n"
            "    res.json(req.body)\n  }\n}\n"
        )
    elif variant == "dispatch-map":
        server = express_app("routes/feedback", "submit", "/feedback").replace("submit())", "handlers[kind])")
    elif variant == "unknown-package":
        mounted = "import gate from 'corporate-gate'\napp.use(gate())\n"
    elif variant == "router-elsewhere":
        server = express_app("routes/feedback", "submit", "/feedback").replace(
            "const app = express()", "const app = makeRouter()"
        )
    else:
        server = express_app("routes/feedback", "submit", "/feedback").replace(
            "submit())", "enabled ? submit() : noop)"
        )
    write(
        tmp_path,
        {
            "server.ts": server or express_app("routes/feedback", "submit", "/feedback", mounted),
            "routes/feedback.ts": handler,
        },
    )
    row = route(ri.build_inventory(tmp_path), "/feedback")
    expected = "none" if variant in {"neighbour-check", "commented-check"} else "unresolved"
    assert row["authn_handler_signal"] == expected
    assert row["authn_signal"] == ("absent" if expected == "none" else "unknown")


def test_registration_guards_keep_their_signal(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": express_app("routes/feedback", "submit", "/feedback").replace(
                "submit())", "requireAuth, submit())"
            ),
            "routes/feedback.ts": "export function submit () {\n  return (req, res) => res.json(req.body)\n}\n",
        },
    )
    assert route(ri.build_inventory(tmp_path), "/feedback")["authn_signal"] == "middleware_present"


LIST_HANDLER = "export function listOrders () {\n  return (req, res) => res.json([])\n}\n"


@pytest.mark.parametrize(
    ("files", "path", "evidence"),
    [
        (
            {
                "lib/access.ts": "import tokenGate from 'express-jwt'\n"
                "export const requireToken = () => tokenGate(({ secret: publicKey }) as any)\n",
                "server.ts": "import express from 'express'\n"
                "import * as access from './lib/access'\n"
                "import { listOrders } from './routes/orders'\n"
                "const app = express()\n"
                "app.use('/api/orders', access.requireToken())\n"
                "app.get('/api/orders/:id', listOrders())\n",
            },
            "/api/orders/:id",
            {"file": "lib/access.ts", "line": 2},
        ),
        (
            {
                "app.js": "const express = require('express')\n"
                "const { expressjwt } = require('express-jwt')\n"
                "const { listOrders } = require('./routes/orders')\n"
                "const app = express()\n"
                "app.get('/reports', expressjwt({ secret: KEY, algorithms: ['HS256'] }), listOrders())\n",
            },
            "/reports",
            {"file": "app.js", "line": 5},
        ),
    ],
)
def test_an_authentication_package_guard_verifies_its_routes(tmp_path, files, path, evidence):
    write(tmp_path, {"routes/orders.ts": LIST_HANDLER, "routes/orders.js": LIST_HANDLER, **files})
    inventory = ri.build_inventory(tmp_path)
    jsonschema.validate(inventory, SCHEMA)
    row = route(inventory, path)
    assert row["authn_handler_signal"] == "verified" and row["authn_handler_scheme"] == "bearer"
    assert row["authn_handler_evidence"] == [evidence]
    assert row["handler_module"] in {"routes/orders.ts", "routes/orders.js"}


@pytest.mark.parametrize(
    ("imported", "mount"),
    [
        ("tokenGate from 'express-jwt'", "'/api/orders', tokenGate({ secret: KEY, credentialsRequired: false })"),
        ("tokenGate from 'express-jwt'", "'/api/orders', tokenGate(options)"),
        ("{ claimCheck } from 'express-oauth2-jwt-bearer'", "'/api/orders', claimCheck((claims) => true)"),
        ("tokenGate from 'express-jwt'", "'/admin', tokenGate({ secret: KEY })"),
    ],
    ids=["rejection-off", "options-by-name", "non-rejecting-member", "prefix-elsewhere"],
)
def test_an_authentication_package_that_may_not_reject_stays_unresolved(tmp_path, imported, mount):
    write(
        tmp_path,
        {
            "routes/orders.ts": LIST_HANDLER,
            "server.ts": "import express from 'express'\n"
            f"import {imported}\n"
            "import { listOrders } from './routes/orders'\n"
            "const app = express()\n"
            f"app.use({mount})\n"
            "app.get('/api/orders/:id', listOrders())\n",
        },
    )
    row = route(ri.build_inventory(tmp_path), "/api/orders/:id")
    assert row["authn_handler_signal"] != "verified"


def test_authz_confirm_reads_the_resolved_handler_not_the_registration_window(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": express_app("routes/avatar", "storeAvatar", "/avatar/file")
            + "function unrelated () { authenticate() }\n",
            "routes/avatar.ts": "export function storeAvatar () {\n  return (req, res) => res.json(req.body)\n}\n",
        },
    )
    inventory = ri.build_inventory(tmp_path)
    findings = ac.confirm_instances(tmp_path, inventory)
    assert [f["check_id"] for f in findings] == ["AUTHZ-302"]
    assert "authenticate" not in findings[0]["evidence_snippet"]

    write(tmp_path, {"routes/avatar.ts": SESSION_HANDLER.format(name="storeAvatar", cookie="token")})
    assert ac.confirm_instances(tmp_path, ri.build_inventory(tmp_path)) == []


HEADER_HANDLER = (
    "export function {name} () {{\n"
    "  return async (req, res) => {{\n"
    "    const who = tokens.get({read})\n"
    "    if (!who) {{\n"
    "      res.status(401).end()\n"
    "      return\n"
    "    }}\n"
    "    res.json({{ ok: true }})\n"
    "  }}\n"
    "}}\n"
)


@pytest.mark.parametrize(
    ("name", "read"),
    [
        ("loadOrders", "req.headers?.authorization"),
        ("listInvoices", "req?.headers?.['authorization']"),
        ("showProfile", "req.headers.authorization"),
    ],
)
def test_optional_chaining_reads_the_credential_like_member_access(tmp_path, name, read):
    write(
        tmp_path,
        {
            "server.ts": express_app("handlers/h", name, "/records"),
            "handlers/h.ts": HEADER_HANDLER.format(name=name, read=read),
        },
    )
    row = route(ri.build_inventory(tmp_path), "/records")
    assert row["authn_handler_signal"] == "verified"
    assert row["authn_signal"] == "present"
    assert not row["missing_auth_suspect"]


GUARD_MODULE = "export function requireSession () {\n  return (req, res, next) => next()\n}\n"


@pytest.mark.parametrize(
    ("file", "factory"),
    [
        (
            "routes/items.js",
            "module.exports.loadItem = () => async (req, res) => {\n"
            "  const item = await Item.findByPk(req.params.id)\n"
            "  if (item.ownerId !== req.user.id) return res.sendStatus(403)\n"
            "  res.json(item)\n"
            "}\n",
        ),
        (
            "routes/items.ts",
            "export const loadItem = (opts) =>\n"
            "  async (req, res) => {\n"
            "    const item = await Item.findByPk(req.params.id)\n"
            "    if (item.ownerId !== req.user.id) return res.sendStatus(403)\n"
            "    res.json(item)\n"
            "  }\n",
        ),
    ],
)
def test_a_handler_factory_yields_the_returned_handler_body(tmp_path, file, factory):
    """The ownership check sits in the handler a factory returns, below its first line."""
    write(
        tmp_path,
        {
            "server.js": "const express = require('express')\n"
            "const { requireSession } = require('./lib/guard')\n"
            f"const {{ loadItem }} = require('./{file.rsplit('.', 1)[0]}')\n"
            "const app = express()\n"
            "app.get('/items/:id', requireSession(), loadItem())\n",
            "lib/guard.js": GUARD_MODULE,
            file: factory,
        },
    )
    row = {"framework": "express", "handler_file": "server.js", "handler_line": 5, "path": "/items/:id"}
    code = HandlerResolver(tmp_path).handler_code(row)
    assert "item.ownerId !== req.user.id" in code
    assert ac.confirm_instances(tmp_path, {"routes": [{**row, "method": "GET", "missing_authz_suspect": True}]}) == []


def test_a_handler_factory_without_an_ownership_check_is_still_confirmed(tmp_path):
    write(
        tmp_path,
        {
            "server.js": "const express = require('express')\n"
            "const { requireSession } = require('./lib/guard')\n"
            "const { loadItem } = require('./routes/items')\n"
            "const app = express()\n"
            "app.get('/items/:id', requireSession(), loadItem())\n",
            "lib/guard.js": GUARD_MODULE,
            "routes/items.js": "module.exports.loadItem = () => async (req, res) => {\n"
            "  res.json(await Item.findByPk(req.params.id))\n"
            "}\n",
        },
    )
    row = {"framework": "express", "handler_file": "server.js", "handler_line": 5, "path": "/items/:id"}
    (finding,) = ac.confirm_instances(tmp_path, {"routes": [{**row, "method": "GET", "missing_authz_suspect": True}]})
    assert finding["check_id"] == "AUTHZ-301"


@pytest.mark.parametrize(
    ("guarded", "open_", "opaque"),
    [("/account", "/feedback", "/export"), ("/v1/orders", "/v1/notes", "/v1/reports")],
)
def test_coverage_counts_only_proven_absence_as_unauthenticated(tmp_path, guarded, open_, opaque):
    write(
        tmp_path,
        {
            "server.ts": (
                "import express from 'express'\n"
                "import { guardedHandler } from './routes/guarded'\n"
                "import { openHandler } from './routes/open'\n"
                "import { opaqueHandler } from 'vendor-handlers'\n"
                "const app = express()\n"
                f"app.post('{guarded}', guardedHandler())\n"
                f"app.post('{open_}', openHandler())\n"
                f"app.post('{opaque}', opaqueHandler())\n"
            ),
            "routes/guarded.ts": SESSION_HANDLER.format(name="guardedHandler", cookie="sid"),
            "routes/open.ts": "export function openHandler () {\n  return (req, res) => res.json(req.body)\n}\n",
        },
    )
    inventory = ri.build_inventory(tmp_path)
    jsonschema.validate(inventory, json.loads((ROOT / "schemas" / "route-inventory.schema.json").read_text()))
    signals = {r["path"]: r["authn_signal"] for r in inventory["routes"]}
    assert signals == {guarded: "present", open_: "absent", opaque: "unknown"}
    coverage = inventory["coverage"]
    assert (coverage["authenticated_count"], coverage["authn_absent_count"], coverage["authn_unknown_count"]) == (
        1,
        1,
        1,
    )


def test_coverage_counts_an_unresolved_chain_as_unknown_not_absent(tmp_path):
    write(
        tmp_path,
        {
            "server.ts": (
                "import express from 'express'\n"
                "import { submit } from 'vendor-handlers'\n"
                "const app = express()\n"
                "app.post('/feedback', submit())\n"
            ),
        },
    )
    coverage = ri.build_inventory(tmp_path)["coverage"]
    assert (coverage["authenticated_count"], coverage["authn_absent_count"], coverage["authn_unknown_count"]) == (
        0,
        0,
        1,
    )


@pytest.mark.parametrize(
    ("path", "text", "expected"),
    [
        (
            "routes/a.ts",
            "import x from '../lib/x'\nconst y = require('./y')\nimport z from 'pkg'\n// import w from './w'\n",
            ["lib/x.ts", "routes/y/index.js"],
        ),
        (
            "svc/api/views.py",
            "from .models import Order\nfrom ..core import auth\nimport os\n",
            ["svc/api/models.py", "svc/core/__init__.py"],
        ),
        ("app/main.py", "from app.security import check\nfrom missing import nothing\n", ["app/security.py"]),
    ],
)
def test_direct_imports_resolve_against_the_admitted_file_set(path, text, expected):
    files = {
        "lib/x.ts",
        "routes/y/index.js",
        "routes/w.ts",
        "svc/api/models.py",
        "svc/core/__init__.py",
        "app/security.py",
    }
    assert direct_imports(path, text, files.__contains__) == expected
