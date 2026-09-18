"""A route's handler chain decides its authentication, not only its registration line."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import authz_confirm as ac  # noqa: E402
import route_inventory as ri  # noqa: E402
from handler_resolver import DECODE_ONLY_SCOPE, HandlerResolver  # noqa: E402

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
