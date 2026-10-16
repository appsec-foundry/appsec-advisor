"""Serving units must reach the component inventory, or the run stops."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyzers import serving_units
from analyzers.route_inventory import build_inventory as route_inventory
from contexts import multi_repo_analysis as analysis
from model.finalize_component_inventory import finalize_assessment
from model.reclassify_components import _primary_component_id
from runtime import multi_repo_discovery as discovery
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER, ModelAnswerFailure
from runtime.multi_repo_scope import admit

# An Express API whose handlers live in their own modules, beside a browser
# app in its own package, plus code that must never form or feed a unit.
NODE = {
    "package.json": json.dumps({"name": "shop", "dependencies": {"express": "4.18.0"}}),
    "server.js": "const express = require('express')\nconst orders = require('./handlers/orders')\n"
    "const app = express()\napp.get('/orders/:id', orders.show)\napp.listen(3000)\n",
    "handlers/orders.js": "function show(req, res) { res.json({ id: req.params.id }) }\nmodule.exports = { show }\n",
    "test/server.test.js": "const app = require('express')()\napp.get('/probe', (req, res) => res.end())\n",
    "web/package.json": json.dumps({"name": "web", "dependencies": {"@angular/core": "17.0.0"}}),
    "web/eslint.config.mjs": "export default []\n",
    "web/src/main.ts": "import { bootstrap } from './app/app'\nbootstrap()\n",
    "web/src/app/app.ts": "export function bootstrap() { document.title = 'shop' }\n",
    "web/src/app/app.spec.ts": "import { bootstrap } from './app'\n",
}
# The same mechanism with other names and another stack: a Flask service in a
# subpackage and a React client.
PYTHON = {
    "service/pyproject.toml": "[project]\nname = 'ledger'\n",
    "service/api.py": "from flask import Flask\nfrom service.views import entries\n"
    "app = Flask(__name__)\n\n@app.route('/entries')\ndef list_entries():\n    return entries()\n",
    "service/views.py": "def entries():\n    return []\n",
    "client/package.json": json.dumps({"name": "client", "dependencies": {"react-dom": "18.2.0"}}),
    "client/src/index.jsx": "import { render } from 'react-dom'\nrender(null, document.body)\n",
}
# A library: no route registration outside tests, no browser framework.
LIBRARY = {
    "package.json": json.dumps({"name": "lib", "dependencies": {"lodash": "4.17.21"}}),
    "src/index.js": "module.exports = (value) => value * 2\n",
    "examples/server.js": "const app = require('express')()\napp.get('/demo', (req, res) => res.end())\n",
}


def write(root: Path, files: dict[str, str]) -> Path:
    root.mkdir()
    for relative, content in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(content)
    return root


def units_of(root: Path) -> list[dict]:
    return serving_units.scan(root, route_inventory(root)["routes"])


def test_api_and_client_app_are_named_without_test_or_tooling_files(tmp_path):
    units = units_of(write(tmp_path / "shop", NODE))
    assert [(u["id"], u["kind"]) for u in units] == [("http-api:.", "http-api"), ("client-app:web", "client-app")]
    assert units[0]["entry_files"] == ["server.js"]
    assert units[1]["entry_files"] == ["web/src/main.ts", "web/src/app/app.ts"]


def test_another_stack_in_subpackages_forms_the_same_units(tmp_path):
    units = units_of(write(tmp_path / "ledger", PYTHON))
    assert [(u["id"], u["entry_files"]) for u in units] == [
        ("http-api:service", ["service/api.py"]),
        ("client-app:client", ["client/src/index.jsx"]),
    ]


def test_a_library_has_no_serving_unit(tmp_path):
    assert units_of(write(tmp_path / "lib", LIBRARY)) == []


def test_only_an_eligible_tier_carries_a_unit_and_carriers_receive_their_code(tmp_path):
    root = write(tmp_path / "shop", NODE)
    routes = route_inventory(root)["routes"]
    units = serving_units.scan(root, routes)
    store = {"id": "store", "tier": "data", "paths": ["server.js", "web/src/main.ts"]}
    assert serving_units.uncovered(units, [store]) == units
    api = {"id": "api", "tier": "application", "paths": ["server.js"]}
    ui = {"id": "ui", "tier": "client", "paths": ["web/src/main.ts"]}
    components = [store, api, ui]
    assert serving_units.uncovered(units, components) == []
    assert serving_units.adopt(units, components, root, routes) == 2
    assert api["paths"] == ["server.js", "handlers/orders.js"]
    assert ui["paths"] == ["web/src/main.ts", "web/src/app/app.ts"]


def test_projection_is_bounded_and_drops_paths_it_cannot_carry(tmp_path):
    units = [
        {
            "id": f"http-api:svc{i}",
            "kind": "http-api",
            "root": f"svc{i}",
            "framework": "express",
            "entry_files": ["../escape.js", *[f"svc{i}/r{j}.js" for j in range(12)]],
        }
        for i in range(20)
    ]
    projected = serving_units.project(units)
    assert len(projected["units"]) == serving_units.MAX_UNITS
    assert projected["limits"]["omitted_units"] == 20 - serving_units.MAX_UNITS
    first = projected["units"][0]
    assert first["entry_files"] == [f"svc0/r{j}.js" for j in range(serving_units.MAX_ENTRY_FILES)]
    assert first["omitted_entry_files"] == 13 - serving_units.MAX_ENTRY_FILES


def test_a_data_store_is_never_the_primary_component():
    components = [
        {"id": "store", "tier": "data", "paths": ["models/index.ts"]},
        {"id": "api", "tier": "application", "paths": ["routes/orders.ts"]},
    ]
    assert _primary_component_id(components) == "api"
    assert _primary_component_id([{**components[1], "paths": ["server.ts"]}, components[0]]) == "api"


def admitted(tmp_path, files):
    root = write(tmp_path / "shop", files)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    identity = ["-c", "user.name=Test", "-c", "user.email=test@example.invalid"]
    subprocess.run(["git", "-C", str(root), *identity, "commit", "-q", "--allow-empty", "-m", "initial"], check=True)
    return admit([str(root)], str(tmp_path / "out"), minimum=1)


def discovered(scope, components):
    return [
        {
            "schema_version": 1,
            "repository_id": scope.repositories[0].repository_id,
            "components": components,
            "interfaces": [],
        }
    ]


def test_finalization_stops_when_a_serving_unit_has_no_component(tmp_path):
    scope = admitted(tmp_path, NODE)
    only_api = [
        {"id": "api", "name": "API", "description": "Request handling", "tier": "application", "paths": ["server.js"]}
    ]
    with pytest.raises(ValueError, match="client-app at web"):
        finalize_assessment(scope, discovered(scope, only_api))


def test_finalization_gives_the_api_its_handler_modules(tmp_path):
    scope = admitted(tmp_path, NODE)
    components = [
        {"id": "api", "name": "API", "description": "Request handling", "tier": "application", "paths": ["server.js"]},
        {"id": "ui", "name": "Web", "description": "Browser app", "tier": "client", "paths": ["web/src/main.ts"]},
    ]
    result, _receipt = finalize_assessment(scope, discovered(scope, components))
    paths = {c["local_id"]: {p["path"] for p in c["paths"]} for c in result["components"]}
    assert {"server.js", "handlers/orders.js"} <= paths["api"]
    assert {"web/src/main.ts", "web/src/app/app.ts"} <= paths["ui"]
    assert not any("test/" in p or p.endswith(".spec.ts") for owned in paths.values() for p in owned)


class Host:
    """Reads one entry file, then answers with the scripted component lists in turn."""

    def __init__(self, answers):
        self.answers, self.reasons = list(answers), []

    def factory(self, ceiling):
        return self

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        rid = packet["context"]["repository_id"]
        if "rejected_result" in packet:
            self.reasons.append(packet["rejected_result"]["reason"])
        if not packet["source_slices"]:
            reads = [
                {"repository_id": rid, "path": path, "start_line": 1, "end_line": 2}
                for path in ("server.js", "web/src/main.ts")
            ]
            return HostReply({"action": "read", "artifact": None, "reads": reads}, 0.01)
        artifact = {"schema_version": 1, "repository_id": rid, "components": self.answers.pop(0), "interfaces": []}
        return HostReply({"action": "complete", "reads": [], "artifact": artifact}, 0.01)


API = {"id": "api", "name": "API", "description": "Request handling", "tier": "application", "paths": ["server.js"]}
UI = {"id": "ui", "name": "Web", "description": "Browser app", "tier": "client", "paths": ["web/src/main.ts"]}


def run_discovery(scope, host):
    root = scope.repositories[0].root
    inventory = {"serving_units": serving_units.project(units_of(root))}
    return discovery.discover(
        scope,
        host_factory=host.factory,
        budget=discovery.DiscoveryBudget(max_usd=1.0, call_usd=0.1, max_calls=12, timeout_s=60),
        should_stop=lambda: False,
        inventories={scope.repositories[0].repository_id: inventory},
    )


def test_discovery_gets_one_correction_naming_the_missing_unit(tmp_path):
    scope = admitted(tmp_path, NODE)
    host = Host([[API], [API, UI]])
    result = run_discovery(scope, host)
    assert [c["id"] for c in result.observations[0]["components"]] == ["api", "ui"]
    assert len(host.reasons) == 1 and "client-app at web" in host.reasons[0]


def test_discovery_that_never_carries_the_unit_fails(tmp_path):
    scope = admitted(tmp_path, NODE)
    with pytest.raises(ModelAnswerFailure, match="client-app at web"):
        run_discovery(scope, Host([[API], [API], [API]]))


def local_artifact(roles):
    entities = [
        {"id": role, "name": role, "kind": "legitimate-role", "description": "User", "evidence": []} for role in roles
    ]
    flows = [{"id": "df-001", "from": "external", "from_entity": roles[0], "to": "api"}] if roles else []
    return {"external_entities": entities, "data_flows": flows}


ENTRY = {"file": "web/src/main.ts", "line": 2, "repository_id": "repo-0123456789abcdef", "sha256": "0" * 64}


def test_the_sole_regular_role_uses_each_client_once():
    artifact = analysis.add_client_use(local_artifact(["ext-customer"]), {"ui": ENTRY})
    [use] = [f for f in artifact["data_flows"] if f.get("interaction")]
    assert (use["id"], use["from_entity"], use["to"], use["evidence"]) == ("df-002", "ext-customer", "ui", [ENTRY])
    assert analysis.add_client_use(artifact, {"ui": ENTRY})["data_flows"] == artifact["data_flows"]


def test_a_privileged_role_does_not_make_the_user_ambiguous():
    artifact = local_artifact(["ext-customer"])
    artifact["external_entities"].append(
        {"id": "ext-admin", "name": "Admin", "kind": "legitimate-role", "access": "internet-priv-user"}
    )
    uses = [f for f in analysis.add_client_use(artifact, {"ui": ENTRY})["data_flows"] if f.get("interaction")]
    assert [u["from_entity"] for u in uses] == ["ext-customer"]


@pytest.mark.parametrize("roles", [[], ["ext-buyer", "ext-seller"]])
def test_without_one_unambiguous_role_the_client_use_stays_with_the_model(roles):
    artifact = local_artifact(roles)
    assert not any(f.get("interaction") for f in analysis.add_client_use(artifact, {"ui": ENTRY})["data_flows"])


def test_client_entry_evidence_cites_the_ui_mount_in_the_carrier(tmp_path):
    scope = admitted(tmp_path, NODE)
    rid = scope.repositories[0].repository_id
    root = scope.repositories[0].root

    def qualified(cid, tier, paths):
        return {"id": cid, "tier": tier, "paths": [{"repository_id": rid, "path": p} for p in paths]}

    local = [qualified("api", "application", ["server.js"]), qualified("ui", "client", ["web/src/main.ts"])]
    evidence = analysis.client_entry_evidence(scope, rid, local, units_of(root))
    assert set(evidence) == {"ui"}
    assert (evidence["ui"]["file"], evidence["ui"]["line"]) == ("web/src/main.ts", 2)
