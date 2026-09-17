"""Access to an embedded database engine is recorded as unauthenticated with code evidence."""

import copy
import json
from pathlib import Path

import embedded_store_access as access
import jsonschema
import orchestration_controller as controller
import pytest
from validate_fragment import repository_path_errors

ROOT = Path(__file__).resolve().parents[1]


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "rel,source,line,engine",
    [
        ("models/index.ts", "const db = new Sequelize('db', 'u', 'p', {\n  dialect: 'sqlite',\n})", 2, "sqlite"),
        ("src/db.js", "module.exports = knex({ client: 'sqlite3', connection: {} })", 1, "sqlite"),
        ("app/store.py", "import sqlite3\nconnection = sqlite3.connect('app.db')", 2, "sqlite"),
        ("src/Store.java", 'var url = "jdbc:sqlite:app.db";', 1, "sqlite"),
        ("store/db.go", 'db, err := sql.Open("sqlite3", "app.db")', 1, "sqlite"),
        ("lib/db.js", "const sqlite3 = require('sqlite3')\nconst db = new sqlite3.Database('app.db')", 2, "sqlite"),
        ("lib/db.ts", "import Database from 'better-sqlite3'\nconst db = new Database('app.db')", 2, "sqlite"),
        (
            "data/docs.ts",
            "import * as Mars from 'marsdb'\nexport const posts = new Mars.Collection('posts')",
            2,
            "marsdb",
        ),
        ("lib/store.js", "const Datastore = require('@seald-io/nedb')\nconst db = new Datastore({})", 2, "nedb"),
        ("lib/cache.js", "const loki = require('lokijs')\nconst db = new loki('cache.db')", 2, "lokijs"),
    ],
)
def test_runtime_instantiations_of_embedded_engines_are_found(tmp_path, rel, source, line, engine):
    _write(tmp_path, rel, source)
    assert access.instantiation_sites(tmp_path) == [access.Site(rel, line, engine)]


@pytest.mark.parametrize(
    "rel,source",
    [
        ("src/db.ts", "// dialect: 'sqlite'"),
        ("tests/db.test.ts", "new Sequelize({ dialect: 'sqlite' })"),
        ("src/db.ts", "new Sequelize({ dialect: 'postgres' })"),
        ("src/db.ts", "const env = isTest ? 'sqlite' : 'postgres'"),
        ("src/db.js", "const PouchDB = require('pouchdb')\nconst db = new PouchDB('https://host/db')"),
        ("src/db.js", "import * as Mars from 'marsdb'\nconst other = new Mars.Cursor()"),
        ("src/db.js", "const db = new Database('app.db')"),
    ],
)
def test_comments_tests_network_engines_and_unrelated_constructors_are_ignored(tmp_path, rel, source):
    _write(tmp_path, rel, source)
    assert access.instantiation_sites(tmp_path) == []


def _repo(tmp_path):
    _write(tmp_path, "models/index.ts", "export const db = new Sequelize('db', 'u', 'p', {\n  dialect: 'sqlite',\n})\n")
    _write(tmp_path, "routes/login.ts", "export const login = () => User.findOne()\n")
    return tmp_path


def _flow(fid, source, target, *evidence, **extra):
    return {
        "id": fid,
        "from": source,
        "to": target,
        "label": "Record access",
        "protocol": "in-process ORM",
        "data_classification": "Restricted",
        "direction": "request-response",
        "evidence": [{"file": file, "line": line} for file, line in evidence],
        "provenance": "architecture",
        **extra,
    }


def _document(*flows):
    return {"schema_version": 1, "component_inventory_fingerprint": "sha256:" + "a" * 64, "data_flows": list(flows)}


def _components(**store):
    return [
        {"id": "api", "tier": "application", "paths": ["routes/**"]},
        {"id": "store", "tier": "data", "paths": ["data/schema.sql"], **store},
    ]


UNKNOWN = {"scheme": "unknown", "scope": "Not located", "evidence": [{"file": "routes/login.ts", "line": 1}]}


@pytest.mark.parametrize(
    "store,flows,marked",
    [
        # A flow citing the constructor links the store; every open access into it is recorded.
        (
            {},
            [
                _flow("df-001", "api", "store", ("models/index.ts", 1)),
                _flow("df-002", "api", "store", ("routes/login.ts", 1)),
            ],
            {"df-001", "df-002"},
        ),
        ({"paths": ["models/**"]}, [_flow("df-001", "api", "store", ("routes/login.ts", 1))], {"df-001"}),
        ({"framework": "SQLite 3"}, [_flow("df-001", "api", "store", ("routes/login.ts", 1))], {"df-001"}),
        ({"framework": "sequelize"}, [_flow("df-001", "api", "store", ("models/index.ts", 2))], {"df-001"}),
        ({}, [_flow("df-001", "api", "store", ("models/index.ts", 2), authentication=UNKNOWN)], set()),
        ({"framework": "PostgreSQL"}, [_flow("df-001", "api", "store", ("models/index.ts", 2))], set()),
        ({}, [_flow("df-001", "api", "store", ("routes/login.ts", 1))], set()),
        ({"tier": "application"}, [_flow("df-001", "api", "store", ("models/index.ts", 2))], set()),
    ],
)
def test_open_accesses_to_linked_embedded_stores_record_no_authentication(tmp_path, store, flows, marked):
    repo = _repo(tmp_path)
    document = _document(*flows)
    before = copy.deepcopy(document)
    result = access.record_embedded_access(repo, _components(**store), document)
    assert document == before
    changed = {f["id"] for f, b in zip(result["data_flows"], before["data_flows"]) if f != b}
    assert changed == marked
    for flow in result["data_flows"]:
        if flow["id"] in marked:
            assert flow["authentication"]["scheme"] == "none"
            assert flow["authentication"]["evidence"] == [{"file": "models/index.ts", "line": 2}]
            assert "SQLite" in flow["authentication"]["scope"]
    schema = json.loads((ROOT / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert repository_path_errors("data-flows", result, repo) == []


def test_controller_handoff_records_embedded_access(tmp_path):
    repo, out = _repo(tmp_path / "repo"), tmp_path / "out"
    out.mkdir()
    components = _components(paths=["models/**"])
    receipt = {"component_inventory_fingerprint": "sha256:" + "a" * 64, "component_ids": ["api", "store"]}
    (out / ".components.json").write_text(json.dumps({"components": components}))
    (out / ".component-inventory-finalization.json").write_text(json.dumps(receipt))
    (out / ".data-flows.json").write_text(
        json.dumps(_document(_flow("df-001", "api", "store", ("routes/login.ts", 1))))
    )
    controller._bind_finalized_component_fingerprint(out, repo)
    flow = json.loads((out / ".data-flows.json").read_text())["data_flows"][0]
    assert flow["authentication"]["scheme"] == "none"
