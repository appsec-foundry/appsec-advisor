"""Unit tests for scripts/extract_data_relations.py.

Covers ORM detection, model extraction (Sequelize/Mongoose/TypeORM), raw-query
collection, association linking, route→model linking, source-file gathering with
exclusions, and the main() CLI for both ORM-present and no-ORM repos.
"""

from __future__ import annotations

import json
from pathlib import Path

import extract_data_relations as edr


# ---------------------------------------------------------------------------
# detect_orms
# ---------------------------------------------------------------------------
class TestDetectOrms:
    def test_detects_sequelize_and_mongoose(self, tmp_path):
        f1 = tmp_path / "a.ts"
        f1.write_text("import { Model } from 'sequelize'\n")
        f2 = tmp_path / "b.js"
        f2.write_text("const mongoose = require('mongoose')\n")
        assert edr.detect_orms(tmp_path, [f1, f2]) == ["mongoose", "sequelize"]

    def test_typeorm_and_prisma(self, tmp_path):
        f = tmp_path / "c.ts"
        f.write_text("import {Entity} from 'typeorm'\nimport {x} from '@prisma/client'\n")
        assert edr.detect_orms(tmp_path, [f]) == ["prisma", "typeorm"]

    def test_none_when_no_orm(self, tmp_path):
        f = tmp_path / "plain.ts"
        f.write_text("export const x = 1\n")
        assert edr.detect_orms(tmp_path, [f]) == ["none"]

    def test_unreadable_file_skipped(self, tmp_path):
        missing = tmp_path / "does-not-exist.ts"  # read_text raises OSError → skip
        assert edr.detect_orms(tmp_path, [missing]) == ["none"]


# ---------------------------------------------------------------------------
# find_models
# ---------------------------------------------------------------------------
class TestFindModels:
    def test_sequelize_define(self, tmp_path):
        f = tmp_path / "models" / "user.ts"
        f.parent.mkdir()
        f.write_text("const User = sequelize.define('User', {})\n")
        models = edr.find_models(tmp_path, [f])
        assert "User" in models
        assert models["User"].model_file == "models/user.ts"

    def test_sequelize_class_extends_model(self, tmp_path):
        f = tmp_path / "basket.ts"
        f.write_text("export class Basket extends Model {}\n")
        models = edr.find_models(tmp_path, [f])
        assert "Basket" in models

    def test_mongoose_model(self, tmp_path):
        f = tmp_path / "review.js"
        f.write_text("module.exports = mongoose.model('Review', schema)\n")
        models = edr.find_models(tmp_path, [f])
        assert "Review" in models

    def test_typeorm_entity(self, tmp_path):
        f = tmp_path / "product.ts"
        f.write_text("@Entity()\nexport class Product {}\n")
        models = edr.find_models(tmp_path, [f])
        assert "Product" in models

    def test_unreadable_skipped(self, tmp_path):
        assert edr.find_models(tmp_path, [tmp_path / "nope.ts"]) == {}


# ---------------------------------------------------------------------------
# collect_raw_queries
# ---------------------------------------------------------------------------
class TestCollectRawQueries:
    def test_finds_raw_query_with_line_and_snippet(self, tmp_path):
        f = tmp_path / "routes" / "login.ts"
        f.parent.mkdir()
        f.write_text(
            "function a() {\n"
            "  return sequelize.query('SELECT * FROM Users WHERE name=' + n)\n"
            "}\n"
        )
        out = edr.collect_raw_queries(tmp_path, [f])
        assert len(out) == 1
        assert out[0]["file"] == "routes/login.ts"
        assert out[0]["line"] == 2
        assert "SELECT" in out[0]["snippet"]

    def test_raw_query_at_eof_no_trailing_newline(self, tmp_path):
        f = tmp_path / "q.ts"
        f.write_text("conn.query(`SELECT 1`)")  # no trailing newline → line_end == -1 path
        out = edr.collect_raw_queries(tmp_path, [f])
        assert len(out) == 1
        assert out[0]["line"] == 1

    def test_no_matches(self, tmp_path):
        f = tmp_path / "clean.ts"
        f.write_text("const x = 1\n")
        assert edr.collect_raw_queries(tmp_path, [f]) == []

    def test_unreadable_skipped(self, tmp_path):
        assert edr.collect_raw_queries(tmp_path, [tmp_path / "x.ts"]) == []


# ---------------------------------------------------------------------------
# collect_associations
# ---------------------------------------------------------------------------
class TestCollectAssociations:
    def test_populates_associations(self, tmp_path):
        f = tmp_path / "user.ts"
        f.write_text(
            "User.hasMany(models.Address)\n"
            "User.belongsTo(Basket)\n"
            "User.hasOne(User)\n"  # self-ref ignored
        )
        models = {"User": edr.ModelInfo(name="User", model_file="user.ts")}
        edr.collect_associations(tmp_path, [f], models)
        assert models["User"].associations == ["Address", "Basket"]

    def test_no_owner_in_file_noop(self, tmp_path):
        f = tmp_path / "other.ts"
        f.write_text("User.hasMany(Address)\n")
        models = {"User": edr.ModelInfo(name="User", model_file="user.ts")}
        edr.collect_associations(tmp_path, [f], models)
        assert models["User"].associations == []

    def test_unreadable_skipped(self, tmp_path):
        models = {"User": edr.ModelInfo(name="User", model_file="user.ts")}
        edr.collect_associations(tmp_path, [tmp_path / "missing.ts"], models)
        assert models["User"].associations == []


# ---------------------------------------------------------------------------
# link_routes_to_models
# ---------------------------------------------------------------------------
class TestLinkRoutes:
    def test_route_consumer_and_raw_caller(self, tmp_path):
        routes = tmp_path / "routes"
        routes.mkdir()
        rf = routes / "basket.ts"
        rf.write_text(
            "import {Basket} from '../models/basket'\n"
            "Basket.findAll()\n"
            "sequelize.query('SELECT * FROM Basket')\n"
        )
        models = {"Basket": edr.ModelInfo(name="Basket", model_file="models/basket.ts")}
        raw = [{"file": "routes/basket.ts", "line": 3, "snippet": "sequelize.query('SELECT * FROM Basket')"}]
        edr.link_routes_to_models(tmp_path, routes, models, raw)
        info = models["Basket"]
        assert "routes/basket.ts" in info.route_consumers
        assert len(info.raw_query_callers) == 1
        assert info.raw_query_callers[0]["line"] == 3

    def test_missing_routes_dir_noop(self, tmp_path):
        models = {"X": edr.ModelInfo(name="X", model_file="x.ts")}
        edr.link_routes_to_models(tmp_path, tmp_path / "no-routes", models, [])
        assert models["X"].route_consumers == []

    def test_dedup_caller(self, tmp_path):
        routes = tmp_path / "routes"
        routes.mkdir()
        rf = routes / "r.ts"
        rf.write_text("Item raw\n")
        models = {"Item": edr.ModelInfo(name="Item", model_file="m.ts")}
        q = {"file": "routes/r.ts", "line": 1, "snippet": "item stuff"}
        # same query passed twice should dedup on (file, line)
        edr.link_routes_to_models(tmp_path, routes, models, [q, q])
        assert len(models["Item"].raw_query_callers) == 1

    def test_unreadable_route_skipped(self, tmp_path, monkeypatch):
        routes = tmp_path / "routes"
        routes.mkdir()
        rf = routes / "good.ts"
        rf.write_text("X here\n")
        models = {"X": edr.ModelInfo(name="X", model_file="x.ts")}

        orig = Path.read_text

        def boom(self, *a, **k):
            if self.name == "good.ts":
                raise OSError("nope")
            return orig(self, *a, **k)

        monkeypatch.setattr(Path, "read_text", boom)
        edr.link_routes_to_models(tmp_path, routes, models, [])
        assert models["X"].route_consumers == []


# ---------------------------------------------------------------------------
# gather_source_files
# ---------------------------------------------------------------------------
class TestGatherSourceFiles:
    def test_includes_source_excludes_junk(self, tmp_path):
        (tmp_path / "app.ts").write_text("x")
        (tmp_path / "main.jsx").write_text("x")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "dep.js").write_text("x")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "a.ts").write_text("x")
        (tmp_path / "types.d.ts").write_text("x")
        (tmp_path / "a.test.ts").write_text("x")
        (tmp_path / "bundle.min.js").write_text("x")
        (tmp_path / "README.md").write_text("x")

        files = {p.name for p in edr.gather_source_files(tmp_path)}
        assert files == {"app.ts", "main.jsx"}


# ---------------------------------------------------------------------------
# main() — direct calls
# ---------------------------------------------------------------------------
class TestMain:
    def test_no_orm_repo(self, tmp_path, capsys):
        (tmp_path / "app.ts").write_text("export const x = 1\n")
        out = tmp_path / "rel.json"
        rc = edr.main([str(tmp_path), "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["orm_detected"] == []
        assert data["models"] == {}
        assert "no ORM patterns" in data["note"]

    def test_full_orm_repo(self, tmp_path):
        models = tmp_path / "models"
        models.mkdir()
        (models / "user.ts").write_text(
            "import {Model} from 'sequelize'\n"
            "export class User extends Model {}\n"
            "User.hasMany(Basket)\n"
        )
        (models / "basket.ts").write_text(
            "import {Model} from 'sequelize'\n"
            "export class Basket extends Model {}\n"
        )
        routes = tmp_path / "routes"
        routes.mkdir()
        (routes / "basket.ts").write_text(
            "import {Basket} from '../models/basket'\n"
            "sequelize.query('SELECT * FROM Basket WHERE id=' + id)\n"
        )
        out = tmp_path / "out.json"
        rc = edr.main([str(tmp_path), "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["orm_detected"] == ["sequelize"]
        assert "User" in data["models"]
        assert "Basket" in data["models"]
        assert "Basket" in data["models"]["User"]["associations"]
        assert any("SELECT" in q["snippet"] for q in data["raw_query_routes"])

    def test_default_output_path(self, tmp_path):
        (tmp_path / "app.ts").write_text("x = 1\n")
        rc = edr.main([str(tmp_path), "--quiet"])
        assert rc == 0
        default = tmp_path / "docs" / "security" / ".fragments" / "data-relations.json"
        assert default.is_file()

    def test_not_a_directory_returns_2(self, tmp_path, capsys):
        f = tmp_path / "afile"
        f.write_text("x")
        rc = edr.main([str(f)])
        assert rc == 2
        assert "not a directory" in capsys.readouterr().err

    def test_quiet_suppresses_stderr(self, tmp_path, capsys):
        (tmp_path / "app.ts").write_text("x = 1\n")
        edr.main([str(tmp_path), "--output", str(tmp_path / "o.json"), "--quiet"])
        assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# CLI via subprocess (covers __main__ dispatch)
# ---------------------------------------------------------------------------
class TestCli:
    def test_cli_runs(self, run_plugin_script, tmp_path):
        (tmp_path / "app.ts").write_text("import {x} from 'mongoose'\n")
        out = tmp_path / "cli.json"
        res = run_plugin_script(
            "extract_data_relations.py",
            str(tmp_path),
            "--output",
            str(out),
        )
        assert res.returncode == 0
        assert out.is_file()
        data = json.loads(out.read_text())
        assert "mongoose" in data["orm_detected"]
