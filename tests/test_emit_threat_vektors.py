from __future__ import annotations

from pathlib import Path

import emit_threat_vektors as etv
import pytest
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _threat(tid: str, *, cwe: str = "CWE-89", file: str = "routes/search.ts", vektor: str | None = None) -> dict:
    threat = {
        "id": tid,
        "title": "Search endpoint injection",
        "cwe": cwe,
        "evidence": [{"file": file, "line": 12}],
    }
    if vektor is not None:
        threat["vektor"] = vektor
    return threat


def test_cwe_overrides_route_reachability(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [
                {"entry_point": "POST /api/keys", "auth_required": False},
                {"entry_point": "POST /api/comments", "auth_required": True},
            ],
            "threats": [
                _threat("T-001", cwe="CWE-321", file="routes/keys.ts"),
                _threat("T-002", cwe="CWE-79", file="routes/comments.ts"),
            ],
        },
    )

    assert etv.emit(tmp_path) == (2, 2, 0)

    by_id = {t["id"]: t for t in _read_yaml(tmp_path)["threats"]}
    assert by_id["T-001"]["vektor"] == "repo-read"
    assert by_id["T-002"]["vektor"] == "victim-required"


def test_route_auth_catalog_sets_internet_anonymous_or_user(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [
                {"entry_point": "GET /api/public-orders", "auth_required": False},
                {"entry_point": "POST /api/admin/users", "auth_required": True},
            ],
            "threats": [
                _threat("T-001", cwe="CWE-915", file="routes/publicOrdersController.ts"),
                _threat("T-002", cwe="CWE-915", file="routes/adminUsersHandler.ts"),
            ],
        },
    )

    assert etv.emit(tmp_path) == (2, 2, 0)

    by_id = {t["id"]: t for t in _read_yaml(tmp_path)["threats"]}
    assert by_id["T-001"]["vektor"] == "internet-anon"
    assert by_id["T-002"]["vektor"] == "internet-user"


def test_preserves_existing_vektor_and_is_idempotent(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [{"entry_point": "GET /api/search", "auth_required": False}],
            "threats": [
                _threat("T-001", cwe="CWE-89", file="routes/search.ts", vektor="build-time"),
                _threat("T-002", cwe="CWE-89", file="routes/search.ts"),
            ],
        },
    )

    assert etv.emit(tmp_path) == (2, 1, 1)
    first = (tmp_path / "threat-model.yaml").read_text(encoding="utf-8")
    assert etv.emit(tmp_path) == (2, 0, 2)
    second = (tmp_path / "threat-model.yaml").read_text(encoding="utf-8")

    by_id = {t["id"]: t for t in _read_yaml(tmp_path)["threats"]}
    assert by_id["T-001"]["vektor"] == "build-time"
    assert by_id["T-002"]["vektor"] == "internet-anon"
    assert first == second


def test_unmatched_route_files_default_to_authenticated_user(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [{"entry_point": "GET /api/orders", "auth_required": False}],
            "threats": [_threat("T-001", cwe="CWE-915", file="routes/adminPanel.ts")],
        },
    )

    etv.emit(tmp_path)

    assert _read_yaml(tmp_path)["threats"][0]["vektor"] == "internet-user"


def test_non_route_or_empty_evidence_defaults_to_internet_anonymous(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [],
            "threats": [
                _threat("T-001", cwe="CWE-915", file="server.ts"),
                {"id": "T-002", "title": "Global middleware weakness", "cwe": "CWE-915", "evidence": []},
            ],
        },
    )

    etv.emit(tmp_path)

    by_id = {t["id"]: t for t in _read_yaml(tmp_path)["threats"]}
    assert by_id["T-001"]["vektor"] == "internet-anon"
    assert by_id["T-002"]["vektor"] == "internet-anon"


MODEL_ACTORS = [
    {"id": "ACT-D-01", "heatmap_slug": "internet-anon"},
    {"id": "ACT-D-02", "heatmap_slug": "internet-user"},
    {"id": "ACT-D-06", "heatmap_slug": "build-time"},
    {"id": "ACT-D-04", "heatmap_slug": "insider"},
]


def _attributed(tid: str, actor_ids: list[str], *, cwe: str = "CWE-915", file: str = "routes/search.ts") -> dict:
    return {
        **_threat(tid, cwe=cwe, file=file),
        "actor_ids": actor_ids,
        "primary_actor": actor_ids[0] if actor_ids else None,
    }


@pytest.mark.parametrize(
    ("actor_ids", "file", "expected"),
    [
        (["ACT-D-06"], "Dockerfile", "build-time"),
        (["ACT-D-06"], ".github/workflows/release.yml", "build-time"),
        (["ACT-D-02"], "routes/search.ts", "internet-user"),
        (["ACT-D-01"], "routes/adminPanel.ts", "internet-anon"),
    ],
)
def test_attributed_actor_decides_the_vektor_over_route_heuristics(tmp_path: Path, actor_ids, file, expected) -> None:
    _write_yaml(
        tmp_path,
        {
            "actors": MODEL_ACTORS,
            "attack_surface": [{"entry_point": "GET /api/search", "auth_required": False}],
            "threats": [_attributed("T-001", actor_ids, file=file)],
        },
    )
    etv.emit(tmp_path)
    assert _read_yaml(tmp_path)["threats"][0]["vektor"] == expected


@pytest.mark.parametrize("cwe", ["CWE-778", "CWE-223"])
def test_a_finding_without_an_attacker_has_no_breach_vector(tmp_path: Path, cwe: str) -> None:
    _write_yaml(
        tmp_path, {"actors": MODEL_ACTORS, "threats": [_attributed("T-001", [], cwe=cwe, file="routes/login.ts")]}
    )
    etv.emit(tmp_path)
    assert _read_yaml(tmp_path)["threats"][0]["vektor"] == "n-a"


def test_cwe_classes_and_unmapped_groups_keep_their_existing_vektor(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "actors": MODEL_ACTORS,
            "attack_surface": [],
            "threats": [
                _attributed("T-001", ["ACT-D-01"], cwe="CWE-798", file="lib/keys.ts"),
                _attributed("T-002", ["ACT-D-01"], cwe="CWE-79", file="routes/search.ts"),
                _attributed("T-003", ["ACT-D-04"], file="server.ts"),
                _attributed("T-004", [], file="server.ts"),
            ],
        },
    )
    etv.emit(tmp_path)
    assert [t["vektor"] for t in _read_yaml(tmp_path)["threats"]] == [
        "repo-read",
        "victim-required",
        "internet-anon",
        "internet-anon",
    ]


def test_no_yaml_is_non_fatal(tmp_path: Path, capsys) -> None:
    assert etv.emit(tmp_path) == (0, 0, 0)

    err = capsys.readouterr().err
    assert "emit_threat_vektors: no yaml" in err


def test_invalid_or_non_mapping_yaml_is_non_fatal(tmp_path: Path, capsys) -> None:
    (tmp_path / "threat-model.yaml").write_text("threats: [\n", encoding="utf-8")

    assert etv.emit(tmp_path) == (0, 0, 0)
    assert "parse failed" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("- not-a-mapping\n", encoding="utf-8")

    assert etv.emit(tmp_path) == (0, 0, 0)


def test_ignores_non_mapping_threats_and_blank_attack_surface_entries(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "attack_surface": [
                {"entry_point": "", "auth_required": False},
                {"entry_point": "GET /api/search", "auth_required": False},
            ],
            "threats": [
                "not-a-threat",
                _threat("T-001", cwe="CWE-915", file="routes/search.ts"),
            ],
        },
    )

    assert etv.emit(tmp_path) == (2, 1, 0)
    assert _read_yaml(tmp_path)["threats"][1]["vektor"] == "internet-anon"


def test_main_prints_summary(tmp_path: Path, capsys) -> None:
    _write_yaml(tmp_path, {"threats": [_threat("T-001", cwe="CWE-321", file="lib/keys.ts")]})

    assert etv.main([str(tmp_path)]) == 0

    assert "total=1 filled=1 preserved=0" in capsys.readouterr().out


def test_cli_usage_error() -> None:
    assert etv.main([]) == 2
