"""Tests for ``scripts/slice_cross_repo_for_component.py`` — per-component
filter for STRIDE dispatch."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import slice_cross_repo_for_component as slicer  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "slice_cross_repo_for_component.py"


def _register(*entries: dict[str, Any]) -> dict[str, Any]:
    return {
        "meta": {"register_version": 1, "sources": ["declared"], "generated_at": "2099-01-01T00:00:00Z"},
        "entries": list(entries),
    }


def _declared(
    name: str,
    *,
    interface: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "source": "declared",
        "interface": interface,
        "type": None,
        "discovery_hint": None,
        "threat_model": {"status": "found", "threats_open": 3, "threats_critical": 1},
        "interface_findings": {
            "included": len(findings or []),
            "excluded_count": 0,
            "findings": findings or [],
        },
    }


def _sibling(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "source": "sibling",
        "interface": None,
        "type": None,
        "discovery_hint": None,
        "threat_model": {"status": "missing"},
        "interface_findings": None,
    }


class TestMatching:
    def test_name_in_component_interface(self) -> None:
        reg = _register(
            _declared("auth-service", interface="REST API"),
            _declared("payment-gateway", interface="gRPC"),
        )
        sliced = slicer.slice_for_component(
            reg,
            component_name="UserController",
            interfaces=["calls auth-service for token validation"],
        )
        assert [s["name"] for s in sliced] == ["auth-service"]

    def test_interface_substring_match(self) -> None:
        reg = _register(_declared("ext-svc", interface="WebSocket /ws/notifications"))
        sliced = slicer.slice_for_component(
            reg,
            component_name="NotifyComponent",
            trust_boundaries=["client ↔ WebSocket /ws/notifications"],
        )
        assert len(sliced) == 1

    def test_no_match_returns_empty(self) -> None:
        reg = _register(_declared("payment-gateway"))
        sliced = slicer.slice_for_component(
            reg,
            component_name="AuthComponent",
        )
        assert sliced == []

    def test_explicit_names_override(self) -> None:
        reg = _register(_declared("payment-gateway", interface="gRPC"))
        sliced = slicer.slice_for_component(
            reg,
            component_name="Unrelated",
            explicit_names=["payment-gateway"],
        )
        assert len(sliced) == 1

    def test_case_insensitive_match(self) -> None:
        reg = _register(_declared("Auth-Service"))
        sliced = slicer.slice_for_component(
            reg,
            component_name="UserController",
            interfaces=["uses AUTH-SERVICE for SSO"],
        )
        assert len(sliced) == 1


class TestFindingsPropagation:
    def test_findings_included_for_declared(self) -> None:
        findings = [
            {"id": "T-1", "severity": "Critical", "title": "x"},
            {"id": "T-2", "severity": "High", "title": "y"},
        ]
        reg = _register(_declared("auth", findings=findings))
        sliced = slicer.slice_for_component(reg, component_name="auth")
        assert sliced[0]["findings"] == findings
        assert sliced[0]["findings_excluded"] == 0

    def test_no_findings_for_sibling(self) -> None:
        reg = _register(_sibling("notif"))
        sliced = slicer.slice_for_component(
            reg,
            component_name="NotifyComponent",
            interfaces=["notif consumer"],
        )
        assert len(sliced) == 1
        assert "findings" not in sliced[0]


class TestCLI:
    def test_missing_register_returns_empty_list(self, tmp_path: Path) -> None:
        out = tmp_path / "slice.json"
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--register",
                str(tmp_path / "nope.json"),
                "--component-id",
                "c1",
                "--component-name",
                "X",
                "--output",
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert json.loads(out.read_text(encoding="utf-8")) == []

    def test_cli_writes_slice(self, tmp_path: Path) -> None:
        reg_path = tmp_path / "register.json"
        reg_path.write_text(json.dumps(_register(_declared("svc"))))
        out = tmp_path / "slice.json"
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--register",
                str(reg_path),
                "--component-id",
                "c1",
                "--component-name",
                "svc consumer",
                "--output",
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 1


class TestAdditiveFields:
    """consumer_declares / upstream_properties / expectation_mismatch are
    forwarded onto the slice only when present on the register entry."""

    def test_additive_fields_forwarded(self) -> None:
        entry = _declared("svc", interface="REST")
        entry["consumer_declares"] = {"expects": "tls"}
        entry["upstream_properties"] = {"tls": True}
        entry["expectation_mismatch"] = {"detail": "no mtls"}
        reg = _register(entry)
        sliced = slicer.slice_for_component(reg, component_name="svc consumer")
        assert sliced[0]["consumer_declares"] == {"expects": "tls"}
        assert sliced[0]["upstream_properties"] == {"tls": True}
        assert sliced[0]["expectation_mismatch"] == {"detail": "no mtls"}

    def test_additive_fields_absent_when_not_present(self) -> None:
        reg = _register(_declared("svc"))
        sliced = slicer.slice_for_component(reg, component_name="svc")
        assert "consumer_declares" not in sliced[0]
        assert "upstream_properties" not in sliced[0]
        assert "expectation_mismatch" not in sliced[0]


class TestMainInProcess:
    """Drive main() in-process so error/stdout branches are covered."""

    def _argv(self, **kw) -> list[str]:
        argv = [
            "--register",
            kw["register"],
            "--component-id",
            "c1",
            "--component-name",
            kw.get("name", "svc consumer"),
            "--output",
            kw["output"],
        ]
        return argv

    def test_main_stdout_dash(self, tmp_path: Path, capsys) -> None:
        reg_path = tmp_path / "register.json"
        reg_path.write_text(json.dumps(_register(_declared("svc"))))
        rc = slicer.main(self._argv(register=str(reg_path), output="-"))
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data[0]["name"] == "svc"

    def test_main_malformed_register_returns_2(self, tmp_path: Path, capsys) -> None:
        reg_path = tmp_path / "register.json"
        reg_path.write_text("{ not valid json")
        out = tmp_path / "slice.json"
        rc = slicer.main(self._argv(register=str(reg_path), output=str(out)))
        assert rc == 2
        assert "slice_cross_repo_for_component" in capsys.readouterr().err

    def test_main_missing_register_empty_slice(self, tmp_path: Path) -> None:
        out = tmp_path / "slice.json"
        rc = slicer.main(self._argv(register=str(tmp_path / "nope.json"), output=str(out)))
        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8")) == []

    def test_main_writes_file(self, tmp_path: Path) -> None:
        reg_path = tmp_path / "register.json"
        reg_path.write_text(json.dumps(_register(_declared("svc"))))
        out = tmp_path / "slice.json"
        rc = slicer.main(self._argv(register=str(reg_path), output=str(out)))
        assert rc == 0
        assert len(json.loads(out.read_text(encoding="utf-8"))) == 1
