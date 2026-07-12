"""Tests for scripts/authz_confirm.py — route-inventory-driven IDOR/BOLA +
missing-route-auth instance confirmer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import authz_confirm as ac  # noqa: E402
import validate_intermediate as vi  # noqa: E402


def _write(tmp: Path, name: str, body: str) -> None:
    (tmp / name).write_text(body, encoding="utf-8")


# --- body extraction --------------------------------------------------------


def test_brace_body_survives_path_template_braces(tmp_path: Path) -> None:
    src = (
        '@GetMapping("/orders/{id}")\n'
        "public Order get(@PathVariable Long id) {\n"
        "    return orderRepo.findById(id).orElseThrow();\n"
        "}\n"
    )
    lines = src.splitlines()
    body = ac.extract_body(lines, 1, Path("Ctrl.java"))
    # must reach the findById line, not stop at the annotation's {id}
    assert "findById" in body


def test_python_indent_body(tmp_path: Path) -> None:
    src = (
        "@app.route('/orders/<int:oid>')\n"
        "def get_order(oid):\n"
        "    o = Order.query.get(oid)\n"
        "    return jsonify(o)\n"
        "\n"
        "def other():\n"
        "    check_owner()\n"
    )
    lines = src.splitlines()
    body = ac.extract_body(lines, 1, Path("v.py"))
    assert "Order.query.get" in body
    assert "check_owner" not in body  # must not bleed into the next function


def test_predicates() -> None:
    assert ac.has_ownership_predicate("if obj.ownerId != currentUser.id: deny()")
    assert not ac.has_ownership_predicate("return repo.findById(id)")
    assert ac.has_auth_check("@PreAuthorize('isAuthenticated()')")
    assert not ac.has_auth_check("return service.process(body)")


# --- confirmation -----------------------------------------------------------


def _inv(routes: list[dict]) -> dict:
    return {"version": 1, "routes": routes}


def test_idor_confirmed_when_no_ownership(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Ctrl.java",
        '@GetMapping("/orders/{id}")\n'
        "public Order get(@PathVariable Long id) {\n"
        "    return orderRepo.findById(id).orElseThrow();\n"
        "}\n",
    )
    inv = _inv(
        [
            {
                "method": "GET",
                "path": "/orders/{id}",
                "handler_file": "Ctrl.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
            }
        ]
    )
    findings = ac.confirm_instances(tmp_path, inv)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "AUTHZ-301"
    assert findings[0]["cwe"] == ["CWE-639"]


def test_idor_suppressed_when_ownership_present(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Ctrl.java",
        '@GetMapping("/orders/{id}")\n'
        "public Order get(@PathVariable Long id, Principal principal) {\n"
        "    Order o = orderRepo.findById(id).orElseThrow();\n"
        "    if (!o.getOwnerId().equals(principal.getId())) throw new ForbiddenException();\n"
        "    return o;\n"
        "}\n",
    )
    inv = _inv(
        [
            {
                "method": "GET",
                "path": "/orders/{id}",
                "handler_file": "Ctrl.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
            }
        ]
    )
    assert ac.confirm_instances(tmp_path, inv) == []


def test_missing_route_auth_confirmed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "admin.go",
        "func DeleteUser(w http.ResponseWriter, r *http.Request) {\n"
        '    id := mux.Vars(r)["id"]\n'
        '    db.Exec("DELETE FROM users WHERE id = $1", id)\n'
        "}\n",
    )
    inv = _inv(
        [
            {
                "method": "DELETE",
                "path": "/admin/users/{id}",
                "handler_file": "admin.go",
                "handler_line": 1,
                "missing_auth_suspect": True,
            }
        ]
    )
    findings = ac.confirm_instances(tmp_path, inv)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "AUTHZ-302"
    assert findings[0]["cwe"] == ["CWE-862"]


def test_missing_route_auth_suppressed_when_auth_present(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "admin.go",
        "func DeleteUser(w http.ResponseWriter, r *http.Request) {\n"
        '    if !authenticate(r) { http.Error(w, "unauthorized", 401); return }\n'
        '    db.Exec("DELETE FROM users WHERE id = $1", id)\n'
        "}\n",
    )
    inv = _inv(
        [
            {
                "method": "DELETE",
                "path": "/admin/users/{id}",
                "handler_file": "admin.go",
                "handler_line": 1,
                "missing_auth_suspect": True,
            }
        ]
    )
    assert ac.confirm_instances(tmp_path, inv) == []


def test_missing_handler_file_skipped(tmp_path: Path) -> None:
    inv = _inv(
        [
            {
                "method": "GET",
                "path": "/x/{id}",
                "handler_file": "nope.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
            }
        ]
    )
    assert ac.confirm_instances(tmp_path, inv) == []


def test_no_suspect_flags_no_findings(tmp_path: Path) -> None:
    _write(tmp_path, "Ctrl.java", "public Order get(Long id) { return repo.findById(id); }\n")
    inv = _inv([{"method": "GET", "path": "/orders/{id}", "handler_file": "Ctrl.java", "handler_line": 1}])
    assert ac.confirm_instances(tmp_path, inv) == []


# --- output is schema-valid -------------------------------------------------


def test_output_document_is_schema_valid(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Ctrl.java",
        '@GetMapping("/orders/{id}")\n'
        "public Order get(@PathVariable Long id) {\n"
        "    return orderRepo.findById(id).orElseThrow();\n"
        "}\n",
    )
    inv = _inv(
        [
            {
                "method": "GET",
                "path": "/orders/{id}",
                "handler_file": "Ctrl.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
            }
        ]
    )
    doc = ac.build_document(tmp_path, inv)
    ok, errs = vi.validate_source_auth_findings(doc)
    assert ok, errs


# --- merge ingestion folds into missing_authz -------------------------------


def test_merge_ingests_and_folds_into_missing_authz(tmp_path: Path) -> None:
    import merge_threats as mt

    doc = {
        "version": 1,
        "generated_at": "2026-07-12T00:00:00Z",
        "checks_run": 2,
        "violations": 1,
        "findings": [
            {
                "local_id": "SAF-001",
                "check_id": "AUTHZ-301",
                "source_type": "java_source",
                "file": "Ctrl.java",
                "line": 3,
                "title": "IDOR — GET /orders/{id}",
                "severity": "High",
                "cwe": ["CWE-639"],
                "finding_type_id": "FT-040",
                "breach_vector": "Internet Anon",
            }
        ],
    }
    (tmp_path / ".authz-confirm-findings.json").write_text(json.dumps(doc), encoding="utf-8")
    threats = mt._load_source_auth_findings(tmp_path, ".authz-confirm-findings.json")
    assert len(threats) == 1
    t = threats[0]
    assert t["source"] == "source-scan"
    assert t["cwe"] == "CWE-639"
    assert t["source_check_id"] == "AUTHZ-301"
