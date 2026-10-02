"""Tests for scripts/analyzers/authz_confirm.py — route-inventory-driven IDOR/BOLA +
missing-route-auth instance confirmer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import analyzers.authz_confirm as ac  # noqa: E402
import validators.validate_intermediate as vi  # noqa: E402


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
                "authn_signal": "absent",
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
                "authn_signal": "absent",
            }
        ]
    )
    assert ac.confirm_instances(tmp_path, inv) == []


def _unguarded_handler(tmp_path: Path, name: str) -> None:
    _write(
        tmp_path,
        name,
        "function removeItem(req, res) {\n"
        "  Items.destroy({ where: { id: req.params.id } })\n"
        "  res.sendStatus(204)\n"
        "}\n",
    )


def _suspect(name: str, path: str, authn_signal: str) -> dict:
    return {
        "method": "DELETE",
        "path": path,
        "handler_file": name,
        "handler_line": 1,
        "missing_auth_suspect": True,
        "authn_signal": authn_signal,
    }


def test_missing_route_auth_needs_proven_absence(tmp_path: Path) -> None:
    """FE-14: only a fully resolved chain without a credential read is `absent`.
    An `unknown` route may sit behind a guard the inventory cannot see, so the
    handler body alone never confirms it as reachable without authentication."""
    _unguarded_handler(tmp_path, "items.js")
    _unguarded_handler(tmp_path, "records.js")
    inv = _inv(
        [
            _suspect("items.js", "/items/:id", "absent"),
            _suspect("records.js", "/v2/records/:recordId", "absent"),
            _suspect("items.js", "/items/:id/archive", "unknown"),
            _suspect("records.js", "/v2/records/:recordId/tags", "unknown"),
        ]
    )
    findings = ac.confirm_instances(tmp_path, inv)
    assert [(f["check_id"], f["file"]) for f in findings] == [("AUTHZ-302", "items.js"), ("AUTHZ-302", "records.js")]
    assert {f["breach_vector"] for f in findings} == {"Internet Anon"}


def test_idor_attacker_is_an_authenticated_user(tmp_path: Path) -> None:
    _write(tmp_path, "Ctrl.java", "public Order get(Long id) {\n    return repo.findById(id);\n}\n")
    inv = _inv(
        [
            {
                "method": "GET",
                "path": "/orders/{id}",
                "handler_file": "Ctrl.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
                "authn_signal": "present",
            }
        ]
    )
    (finding,) = ac.confirm_instances(tmp_path, inv)
    assert finding["check_id"] == "AUTHZ-301"
    assert finding["breach_vector"] == "Internet User"


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
    import model.merge_threats as mt

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


@pytest.mark.parametrize("via", ["symlink", "absolute"])
def test_handler_outside_the_repository_is_never_read(tmp_path: Path, via: str) -> None:
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    _unguarded_handler(outside, "items.js")
    if via == "symlink":
        (repo / "items.js").symlink_to(outside / "items.js")
        handler_file = "items.js"
    else:
        handler_file = str(outside / "items.js")
    assert ac.confirm_instances(repo, _inv([_suspect(handler_file, "/items/:id", "absent")])) == []


def test_handler_symlinked_inside_the_repository_is_still_read(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    _unguarded_handler(tmp_path, "src/items.js")
    (tmp_path / "items.js").symlink_to(tmp_path / "src" / "items.js")
    findings = ac.confirm_instances(tmp_path, _inv([_suspect("items.js", "/items/:id", "absent")]))
    assert [f["check_id"] for f in findings] == ["AUTHZ-302"]


# --- unresolved suspects are told apart from cleared ones -------------------


def test_unresolved_suspects_lists_only_unreadable_handlers(tmp_path: Path) -> None:
    """A consumer must tell a suspect whose body was read and cleared from one
    the confirmer could not read; only the latter is a remaining hypothesis."""
    _write(
        tmp_path,
        "Owned.java",
        "public Order get(Long id, Principal principal) { return repo.byOwner(id, principal); }\n",
    )
    _write(tmp_path, "Open.py", "def update(item_id):\n    return repo.save(request.json)\n")
    inv = _inv(
        [
            # read and cleared by its ownership predicate
            {
                "route_id": "R-001",
                "method": "GET",
                "path": "/o/{id}",
                "handler_file": "Owned.java",
                "handler_line": 1,
                "missing_authz_suspect": True,
            },
            # handler file missing — unresolved
            {
                "route_id": "R-002",
                "method": "GET",
                "path": "/i/{id}",
                "handler_file": "gone.ts",
                "handler_line": 4,
                "missing_authz_suspect": True,
            },
            # missing-auth suspect with proven absence, no line — unresolved
            {
                "route_id": "R-003",
                "method": "POST",
                "path": "/admin/x",
                "handler_file": "Open.py",
                "missing_auth_suspect": True,
                "authn_signal": "absent",
            },
            # missing-auth suspect whose authentication is only unknown — never examined
            {
                "route_id": "R-004",
                "method": "POST",
                "path": "/admin/y",
                "handler_file": "gone.py",
                "handler_line": 1,
                "missing_auth_suspect": True,
                "authn_signal": "unknown",
            },
            # not a suspect at all
            {"route_id": "R-005", "method": "GET", "path": "/health", "handler_file": "gone.go", "handler_line": 1},
        ]
    )
    doc = ac.build_document(tmp_path, inv)
    assert doc["unresolved_suspects"] == ["R-002", "R-003"]
    assert doc["findings"] == []
    ok, errs = vi.validate_source_auth_findings(doc)
    assert ok, errs
