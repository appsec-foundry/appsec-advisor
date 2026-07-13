"""P1 (STRIDE bespoke-recall) — entity-aware Spring mass-assignment detector
(scripts/mass_assignment_scanner.py + data/mass-assignment-signatures.yaml,
CWE-915 / AUTHZ-202 / FT-041).

The two-pass detector correlates a privileged @Entity (Pass 1) with a write
handler that binds it via @RequestBody (Pass 2). The core FP guard is that a
handler binding a non-entity DTO is the safe pattern and must never flag."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import mass_assignment_scanner as M  # noqa: E402

CATALOG = M.load_catalog(REPO_ROOT / "data" / "mass-assignment-signatures.yaml")

_ENTITY = """\
package com.example.domain;
import jakarta.persistence.Entity;

@Entity
public class AppUser {
    private Long id;
    private String username;
    private String role;
    private boolean admin;
    public String getRole() { return role; }
    public void setRole(String r) { this.role = r; }
}
"""

_CONTROLLER = """\
package com.example.web;
import org.springframework.web.bind.annotation.*;

@RestController
public class ProfileController {
    @PutMapping("/me")
    public ResponseEntity<ProfileResponse> update(Authentication auth, @RequestBody AppUser incoming) {
        return ok(repo.save(incoming));
    }
}
"""


def _write(tmp_path: Path, name: str, body: str) -> None:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _scan(tmp_path: Path) -> list[M.Finding]:
    return M.scan_repo(tmp_path, CATALOG)


# --- positive: the reference-fixture shape ---------------------------------


def test_spring_entity_binding_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileController.java", _CONTROLLER)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "AUTHZ-202"
    assert f.finding_type_id == "FT-041"
    assert f.cwe == ["CWE-915"]
    assert f.severity == "High"
    assert f.file == "ProfileController.java"
    assert "role" in f.scenario and "admin" in f.scenario


# --- the core FP guard: safe DTO ------------------------------------------


def test_safe_dto_not_flagged(tmp_path: Path) -> None:
    dto = (
        "public class ProfileUpdateDto {\n"
        "    private String email;\n"
        "    public String getEmail() { return email; }\n}\n"
    )
    ctrl = _CONTROLLER.replace("@RequestBody AppUser incoming", "@RequestBody ProfileUpdateDto incoming")
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileUpdateDto.java", dto)
    _write(tmp_path, "ProfileController.java", ctrl)
    assert _scan(tmp_path) == []


# --- entity without privileged fields --------------------------------------


def test_entity_without_privileged_field_not_flagged(tmp_path: Path) -> None:
    note = "@Entity\npublic class Note {\n    private String title;\n    private String body;\n}\n"
    ctrl = _CONTROLLER.replace("AppUser", "Note")
    _write(tmp_path, "Note.java", note)
    _write(tmp_path, "NoteController.java", ctrl)
    assert _scan(tmp_path) == []


# --- suppressor: privileged fields are @JsonIgnore -------------------------


def test_jsonignore_suppresses(tmp_path: Path) -> None:
    entity = _ENTITY.replace("    private String role;", "    @JsonIgnore\n    private String role;").replace(
        "    private boolean admin;", "    @JsonIgnore\n    private boolean admin;"
    )
    _write(tmp_path, "AppUser.java", entity)
    _write(tmp_path, "ProfileController.java", _CONTROLLER)
    assert _scan(tmp_path) == []


# --- read-only access suppressor -------------------------------------------


def test_read_only_access_suppresses(tmp_path: Path) -> None:
    entity = _ENTITY.replace(
        "    private String role;",
        "    @JsonProperty(access = Access.READ_ONLY)\n    private String role;",
    ).replace(
        "    private boolean admin;",
        "    @JsonProperty(access = Access.READ_ONLY)\n    private boolean admin;",
    )
    _write(tmp_path, "AppUser.java", entity)
    _write(tmp_path, "ProfileController.java", _CONTROLLER)
    assert _scan(tmp_path) == []


# --- a bind with no write mapping is not a state-changing sink --------------


def test_read_only_get_handler_not_flagged(tmp_path: Path) -> None:
    ctrl = _CONTROLLER.replace('@PutMapping("/me")', '@GetMapping("/me")')
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileController.java", ctrl)
    assert _scan(tmp_path) == []


# --- normalisation: isAdmin / is_admin collapse to the privileged vocab ----


def test_is_admin_variant_flagged(tmp_path: Path) -> None:
    entity = (
        "@Entity\npublic class Account {\n"
        "    private String name;\n"
        "    private boolean isAdmin;\n}\n"
    )
    ctrl = _CONTROLLER.replace("AppUser", "Account")
    _write(tmp_path, "Account.java", entity)
    _write(tmp_path, "AccountController.java", ctrl)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert "isAdmin" in findings[0].scenario


# --- admin-guard downgrade (implementation weakness, not dropped) ----------


def test_method_level_admin_guard_downgrades(tmp_path: Path) -> None:
    ctrl = _CONTROLLER.replace(
        '    @PutMapping("/me")',
        '    @PostMapping\n    @PreAuthorize("hasRole(\'ADMIN\')")',
    )
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "AdminUserController.java", ctrl)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "Medium"
    assert "admin-guarded" in f.title
    assert "not exploitable by a normal user" in f.scenario


def test_class_level_admin_guard_downgrades(tmp_path: Path) -> None:
    ctrl = _CONTROLLER.replace(
        "public class ProfileController {",
        '@PreAuthorize("hasRole(\'ADMIN\')")\npublic class ProfileController {',
    )
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileController.java", ctrl)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "Medium"


def test_unguarded_handler_stays_high(tmp_path: Path) -> None:
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileController.java", _CONTROLLER)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert "admin-guarded" not in findings[0].title


# --- ownership tier: horizontal tampering → Medium -------------------------


def test_ownership_field_binding_is_medium(tmp_path: Path) -> None:
    entity = (
        "@Entity\npublic class CustomerOrder {\n"
        "    private Long id;\n"
        "    private String product;\n"
        "    private String tenant;\n}\n"
    )
    ctrl = _CONTROLLER.replace("AppUser", "CustomerOrder")
    _write(tmp_path, "CustomerOrder.java", entity)
    _write(tmp_path, "OrderController.java", ctrl)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "Medium"  # ownership-only, unguarded
    assert "horizontal authorization tampering" in f.scenario


def test_ownership_field_admin_guarded_is_low(tmp_path: Path) -> None:
    entity = (
        "@Entity\npublic class CustomerOrder {\n"
        "    private Long id;\n"
        "    private String owner;\n}\n"
    )
    ctrl = _CONTROLLER.replace("AppUser", "CustomerOrder").replace(
        '    @PutMapping("/me")',
        '    @PostMapping\n    @PreAuthorize("hasRole(\'ADMIN\')")',
    )
    _write(tmp_path, "CustomerOrder.java", entity)
    _write(tmp_path, "OrderController.java", ctrl)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "Low"  # Medium base stepped down one band


def test_vertical_field_wins_severity_over_ownership(tmp_path: Path) -> None:
    # An entity carrying BOTH a vertical (role) and an ownership (owner) field
    # is High (vertical dominates), not Medium.
    entity = (
        "@Entity\npublic class AppUser {\n"
        "    private String owner;\n"
        "    private String role;\n}\n"
    )
    _write(tmp_path, "AppUser.java", entity)
    _write(tmp_path, "ProfileController.java", _CONTROLLER)
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "High"


# --- @ModelAttribute binding path ------------------------------------------


def test_model_attribute_binding_flagged(tmp_path: Path) -> None:
    ctrl = _CONTROLLER.replace("@RequestBody AppUser", "@ModelAttribute AppUser").replace(
        "@PutMapping", "@PostMapping"
    )
    _write(tmp_path, "AppUser.java", _ENTITY)
    _write(tmp_path, "ProfileController.java", ctrl)
    assert len(_scan(tmp_path)) == 1


# --- test sources are excluded from the walk -------------------------------


def test_test_sources_excluded(tmp_path: Path) -> None:
    _write(tmp_path, "src/test/java/AppUser.java", _ENTITY)
    _write(tmp_path, "src/test/java/ProfileController.java", _CONTROLLER)
    assert _scan(tmp_path) == []
