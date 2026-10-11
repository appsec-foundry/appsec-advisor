"""Deterministic source scanners for every repository of a combined assessment.

The scanners read frozen snapshots only. Each finding keeps its repository,
its file hash and an owner from its own repository's components. The
evidence verifier then decides it like a STRIDE finding.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
from pathlib import Path

import yaml
from analyzers import authz_confirm, config_iac_scanner, mass_assignment_scanner, source_auth_scanner
from analyzers.route_inventory import build_inventory
from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json
from validators.validate_intermediate import validate_config_scan_findings

from model.finding_intake import apply_intake
from model.merge_threats import _config_finding_to_threat, _source_auth_finding_to_threat
from model.reclassify_components import resolve_owner

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "source-auth-findings.schema.yaml"
# All three scanners write the source-auth sidecar shape single-repository
# merging ingests; authz_confirm reads the route inventory first.
SIDECARS = (".source-auth-findings.json", ".authz-confirm-findings.json", ".mass-assignment-findings.json")
LOCAL_ID_PREFIX = "deterministic-scan-"


def _run_scanners(root: Path, output: Path) -> None:
    atomic_write_json(output / ".route-inventory.json", build_inventory(root))
    argv = ["--repo-root", str(root), "--output-dir", str(output)]
    # The scanners report progress on stderr; the controller owns progress.
    with contextlib.redirect_stderr(io.StringIO()):
        codes = (
            source_auth_scanner.main([*argv, "--quiet"]),
            authz_confirm.main(argv),
            mass_assignment_scanner.main([*argv, "--quiet"]),
        )
    if any(codes):
        raise ValueError("A deterministic source scanner failed on an admitted repository")


def config_scan(root: Path, depth: str) -> dict | None:
    """Run the config/IaC catalog on one snapshot; None without an IaC surface.

    The single-repository pipeline gates the catalog on the same surface
    check, so a repository without IaC files reports no catalog absences.
    """
    # Imported here: the controller imports this module lazily as well.
    from orchestrator.orchestration_controller import _has_iac_surface

    if not _has_iac_surface(root):
        return None
    with tempfile.TemporaryDirectory(prefix="appsec-config-") as directory:
        path = Path(directory) / ".config-scan-findings.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = config_iac_scanner.main(
                ["--repo-root", str(root), "--output", str(path), "--assessment-depth", depth]
            )
        if code or not path.is_file():
            raise ValueError("The config/IaC scanner failed on an admitted repository")
        document = json.loads(path.read_text(encoding="utf-8"))
    # The deterministic producer emits canonical values, so the legacy
    # normalize_config_scan pass has nothing to repair here.
    valid, _ = validate_config_scan_findings(document)
    if not valid or "parse_error" in document:
        raise ValueError("The config/IaC scanner wrote an invalid sidecar")
    return document


def _scanner_outputs(scope, rid: str, depth: str) -> tuple[list[dict], dict | None]:
    """Run every deterministic scanner on one frozen repository snapshot."""
    with scope.scanner_snapshot(rid) as root, tempfile.TemporaryDirectory(prefix="appsec-scan-") as directory:
        output = Path(directory)
        _run_scanners(root, output)
        documents = [json.loads((output / name).read_text(encoding="utf-8")) for name in SIDECARS]
        config = config_scan(root, depth)
    return documents, config


def _config_anchor(finding: dict) -> str | None:
    """The file a config/IaC finding is anchored at; None for an absence that searched nothing."""
    if finding.get("evidence_kind") != "absence":
        return finding["file"]
    searched = finding.get("searched_files") or []
    if not searched:
        return None
    return finding["file"] if finding["file"] in searched else searched[0]


def _anchor_files(scope, repo) -> set[str]:
    """Files of one repository that a deterministic scanner finding can cite.

    Standard depth selects a superset of the files quick depth scans.
    """
    documents, config = _scanner_outputs(scope, repo.repository_id, "standard")
    files = {finding["file"] for document in documents for finding in document.get("findings") or []}
    files.update(anchor for finding in (config or {}).get("findings", []) if (anchor := _config_anchor(finding)))
    return {path for path in files if path in repo.files}


def own_scanner_anchors(scope, components: list[dict]) -> int:
    """Give every file a scanner finding can cite an owner that lists it; return how many were added.

    The combined model accepts a finding only when its component lists the
    cited file. A file no component lists, such as a root Dockerfile or
    package manifest, goes to the owner the single-repository rule picks
    (`resolve_owner`), as a literal path. Component finalization calls this
    before the inventory fingerprint is taken.
    """
    added = 0
    for repo in sorted(scope.repositories, key=lambda row: row.repository_id):
        rid = repo.repository_id
        rows = [row for row in components if rid in row["repository_ids"]]
        listed = {p["path"] for row in rows for p in row["paths"] if p["repository_id"] == rid}
        registry = [
            {
                "id": row["id"],
                "name": row["name"],
                "paths": [p["path"] for p in row["paths"] if p["repository_id"] == rid],
            }
            for row in rows
        ]
        by_id = {row["id"]: row for row in rows}
        for path in sorted(_anchor_files(scope, repo) - listed):
            owner = resolve_owner(path, registry)
            if owner is None:
                continue  # No component in this repository; scanner intake refuses its findings.
            paths = by_id[owner[0]]["paths"]
            paths.append({"repository_id": rid, "path": path, "sha256": hashlib.sha256(repo.files[path]).hexdigest()})
            paths.sort(key=lambda p: (p["repository_id"], p["path"]))
            added += 1
    return added


def _qualify(threat: dict, rid: str, repo, owned: list[dict]) -> None:
    threat["local_id"] = f"{LOCAL_ID_PREFIX}{len(owned) + 1:03d}"
    evidence = threat["evidence"]
    # An absence keeps its kind and searched files, as in single-repository merging.
    threat["evidence"] = {
        **{key: evidence[key] for key in ("kind", "searched_files", "searched_file_count") if key in evidence},
        "repository_id": rid,
        "file": evidence["file"],
        "line": evidence["line"],
        "sha256": hashlib.sha256(repo.files[evidence["file"]]).hexdigest(),
    }
    owned.append(threat)


def scan(scope, components: dict, *, depth: str = "standard") -> dict[str, list[dict]]:
    """Return verifier-ready scanner findings keyed by finalized component ID.

    Config/IaC findings join the source-scanner findings. An absence finding
    is anchored at line 1 of the first file it searched, the file-level
    convention of the SARIF export; the verifier decides it by reading that
    file. An absence that searched no file (a missing file or a repository
    capability without a candidate file) has no captured anchor; the posture
    sidecar keeps it and its receipt records that it was not merged.
    """
    validator = Draft202012Validator(yaml.safe_load(SCHEMA.read_text(encoding="utf-8")))
    scope.verify_unchanged()
    result: dict[str, list[dict]] = {row["id"]: [] for row in components["components"]}
    for repo in sorted(scope.repositories, key=lambda row: row.repository_id):
        rid = repo.repository_id
        # The repository-local view keeps the existing owner rule: the most
        # specific owning component, else that repository's primary one.
        local = [
            {
                "id": row["id"],
                "name": row["name"],
                "tier": row["tier"],
                "paths": [p["path"] for p in row["paths"] if p["repository_id"] == rid],
            }
            for row in components["components"]
            if rid in row["repository_ids"]
        ]
        documents, config = _scanner_outputs(scope, rid, depth)
        threats = []
        for document in documents:
            errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
            # The shared schema also admits an error stub; here it would hide
            # a failed scan behind an empty finding list.
            if errors or "parse_error" in document:
                raise ValueError("A deterministic source scanner wrote an invalid sidecar")
            for finding in document["findings"]:
                if finding["file"] not in repo.files or not finding["line"]:
                    raise ValueError("A deterministic scanner finding lacks a source line in its repository")
                threats.append(_source_auth_finding_to_threat(finding, local))
        for finding in (config or {}).get("findings", []):
            anchor = _config_anchor(finding)
            if anchor is None:
                continue
            if finding.get("evidence_kind") == "absence":
                if any(path not in repo.files for path in finding["searched_files"]):
                    raise ValueError("A config/IaC absence searched a file outside its repository")
            elif finding["file"] not in repo.files or not finding.get("line"):
                raise ValueError("A config/IaC finding lacks a source line in its repository")
            threat = _config_finding_to_threat(finding)
            if threat["evidence"].get("kind") == "absence":
                threat["evidence"].update(file=anchor, line=1)
            # A config finding names no owner; resolve it like a source scan.
            owner = resolve_owner(anchor, local)
            if owner is None:
                raise ValueError("A deterministic scanner finding has no owner in its repository")
            apply_intake(threat, dispatch_component=owner[0], component_name=owner[1])
            threats.append(threat)
        owned = {row["id"]: set(row["paths"]) for row in local}
        for threat in threats:
            if threat["component_id"] not in result:
                raise ValueError("A deterministic scanner finding has no owner in its repository")
            # The combined model requires the owner to list the cited file.
            # Finalization makes every scanner anchor owned; stop here, before
            # any model call, if that ever fails.
            if threat["evidence"]["file"] not in owned[threat["component_id"]]:
                raise ValueError("A deterministic scanner finding cites a file its component does not own")
            _qualify(threat, rid, repo, result[threat["component_id"]])
    scope.verify_unchanged()
    return result
