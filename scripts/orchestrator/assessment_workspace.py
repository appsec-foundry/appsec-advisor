"""Private legacy-shaped workspace for a qualified multi-repository assessment.

The semantic stages of a combined assessment produce repository-qualified
(version 2) artifacts. The deterministic producers, emitters, renderers and
quality gates downstream of them consume the single-root legacy shapes. This
module projects the qualified artifacts into a private workspace in which every
source location is ``<repository label>/<relative path>`` and the matching
source root holds one directory per selected repository. It converts the
finished model back into the qualified version-2 contract before publication.

The workspace and its combined source root are controller-owned private state.
No model runs in either of them; models only receive scoped exchanges.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from model.finalize_component_inventory import component_inventory_fingerprint
from runtime.multi_repo_scope import AssessmentScope, _masked_bytes, _relative
from shared._atomic_io import atomic_write_json

# A display locator `<path>:<line>` or `<path>:<start>-<end>`.
_LOCATOR = re.compile(r"(.+):(\d+)(?:-\d+)?")
# Fields of a qualified source reference that the legacy shapes do not carry.
_QUALIFIERS = ("repository_id", "sha256")


class WorkspaceError(ValueError):
    """A qualified artifact cannot be represented faithfully in the workspace."""


class Namespaces:
    """Bijective mapping between repository IDs and their path prefixes."""

    def __init__(self, scope: AssessmentScope):
        rows = scope.inventory()["repositories"]
        self.prefix = {row["repository_id"]: row["label"] for row in rows}
        self.repository = {label: rid for rid, label in self.prefix.items()}
        if len(self.repository) != len(self.prefix):
            raise WorkspaceError("Repository labels are not unique")
        for label in self.repository:
            if "/" in label or label in {"", ".", ".."} or label.startswith("."):
                raise WorkspaceError("Repository label cannot be used as a path namespace")
        self.files = {repo.repository_id: repo.files for repo in scope.repositories}

    def qualify(self, rid: str, path: str) -> str:
        if rid not in self.prefix:
            raise WorkspaceError("Source reference names a repository outside the admitted scope")
        return f"{self.prefix[rid]}/{path}"

    def split(self, value: str) -> tuple[str, str]:
        label, separator, path = value.partition("/")
        if not separator or label not in self.repository or not path:
            raise WorkspaceError(f"Workspace location has no repository namespace: {value[:200]}")
        return self.repository[label], path

    def sha256(self, rid: str, path: str) -> str | None:
        data = self.files[rid].get(path)
        return hashlib.sha256(data).hexdigest() if data is not None else None


def _project(value, names: Namespaces):
    """Return a legacy copy: qualified locations become namespaced strings."""
    if isinstance(value, list):
        return [_project(child, names) for child in value]
    if not isinstance(value, dict):
        return value
    row = {key: _project(child, names) for key, child in value.items() if key not in _QUALIFIERS}
    rid = value.get("repository_id")
    if rid is not None:
        for key in ("file", "path"):
            if isinstance(value.get(key), str):
                row[key] = names.qualify(rid, value[key])
    return row


def project_components(components: dict, names: Namespaces) -> dict:
    rows = []
    for component in components["components"]:
        row = _project({k: v for k, v in component.items() if k not in ("origin", "local_id", "repository_ids")}, names)
        row["paths"] = [names.qualify(p["repository_id"], p["path"]) for p in component["paths"]]
        # Repository membership is a short annotation, never a trust zone.
        owners = ", ".join(names.prefix[rid] for rid in component["repository_ids"])
        row["name"] = f"{component['name']} [{owners}]"
        rows.append(row)
    return {"schema_version": 1, "components": rows}


def project_finalization(receipt: dict, legacy_components: dict) -> dict:
    return {
        "schema_version": 1,
        "component_inventory_fingerprint": component_inventory_fingerprint(legacy_components["components"]),
        "component_ids": [row["id"] for row in legacy_components["components"]],
        "injected_component_ids": list(receipt["injected_component_ids"]),
        "collapsed_duplicate_count": receipt["collapsed_duplicate_count"],
    }


def project_flows(flows: dict, fingerprint: str, names: Namespaces) -> dict:
    document = _project({k: v for k, v in flows.items() if k != "source_scope_sha256"}, names)
    document.update(schema_version=1, component_inventory_fingerprint=fingerprint)
    return document


def project_document(document: dict, names: Namespaces, *, schema_version: int | None = None) -> dict:
    projected = _project(
        {k: v for k, v in document.items() if k not in ("source_scope_sha256", "component_inventory_fingerprint")},
        names,
    )
    if schema_version is not None:
        projected["schema_version"] = schema_version
    return projected


def legacy_model(document: dict, names: Namespaces) -> dict:
    """Project a version-2 model to the legacy output shape."""
    view = _project({k: v for k, v in document.items() if k != "source_inventory"}, names)
    view["meta"] = {
        k: v for k, v in view["meta"].items() if k not in ("source_scope_sha256", "component_inventory_fingerprint")
    }
    view["meta"]["schema_version"] = 1
    for component, original in zip(view["components"], document["components"], strict=True):
        component.pop("repository_ids", None)
        component.pop("origin", None)
        component.pop("local_id", None)
        component["paths"] = [names.qualify(p["repository_id"], p["path"]) for p in original["paths"]]
    return view


def _qualify(value, names: Namespaces):
    """Inverse of ``_project`` for every namespaced location of the model."""
    if isinstance(value, list):
        return [_qualify(child, names) for child in value]
    if not isinstance(value, dict):
        return value
    row = {key: _qualify(child, names) for key, child in value.items()}
    if isinstance(value.get("file"), str) and value["file"]:
        rid, path = names.split(value["file"])
        digest = names.sha256(rid, path)
        locator = _LOCATOR.fullmatch(path)
        if digest is None and locator and names.sha256(rid, locator.group(1)) is not None:
            # A `path:line` locator keeps its line as a separate field.
            path = locator.group(1)
            digest = names.sha256(rid, path)
            row.setdefault("line", int(locator.group(2)))
        row["file"], row["repository_id"] = path, rid
        if digest is None:
            raise WorkspaceError(f"Model location is outside the captured source: {value['file'][:200]}")
        row["sha256"] = digest
    return row


def canonical_model(view: dict, original: dict, names: Namespaces) -> dict:
    """Convert the enriched workspace model back into the qualified contract.

    Every location must resolve to a captured file of a selected repository.
    Component identity and qualified paths come from the accepted original.
    """
    by_id = {row["id"]: row for row in original["components"]}
    document = _qualify({k: v for k, v in view.items() if k not in ("meta", "components")}, names)
    components = []
    for component in view["components"]:
        accepted = by_id.get(component["id"])
        if accepted is None:
            raise WorkspaceError("Enrichment introduced a component outside the accepted inventory")
        row = _qualify({k: v for k, v in component.items() if k != "paths"}, names)
        for key in ("name", "paths", "repository_ids", "origin", "local_id"):
            if key in accepted:
                row[key] = copy.deepcopy(accepted[key])
        components.append(row)
    if {row["id"] for row in components} != set(by_id):
        raise WorkspaceError("Enrichment removed an accepted component")
    meta = {k: v for k, v in view["meta"].items() if k != "source_repositories"}
    meta.update(
        schema_version=2,
        source_scope_sha256=original["meta"]["source_scope_sha256"],
        component_inventory_fingerprint=original["meta"]["component_inventory_fingerprint"],
    )
    return {
        "meta": meta,
        "source_inventory": copy.deepcopy(original["source_inventory"]),
        "components": components,
        **document,
    }


@contextmanager
def combined_root(scope: AssessmentScope, names: Namespaces):
    """Masked, link-free copy of every selected source under its namespace."""
    with tempfile.TemporaryDirectory(prefix="appsec-combined-") as directory:
        root = Path(directory)
        for repo in scope.repositories:
            base = root / names.prefix[repo.repository_id]
            for relative, data in repo.files.items():
                target = base.joinpath(*_relative(relative))
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as handle:
                    os.chmod(target, 0o600)
                    handle.write(_masked_bytes(data))
        yield root


def source_repositories(scope: AssessmentScope) -> list[dict]:
    """Presentation rows of the selected checkouts for the workspace model."""
    return [
        {"label": row["label"], "head": row["head"], "dirty": row["dirty"]} for row in scope.inventory()["repositories"]
    ]


def recon_summary(project: str, scope: AssessmentScope) -> str:
    """Bounded deterministic project facts for the legacy consumers."""
    lines = [f"# Recon Summary — {project}", "", "## Project", "", f"**Project**: {project}", "", "## Repositories", ""]
    for row in scope.inventory()["repositories"]:
        state = "uncommitted changes" if row["dirty"] else "clean"
        lines.append(f"- {row['label']} — revision {row['head'][:12]}, {state}, {len(row['files'])} captured files")
    return "\n".join(lines) + "\n"


def write_json(path: Path, value) -> None:
    atomic_write_json(path, value)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
