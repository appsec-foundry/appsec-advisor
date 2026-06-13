#!/usr/bin/env python3
"""requirements_state.py — shared state for the security-requirements source.

Two deterministic scripts cooperate to pick and load the requirements catalog:

  * ``resolve_requirements_source.py`` — decides *which* source is active
    (precedence resolution).
  * ``fetch_requirements.py``          — actually loads it (fetch / cache / abort).

This module holds the pieces both of them need so the logic lives in exactly
one place:

  * the **source sidecar** (``.cache/requirements.source.json``) — remembers the
    URL the catalog was last fetched from, when, its sha256, and a little catalog
    metadata. This is what lets ``--update`` re-pull without the user retyping a
    URL and what ``--status`` reports.
  * **freshness** — is the cached copy young enough to use without re-fetching?
  * **local repo source** detection — a developer-authored
    ``docs/security/requirements.yaml`` (NOT the generated dotfile
    ``.requirements.yaml``) takes precedence over the org-profile, surfaced to
    the user.
  * **catalog metadata** parsing — ``generated`` / ``url`` / ``description`` /
    requirement count for the startup banner.

Nothing here performs network I/O or aborts a run; it is pure state + parsing so
it stays trivially unit-testable.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

try:  # PyYAML is available across the plugin; degrade gracefully if not.
    import yaml
except Exception:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]

# The user-authored local catalog lives next to the audit output (docs/security/)
# under a NON-dot name so it is never confused with the generated, resolved
# ``.requirements.yaml`` the gate writes.
LOCAL_REPO_FILENAMES = ("requirements.yaml", "requirements.yml")

SIDECAR_FILENAME = "requirements.source.json"

# A cached catalog older than this (by fetch time) is treated as stale and the
# default flow will try to refresh it before falling back to the cache.
DEFAULT_FRESHNESS_DAYS = 30


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def sidecar_path_for_cache(cache_file: Path) -> Path:
    """The source sidecar lives next to the cached catalog body."""
    return cache_file.parent / SIDECAR_FILENAME


def local_repo_source(output_dir: Path) -> str | None:
    """Return the path to a developer-authored local catalog, if one exists.

    Looks for ``requirements.yaml`` / ``.yml`` directly in ``output_dir``
    (``docs/security/``). Ignores the generated dotfile ``.requirements.yaml``.
    """
    for name in LOCAL_REPO_FILENAMES:
        p = output_dir / name
        try:
            if p.is_file() and p.stat().st_size > 0:
                return str(p)
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Catalog metadata
# ---------------------------------------------------------------------------


def catalog_meta(body: bytes) -> dict:
    """Parse top-level catalog metadata + requirement count from YAML ``body``.

    Returns a dict with ``generated`` / ``url`` / ``description`` / ``label`` /
    ``count`` (any of which may be ``None``). Never raises — a malformed body
    yields ``{"count": None}`` so callers can still proceed.
    """
    meta: dict = {"generated": None, "url": None, "description": None, "label": None, "count": None}
    if yaml is None:
        return meta
    try:
        doc = yaml.safe_load(body)
    except Exception:
        return meta
    if not isinstance(doc, dict):
        return meta
    meta["generated"] = doc.get("generated")
    meta["url"] = doc.get("url")
    meta["description"] = doc.get("description")
    meta["label"] = doc.get("label")
    count = 0
    cats = doc.get("categories")
    if isinstance(cats, list):
        for cat in cats:
            if isinstance(cat, dict):
                reqs = cat.get("requirements")
                if isinstance(reqs, list):
                    count += len(reqs)
    meta["count"] = count
    return meta


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# ---------------------------------------------------------------------------
# Sidecar I/O
# ---------------------------------------------------------------------------


def read_sidecar(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def build_sidecar(url: str | None, source_kind: str, body: bytes, fetched_at: str) -> dict:
    meta = catalog_meta(body)
    return {
        "url": url,
        "source_kind": source_kind,
        "fetched_at": fetched_at,
        "sha256": sha256(body),
        "generated": meta.get("generated"),
        "description": meta.get("description"),
        "label": meta.get("label"),
        "count": meta.get("count"),
    }


def write_sidecar(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def clear_state(cache_file: Path) -> list[str]:
    """Delete the cached catalog body and its source sidecar. Returns removed paths."""
    removed: list[str] = []
    for p in (cache_file, sidecar_path_for_cache(cache_file)):
        try:
            if p.exists():
                p.unlink()
                removed.append(str(p))
        except OSError:
            continue
    return removed


def backfill_sidecar_from_cache(cache_file: Path) -> dict | None:
    """Synthesize a sidecar from an existing cache that predates the sidecar feature.

    Uses the cache file's mtime as ``fetched_at`` (when the bytes actually
    landed) and the catalog's internal ``url`` / ``generated`` as the remembered
    source. Returns the sidecar dict (already written), or ``None`` if there is
    no usable cache. A pre-existing sidecar is left untouched.
    """
    sidecar = sidecar_path_for_cache(cache_file)
    if read_sidecar(sidecar) is not None:
        return read_sidecar(sidecar)
    try:
        if not cache_file.is_file() or cache_file.stat().st_size == 0:
            return None
        body = cache_file.read_bytes()
        mtime = cache_file.stat().st_mtime
    except OSError:
        return None
    fetched_at = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    meta = catalog_meta(body)
    data = build_sidecar(meta.get("url"), "backfilled", body, fetched_at)
    write_sidecar(sidecar, data)
    return data


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def freshness(fetched_at: str | None, now: datetime | None = None, days: int = DEFAULT_FRESHNESS_DAYS) -> dict:
    """Return a freshness verdict for a cached catalog.

    ``{"age_days": int|None, "fresh": bool, "stale": bool, "threshold_days": int,
       "known": bool}``. When ``fetched_at`` is unparseable the verdict is
    ``known=False`` and ``stale=True`` (unknown age forces a refresh attempt).
    """
    now = now or datetime.now(timezone.utc)
    dt = _parse_iso(fetched_at)
    if dt is None:
        return {"age_days": None, "fresh": False, "stale": True, "threshold_days": days, "known": False}
    age_days = (now - dt).days
    fresh = age_days <= days
    return {
        "age_days": age_days,
        "fresh": fresh,
        "stale": not fresh,
        "threshold_days": days,
        "known": True,
    }


def now_iso(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Catalog validation against schemas/requirements-catalog.schema.yaml
# ---------------------------------------------------------------------------

CATALOG_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "requirements-catalog.schema.yaml"

_PRIORITIES = {"MUST", "SHOULD", "MAY"}


def _structural_errors_without_jsonschema(doc: object) -> list[str]:
    """Minimal structural check when jsonschema is unavailable.

    Catches the high-value failures (not a mapping, no `categories` array,
    a category/requirement missing its `id`) without the dependency.
    """
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["top level is not a mapping (got %s)" % type(doc).__name__]
    cats = doc.get("categories")
    if cats is None:
        return ["missing required key: categories"]
    if not isinstance(cats, list):
        return ["categories must be a list"]
    for ci, cat in enumerate(cats):
        if not isinstance(cat, dict):
            errors.append(f"categories[{ci}] is not a mapping")
            continue
        if not cat.get("id"):
            errors.append(f"categories[{ci}] missing required key: id")
        for ri, req in enumerate(cat.get("requirements") or []):
            if not isinstance(req, dict):
                errors.append(f"categories[{ci}].requirements[{ri}] is not a mapping")
            elif not req.get("id"):
                errors.append(f"categories[{ci}].requirements[{ri}] missing required key: id")
    return errors


def validate_catalog(body: bytes, schema_path: Path | None = None, max_item_warnings: int = 10) -> tuple[list[str], list[str]]:
    """Validate a requirements catalog body.

    Returns ``(errors, warnings)``:

      * ``errors`` — structural violations of the catalog contract (not a
        mapping, missing `categories`, a category/requirement without an `id`).
        A non-empty list means the document is not a usable catalog.
      * ``warnings`` — content-quality issues that do not block a run (zero
        requirements, a requirement missing `text`, an unrecognised `priority`,
        duplicate requirement IDs).

    Never raises — a YAML parse failure is returned as an error.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if yaml is None:
        return (["PyYAML unavailable — cannot validate catalog"], warnings)
    try:
        doc = yaml.safe_load(body)
    except Exception as exc:
        return ([f"not valid YAML: {exc}"], warnings)

    # Structural validation: prefer jsonschema (repo dependency); degrade to a
    # minimal hand-rolled check so the fetch gate never crashes on a missing lib.
    try:
        import jsonschema  # noqa: PLC0415

        sp = schema_path or CATALOG_SCHEMA_PATH
        schema = yaml.safe_load(sp.read_text())
        validator = jsonschema.Draft202012Validator(schema)
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
            loc = ".".join(str(p) for p in e.absolute_path) or "root"
            errors.append(f"{loc}: {e.message}")
    except ImportError:
        errors.extend(_structural_errors_without_jsonschema(doc))
    except OSError:
        # Schema file missing/unreadable — fall back to the structural check.
        errors.extend(_structural_errors_without_jsonschema(doc))

    if errors:
        return (errors, warnings)

    # Content-quality warnings (only meaningful once the structure is sound).
    total = 0
    seen_ids: dict[str, int] = {}
    missing_text = 0
    bad_priority = 0
    for cat in doc.get("categories") or []:
        if not isinstance(cat, dict):
            continue
        for req in cat.get("requirements") or []:
            if not isinstance(req, dict):
                continue
            total += 1
            rid = req.get("id")
            if rid:
                seen_ids[rid] = seen_ids.get(rid, 0) + 1
            if not (req.get("text") or "").strip():
                missing_text += 1
            pr = req.get("priority")
            if pr is not None and pr not in _PRIORITIES:
                bad_priority += 1

    if total == 0:
        warnings.append("catalog contains 0 requirements — nothing will be graded")
    if missing_text:
        warnings.append(f"{missing_text} requirement(s) have no text — grading basis is missing")
    if bad_priority:
        warnings.append(f"{bad_priority} requirement(s) have a priority outside MUST/SHOULD/MAY")
    dups = [rid for rid, n in seen_ids.items() if n > 1]
    if dups:
        shown = ", ".join(sorted(dups)[:max_item_warnings])
        warnings.append(f"{len(dups)} duplicate requirement ID(s): {shown}")

    return (errors, warnings)


def _main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Validate a security-requirements catalog against the canonical schema.")
    p.add_argument("--validate", metavar="PATH", required=True, help="catalog YAML to validate")
    p.add_argument("--strict", action="store_true", help="treat content warnings as failures too")
    args = p.parse_args(argv)

    try:
        body = Path(args.validate).expanduser().read_bytes()
    except OSError as exc:
        print(f"✗ cannot read {args.validate}: {exc}")
        return 2
    errors, warnings = validate_catalog(body)
    for w in warnings:
        print(f"⚠ {w}")
    for e in errors:
        print(f"✗ {e}")
    if errors:
        print(f"✗ INVALID catalog: {len(errors)} structural error(s).")
        return 1
    if warnings and args.strict:
        print(f"✗ catalog valid but {len(warnings)} warning(s) under --strict.")
        return 1
    print(f"✓ valid catalog ({len(warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    import sys as _sys

    raise SystemExit(_main(_sys.argv[1:]))
