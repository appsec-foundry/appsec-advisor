"""Guards for the per-component STRIDE output glob (scripts/stride_outputs.py).

`.stride-dispatch-manifest.json`, `.stride-selection.json` and
`.stride-analyst-context.json` share the `.stride-` prefix with the
per-component results but are written BEFORE the Phase-9 fan-out. A bare
`glob(".stride-*.json")` counts them as finished components: the watchdog's
`stride_count == 0` canary can then never fire, the progress widget reports
more components ready than exist, and `.merge-candidates.json` records
`analyst-context` / `dispatch-manifest` / `selection` as component ids.

Two halves are guarded here: the helper's behaviour, and the rule that
read/count consumers go through it instead of re-inlining the raw glob.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import stride_outputs  # noqa: E402


def _make_run(tmp_path: Path, component_ids: list[str], with_sidecars: bool = True) -> Path:
    out = tmp_path / "run"
    out.mkdir()
    for cid in component_ids:
        (out / f".stride-{cid}.json").write_text(
            json.dumps({"component_id": cid, "component_name": cid, "threats": []}),
            encoding="utf-8",
        )
    if with_sidecars:
        for name in stride_outputs.RESERVED_SIDECARS:
            (out / name).write_text("{}", encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Helper behaviour
# ---------------------------------------------------------------------------


def test_sidecars_are_excluded(tmp_path):
    out = _make_run(tmp_path, ["auth", "express-backend"])
    names = [p.name for p in stride_outputs.stride_output_files(out)]
    assert names == [".stride-auth.json", ".stride-express-backend.json"]


def test_sidecars_only_yields_nothing(tmp_path):
    """The canary state: manifest on disk, fan-out has produced nothing yet."""
    out = _make_run(tmp_path, [], with_sidecars=True)
    assert stride_outputs.stride_output_files(out) == []


def test_component_id_round_trip(tmp_path):
    out = _make_run(tmp_path, ["file-upload-service"])
    (path,) = stride_outputs.stride_output_files(out)
    assert stride_outputs.component_id(path) == "file-upload-service"


def test_is_stride_output_rejects_each_reserved_name():
    for name in stride_outputs.RESERVED_SIDECARS:
        assert not stride_outputs.is_stride_output(Path("/tmp") / name), name


# ---------------------------------------------------------------------------
# Consumer regressions — each of these counted the sidecars before the fix
# ---------------------------------------------------------------------------


def test_watchdog_scan_counts_only_components(tmp_path):
    import skill_watchdog

    out = _make_run(tmp_path, ["auth"])
    assert skill_watchdog._scan_stride(out)["stride_count"] == 1


def test_merge_loader_yields_only_component_ids(tmp_path):
    import merge_threats

    out = _make_run(tmp_path, ["auth", "data-layer"])
    assert [cid for cid, _ in merge_threats._load_stride_outputs(out)] == ["auth", "data-layer"]


def test_baseline_hashes_only_components(tmp_path):
    import baseline_state

    out = _make_run(tmp_path, ["auth"])
    assert list(baseline_state._hash_stride_files(out)) == ["auth"]


def test_reanalyzed_ids_ignore_legacy_sidecar_keys(tmp_path):
    """A baseline written before the fix carries sidecar ids. Their content
    changes nearly every run, so they must not surface as changed components."""
    import build_threat_model_yaml

    out = _make_run(tmp_path, ["auth"])
    cache = out / ".appsec-cache"
    cache.mkdir()
    (cache / "baseline.json").write_text(
        json.dumps(
            {
                "stride_files": {
                    "auth": {"path": ".stride-auth.json", "sha256": "sha256:stale"},
                    "dispatch-manifest": {"path": ".stride-dispatch-manifest.json", "sha256": "sha256:stale"},
                    "analyst-context": {"path": ".stride-analyst-context.json", "sha256": "sha256:stale"},
                }
            }
        ),
        encoding="utf-8",
    )
    assert build_threat_model_yaml._reanalyzed_component_ids(out) == {"auth"}


def test_durations_ignore_sidecars(tmp_path):
    import record_component_durations

    out = _make_run(tmp_path, ["auth"])
    # Legacy mtime fallback path — the sidecars must not appear as components.
    durations = record_component_durations._stride_durations(out, phase_9_start=1)
    assert set(durations) <= {"auth"}


# ---------------------------------------------------------------------------
# Drift guard — new consumers must use the helper
# ---------------------------------------------------------------------------

# Modules allowed to keep the broad `.stride-*.json` pattern. These delete,
# publish-block or JSON-lint every matching file; sweeping the sidecars in
# with the results is the correct behaviour there.
_BROAD_GLOB_ALLOWED = {
    "stride_outputs.py",  # defines the pattern
    "orchestration_controller.py",  # full/rebuild cleanup
    "runtime_cleanup.py",  # cleanup whitelist (docstring)
    "publish_threat_model.py",  # never-publish list
    "validate_cache.py",  # JSON-validity sweep
}

_GLOB_CALL_RE = re.compile(r"""glob\(\s*["']\.stride-\*\.json["']""")


def test_no_new_inline_stride_glob():
    offenders = []
    for path in sorted(SCRIPTS.glob("*.py")):
        if path.name in _BROAD_GLOB_ALLOWED:
            continue
        if _GLOB_CALL_RE.search(path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    assert not offenders, (
        f"{offenders} glob '.stride-*.json' directly — use "
        "stride_outputs.stride_output_files() so the `.stride-` sidecars "
        "(dispatch manifest, selection, analyst context) are not counted as "
        "finished components."
    )


def test_every_reserved_sidecar_is_a_real_artifact():
    """Each reserved name must be written somewhere in the plugin — a stale
    entry would silently hide a real component id from every consumer."""
    haystack = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in list(SCRIPTS.glob("*.py")) + list((REPO_ROOT / "agents").rglob("*.md"))
    )
    for name in stride_outputs.RESERVED_SIDECARS:
        assert name in haystack, f"{name} is registered as a sidecar but nothing writes it"
