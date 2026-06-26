"""Deterministic 2-run incremental E2E — drives scripts/build_threat_model_yaml.py
`main()` TWICE in sequence (run1 full → mutate → run2 incremental) against a
self-built minimal output dir, with NO LLM and NO `_last-run` fixture dependency.

Why this exists (gap analysis 2026-06-26): the existing suite has
  (a) direct-function unit tests for the reconciler/changelog
      (test_build_threat_model_yaml.py::test_reconcile_* / ::test_changelog_*), and
  (b) single-run main() tests against the git-ignored `_last-run` fixture.
NOTHING runs main() twice in succession, so the integration — run1's
threat-model.yaml becoming run2's `prior_yaml`, the reconciler firing inside
main()'s gate, and the changelog extending rather than overwriting across two
real builds — was never exercised end-to-end. These are exactly the seams where
real bugs landed historically (silent threat loss on shallower re-scan;
changelog overwritten not extended).

Hermetic strategy:
  * Minimal sidecars only (.skill-config / .threats-merged / .components /
    .assets / .trust-boundaries / .security-controls) so main() runs.
  * --plugin-root → an EMPTY dir, which makes main() skip the
    validate_intermediate.py subprocess (see main(): `if validator.exists()`),
    so the test needs no schema-perfect output and spawns no child process.
  * --repo-root → a non-git tmp dir, so build_meta's git lookups resolve to
    "unknown" → fully deterministic output.
  * baseline.json + .stride-<id>.json are seeded by hand between the two runs
    exactly as the real skill (baseline_state.py) would write them — that is the
    LLM-free seam the reconciler reads from.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_threat_model_yaml.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_threat_model_yaml", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = _load()


# ─── fixture builders ──────────────────────────────────────────────────────


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _threat(tid, comp, cwe, title):
    """A .threats-merged.json[threats] entry (pre-build_threats shape)."""
    return {
        "id": tid,
        "component_id": comp,
        "cwe": cwe,
        "title": title,
        "risk": "High",
        "likelihood": "Medium",
        "impact": "High",
    }


_COMPONENTS = [
    {"id": "auth", "name": "Auth Service", "type": "service"},
    {"id": "api", "name": "API Gateway", "type": "service"},
]


def _seed_sidecars(out: Path, repo: Path, *, mode: str, depth: str, threats: list[dict]) -> None:
    """Write the minimal sidecar set main() consumes for one run."""
    _write_json(out / ".skill-config.json", {"mode": mode, "assessment_depth": depth, "repo_root": str(repo)})
    _write_json(out / ".threats-merged.json", {"threats": threats})
    _write_json(out / ".components.json", {"components": _COMPONENTS})
    _write_json(out / ".assets.json", {"assets": [{"id": "A-1", "name": "User DB", "classification": "PII"}]})
    _write_json(out / ".trust-boundaries.json", {"trust_boundaries": [{"id": "TB-1", "name": "Internet edge"}]})
    _write_json(out / ".security-controls.json", {"security_controls": [{"id": "SC-1", "name": "TLS"}]})


def _seed_baseline(out: Path, *, prior_depth: str, stride: dict[str, tuple[bytes, bytes]]) -> None:
    """Seed .appsec-cache/baseline.json + on-disk .stride-<id>.json exactly as
    baseline_state.py would, so the reconciler's sha-diff dirty-detection fires.

    stride: {cid: (baseline_bytes, current_bytes)} — a component is "re-analyzed"
    when current != baseline (on-disk stride no longer matches the recorded hash).
    """
    cache = out / ".appsec-cache"
    cache.mkdir(parents=True, exist_ok=True)
    sf = {}
    for cid, (baseline_bytes, current_bytes) in stride.items():
        sf[cid] = {"sha256": "sha256:" + hashlib.sha256(baseline_bytes).hexdigest()}
        (out / f".stride-{cid}.json").write_bytes(current_bytes)
    (cache / "baseline.json").write_text(json.dumps({"last_run_depth": prior_depth, "stride_files": sf}))


def _run_main(monkeypatch, out: Path, plugin_root: Path, repo: Path) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        ["build_threat_model_yaml.py", str(out), "--plugin-root", str(plugin_root), "--repo-root", str(repo)],
    )
    return b.main()


def _scaffold(tmp_path: Path):
    """Return (out_dir, empty_plugin_root, non_git_repo_root)."""
    out = tmp_path / "run"
    out.mkdir()
    plugin = tmp_path / "empty_plugin"  # lacks scripts/validate_intermediate.py → main skips validation
    plugin.mkdir()
    repo = tmp_path / "repo"  # non-git → deterministic "unknown" commit
    repo.mkdir()
    return out, plugin, repo


# ─── canonical scenario: shallower re-scan must carry the dropped threat ────


def test_two_run_incremental_carries_dropped_threat_and_extends_changelog(tmp_path, monkeypatch):
    out, plugin, repo = _scaffold(tmp_path)

    # ── Run 1: full scan at STANDARD depth, two findings (one per component).
    _seed_sidecars(
        out,
        repo,
        mode="full",
        depth="standard",
        threats=[
            _threat("T-001", "auth", "CWE-287", "Weak auth (login.ts:10)"),
            _threat("T-002", "api", "CWE-89", "SQLi (query.ts:5)"),
        ],
    )
    assert _run_main(monkeypatch, out, plugin, repo) == 0

    run1 = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert {t["id"] for t in run1["threats"]} == {"T-001", "T-002"}
    assert len(run1["changelog"]) == 1
    assert run1["changelog"][0]["delta_basis"] == "initial"
    auth_fp = b._threat_fingerprint(next(t for t in run1["threats"] if t["component"] == "auth"))

    # ── Between runs: the source changed and the auth component was re-analyzed.
    # baseline records the PRIOR (standard) depth + the prior stride hash; the
    # on-disk auth stride now differs (dirty), api is untouched (carried-forward).
    _seed_baseline(
        out,
        prior_depth="standard",
        stride={"auth": (b"auth-old", b"auth-new"), "api": (b"api-same", b"api-same")},
    )

    # ── Run 2: INCREMENTAL at QUICK depth (strictly shallower). The shallower
    # re-scan of auth drops its finding without affirming a fix; api re-emitted.
    _seed_sidecars(
        out,
        repo,
        mode="incremental",
        depth="quick",
        threats=[_threat("T-001", "api", "CWE-89", "SQLi (query.ts:5)")],
    )
    assert _run_main(monkeypatch, out, plugin, repo) == 0
    run2 = yaml.safe_load((out / "threat-model.yaml").read_text())

    # (1) Preservation: the dropped auth finding was re-injected, flagged honest,
    #     with a fresh collision-free id (NOT silently lost).
    carried = [t for t in run2["threats"] if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert len(carried) == 1, "shallower re-scan must carry the dropped auth threat"
    assert carried[0]["component"] == "auth"
    assert b._threat_fingerprint(carried[0]) == auth_fp
    assert carried[0]["id"] not in {"T-001"}  # renumbered past the run-2 max

    # (2) Additive history THROUGH main(): run2 extends, never overwrites.
    assert len(run2["changelog"]) == 2, "changelog must extend across runs, not reset"
    assert run2["changelog"][0]["delta_basis"] == "incremental"
    assert run2["changelog"][1] == run1["changelog"][0], "prior entry must survive verbatim"


# ─── control: at EQUAL/deeper depth a non-reproduced finding is resolved ─────


def test_two_run_incremental_equal_depth_resolves_not_carries(tmp_path, monkeypatch):
    out, plugin, repo = _scaffold(tmp_path)
    _seed_sidecars(
        out,
        repo,
        mode="full",
        depth="standard",
        threats=[_threat("T-001", "auth", "CWE-287", "Weak auth (login.ts:10)")],
    )
    assert _run_main(monkeypatch, out, plugin, repo) == 0

    _seed_baseline(out, prior_depth="standard", stride={"auth": (b"auth-old", b"auth-new")})
    # Run 2 at the SAME depth → a non-reproduced prior finding is genuinely
    # resolved, recorded, never carried as an unverified ghost.
    _seed_sidecars(out, repo, mode="incremental", depth="standard", threats=[])
    assert _run_main(monkeypatch, out, plugin, repo) == 0
    run2 = yaml.safe_load((out / "threat-model.yaml").read_text())

    assert not [t for t in run2["threats"] if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    resolved = run2["changelog"][0].get("resolved", {})
    assert "T-001" in (resolved.get("threats") or [])


# ─── control: a FULL re-run must NOT reconcile, even with a baseline present ─


def test_two_run_full_mode_does_not_reconcile(tmp_path, monkeypatch):
    out, plugin, repo = _scaffold(tmp_path)
    _seed_sidecars(
        out,
        repo,
        mode="full",
        depth="standard",
        threats=[_threat("T-001", "auth", "CWE-287", "Weak auth (login.ts:10)")],
    )
    assert _run_main(monkeypatch, out, plugin, repo) == 0

    # Baseline on disk would let the reconciler fire — but main() gates carry on
    # mode == "incremental", so a re-run that resolved to FULL must be a no-op.
    _seed_baseline(out, prior_depth="thorough", stride={"auth": (b"auth-old", b"auth-new")})
    _seed_sidecars(out, repo, mode="full", depth="quick", threats=[])
    assert _run_main(monkeypatch, out, plugin, repo) == 0
    run2 = yaml.safe_load((out / "threat-model.yaml").read_text())

    assert not [t for t in run2["threats"] if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert run2["changelog"][0]["delta_basis"] != "incremental"
