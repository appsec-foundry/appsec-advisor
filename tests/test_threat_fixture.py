"""Tests for scripts/threat_fixture.py — the freeze/replay golden-master tool.

Split into fast pure-function unit tests and a small set of end-to-end tests
that actually run the deterministic tail (build_threat_model_yaml → compose →
export_sarif) via subprocess. The e2e source is derived from the committed
`tests/fixtures/e2e/_last-run` run dir (a real `--requirements --quick` run);
we flip `check_requirements` off so the requirements fragment is not demanded,
giving a fully buildable run dir without inventing one.
"""

from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path

import pytest
import threat_fixture as tf
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_LAST_RUN = _REPO_ROOT / "tests" / "fixtures" / "e2e" / "_last-run"
_SYNTH_REPO = _REPO_ROOT / "tests" / "fixtures" / "e2e" / "synthetic-repo"


# ---------------------------------------------------------------------------
# pure unit tests
# ---------------------------------------------------------------------------


def test_scrub_yaml_obj_replaces_volatile_fields():
    obj = {
        "meta": {
            "generated": "2026-06-14T08:00:00Z",
            "git": {"commit_sha": "abc123", "branch": "feature/x", "remote_url": "https://example/r"},
            "model": "sonnet",
        },
        "changelog": [
            {"version": 1, "date": "2026-06-14", "current_sha": "abc123", "previous_date": "2026-06-01"},
        ],
    }
    out = tf.scrub_yaml_obj(obj)
    assert out["meta"]["generated"] == tf.SENTINEL_TS
    assert out["meta"]["git"] == {"commit_sha": tf.SENTINEL_SHA, "branch": "main", "remote_url": ""}
    assert out["meta"]["model"] == "sonnet"  # untouched
    cl = out["changelog"][0]
    assert cl["date"] == tf.SENTINEL_DATE
    assert cl["current_sha"] == tf.SENTINEL_SHA
    assert cl["previous_date"] == tf.SENTINEL_DATE


def test_scrub_tolerates_missing_optional_fields():
    # no git block, no changelog — must not raise
    obj = {"meta": {"model": "sonnet"}, "threats": []}
    out = tf.scrub_yaml_obj(obj)
    assert out["meta"]["model"] == "sonnet"


def test_normalize_yaml_text_idempotent_and_deterministic():
    text = yaml.safe_dump(
        {
            "meta": {"generated": "2026-06-14T08:00:00Z", "git": {"commit_sha": "deadbeef"}},
            "b": 2,
            "a": 1,
        }
    )
    once = tf.normalize_yaml_text(text)
    twice = tf.normalize_yaml_text(once)
    assert once == twice  # idempotent
    assert tf.SENTINEL_TS in once
    assert "deadbeef" not in once
    # canonical sort_keys: top-level keys emitted in sorted order a, b, meta
    top_keys = [ln.split(":", 1)[0] for ln in once.splitlines() if ln and not ln.startswith((" ", "-"))]
    assert top_keys == sorted(top_keys)


def test_canonical_scanner_json_scrubs_timestamp_and_path():
    raw = json.dumps(
        {
            "generated_at": "2026-06-14T08:22:59Z",
            "repo_root": "/home/me/repo",
            "routes": [],
            "version": 1,
        }
    )
    out = tf.canonical_scanner_json(raw)
    parsed = json.loads(out)
    assert parsed["generated_at"] == tf.SENTINEL_TS
    assert parsed["repo_root"] == ""
    assert parsed["version"] == 1


@pytest.mark.parametrize(
    "name",
    [
        "threat-model.yaml",
        "threat-model.md",
        "threat-model.pdf",
        ".appsec-cache",
        "docs",
        ".agent-run.log",
        ".hook-events.log.1",
        ".appsec-progress.json",
        ".phase-epoch",
        ".stage1b-start",
        ".skill-watchdog.tick",
    ],
)
def test_is_noise_top_true(name):
    assert tf._is_noise_top(name) is True


@pytest.mark.parametrize(
    "name",
    [
        ".components.json",
        ".threats-merged.json",
        ".fragments",
        ".skill-config.json",
        ".stride-backend-api.json",
        ".recon-summary.md",
        ".route-inventory.json",
        ".requirements.yaml",
    ],
)
def test_is_noise_top_false(name):
    assert tf._is_noise_top(name) is False


def test_manifest_roundtrip_and_tamper(tmp_path):
    fx = tmp_path / "fx"
    (fx / "golden").mkdir(parents=True)
    (fx / "golden" / "a.txt").write_text("hello")
    (fx / "b.txt").write_text("world")
    tf.write_manifest(fx)
    assert tf.verify_manifest(fx) == []  # clean

    (fx / "golden" / "a.txt").write_text("HELLO")  # mutate
    problems = tf.verify_manifest(fx)
    assert any(p.startswith("changed: golden/a.txt") for p in problems)

    (fx / "c.txt").write_text("extra")  # untracked
    assert any(p.startswith("untracked: c.txt") for p in tf.verify_manifest(fx))

    (fx / "b.txt").unlink()  # missing
    assert any(p.startswith("missing: b.txt") for p in tf.verify_manifest(fx))


def test_make_archive_reproducible_and_valid(tmp_path):
    a = tmp_path / "fxa"
    b = tmp_path / "fxb"
    for d in (a, b):
        (d / "golden").mkdir(parents=True)
        (d / "golden" / "x.txt").write_text("same")
        (d / "expected-meta.json").write_text("{}")
        tf.write_manifest(d)
    tgz_a = tf.make_archive(a)
    tgz_b = tf.make_archive(b)
    # identical content under different dir names → same member set, and the
    # archive of the SAME dir is byte-stable: re-archiving a must match itself.
    assert tf.make_archive(a).read_bytes() == tgz_a.read_bytes()
    assert tarfile.is_tarfile(tgz_a)
    with tarfile.open(tgz_a) as t:
        names = sorted(m.name for m in t.getmembers())
    assert "fxa/golden/x.txt" in names
    # mtimes zeroed for reproducibility
    with tarfile.open(tgz_a) as t:
        assert all(m.mtime == 0 for m in t.getmembers())
    assert tgz_b.exists()


# ---------------------------------------------------------------------------
# end-to-end (subprocess) tests
# ---------------------------------------------------------------------------


def _prepare_source(dest: Path) -> Path:
    shutil.copytree(_LAST_RUN, dest)
    cfg_path = dest / ".skill-config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["check_requirements"] = False
    cfg["repo_root"] = "."
    cfg_path.write_text(json.dumps(cfg, indent=1))
    return dest


@pytest.fixture(scope="session")
def frozen(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("threat_fixture_e2e")
    src = _prepare_source(base / "run")
    into = base / "fixture"
    tf.freeze(src, into, _SYNTH_REPO, archive=False)
    return into


def test_freeze_layout(frozen):
    for rel in (
        "inputs",
        "golden/threat-model.yaml",
        "golden/threat-model.md",
        "golden/threat-model.sarif.json",
        "expected-meta.json",
        "MANIFEST.json",
        "scanner-golden/.route-inventory.json",
    ):
        assert (frozen / rel).exists(), rel


def test_freeze_golden_yaml_is_scrubbed(frozen):
    data = yaml.safe_load((frozen / "golden" / "threat-model.yaml").read_text())
    assert data["meta"]["generated"] == tf.SENTINEL_TS
    assert data["meta"]["git"]["commit_sha"] == tf.SENTINEL_SHA
    for entry in data.get("changelog", []):
        assert entry["date"] == tf.SENTINEL_DATE


def test_freeze_excludes_noise_and_outputs_from_inputs(frozen):
    names = {p.name for p in (frozen / "inputs").iterdir()}
    assert "threat-model.yaml" not in names  # output, not input
    assert ".appsec-cache" not in names  # volatile cache
    assert not any(n.endswith(".log") for n in names)
    # but real producer inputs are kept
    assert ".skill-config.json" in names
    assert ".threats-merged.json" in names
    assert ".components.json" in names
    assert ".fragments" in names


def test_expected_meta_pins_repo_and_scanners(frozen):
    meta = json.loads((frozen / "expected-meta.json").read_text())
    assert meta["fixture_version"] == 1
    assert meta["repo"] is not None
    assert meta["repo"]["commit_sha"]  # some sha string
    assert meta["scanners"] == {".route-inventory.json": "route_inventory.py"}
    assert meta["plugin_version"]


def test_replay_zero_drift_all_stages(frozen):
    res = tf.replay(frozen, ["yaml", "md", "sarif", "scanner"], _SYNTH_REPO)
    assert res["integrity"] == []
    for stage, diffs in res["stages"].items():
        assert diffs == [], f"{stage} drifted:\n{''.join(diffs)}"


@pytest.mark.parametrize(
    "golden_name,stage",
    [
        ("threat-model.yaml", "yaml"),
        ("threat-model.md", "md"),
        ("threat-model.sarif.json", "sarif"),
    ],
)
def test_replay_detects_golden_drift(frozen, tmp_path, golden_name, stage):
    work = tmp_path / "f"
    shutil.copytree(frozen, work)
    g = work / "golden" / golden_name
    g.write_text(g.read_text() + "\nDRIFT INJECTED\n")
    res = tf.replay(work, [stage], _SYNTH_REPO)
    assert res["stages"][stage], "expected drift to be reported"


def test_replay_integrity_detects_input_tamper(frozen, tmp_path):
    work = tmp_path / "f"
    shutil.copytree(frozen, work)
    target = work / "inputs" / ".threats-merged.json"
    target.write_text(target.read_text() + " ")
    res = tf.replay(work, ["sarif"], _SYNTH_REPO)
    assert any("changed: inputs/.threats-merged.json" in p for p in res["integrity"])


def test_replay_scanner_skipped_without_repo(frozen):
    res = tf.replay(frozen, ["scanner"], repo=None)
    # meta records a repo path; if it resolves the scanner runs, otherwise skip.
    diffs = res["stages"]["scanner"]
    assert diffs == [] or diffs[0].startswith("SKIPPED")


def test_freeze_refuses_incomplete_run(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / ".skill-config.json").write_text("{}")  # no threat-model.yaml
    with pytest.raises(SystemExit):
        tf.freeze(run, tmp_path / "fx", None, False)


def test_freeze_refuses_existing_target(frozen, tmp_path):
    src = _prepare_source(tmp_path / "run")
    with pytest.raises(SystemExit):
        tf.freeze(src, frozen, None, False)  # frozen already exists


def test_freeze_without_repo_skips_scanner_and_pin(tmp_path):
    src = _prepare_source(tmp_path / "run")
    into = tmp_path / "fx"
    tf.freeze(src, into, None, False)
    meta = json.loads((into / "expected-meta.json").read_text())
    assert meta["repo"] is None
    assert meta["scanners"] == {}
    assert not (into / "scanner-golden").exists()
    # the deterministic tail goldens still exist and replay clean
    res = tf.replay(into, ["yaml", "md", "sarif"], None)
    assert all(d == [] for d in res["stages"].values())


def test_cli_freeze_then_replay(tmp_path):
    src = _prepare_source(tmp_path / "run")
    into = tmp_path / "fx"
    assert tf.main(["freeze", "--run", str(src), "--into", str(into), "--repo", str(_SYNTH_REPO)]) == 0
    assert tf.main(["replay", "--fixture", str(into), "--repo", str(_SYNTH_REPO)]) == 0


def test_cli_replay_exits_nonzero_on_drift(frozen, tmp_path):
    work = tmp_path / "f"
    shutil.copytree(frozen, work)
    g = work / "golden" / "threat-model.md"
    g.write_text(g.read_text() + "\nDRIFT\n")
    # manifest now also disagrees → integrity + stage drift both reported
    assert tf.main(["replay", "--fixture", str(work), "--stage", "md", "--repo", str(_SYNTH_REPO)]) == 1


def test_freeze_archive_emits_reproducible_tgz(tmp_path):
    src = _prepare_source(tmp_path / "run")
    into = tmp_path / "fx"
    tf.freeze(src, into, None, archive=True)
    tgz = into.with_suffix(".tgz")
    assert tgz.exists() and tarfile.is_tarfile(tgz)


def test_replay_rejects_non_fixture_dir(tmp_path):
    (tmp_path / "expected-meta.json").write_text("{}")  # no golden/
    with pytest.raises(SystemExit):
        tf.replay(tmp_path, ["yaml"], None)


def test_replay_scanner_skipped_when_pinned_repo_missing(frozen, tmp_path):
    work = tmp_path / "f"
    shutil.copytree(frozen, work)
    meta_path = work / "expected-meta.json"
    meta = json.loads(meta_path.read_text())
    meta["repo"]["repo_path"] = str(tmp_path / "does-not-exist")
    meta_path.write_text(json.dumps(meta))
    res = tf.replay(work, ["scanner"], repo=None)
    assert res["stages"]["scanner"][0].startswith("SKIPPED")


def test_resolve_stages_explicit_list(frozen):
    assert tf._resolve_stages("yaml,md", frozen) == ["yaml", "md"]
    assert "scanner" in tf._resolve_stages("all", frozen)  # meta has scanners
