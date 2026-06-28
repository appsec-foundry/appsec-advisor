"""Tests for scripts/redact_known_secrets.py — deterministic exact-value secret
redaction. The key property is that a secret VALUE copied into PROSE (which the
pattern-based masker cannot catch) is still scrubbed, because the value is
discovered in the source via a matchable assignment form and then exact-string
replaced everywhere."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import redact_known_secrets as R  # noqa: E402

SECRET = "e2e-fixture-jwt-secret-7f4c91"


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.js").write_text(f"const secret = '{SECRET}'\n", encoding="utf-8")
    return repo


def test_collect_source_secrets_finds_value(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    secrets = R.collect_source_secrets(repo)
    assert SECRET in secrets
    assert "****" in secrets[SECRET]  # masked form carries the marker


def test_redacts_prose_form_across_artifacts(tmp_path: Path) -> None:
    """The prose form (no assignment operator) evades pattern masking but must
    still be scrubbed by exact-value redaction."""
    repo = _make_repo(tmp_path)
    out = tmp_path / "out"
    (out / ".fragments").mkdir(parents=True)
    (out / "threat-model.md").write_text(
        f"The signing secret is the literal {SECRET} in server.js.\n", encoding="utf-8"
    )
    (out / "threat-model.sarif.json").write_text(json.dumps({"x": f"leaked {SECRET}"}), encoding="utf-8")
    (out / ".fragments" / "attack-walkthroughs.md").write_text(
        f"attacker reads secret = '{SECRET}'\n", encoding="utf-8"
    )

    rc = R.main(["--repo-root", str(repo), "--output-dir", str(out), "--write-scan-json"])
    assert rc == 0

    # No raw secret survives in ANY artifact.
    for p in out.rglob("*"):
        if p.is_file():
            assert SECRET not in p.read_text(encoding="utf-8"), f"raw secret still in {p.name}"

    scan = json.loads((out / ".qa-secret-scan.json").read_text(encoding="utf-8"))
    assert scan["ok"] == 1
    assert scan["redaction"]["total_redactions"] >= 3


def test_short_values_not_redacted(tmp_path: Path) -> None:
    """Values below the min length are not collected (avoids scrubbing common
    short tokens)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "c.js").write_text("const key = 'abc'\n", encoding="utf-8")  # 3 chars
    secrets = R.collect_source_secrets(repo)
    assert "abc" not in secrets


def test_no_source_secrets_is_noop(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clean.js").write_text("const x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("nothing secret here\n", encoding="utf-8")
    rc = R.main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    report = json.loads((out / ".secret-redaction.json").read_text(encoding="utf-8"))
    assert report["total_redactions"] == 0
