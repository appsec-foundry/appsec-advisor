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


def _write_prior_assessment_output(repo: Path, rel: str) -> Path:
    """A prior run's output directory, carrying the marker pair that
    scan_excludes.is_assessment_output_dir() recognises."""
    out = repo / rel
    out.mkdir(parents=True)
    (out / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")
    (out / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    return out


def test_prior_assessment_output_is_not_harvested(tmp_path: Path) -> None:
    """A previous run's artifacts are the plugin's OWN prose about credentials
    — the densest false-positive source there is. Harvesting them makes each
    run poison the next one (juice-shop 2026-08-28: 204 prior-run artifacts
    were read as repository source).

    The static exclude list cannot carry this: ``--output-dir`` is
    user-selectable and copies get arbitrary names, so detection must be
    structural.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.js").write_text(f"const secret = '{SECRET}'\n", encoding="utf-8")

    # Not `docs/security/` — the name the static path_prefix rule knows.
    prior = _write_prior_assessment_output(repo, "reports/appsec-2026-08")
    (prior / ".stride-backend.json").write_text(
        '{"evidence": "the seeded config sets password: Zx9Kq2LmPv4Ts"}\n', encoding="utf-8"
    )

    secrets = R.collect_source_secrets(repo)
    assert "Zx9Kq2LmPv4Ts" not in secrets, "value harvested out of a prior run's own output"
    assert SECRET in secrets, "real source secrets must still be harvested"


def test_word_shaped_value_does_not_corrupt_unrelated_prose(tmp_path: Path) -> None:
    """Independent blast-radius bound on the global substring replace.

    The module's premise is that the scanner never yields a false positive, so
    a context-free ``str.replace`` over the whole report is safe. When that
    premise fails, an ordinary English word is destroyed everywhere it occurs.
    A word-shaped value is therefore replaced only where it stands as an
    ASSIGNED credential, never in running prose — in prose it is simply the
    word, and nothing separates it from a leak.

    Nearness to a credential keyword does not qualify. A threat model discusses
    authentication on every page, and the first sentence below (verbatim from
    threat-model.md:856 of the juice-shop 2026-08-28 run) carries
    "authentication" one clause ahead of the word.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    # Indent-only lead-in → a YAML key, so this stays flagged and is harvested
    # as a word-shaped value.
    (repo / "config.yml").write_text("  secret: referenced\n", encoding="utf-8")

    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text(
        "Network-reachable entry points classified by authentication requirement. "
        "Each row links to the threat(s) referenced in its Notes column.\n"
        "Most third-party actions are referenced at mutable version tags.\n"
        "The evidence line reads api_key: referenced in the manifest.\n",
        encoding="utf-8",
    )

    rc = R.main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    text = (out / "threat-model.md").read_text(encoding="utf-8")

    assert "threat(s) referenced in its Notes column" in text, "prose near a credential keyword was corrupted"
    assert "actions are referenced at mutable version tags" in text, "unrelated prose was corrupted"
    assert "api_key: referenced" not in text, "an assigned credential was left unmasked"


def test_high_entropy_value_still_replaced_in_bare_prose(tmp_path: Path) -> None:
    """The context gate applies ONLY to word-shaped values. A real secret with
    token shape keeps the unconditional global replace, including in a sentence
    that names no credential keyword at all."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.js").write_text(f"const secret = '{SECRET}'\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text(f"An attacker replays {SECRET} against the API.\n", encoding="utf-8")

    rc = R.main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
    assert SECRET not in (out / "threat-model.md").read_text(encoding="utf-8")


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
