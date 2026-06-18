from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import postscan_secret_check as postscan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _hit(pattern: str = "generic_credential_assignment", snippet: str = "password=admin123", line: int = 1):
    return SimpleNamespace(pattern=pattern, snippet=snippet, line=line)


def test_candidate_files_include_existing_defaults_and_extra_paths(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "report")
    _write(out / ".architect-review.md", "review")
    _write(out / "custom" / "sidecar.txt", "sidecar")

    candidates = postscan._candidate_files(out, ["custom/sidecar.txt", "missing.txt"])

    assert [path.relative_to(out).as_posix() for path in candidates] == [
        "threat-model.md",
        ".architect-review.md",
        "custom/sidecar.txt",
    ]


def test_run_aggregates_hits_by_relative_file_and_counts_checked_files(monkeypatch, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "report")
    _write(out / "threat-model.yaml", "yaml")
    _write(out / "extra.json", "extra")

    def fake_scan_file(path: Path):
        if path.name == "threat-model.md":
            return [_hit("aws_access_key", "AKIAABCDEFGHIJKLMNOP", 4)]
        if path.name == "extra.json":
            return [_hit("github_pat", "ghp_x", 2), _hit("jwt", "eyJ.x.y", 3)]
        return []

    monkeypatch.setattr(postscan, "scan_file", fake_scan_file)

    report = postscan.run(out, extra=["extra.json"])

    assert report == {
        "output_dir": str(out),
        "checked_files": ["threat-model.md", "threat-model.yaml", "extra.json"],
        "masked_files": {},
        "hit_count": 3,
        "by_file": {
            "threat-model.md": [{"pattern": "aws_access_key", "snippet": "AKIAABCDEFGHIJKLMNOP", "line": 4}],
            "extra.json": [
                {"pattern": "github_pat", "snippet": "ghp_x", "line": 2},
                {"pattern": "jwt", "snippet": "eyJ.x.y", "line": 3},
            ],
        },
    }


def test_run_uses_real_secret_scan_for_clean_masked_and_leaky_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "Masked API key: AIza****\n")
    _write(out / "threat-model.yaml", "finding: password=supersecret123\n")

    report = postscan.run(out)

    assert report["checked_files"] == ["threat-model.md", "threat-model.yaml"]
    assert report["hit_count"] == 1
    assert report["by_file"]["threat-model.yaml"][0]["pattern"] == "generic_credential_assignment"
    assert report["by_file"]["threat-model.yaml"][0]["line"] == 1


def test_main_missing_output_dir_returns_3(tmp_path: Path, capsys) -> None:
    rc = postscan.main(["--output-dir", str(tmp_path / "missing")])

    assert rc == 3
    assert "output dir not found" in capsys.readouterr().err


def test_main_clean_text_output_returns_0(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "clean")
    monkeypatch.setattr(postscan, "scan_file", lambda path: [])

    rc = postscan.main(["--output-dir", str(out)])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "clean (1 files scanned)" in captured.err


def test_main_text_output_reports_hits_and_returns_2(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "leak")
    _write(out / ".recon-summary.md", "leak")

    def fake_scan_file(path: Path):
        return [_hit("stripe_live_secret", "sk_live_x", 7)] if path.name == ".recon-summary.md" else []

    monkeypatch.setattr(postscan, "scan_file", fake_scan_file)

    rc = postscan.main(["--output-dir", str(out)])

    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "1 unmasked secret hit(s) across 1 file(s)" in captured.err
    assert ".recon-summary.md:7  [stripe_live_secret]  'sk_live_x'" in captured.err


def test_main_json_output_includes_extra_paths_and_returns_2(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "report")
    _write(out / "sidecar.txt", "sidecar")

    def fake_scan_file(path: Path):
        return [_hit("jwt", "eyJ.header.payload", 11)] if path.name == "sidecar.txt" else []

    monkeypatch.setattr(postscan, "scan_file", fake_scan_file)

    rc = postscan.main(["--output-dir", str(out), "--also", "sidecar.txt", "--json"])

    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["checked_files"] == ["threat-model.md", "sidecar.txt"]
    assert payload["hit_count"] == 1
    assert payload["by_file"] == {"sidecar.txt": [{"pattern": "jwt", "snippet": "eyJ.header.payload", "line": 11}]}


def test_mask_neutralises_pem_marker_in_recon_summary_then_passes(tmp_path: Path, capsys) -> None:
    """The exact e2e-full-repair failure: a recon-summary table cell keeps the
    `-----BEGIN RSA PRIVATE KEY-----` marker (body truncated), which the detector
    flags unconditionally. `--mask` must deterministically neutralise it on disk
    so the always-on gate passes without depending on LLM authoring discipline."""
    out = tmp_path / "out"
    out.mkdir()
    recon = out / ".recon-summary.md"
    leaky = (
        "| RSA private key | lib/insecurity.ts:23 | "
        "`-----BEGIN RSA PRIVATE KEY-----\\r\\nMIICXAIBAAKBgQDNwqL...` (1024-bit, **** chars) |\n"
    )
    _write(recon, leaky)

    # Without --mask the real detector flags the marker (the failure).
    assert postscan.run(out)["hit_count"] >= 1

    rc = postscan.main(["--output-dir", str(out), "--mask"])

    assert rc == 0
    masked_text = recon.read_text(encoding="utf-8")
    assert "BEGIN RSA PRIVATE KEY" not in masked_text
    assert "[PEM PRIVATE KEY — REDACTED]" in masked_text
    # The finding's location context is preserved — only the secret value dies.
    assert "lib/insecurity.ts:23" in masked_text
    err = capsys.readouterr().err
    assert "masked .recon-summary.md" in err


def test_mask_is_noop_on_already_clean_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / "threat-model.md", "no secrets here")

    report = postscan.run(out, mask=True)

    assert report["hit_count"] == 0
    assert report["masked_files"] == {}
