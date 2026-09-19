"""Guard the source-route audit: dependency rules, verdicts, and real measurement."""

from __future__ import annotations

import textwrap
from pathlib import Path

import audit_test_routes as audit_routes
import pytest
from audit_test_routes import Measurement, Report


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def _run(lines: dict[str, set[int]] | None = None, reads: set[str] = frozenset(), **counts) -> Measurement:
    return Measurement(
        {path: frozenset(numbers) for path, numbers in (lines or {}).items()}, frozenset(reads), **counts
    )


@pytest.fixture
def repo(tmp_path):
    _write(
        tmp_path,
        "scripts/producer.py",
        """\
        LIMIT = 3


        def produce():
            return LIMIT
        """,
    )
    _write(
        tmp_path,
        "scripts/consumer.py",
        """\
        from producer import LIMIT, produce


        def uses_limit():
            return LIMIT


        def uses_function():
            return produce()


        def unrelated():
            return 0
        """,
    )
    return tmp_path


def test_execution_constant_use_and_reads_are_dependencies_but_imports_are_not(repo):
    measurements = {
        "tests/test_body.py": _run({"scripts/producer.py": {1, 4, 5}}),
        "tests/test_import_only.py": _run({"scripts/producer.py": {1, 4}}),
        "tests/test_constant.py": _run({"scripts/consumer.py": {1, 4, 5}}),
        "tests/test_unrelated.py": _run({"scripts/consumer.py": {1, 4, 8, 12, 13}}),
        "tests/test_reader.py": _run(reads={"scripts/producer.py"}),
    }
    trees = audit_routes._script_trees(repo)
    assert audit_routes.dependents("scripts/producer.py", measurements, trees) == {
        "tests/test_body.py",
        "tests/test_constant.py",
        "tests/test_reader.py",
    }


def test_module_level_constant_use_makes_every_function_of_the_user_dependent(repo):
    _write(
        repo,
        "scripts/derived.py",
        """\
        from producer import LIMIT

        DOUBLE = LIMIT * 2


        def double():
            return DOUBLE
        """,
    )
    measurements = {
        "tests/test_derived.py": _run({"scripts/derived.py": {1, 3, 6, 7}}),
        "tests/test_loaded.py": _run({"scripts/derived.py": {1, 3, 6}}),
    }
    trees = audit_routes._script_trees(repo)
    assert audit_routes.dependents("scripts/producer.py", measurements, trees) == {"tests/test_derived.py"}


def test_document_routes_depend_only_on_reads(repo):
    measurements = {
        "tests/test_reader.py": _run(reads={"docs/guide.md"}),
        "tests/test_other.py": _run({"scripts/producer.py": {5}}, reads={"docs/other.md"}),
    }
    trees = audit_routes._script_trees(repo)
    assert audit_routes.dependents("docs/guide.md", measurements, trees) == {"tests/test_reader.py"}


def test_audit_rejects_missing_dependents_and_only_notes_idle_routed_tests(repo):
    measurements = {
        "tests/test_routed.py": _run({"scripts/producer.py": {5}, "scripts/consumer.py": {1}}),
        "tests/test_missing.py": _run({"scripts/producer.py": {5}}),
        "tests/test_idle.py": _run(),
        "tests/test_skipped.py": _run(skipped=1),
    }
    routes = {"scripts/producer.py": ("tests/test_routed.py", "tests/test_idle.py", "tests/test_skipped.py")}
    report = audit_routes.audit(measurements, repo, routes)
    assert report.problems == ("route scripts/producer.py misses dependent tests: tests/test_missing.py",)
    assert report.notes == (
        "route scripts/producer.py lists tests without a measured dependency: tests/test_idle.py, "
        "tests/test_skipped.py (skipped or failed during measurement)",
    )


def test_audit_requires_a_routed_test_that_loads_each_importer(repo):
    measurements = {"tests/test_routed.py": _run({"scripts/producer.py": {5}})}
    report = audit_routes.audit(measurements, repo, {"scripts/producer.py": ("tests/test_routed.py",)})
    assert report.problems == ("route scripts/producer.py loads no test that imports scripts/consumer.py",)


def test_timed_out_measurement_fails_the_audit(repo):
    measurements = {"tests/test_slow.py": Measurement({}, frozenset(), timed_out=True)}
    report = audit_routes.audit(measurements, repo, {})
    assert report.problems == ("measurement timed out: tests/test_slow.py",)


def test_measurement_records_in_process_and_subprocess_lines_and_reads_but_not_imports(tmp_path):
    _write(
        tmp_path,
        "scripts/producer.py",
        """\
        def produce():
            return 3
        """,
    )
    _write(
        tmp_path,
        "scripts/cli.py",
        """\
        def main():
            return 0


        main()
        """,
    )
    _write(
        tmp_path,
        "scripts/monitor.py",
        """\
        import time


        def run():
            print("ready", flush=True)
            time.sleep(60)


        run()
        """,
    )
    _write(tmp_path, "docs/guide.md", "guide\n")
    _write(tmp_path, "docs/packaged.md", "packaged\n")
    _write(tmp_path, "tests/conftest.py", "import sys\nsys.path.insert(0, 'scripts')\n")
    _write(
        tmp_path,
        "tests/test_probe.py",
        """\
        import shutil
        import subprocess
        import sys
        from pathlib import Path

        import producer

        ROOT = Path(__file__).resolve().parent.parent


        def test_probe(tmp_path):
            assert producer.produce() == 3
            subprocess.run([sys.executable, str(ROOT / "scripts" / "cli.py")], check=True)
            assert (ROOT / "docs" / "guide.md").read_text() == "guide\\n"
            shutil.copyfile(ROOT / "docs" / "packaged.md", tmp_path / "packaged.md")
            monitor = subprocess.Popen(
                [sys.executable, str(ROOT / "scripts" / "monitor.py")], stdout=subprocess.PIPE, text=True
            )
            assert monitor.stdout.readline() == "ready\\n"
            monitor.terminate()
            monitor.wait(timeout=30)
        """,
    )
    measured = audit_routes.measure(["tests/test_probe.py"], tmp_path, tmp_path / "work", 1, 120)["tests/test_probe.py"]
    assert 2 in measured.lines["scripts/producer.py"]
    assert 2 in measured.lines["scripts/cli.py"]
    assert 5 in measured.lines["scripts/monitor.py"]
    assert "docs/guide.md" in measured.reads
    assert not {"scripts/producer.py", "scripts/cli.py", "docs/packaged.md"} & measured.reads
    assert (measured.skipped, measured.failed, measured.timed_out) == (0, 0, False)


def test_cli_reports_notes_and_problems_with_exit_status(monkeypatch, capsys):
    monkeypatch.setattr(audit_routes.run_tests, "group_problems", lambda: [])
    monkeypatch.setattr(audit_routes, "measure", lambda *args: {})
    monkeypatch.setattr(audit_routes, "audit", lambda measurements: Report(("route gap",), ("idle test",)))
    assert audit_routes.main(["--jobs", "1"]) == 1
    captured = capsys.readouterr()
    assert "note: idle test" in captured.out
    assert "route gap" in captured.err

    monkeypatch.setattr(audit_routes, "audit", lambda measurements: Report((), ()))
    assert audit_routes.main(["--jobs", "1"]) == 0


def test_cli_stops_on_inventory_drift_before_measuring(monkeypatch, capsys):
    monkeypatch.setattr(audit_routes.run_tests, "group_problems", lambda: ["test needs an explicit group"])
    monkeypatch.setattr(audit_routes, "measure", lambda *args: pytest.fail("measured despite inventory drift"))
    assert audit_routes.main([]) == 2
    assert "explicit group" in capsys.readouterr().err
