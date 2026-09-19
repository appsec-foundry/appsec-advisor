"""Measure test-module dependencies and report incomplete source routes.

`run_tests.SOURCE_TESTS` selects the tests for a changed file. A test module
depends on a routed script when it executes a line inside one of the script's
functions, executes a line of another script that uses one of the script's
module-level constants or classes, or reads the script's file. For any other
routed file, reading the file is the dependency. Every script that imports a
routed script must also be loaded by one of its routed tests, so that a removed
name fails at import.

Each inventoried test module runs in its own pytest process under coverage,
which also measures subprocesses, including those stopped by SIGTERM. File reads
are recorded in the pytest process only; copying a file is not a read. A route
that misses a dependent test fails the audit. A routed test without a measured
dependency is reported but kept: skipped tests, environment failures, reads in
subprocesses, and subprocesses killed by another signal are invisible to the
measurement.
"""

from __future__ import annotations

import argparse
import ast
import compileall
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import run_tests

ROOT = run_tests.ROOT

# Runs as the measured pytest process. Records repository files opened for
# reading during collection and test execution, and counts skipped and failed
# tests. Cached bytecode keeps imports from opening script sources.
_WORKER = r"""
import json, os, sys
import pytest

root, out, args = sys.argv[1], sys.argv[2], sys.argv[3:]
prefix = os.path.join(root, "")
state = {"active": False, "reads": set(), "copying": set(), "skipped": 0, "failed": 0}


def hook(event, hook_args):
    if not state["active"]:
        return
    if event == "shutil.copyfile":
        # Copying a file does not depend on its content.
        state["copying"].add(os.path.abspath(os.fsdecode(hook_args[0])))
        return
    if event != "open":
        return
    path, mode, flags = hook_args
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    reading = not set(mode) & set("wax+") if isinstance(mode, str) else (flags & 3) == os.O_RDONLY
    path = os.path.abspath(os.fsdecode(path))
    if path in state["copying"]:
        state["copying"].discard(path)
        return
    if reading and path.startswith(prefix) and "__pycache__" not in path:
        state["reads"].add(os.path.relpath(path, root).replace(os.sep, "/"))


class Recorder:
    @pytest.hookimpl(wrapper=True)
    def pytest_collection(self, session):
        state["active"] = True
        try:
            return (yield)
        finally:
            state["active"] = False

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_protocol(self, item, nextitem):
        state["active"] = True
        try:
            return (yield)
        finally:
            state["active"] = False

    def pytest_runtest_logreport(self, report):
        state["skipped"] += report.skipped
        state["failed"] += report.failed


sys.addaudithook(hook)
code = int(pytest.main(args, plugins=[Recorder()]))
result = {"reads": sorted(state["reads"]), "skipped": state["skipped"], "failed": state["failed"], "exit": code}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(result, handle)
sys.exit(code)
"""


@dataclass(frozen=True)
class Measurement:
    lines: dict[str, frozenset[int]]
    reads: frozenset[str]
    skipped: int = 0
    failed: int = 0
    timed_out: bool = False


@dataclass(frozen=True)
class Report:
    problems: tuple[str, ...]
    notes: tuple[str, ...]


def measure_module(test: str, root: Path, workdir: Path, timeout: float) -> Measurement:
    """Run one test module under coverage and record its executed lines and reads."""
    import coverage

    root = root.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    data_file, result_file, config = workdir / ".coverage", workdir / "result.json", workdir / "coveragerc"
    # Measure subprocesses, including those stopped by SIGTERM such as reaped monitors.
    config.write_text("[run]\nsource = scripts\npatch = subprocess\nsigterm = true\n", encoding="utf-8")
    command = [sys.executable, "-c", _WORKER, str(root), str(result_file), test, "-q", "-p", "no:cacheprovider"]
    command += ["--cov=scripts", f"--cov-config={config}", "--cov-report=", "--cov-fail-under=0"]
    # An outer coverage run must not pull the measured process into its own data.
    env = {key: value for key, value in os.environ.items() if not key.startswith(("COVERAGE_", "COV_CORE_"))}
    env["COVERAGE_FILE"] = str(data_file)
    try:
        subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return Measurement({}, frozenset(), timed_out=True)
    result = json.loads(result_file.read_text(encoding="utf-8")) if result_file.is_file() else {"failed": 1}
    lines = {}
    if data_file.is_file():
        data = coverage.CoverageData(basename=str(data_file))
        data.read()
        for measured in data.measured_files():
            path = Path(measured).resolve()
            if path.is_relative_to(root / "scripts") and data.lines(measured):
                lines[path.relative_to(root).as_posix()] = frozenset(data.lines(measured))
    return Measurement(lines, frozenset(result.get("reads", ())), result.get("skipped", 0), result.get("failed", 0))


def measure(tests: list[str], root: Path, workdir: Path, jobs: int, timeout: float) -> dict[str, Measurement]:
    compileall.compile_dir(root / "scripts", quiet=1)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            test: pool.submit(measure_module, test, root, workdir / PurePosixPath(test).stem, timeout) for test in tests
        }
    return {test: future.result() for test, future in futures.items()}


def _script_trees(root: Path) -> dict[str, ast.Module]:
    return {
        path.relative_to(root).as_posix(): ast.parse(path.read_text(encoding="utf-8"))
        for path in sorted((root / "scripts").glob("*.py"))
    }


def _function_lines(tree: ast.Module) -> set[int]:
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            lines.update(range(node.body[0].lineno, node.end_lineno + 1))
    return lines


def _imports(tree: ast.Module, module: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name == module for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module:
            return True
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", getattr(node.func, "id", None)) == "import_module"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == module
        ):
            return True
    return False


def _data_uses(tree: ast.Module, module: str, functions: set[str]) -> set[int]:
    """Lines that use a module-level constant or class of `module`."""
    names, aliases = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module:
            names |= {alias.asname or alias.name for alias in node.names if alias.name not in functions}
        elif isinstance(node, ast.Import):
            aliases |= {alias.asname or alias.name for alias in node.names if alias.name == module}
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            lines.add(node.lineno)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
            and node.attr not in functions
        ):
            lines.add(node.lineno)
    return lines


def dependents(path: str, measurements: dict[str, Measurement], trees: dict[str, ast.Module]) -> set[str]:
    """Return the measured test modules that depend on the routed file."""
    readers = {test for test, measured in measurements.items() if path in measured.reads}
    if path not in trees:
        return readers
    module = PurePosixPath(path).stem
    tree = trees[path]
    functions = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    targets = {path: _function_lines(tree)}
    for other, other_tree in trees.items():
        if other == path:
            continue
        uses = _data_uses(other_tree, module, functions)
        if uses:
            body = _function_lines(other_tree)
            # A module-level use feeds values that any function of the user may read.
            targets[other] = targets.get(other, set()) | (uses if uses <= body else body)
    executed = {
        test
        for test, measured in measurements.items()
        if any(measured.lines.get(target, frozenset()) & lines for target, lines in targets.items())
    }
    return readers | executed


def audit(
    measurements: dict[str, Measurement],
    root: Path = ROOT,
    routes: dict[str, tuple[str, ...]] | None = None,
) -> Report:
    """Reject routes that miss dependent tests or leave an importer unloaded."""
    routes = run_tests.SOURCE_TESTS if routes is None else routes
    trees = _script_trees(root)
    problems = [
        f"measurement timed out: {test}" for test, measured in sorted(measurements.items()) if measured.timed_out
    ]
    notes = []
    for path, route in routes.items():
        needed = dependents(path, measurements, trees)
        missing = sorted(needed - set(route))
        if missing:
            problems.append(f"route {path} misses dependent tests: {', '.join(missing)}")
        if path in trees:
            module = PurePosixPath(path).stem
            for importer, tree in trees.items():
                if importer == path or not _imports(tree, module):
                    continue
                if not any(importer in measurements[test].lines for test in route if test in measurements):
                    problems.append(f"route {path} loads no test that imports {importer}")
        idle = []
        for test in route:
            measured = measurements.get(test)
            if test not in needed and measured is not None:
                uncertain = measured.skipped or measured.failed
                idle.append(f"{test} (skipped or failed during measurement)" if uncertain else test)
        if idle:
            notes.append(f"route {path} lists tests without a measured dependency: {', '.join(idle)}")
    return Report(tuple(problems), tuple(notes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="parallel test modules")
    parser.add_argument("--timeout", type=float, default=3600, help="seconds per test module")
    args = parser.parse_args(argv)
    inventory = run_tests.group_problems()
    if inventory:
        print("\n".join(inventory), file=sys.stderr)
        return 2
    tests = sorted({test for tests in run_tests.GROUPS.values() for test in tests})
    print(f"Measuring {len(tests)} test modules with {args.jobs} jobs; this runs every test under coverage.")
    with tempfile.TemporaryDirectory() as workdir:
        report = audit(measure(tests, ROOT, Path(workdir), args.jobs, args.timeout))
    for note in report.notes:
        print(f"note: {note}")
    if report.problems:
        print("\n".join(report.problems), file=sys.stderr)
        return 1
    print("Every source route contains the tests that depend on its file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
