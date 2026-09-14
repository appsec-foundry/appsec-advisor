"""Run shared maintainer test groups without implicit coverage or model calls."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# These are starting sets, not a source dependency graph. Add tests for affected
# producers and consumers; use all when the impact cannot be bounded confidently.
# Globs include newly added tests in an existing family. An unmatched selector
# fails instead of silently shrinking a group after a rename.
GROUPS = {
    "quick": (
        "tests/test_contract_integrity.py",
        "tests/test_schema_integrity.py",
        "tests/test_new_schemas.py",
        "tests/test_runtime_cleanup.py",
        "tests/test_taxonomy_coverage.py",
        "tests/test_agent_definitions.py",
        "tests/test_check_specs.py",
        "tests/test_run_tests.py",
        "tests/test_ci_test_workflow.py",
    ),
    "report": (
        "tests/test_compose*.py",
        "tests/test_render_properties.py",
        "tests/test_final_render_guards.py",
        "tests/test_render_integrity.py",
        "tests/test_render_threat_model.py",
        "tests/test_section*.py",
        "tests/test_fragment*.py",
        "tests/test_validate_fragment.py",
        "tests/test_export_*.py",
        "tests/test_sarif_validation.py",
        "tests/test_e2e_pipeline.py",
    ),
    "scanner": (
        "tests/test_*scanner*.py",
        "tests/test_config_iac_checks.py",
        "tests/test_crypto_path_xxe_checks.py",
        "tests/test_credential_lifecycle_checks.py",
        "tests/test_detect_open_registration.py",
        "tests/test_scan_excludes.py",
        "tests/test_secret_scan.py",
        "tests/test_postscan_secret_check.py",
        "tests/test_check_target_specificity.py",
    ),
    "prompts": (
        "tests/test_agent_definitions.py",
        "tests/test_agent_doc_shell_snippets.py",
        "tests/test_skill_definitions.py",
        "tests/test_check_permissions*.py",
        "tests/test_context_routing.py",
        "tests/test_*prompt*.py",
        "tests/test_runtime_doc_cli_contract.py",
    ),
    "runtime": (
        "tests/test_orchestration_controller.py",
        "tests/test_runtime*.py",
        "tests/test_check_state*.py",
        "tests/test_agent_logger*.py",
        "tests/test_hook_payload*.py",
        "tests/test_*dispatch*.py",
        "tests/test_run_headless_completion.py",
        "tests/test_completion*.py",
        "tests/test_render_completion_summary*.py",
    ),
    "incremental": (
        "tests/test_incremental_two_run_e2e.py",
        "tests/test_build_threat_model_yaml.py",
    ),
    "e2e": ("tests/test_e2e_pipeline.py",),
}


def select_tests(group: str, root: Path = ROOT) -> list[str]:
    """Resolve a reviewed group, preserving order and rejecting stale selectors."""
    if group == "all":
        return ["tests/"]
    selected = []
    for pattern in GROUPS[group]:
        matches = sorted(path for path in root.glob(pattern) if path.is_file())
        if not matches:
            raise ValueError(f"test group {group!r} has no files matching {pattern!r}")
        selected.extend(path.relative_to(root).as_posix() for path in matches)
    return list(dict.fromkeys(selected))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print selected paths without running pytest")
    parser.add_argument("group", nargs="?", default="all", choices=["all", *GROUPS])
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER, help="arguments forwarded to pytest")
    args = parser.parse_args(argv)
    try:
        paths = select_tests(args.group)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    if args.list:
        print("\n".join(paths))
        return 0
    return subprocess.run([sys.executable, "-m", "pytest", *paths, *args.pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
