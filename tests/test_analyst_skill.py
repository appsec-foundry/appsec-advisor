"""The analyze-threats skill stays a thin adapter over the CLI contract."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "skills" / "analyze-threats"
SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
HELP = (SKILL_DIR / "HELP.txt").read_text(encoding="utf-8")


def cli_parser():
    sys.path.insert(0, str(ROOT / "scripts"))
    loader = importlib.machinery.SourceFileLoader("appsec_analyst_cli", str(ROOT / "scripts" / "appsec-analyst-cli"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.build_parser()


def known_flags() -> set[str]:
    parser = cli_parser()
    flags = set()
    for action in parser._subparsers._group_actions[0].choices.values():
        for sub_action in action._actions:
            flags.update(o for o in sub_action.option_strings if o.startswith("--"))
    return flags


def test_every_flag_the_skill_and_help_name_exists_in_the_cli():
    named = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", SKILL + HELP)) - {"--help", "--show-toplevel"}
    assert named <= known_flags(), sorted(named - known_flags())


def test_the_skill_runs_the_shared_cli_interactively_and_quotes_free_text():
    assert SKILL.count('"$CLAUDE_PLUGIN_ROOT/scripts/appsec-analyst-cli"') == 2
    assert SKILL.count("--interactive") >= 2
    assert SKILL.count("<<'APPSEC_ANALYST_TEXT'") == 2
    assert 'cat "<base-dir>/HELP.txt"' in SKILL and HELP.startswith("/appsec-advisor:analyze-threats ")


def test_the_skill_never_widens_authority_or_invents_answers():
    lowered = SKILL.lower()
    for forbidden in ("bypasspermissions", "dangerously", "--allowedtools", "git commit", "npm test", "pytest"):
        assert forbidden not in lowered
    assert "never answer a question yourself" in lowered
    assert "only when the developer explicitly asks" in lowered
    assert "never claims security approval" in lowered or "never summarize it as approval" in lowered


def test_the_skill_offers_the_manifesto_profile_only_as_an_explicit_addition():
    assert "tmm/threat-modeling-manifesto@1.0.0" in HELP
    assert "Do not add packages" in SKILL


def test_hypothesis_and_context_options_are_exposed_without_implicit_scope():
    for flag in (
        "--hypothesis",
        "--revision",
        "--path",
        "--requirements",
        "--requirements-required",
        "--threat-model",
        "--threat-model-required",
    ):
        assert flag in SKILL and flag in HELP
    assert "ask for any missing revision or paths" in SKILL
    assert "Do not silently turn it into a design question" in SKILL
    assert "Not confirmed never means disproved or safe" in HELP
