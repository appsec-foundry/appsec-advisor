"""Stage-transition dispatch_values must stay compact without starving a stage.

``_dispatch_values_stage`` trims the resolved config at the Stage 1d/2/3/4
boundaries, the same way ``_dispatch_values_transition`` already does inside the
context-v2 loop. Trimming is only safe while every value a thin runtime actually
reads survives the cut, so the expectation here is re-derived from the runtimes
themselves rather than hard-coded: add a key to a runtime and this test fails
until the transition payload carries it.
"""

from __future__ import annotations

import re
from pathlib import Path

import orchestration_controller as controller

SKILLS = Path(controller.PLUGIN_ROOT) / "skills" / "create-threat-model"
FULL_RUNTIME = SKILLS / "SKILL-full-runtime.md"

# The runtimes that run after `prepare` has bound state once (§3).
STAGE_RUNTIMES = (
    "SKILL-thin-stage1d.md",
    "SKILL-thin-stage2.md",
    "SKILL-thin-stage3.md",
    "SKILL-thin-completion.md",
)


def _alias_map() -> dict[str, str]:
    """Parse the `UPPERCASE = config_key` bindings out of SKILL-full-runtime §3."""
    pairs = re.findall(r"^([A-Z][A-Z0-9_]*) = ([a-z][a-z0-9_]*)$", FULL_RUNTIME.read_text(), re.M)
    # `DRY_RUN = false` and friends bind literals, not config keys.
    return {alias: key for alias, key in pairs if key not in {"true", "false"}}


def _cfg() -> dict:
    """A config with every dispatch key populated, so a dropped key is visible."""
    cfg = {key: f"value-{key}" for key in controller._DISPATCH_KEYS}
    cfg.update(
        mode="full",
        output_dir="/tmp/out",
        repo_root="/tmp/repo",
        run_id="run-1",
        assessment_depth="standard",
        renderer_model="claude-sonnet-5",
        abuse_verifier_model="claude-sonnet-5",
        qa_content_model="claude-sonnet-4-6",
        qa_routine_model="haiku",
        architect_model=None,
        stride_profile={"stride_profile_label": "full"},
    )
    return cfg


# Deliberately not replayed at a transition. `estimate_*` is computed for
# `prepare` from a separate estimate object rather than read from config, and
# feeds only a banner string the session bound in §3 — losing it costs a number
# in one line of console text, not a dispatch.
DISPLAY_ONLY_KEYS = {
    "estimate_stage1_min",
    "estimate_stage2_min",
    "estimate_stage3_min",
    "estimate_stage4_min",
    "estimate_total_pretty",
    "estimate_source",
}


def test_every_alias_a_stage_runtime_reads_survives_the_trim():
    aliases = _alias_map()
    values = controller._dispatch_values_stage(_cfg())

    missing: list[str] = []
    for name in STAGE_RUNTIMES:
        text = (SKILLS / name).read_text()
        for alias, key in aliases.items():
            if key in DISPLAY_ONLY_KEYS:
                continue
            if not re.search(rf"\b{alias}\b", text):
                continue
            if key not in values:
                missing.append(f"{name}: {alias} -> {key}")

    assert not missing, "stage transition drops config a runtime reads: " + "; ".join(sorted(missing))


def test_direct_dispatch_values_references_resolve():
    """`dispatch_values.<key>` named verbatim in a runtime must be present and non-null."""
    values = controller._dispatch_values_stage(_cfg())
    referenced: set[str] = set()
    for name in STAGE_RUNTIMES:
        referenced.update(re.findall(r"dispatch_values\.([a-z_]+)", (SKILLS / name).read_text()))

    assert referenced, "expected the runtimes to name dispatch_values keys"
    for key in sorted(referenced):
        assert key in values, f"{key} is referenced by a runtime but dropped from the transition"

    # A model alias that trims to None makes a stage dispatch against a null model.
    for key in ("renderer_model_alias", "abuse_verifier_model_alias", "qa_content_model_alias"):
        assert values[key] is not None, f"{key} must resolve for its stage to dispatch"


def test_transition_is_materially_smaller_than_the_binding_payload():
    cfg = _cfg()
    full = controller._dispatch_values(cfg)
    stage = controller._dispatch_values_stage(cfg)
    assert len(stage) < len(full), "the trimmed payload must actually be smaller"
    # Stage-1-only knobs have no reader left after prepare.
    for key in ("stride_turns_complex", "invocation_args", "reasoning_label"):
        assert key not in stage, f"{key} is Stage-1/display only and should not be replayed"


def test_stage_keys_stay_within_the_dispatch_schema():
    """Emitting a key outside the dispatch enum fails action validation at runtime."""
    values = controller._dispatch_values_stage(_cfg())
    allowed = set(controller._DISPATCH_KEYS)
    extra = {k for k in values if k not in allowed and not k.endswith("_alias")}
    # Both are emitted by the existing context-v2 transition form too: the
    # aliases and `model_pins_dropped` come from `_with_model_aliases`, and
    # `plugin_root` is resolved at runtime rather than read from config.
    extra -= {"model_pins_dropped", "plugin_root"}
    assert not extra, f"keys outside the dispatch schema: {sorted(extra)}"
