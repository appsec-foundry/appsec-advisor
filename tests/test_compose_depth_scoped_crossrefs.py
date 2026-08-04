"""Depth-scoped cross-references — a link is emitted only when its target is.

Regression cover for the 2026-08-02 defect class: a cross-reference emitter
decided on a *proxy* signal while the target of that reference was emitted from
the real render scope. At ``--quick`` the two diverged and the hard
``qa_checks.py toc_closure`` release gate failed on every run.

Two instances, both fixed by gating on the predicate the section-presence check
already uses:

  * §8 Story Card → ``[Walkthrough §3.N](#3n-…)``. ``_build_finding_to_chain_map``
    keyed off ``.fragments/attack-walkthroughs.md`` existing, but Stage-2
    pregeneration writes that fragment unconditionally — so at ``--quick``
    (§3 omitted) the file was there and the section was not.
  * §1 trust-boundary table → ``[§6.N](#ctrl-…)``. ``_leg_control_link`` resolves
    from a static leg→domain dict and is unconditional; the ``#ctrl-…`` anchor it
    targets is injected only next to a rendered §6 domain heading.

The invariant these tests pin is deliberately narrow: emitting the reference and
emitting its target must be decided by ONE condition.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


compose = _load("compose_threat_model_xref", SCRIPT_PATH)


def _ctx(tmp_path, **eval_context):
    return compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path / ".fragments",
        eval_context=eval_context,
    )


LEGS = [
    {"leg": "validation", "state": "refuted", "finding_ids": ["F-007"], "adjacent_finding_ids": []},
    {"leg": "authentication", "state": "unconfirmed", "finding_ids": [], "adjacent_finding_ids": []},
]


class TestSection6BackLink:
    """`[§6.N](#ctrl-…)` may only appear when §6 is rendered."""

    def test_omitted_when_section6_absent(self, tmp_path):
        lines = compose._boundary_leg_lines(LEGS, _ctx(tmp_path, render_security_architecture=False))
        assert lines, "leg lines themselves must still render"
        assert not any("#ctrl-" in line for line in lines)

    def test_present_when_section6_rendered(self, tmp_path):
        lines = compose._boundary_leg_lines(LEGS, _ctx(tmp_path, render_security_architecture=True))
        joined = "\n".join(lines)
        assert "#ctrl-input-boundary-validation-controls" in joined
        assert "#ctrl-identity-and-authentication-controls" in joined

    def test_leg_text_survives_either_way(self, tmp_path):
        """Suppressing the link must not suppress the assessment itself."""
        off = compose._boundary_leg_lines(LEGS, _ctx(tmp_path, render_security_architecture=False))
        on = compose._boundary_leg_lines(LEGS, _ctx(tmp_path, render_security_architecture=True))
        assert len(off) == len(on) == len(LEGS)
        for line in off:
            assert line.split(":")[0] in ("Validation", "Authentication")

    def test_every_emitted_anchor_is_injectable(self, tmp_path):
        """Each `#ctrl-…` the table can emit must match an injectable §6 anchor.

        Guards the two halves against silent drift: the link side resolves via
        `_LEG_SECTION7_DOMAIN`, the anchor side injects via `_SECTION7_DOMAIN_LEG`.
        """
        injectable = {compose._control_domain_anchor(domain) for domain in compose._SECTION7_DOMAIN_LEG}
        for leg in compose._LEG_SECTION7_DOMAIN:
            link = compose._leg_control_link(leg)
            anchor = link.split("(#", 1)[1].rstrip(")")
            assert anchor in injectable, f"leg {leg!r} links to un-injectable anchor {anchor!r}"


class TestWalkthroughBackLink:
    """`[Walkthrough §3.N](#3n-…)` may only appear when §3 carries walkthroughs."""

    @staticmethod
    def _write_fragment(tmp_path):
        frag_dir = tmp_path / ".fragments"
        frag_dir.mkdir(parents=True, exist_ok=True)
        (frag_dir / "attack-walkthroughs.md").write_text(
            "## 3. Attack Walkthroughs\n\n### 3.1 JWT algorithm none accepted\n\n**Source:** 🔴 [F-003]\n\nSteps.\n",
            encoding="utf-8",
        )

    def test_empty_when_section3_skipped_despite_fragment(self, tmp_path):
        """The quick-depth case: fragment on disk, section not rendered."""
        self._write_fragment(tmp_path)
        ctx = _ctx(tmp_path, has_authored_walkthroughs=False)
        assert compose._build_finding_to_chain_map(ctx) == {}

    def test_populated_when_section3_rendered(self, tmp_path):
        self._write_fragment(tmp_path)
        ctx = _ctx(tmp_path, has_authored_walkthroughs=True)
        mapping = compose._build_finding_to_chain_map(ctx)
        assert "F-003" in mapping and "T-003" in mapping
        label, anchor = mapping["F-003"]
        assert label == "Walkthrough §3.1"
        assert anchor.startswith("31-")

    def test_empty_when_fragment_missing(self, tmp_path):
        ctx = _ctx(tmp_path, has_authored_walkthroughs=True)
        assert compose._build_finding_to_chain_map(ctx) == {}
