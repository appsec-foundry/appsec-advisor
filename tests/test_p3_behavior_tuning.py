"""Tests for Patch P3 — Behavior Tuning (A6 + B2).

Two orthogonal regressions:

    A6 — Quick-mode STRIDE profile no longer suppresses evidence excerpts.
         The flag was demoted from True to False so the §8 Threat Register
         Finding column and the Linked Threats columns regain their
         truncated descriptions. The other flags (max_threats_per_category,
         skip_verification_greps, skip_code_examples, skip_cvss_scoring)
         keep the real token-budget reductions.

    B2 — `_build_attack_arrows` and `_build_consequence_arrows` correctly
         identify victim-targeting attack classes (XSS / CSRF) regardless
         of whether the fragment was LLM-authored (target=victim) or
         deterministic-fallback (target=client + actor=victim-required).
         For victim-targeting classes the renderer now emits TWO arrows:
           1. attacker → client tier (injection path)
           2. client tier → victim actor (consequence path)
         Pre-fix, only one arrow was emitted with reversed direction
         (SHOPUSER → BROWSER) because the data shape didn't match the
         hardcoded `target == "victim"` check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rc = _load("resolve_config", _SCRIPTS / "resolve_config.py")
compose = _load("compose_threat_model", _SCRIPTS / "compose_threat_model.py")


# ---------------------------------------------------------------------------
# A6 — Quick-profile rebalance
# ---------------------------------------------------------------------------


class TestQuickProfileEvidenceExcerptRestored:
    """The cheap, high-impact rebalance: evidence excerpt is back at quick."""

    def test_quick_haiku_economy_keeps_evidence_excerpt(self):
        profile = rc.resolve_stride_profile("haiku-economy", "quick")
        sp = profile["stride_profile"]
        assert sp["skip_evidence_excerpt"] is False, (
            "P3 (A6) — skip_evidence_excerpt must be False at quick depth so "
            "§8 Threat Register and Linked Threats columns regain their "
            "truncated descriptions"
        )

    def test_other_quick_flags_unchanged(self):
        """The token-budget reductions must remain in place — only the
        cheap-but-impactful evidence flag flipped."""
        profile = rc.resolve_stride_profile("haiku-economy", "quick")
        sp = profile["stride_profile"]
        assert sp["skip_verification_greps"] is True
        assert sp["max_threats_per_category"] == 2
        assert sp["skip_code_examples"] is True
        assert sp["skip_cvss_scoring"] is True
        assert sp["turn_budget_hard_cap"] == 25

    def test_non_quick_depths_get_full_profile(self):
        """The rebalance only touches the haiku-economy quick branch.
        Standard / thorough must still see the full-profile label."""
        for depth in ("standard", "thorough"):
            profile = rc.resolve_stride_profile("haiku-economy", depth)
            assert profile["stride_profile"].get("stride_profile_label") == "full", (
                f"depth={depth} must keep the full STRIDE profile"
            )


# ---------------------------------------------------------------------------
# B2 — Multi-arrow heatmap
# ---------------------------------------------------------------------------

# Minimal taxonomy + actor/tier card fixtures suitable for unit-testing
# `_build_attack_arrows` directly.


def _taxonomy():
    return {
        "glyph_sequence": ["①", "②", "③", "④", "⑤", "⑥", "⑦"],
        "classes": [
            {"id": "injection", "label": "Injection", "short_label": "Injection"},
            {"id": "auth-bypass", "label": "Auth Bypass", "short_label": "Auth Bypass"},
            {"id": "remote-code-execution", "label": "RCE", "short_label": "RCE"},
            {"id": "cross-site-scripting", "label": "XSS", "short_label": "XSS"},
            {"id": "cross-site-request-forgery", "label": "CSRF", "short_label": "CSRF"},
        ],
    }


def _actors():
    return [
        {"slug": "internet-anon", "id": "ANON", "label": "Anon"},
        {"slug": "victim-required", "id": "SHOPUSER", "label": "Shop User"},
    ]


def _tiers():
    return [
        {"key": "client", "node_id": "BROWSER", "name": "Client Tier"},
        {"key": "application", "node_id": "SERVER", "name": "Application Tier"},
    ]


class TestVictimTargetingArrowDirection:
    """Pre-P3 bug: when the fallback emitted ``target: client`` +
    ``actor: victim-required``, the renderer fell into the else branch and
    emitted ``SHOPUSER → BROWSER`` (victim as source). P3 detects victim-
    targeting classes via either ``target == "victim"`` or
    ``actor == "victim-required"`` and emits two arrows in the correct
    direction."""

    def test_target_victim_form_emits_dual_arrows(self):
        """LLM-authored fragment shape: ``target: victim``."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 2, "victim-targeting must emit 2 arrows"
        # Edge 1 — injection attacker → client tier.
        assert arrows[0] == {"src": "ANON", "glyph": "①", "label": "XSS", "dst": "BROWSER"}
        # Edge 2 — consequence client tier → victim.
        assert arrows[1] == {"src": "BROWSER", "glyph": "①", "label": "XSS", "dst": "SHOPUSER"}

    def test_target_client_actor_victim_form_emits_dual_arrows(self):
        """Deterministic-fallback shape: ``target: client`` +
        ``actor: victim-required``. Pre-P3 this triggered the else branch
        and emitted SHOPUSER → BROWSER (wrong direction)."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "client"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 2
        # Same dual-arrow shape as the explicit target=victim form.
        assert arrows[0]["src"] == "ANON"
        assert arrows[0]["dst"] == "BROWSER"
        assert arrows[1]["src"] == "BROWSER"
        assert arrows[1]["dst"] == "SHOPUSER"

    def test_csrf_also_dual_arrow(self):
        """CSRF is the second victim-targeting class; same treatment."""
        attack_paths = {
            "attack_paths": [{"class": "cross-site-request-forgery", "actor": "victim-required", "target": "client"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 2
        assert arrows[0]["src"] == "ANON" and arrows[0]["dst"] == "BROWSER"
        assert arrows[1]["src"] == "BROWSER" and arrows[1]["dst"] == "SHOPUSER"


class TestDirectAttackArrowsUnchanged:
    """The pre-P3 single-arrow shape for direct-attack classes must be
    preserved. Regression guard so the dual-arrow logic doesn't bleed
    into Injection / Auth Bypass / RCE etc."""

    def test_injection_emits_single_arrow_anon_to_application(self):
        attack_paths = {"attack_paths": [{"class": "injection", "actor": "internet-anon", "target": "application"}]}
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 1
        assert arrows[0] == {"src": "ANON", "glyph": "①", "label": "Injection", "dst": "SERVER"}

    def test_rce_emits_single_arrow_anon_to_application(self):
        attack_paths = {
            "attack_paths": [{"class": "remote-code-execution", "actor": "internet-anon", "target": "application"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 1
        assert arrows[0]["src"] == "ANON"
        assert arrows[0]["dst"] == "SERVER"

    def test_mixed_classes_correct_arrow_count(self):
        """5 direct + 1 victim = 5 + 2 = 7 arrows."""
        attack_paths = {
            "attack_paths": [
                {"class": "injection", "actor": "internet-anon", "target": "application"},
                {"class": "auth-bypass", "actor": "internet-anon", "target": "application"},
                {"class": "remote-code-execution", "actor": "internet-anon", "target": "application"},
                {"class": "cross-site-scripting", "actor": "victim-required", "target": "client"},
            ]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert len(arrows) == 5  # 3 direct + 2 victim-arrows


class TestGlyphSharingAcrossDualArrow:
    """Both arrows of a victim-targeting class share the same glyph so
    they render as one numbered path with two segments."""

    def test_dual_arrows_share_glyph(self):
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        assert arrows[0]["glyph"] == arrows[1]["glyph"] == "①"

    def test_glyph_sequence_advances_per_class_not_per_arrow(self):
        """Glyph index ticks once per attack-class, not once per emitted
        arrow. After XSS (which emits 2 arrows with glyph ①) the next
        direct attack should still be glyph ②, not ③."""
        attack_paths = {
            "attack_paths": [
                {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"},
                {"class": "injection", "actor": "internet-anon", "target": "application"},
            ]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), _actors(), _tiers())
        # First class XSS: glyphs are ① ①
        assert arrows[0]["glyph"] == "①"
        assert arrows[1]["glyph"] == "①"
        # Second class Injection: glyph is ②
        assert arrows[2]["glyph"] == "②"


class TestNoAttackerActorPresent:
    """When the actor list contains ONLY the victim, no injection edge can
    be emitted (no attacker to route the edge from). The consequence edge
    still emits so the diagram remains correct."""

    def test_only_victim_in_actor_list_emits_consequence_edge_only(self):
        actors = [{"slug": "victim-required", "id": "SHOPUSER", "label": "Shop User"}]
        attack_paths = {
            "attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim"}]
        }
        arrows = compose._build_attack_arrows(attack_paths, _taxonomy(), actors, _tiers())
        # Only the consequence edge — no injection edge from a non-existent attacker.
        assert len(arrows) == 1
        assert arrows[0]["src"] == "BROWSER"
        assert arrows[0]["dst"] == "SHOPUSER"


class TestConsequenceArrowsVictimTargetingDetection:
    """Mirror dual-form detection in `_build_consequence_arrows` so the
    dashed tier→impact edges originate from the correct tier regardless
    of fragment shape."""

    def _impact_cards(self):
        return [
            {"id": "customer-session-hijack", "node_id": "HIJACK"},
            {"id": "full-server-compromise", "node_id": "COMPROMISE"},
        ]

    def test_target_victim_uses_client_tier(self):
        attack_paths = {
            "attack_paths": [
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "victim",
                    "impact": ["customer-session-hijack"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "BROWSER", "dst": "HIJACK"}]

    def test_target_client_actor_victim_also_uses_client_tier(self):
        """The fallback shape must also route consequence arrows from the
        client tier, not from the wrongly-interpreted ``client`` target."""
        attack_paths = {
            "attack_paths": [
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "client",
                    "impact": ["customer-session-hijack"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "BROWSER", "dst": "HIJACK"}]

    def test_direct_attack_routes_from_named_tier(self):
        attack_paths = {
            "attack_paths": [
                {
                    "class": "remote-code-execution",
                    "actor": "internet-anon",
                    "target": "application",
                    "impact": ["full-server-compromise"],
                }
            ]
        }
        arrows = compose._build_consequence_arrows(attack_paths, self._impact_cards(), _tiers())
        assert arrows == [{"src": "SERVER", "dst": "COMPROMISE"}]
