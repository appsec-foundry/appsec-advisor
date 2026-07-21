"""Serial-vs-parallel STRIDE wave detection (`check_stride_dispatch`).

Regression cover for the 2026-07-20 juice-shop run: the orchestrator emitted
one Agent call per assistant message instead of one message per wave. Every
existing gate passed — same artifacts, same `.progress/` files, same dispatch
count — and the only symptom was ~66 min of wall-clock for a wave of 8.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_stride_dispatch  # noqa: E402


def _start_line(ts: str, cid: str) -> str:
    # Real logs append a component name here; the tail must stay ignorable.
    return f"{ts}  [--------]  INFO   stride-analyzer     STEP_START          [{cid}] Starting STRIDE analysis for {cid.title()}"


def _end_line(ts: str, cid: str) -> str:
    return f"{ts}  [--------]  INFO   stride-analyzer     STEP_END            [{cid}] STRIDE analysis complete — 9 threats written"


def _write_run(
    tmp_path: Path,
    spans: dict[str, tuple[str | None, str | None]],
    *,
    generated_at: str = "2026-07-20T18:56:23Z",
) -> Path:
    """Materialise an output dir with a manifest and an agent-run log."""
    out = tmp_path / "security"
    out.mkdir()
    (out / ".stride-dispatch-manifest.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "components": [{"component_id": cid} for cid in spans],
            }
        ),
        encoding="utf-8",
    )
    lines: list[str] = []
    for cid, (start, end) in spans.items():
        if start:
            lines.append(_start_line(start, cid))
        if end:
            lines.append(_end_line(end, cid))
    lines.sort()
    (out / ".agent-run.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


# The real 2026-07-20 juice-shop wave: every dispatch lands ~20-30s AFTER the
# previous analyzer returned. Invoke timestamps are the observed STEP_END times.
JUICE_SHOP_SERIAL = {
    "frontend-spa": ("2026-07-20T18:57:07Z", "2026-07-20T19:05:40Z"),
    "backend-api": ("2026-07-20T19:06:11Z", "2026-07-20T19:16:02Z"),
    "auth-service": ("2026-07-20T19:16:27Z", "2026-07-20T19:24:57Z"),
    "sqlite-db": ("2026-07-20T19:25:27Z", "2026-07-20T19:32:50Z"),
    "llm-chat-integration": ("2026-07-20T19:33:12Z", "2026-07-20T19:45:30Z"),
    "realtime-channel": ("2026-07-20T19:46:01Z", "2026-07-20T19:52:45Z"),
    "web3-nft": ("2026-07-20T19:53:08Z", "2026-07-20T20:03:10Z"),
    "ci-cd-pipeline": ("2026-07-20T20:03:35Z", "2026-07-20T20:12:40Z"),
}

# The 2026-07-20 15:42 run on the same repo: 8 spawns inside 3m22s while each
# analyzer ran for minutes — heavy overlap, the shape a real fan-out has.
JUICE_SHOP_PARALLEL = {
    "backend-api": ("2026-07-20T15:42:30Z", "2026-07-20T15:58:10Z"),
    "frontend-spa": ("2026-07-20T15:43:03Z", "2026-07-20T15:57:20Z"),
    "data-persistence": ("2026-07-20T15:43:31Z", "2026-07-20T15:55:02Z"),
    "auth-service": ("2026-07-20T15:44:07Z", "2026-07-20T15:56:44Z"),
    "file-handling": ("2026-07-20T15:44:41Z", "2026-07-20T15:54:19Z"),
    "ci-cd-pipeline": ("2026-07-20T15:45:11Z", "2026-07-20T15:53:38Z"),
    "realtime-channel": ("2026-07-20T15:45:35Z", "2026-07-20T15:52:07Z"),
    "web3-nft": ("2026-07-20T15:45:52Z", "2026-07-20T15:57:55Z"),
}


def test_real_serial_wave_is_detected(tmp_path: Path) -> None:
    out = _write_run(tmp_path, JUICE_SHOP_SERIAL)
    assert check_stride_dispatch.detect_serial_dispatch(out) == [
        "frontend-spa",
        "backend-api",
        "auth-service",
        "sqlite-db",
        "llm-chat-integration",
        "realtime-channel",
        "web3-nft",
        "ci-cd-pipeline",
    ]


def test_real_parallel_wave_is_not_flagged(tmp_path: Path) -> None:
    out = _write_run(tmp_path, JUICE_SHOP_PARALLEL, generated_at="2026-07-20T15:40:00Z")
    assert check_stride_dispatch.detect_serial_dispatch(out) == []


def test_single_overlapping_pair_suppresses_the_finding(tmp_path: Path) -> None:
    """One genuine overlap anywhere means the fan-out fired — stay silent."""
    spans = dict(JUICE_SHOP_SERIAL)
    # Pull ci-cd-pipeline's dispatch back so it overlaps web3-nft's run.
    spans["ci-cd-pipeline"] = ("2026-07-20T19:53:20Z", "2026-07-20T20:12:40Z")
    assert check_stride_dispatch.detect_serial_dispatch(_write_run(tmp_path, spans)) == []


@pytest.mark.parametrize(
    "spans",
    [
        pytest.param({}, id="no-dispatches"),
        pytest.param(
            {"backend-api": ("2026-07-20T19:06:11Z", "2026-07-20T19:16:02Z")},
            id="single-component",
        ),
    ],
)
def test_inconclusive_input_returns_no_finding(tmp_path: Path, spans: dict) -> None:
    assert check_stride_dispatch.detect_serial_dispatch(_write_run(tmp_path, spans)) == []


def test_half_logged_pairs_are_excluded(tmp_path: Path) -> None:
    """A component without both events cannot be placed on the timeline.

    Only one component is fully paired here, so the comparison is inconclusive
    and the detector must stay silent rather than guess at the missing edge.
    """
    out = _write_run(
        tmp_path,
        {
            "backend-api": ("2026-07-20T19:06:11Z", "2026-07-20T19:16:02Z"),
            "auth-service": ("2026-07-20T19:16:27Z", None),
            "sqlite-db": (None, "2026-07-20T19:32:50Z"),
        },
    )
    assert check_stride_dispatch.detect_serial_dispatch(out) == []


def test_prior_run_dispatches_are_excluded_by_manifest_timestamp(tmp_path: Path) -> None:
    """`.agent-run.log` can carry more than one run's events.

    The parallel 15:42 wave and the serial 18:57 wave both live in juice-shop's
    logs. Bounding on the manifest timestamp must leave only the current run, or
    the stale parallel spans would mask the serial one.
    """
    out = _write_run(tmp_path, {**JUICE_SHOP_PARALLEL, **JUICE_SHOP_SERIAL})
    assert check_stride_dispatch.detect_serial_dispatch(out) == list(JUICE_SHOP_SERIAL)


def test_hook_log_events_are_not_used_as_interval_bounds(tmp_path: Path) -> None:
    """`AGENT_SPAWN`/`AGENT_INVOKE` both fire at dispatch — they bracket nothing.

    On 2026-07-20 juice-shop logged both for web3-nft at the identical
    15:45:52, and the headless run emitted 19 SPAWN lines and zero INVOKE.
    Deriving intervals from the hook log would therefore be blind (no pairs) or
    wrong (zero-width spans). A run whose ONLY evidence is the hook log must
    yield no finding rather than a bogus verdict.
    """
    out = _write_run(tmp_path, {})
    (out / ".hook-events.log").write_text(
        "\n".join(
            f"{ts}  [6f373f38]  INFO   {ev}        appsec-advisor:appsec-stride-analyzer"
            f"  model=sonnet  [REPO_ROOT=/r  COMPONENT_ID={cid}]"
            for cid, ts in (("web3-nft", "2026-07-20T19:53:08Z"), ("sqlite-db", "2026-07-20T19:25:27Z"))
            for ev in ("AGENT_SPAWN", "AGENT_INVOKE")
        )
        + "\n",
        encoding="utf-8",
    )
    assert check_stride_dispatch._dispatch_intervals(out) == {}
    assert check_stride_dispatch.detect_serial_dispatch(out) == []


def test_serial_wave_is_reported_but_does_not_fail_the_run(tmp_path: Path, capsys) -> None:
    """Exit 0: a serial wave is complete and correct, only slow."""
    out = _write_run(tmp_path, JUICE_SHOP_SERIAL)
    (out / ".progress").mkdir()
    for cid in JUICE_SHOP_SERIAL:
        (out / f".stride-{cid}.json").write_text(json.dumps({"threats": [{"title": "real finding"}]}), encoding="utf-8")
        (out / ".progress" / f"{cid}.json").write_text("{}", encoding="utf-8")

    assert check_stride_dispatch.main([str(out)]) == 0
    err = capsys.readouterr().err
    assert "dispatched SERIALLY" in err
    assert "ci-cd-pipeline" in err


def test_skill_forbids_sequential_wave_dispatch() -> None:
    """The mechanical detector above only reports; the prose must forbid.

    The 71eeb70 thin-orchestrator rebuild compacted the original HARD-CONSTRAINT
    block (SKILL-impl.md) down to one descriptive sentence, dropping the
    imperative + concrete anti-serial check — which is what let the orchestrator
    dispatch the wave serially. These substrings pin the restored imperative so a
    future compaction pass cannot silently weaken it back to a description.
    """
    text = (REPO_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1.md").read_text(encoding="utf-8")
    assert "one assistant message" in text
    # The imperative force, not just the phrasing: an explicit anti-serial order
    # and the concrete self-check that names the exact violation.
    assert "do NOT send one call, wait for it" in text
    assert "you have already violated" in text
