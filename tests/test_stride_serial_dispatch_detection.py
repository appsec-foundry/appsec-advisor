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

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


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


def test_skill_forbids_sequential_wave_dispatch() -> None:
    """OR-5: context-v2 must remain parallel even if calls drift across turns."""
    text = (REPO_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    # The Agent tool exposes no background flag (Claude Code >=2.x dropped it),
    # so concurrency comes from issuing the whole wave in one assistant message.
    assert "in ONE assistant message" in flat, "OR-5: STRIDE fan-out must be non-blocking"
    assert "Pass no `run_in_background`" in flat, (
        "OR-5: instructing a flag the Agent schema rejects loses the whole wave"
    )
    assert "orchestrator/wait_stride_progress.py" in text, "OR-5: a concurrent wave requires a deterministic waiter"
    assert "Never wait for one STRIDE job before launching the next" in flat, (
        "OR-5: a wave must not serialize when tool calls span assistant turns"
    )


# ---------------------------------------------------------------------------
# Production event shapes — the 2026-08-16 juice-shop run
#
# `_COMPONENT_ID_RE` used to match only `COMPONENT_ID=`, while the hook writes
# `component_id=`. Every fixture above invented the upper-case spelling, so the
# suite stayed green while the detector read an empty set on every real run and
# reported "parallel" no matter what the orchestrator did.
# ---------------------------------------------------------------------------


def _v2_spawn(ts: str, cid: str) -> str:
    return (
        f"{ts}  [aa40ceb8]  INFO   AGENT_SPAWN         "
        f"agent_call_id=toolu_{cid}  agent_type=appsec-advisor:appsec-stride-analyzer-v2  "
        f"model=sonnet  background=false  action_id=stage1c:9536d86a2e3258d2  "
        f"job_id=stride:{cid}:attempt-1  component_id={cid}  attempt=1  "
        f"analysis_depth=full  description=STRIDE (full): {cid}"
    )


def _v2_usage(ts: str, cid: str) -> str:
    return (
        f"{ts}  [aa40ceb8]  INFO   stride-analyzer-v2  AGENT_USAGE         "
        f"agent_call_id=toolu_{cid}  component_id={cid}  attempt=1  "
        f"in=48  out=67284  cache_write=133025  cache_read=2126193  tool_uses=33"
    )


def _write_v2_run(out_dir: Path, spans: dict[str, tuple[str, str]]) -> Path:
    out = out_dir / "security"
    out.mkdir(exist_ok=True)
    (out / ".stride-dispatch-manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-08-16T06:59:08Z",
                "components": [{"component_id": cid} for cid in spans],
            }
        ),
        encoding="utf-8",
    )
    (out / ".hook-events.log").write_text(
        "\n".join(_v2_spawn(start, cid) for cid, (start, _) in spans.items()) + "\n",
        encoding="utf-8",
    )
    (out / ".agent-run.log").write_text(
        "\n".join(_v2_usage(end, cid) for cid, (_, end) in spans.items()) + "\n",
        encoding="utf-8",
    )
    return out


# ---------------------------------------------------------------------------
# Wave boundaries are sequential by design
#
# Once the detector could actually read a production log, it compared the last
# component of one wave against the first of the next and called every healthy
# multi-wave run serial. Its own contract forbids that: "Being blind is
# strictly preferable to false-tripping a healthy parallel run."
# ---------------------------------------------------------------------------


def _write_waves(out: Path, waves: list[list[str]]) -> None:
    (out / ".dispatch-waves.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "concurrency": 5,
                "waves": [{"index": i, "component_ids": ids} for i, ids in enumerate(waves, start=1)],
            }
        ),
        encoding="utf-8",
    )
