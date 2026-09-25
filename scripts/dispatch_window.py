"""Start of the current agent dispatch window, recorded by the controller.

Every dispatch action the controller emits stamps this file, so the join
(`wait_agent_calls.py`) and stats (`record_stage_stats.py`) default to it and
the orchestrator spends no turn capturing a timestamp before each dispatch.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

DISPATCH_WINDOW_NAME = ".dispatch-window.json"
_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def record(output_dir: str | Path, stage: str) -> str:
    """Stamp a new window; return its ISO start."""
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = Path(output_dir) / DISPATCH_WINDOW_NAME
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"since": since, "stage": stage}) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return since


def since(output_dir: str | Path) -> str:
    """ISO start of the current window, or empty when none was recorded."""
    try:
        value = json.loads((Path(output_dir) / DISPATCH_WINDOW_NAME).read_text(encoding="utf-8")).get("since")
    except (OSError, ValueError, AttributeError):
        return ""
    return value if isinstance(value, str) and _ISO_RE.fullmatch(value) else ""
