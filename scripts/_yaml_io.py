"""Single source of truth for YAML read semantics across scripts/.

Replaces five divergent ``_load_yaml`` implementations whose error-handling
behavior had drifted (raise vs. None vs. {} vs. caller-default). Callers
declare the missing/malformed semantic explicitly via ``default``.

Examples::

    load_yaml(path)                 # raise on any error
    load_yaml(path, default=None)   # None on missing/malformed
    load_yaml(path, default={})     # {} on missing/malformed
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

__all__ = ["load_yaml"]

_RAISE = object()


def load_yaml(path: Path, *, default: Any = _RAISE) -> Any:
    """Read ``path`` and parse as YAML.

    On ``FileNotFoundError`` or ``yaml.YAMLError``: return ``default`` if
    provided, else re-raise. Any other ``OSError`` (permissions, IO) is
    also routed through the same fallback to keep semantics predictable.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        if default is _RAISE:
            raise
        return default
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        if default is _RAISE:
            raise
        return default
