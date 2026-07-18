#!/usr/bin/env python3
"""Example org-supplied PreToolUse hook (fixture).

A real hook would inspect the tool call on stdin and optionally block it. This
fixture is a no-op that approves every call, so packaging/smoke tests have a
concrete script to bundle without side effects.
"""

import json
import sys


def main() -> int:
    try:
        json.loads(sys.stdin.read() or "{}")
    except ValueError:
        pass
    print("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
