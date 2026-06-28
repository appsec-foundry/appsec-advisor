#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# run-interruptible.sh — Run a long command so terminal Ctrl-C aborts it
#                        promptly, with graceful → forceful escalation.
#
# Usage:
#   scripts/run-interruptible.sh <logfile> <command> [args...]
#
# Behaviour:
#   * Runs the command in its OWN process group and `wait`s on it, instead of
#     as a blocking foreground child. As a foreground child, bash defers its
#     INT trap until the child returns, so Ctrl-C can feel uninterruptible
#     during a long in-flight step (e.g. the pytest suite). Backgrounding +
#     `wait` lets the trap fire immediately.
#   * The trap forwards signals to the WHOLE command group with escalation:
#     1st Ctrl-C → SIGINT (graceful), 2nd → SIGTERM, 3rd → SIGKILL. This also
#     reaches grandchildren that put themselves in their own process group and
#     would otherwise survive a single terminal Ctrl-C.
#   * Combined stdout+stderr is tee'd to <logfile>; the command's real exit
#     code is preserved (not 128+signal).
#   * stdin is redirected from /dev/null so the backgrounded group never
#     blocks on a terminal read (SIGTTIN).
#
# This mirrors the interrupt handling in run-headless.sh; keep the two in sync.
# ──────────────────────────────────────────────────────────────────────
set -u

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <logfile> <command> [args...]" >&2
    exit 2
fi

LOG="$1"
shift

# Background a single subshell that runs the work and tees its output. Because
# it is one job under `set -m`, the subshell is the process-group leader
# (PGID == $!), so we can signal the entire tree with `kill -<sig> -$GRP`.
# (Backgrounding a *pipeline* directly would make $! the last element — tee —
# not the group leader, so we wrap the pipeline in a subshell.)
set +e
set -m
(
    set -o pipefail
    "$@" 2>&1 | tee "$LOG"
) < /dev/null &
GRP=$!
set +m

SIGINT_COUNT=0
on_interrupt() {
    SIGINT_COUNT=$((SIGINT_COUNT + 1))
    if [ "$SIGINT_COUNT" -ge 3 ]; then
        echo "" >&2
        echo "Third interrupt — sending SIGKILL to the process group." >&2
        kill -KILL "-$GRP" 2>/dev/null || true
    elif [ "$SIGINT_COUNT" -eq 2 ]; then
        echo "" >&2
        echo "Second interrupt — sending SIGTERM to the process group." >&2
        kill -TERM "-$GRP" 2>/dev/null || true
    else
        echo "" >&2
        echo "Interrupt — aborting (press Ctrl-C again to escalate)." >&2
        kill -INT "-$GRP" 2>/dev/null || true
    fi
}
trap 'on_interrupt' INT
trap 'kill -TERM "-$GRP" 2>/dev/null || true' TERM HUP

wait "$GRP"
EXIT_CODE=$?
# A trapped signal interrupts `wait` (exit > 128) before the group has finished
# shutting down; keep waiting until it actually exits so we report the real
# exit code, not 128+signal.
while [ "$EXIT_CODE" -gt 128 ] && kill -0 "$GRP" 2>/dev/null; do
    wait "$GRP"
    EXIT_CODE=$?
done

if [ "$SIGINT_COUNT" -gt 0 ]; then
    echo "Aborted by user." >&2
fi

exit "$EXIT_CODE"
