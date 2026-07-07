#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# run-interruptible.sh — Run a long command so terminal Ctrl-C aborts it
#                        promptly, with graceful → forceful escalation.
#
# Usage:
#   scripts/run-interruptible.sh <logfile> <command> [args...]
#
# Behaviour:
#   * Runs the command in its OWN session/process group and `wait`s on it, instead of
#     as a blocking foreground child. As a foreground child, bash defers its
#     INT trap until the child returns, so Ctrl-C can feel uninterruptible
#     during a long in-flight step (e.g. the pytest suite). Backgrounding +
#     `wait` lets the trap fire immediately.
#   * The command session has no controlling terminal. This matters when a
#     nested script enables job control (`set -m`): a background process group
#     that shares our terminal is otherwise stopped by SIGTTOU, which made
#     `make release-check` freeze inside run-headless.sh tests.
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

if [ "${1:-}" = "--command-session" ]; then
    shift
    LOG="$1"
    shift
    set -o pipefail
    "$@" 2>&1 | tee "$LOG"
    exit $?
fi

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <logfile> <command> [args...]" >&2
    exit 2
fi

LOG="$1"
shift

# Start a detached command session so nested job-control users cannot contend
# with this wrapper for the terminal's foreground process group. The short
# Python launcher is used instead of `setsid(1)` because Python is already a
# project prerequisite and exposes the same primitive on both Linux and macOS.
# It resets signals that Bash marks ignored for asynchronous children before
# replacing itself with this script's internal tee worker. PID, SID, and PGID
# therefore all remain `$GRP`, so one negative-PID signal reaches the full tree.
set +e
python3 -c '
import os
import signal
import sys

for name in ("SIGINT", "SIGQUIT", "SIGTERM", "SIGHUP"):
    signal.signal(getattr(signal, name), signal.SIG_DFL)
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])
' "$0" --command-session "$LOG" "$@" < /dev/null &
GRP=$!

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
