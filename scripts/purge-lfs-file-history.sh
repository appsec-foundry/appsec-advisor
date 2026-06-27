#!/usr/bin/env bash
#
# purge-lfs-file-history.sh — collapse a tracked file's git history to a single
# (current) version.
#
# It removes ALL past versions of the given path(s) from the CURRENT branch's
# history, then re-commits the current working copy as one fresh blob. Use for
# large/regenerated artifacts (e.g. the example PDFs on Git LFS) so repeated
# regeneration doesn't pile up versions in history.
#
#   scripts/purge-lfs-file-history.sh examples/threat-modeler/threat-model-juice-shop-standard.pdf \
#                                     examples/threat-modeler/threat-model-juice-shop-thorough.pdf
#
# DESTRUCTIVE — rewrites history on the CURRENT branch only. Requires a
# force-push afterwards. Does NOT push. Does NOT touch other branches/worktrees.
#
# Git LFS caveat: a remote like GitHub retains every LFS blob version server-side
# regardless of this rewrite. The real win is local — smaller history plus a
# reclaimable LFS cache (this script runs `git lfs prune` at the end).
#
# Flags: --yes / -y  skip the confirmation prompt.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <path> [<path>...] [--yes]" >&2
  exit 2
fi

ASSUME_YES=0
PATHS=()
for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=1 ;;
    *) PATHS+=("$arg") ;;
  esac
done

if [ "${#PATHS[@]}" -eq 0 ]; then
  echo "ERROR: no paths given." >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

# Safety: clean working tree (rewrite + re-commit needs a known state).
if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: working tree not clean. Commit or stash your changes first." >&2
  exit 1
fi

# All paths must be currently tracked.
for p in "${PATHS[@]}"; do
  if ! git ls-files --error-unmatch "$p" >/dev/null 2>&1; then
    echo "ERROR: '$p' is not tracked by git." >&2
    exit 1
  fi
done

# Print the repo's packed-history size + local LFS cache size.
repo_size() {
  echo "  history (size-pack): $(git count-objects -vH | sed -n 's/^size-pack: //p')"
  echo "  local LFS cache:     $(du -sh .git/lfs 2>/dev/null | cut -f1)"
}

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="refs/backup/${BRANCH}-${TS}"

echo "Branch:     $BRANCH"
echo "Paths:      ${PATHS[*]}"
echo "Backup ref: $BACKUP"
echo
echo "This REWRITES the history of '$BRANCH' (force-push required afterwards)."
echo "Other branches and worktrees are left untouched."
if [ "$ASSUME_YES" -ne 1 ]; then
  read -r -p "Type 'yes' to proceed: " ans
  [ "$ans" = "yes" ] || { echo "aborted."; exit 1; }
fi

# Backup the current tip so the rewrite is reversible.
git update-ref "$BACKUP" HEAD
echo "Backup created at $BACKUP"

echo
echo "Repo size BEFORE:"
repo_size

# Keep current copies aside, then re-add them after the rewrite.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
for p in "${PATHS[@]}"; do
  mkdir -p "$TMP/$(dirname "$p")"
  cp "$p" "$TMP/$p"
done

# Strip the paths from every commit on this branch.
FILTER=""
for p in "${PATHS[@]}"; do
  FILTER+="git rm --cached --ignore-unmatch -- '$p'; "
done
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --index-filter "$FILTER" \
  --prune-empty -- "$BRANCH"

# Re-add the current copies as a single fresh commit.
for p in "${PATHS[@]}"; do
  mkdir -p "$(dirname "$p")"
  cp "$TMP/$p" "$p"
  git add -- "$p"
done
git commit -m "Collapse history of ${PATHS[*]} to current version"

# Drop filter-branch leftovers, expire reflog, gc, prune LFS cache.
rm -rf .git/refs/original
git reflog expire --expire=now --all
git gc --prune=now >/dev/null 2>&1 || true
git lfs prune || true

echo
echo "Repo size AFTER:"
repo_size

echo
echo "Done. Verify the result, then force-push:"
echo "  git push --force-with-lease origin $BRANCH"
echo
echo "Rollback if needed:"
echo "  git reset --hard $BACKUP"
