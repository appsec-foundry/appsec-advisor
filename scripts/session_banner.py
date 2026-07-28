#!/usr/bin/env python3
"""SessionStart hook: status banner for the appsec-advisor plugin.

Claude Code has no "plugin loaded" event, so the banner is emitted from the
``SessionStart`` hook and shown to the user through the ``systemMessage`` field.
It reports the state a user would otherwise have to look up — whether this
repository has a threat model, how bad it looks, how old it is — and offers the
one command that state calls for. Outside a repository it shrinks to the plugin
version and the help page: there is no project to report on, and a missing model
is not news about a directory nobody meant to scan.

The banner is decoration, not a contract. It must never delay or break session
start, so every failure path is silent: on any error the script prints nothing
and exits 0.

Three consequences of that rule shape the implementation:

* No network. Whether a newer release exists is deliberately not checked here;
  that would be a hidden network call on every session start, it would fail in
  the air-gapped environments where packaged builds run, and it would leak usage
  timing. The compatibility signal below is the local substitute.
* No third-party imports. ``python3`` here is the user's interpreter, which is
  not guaranteed to have PyYAML, so the ``meta:`` block is read with a tolerant
  scan of flat ``key: value`` lines instead of a YAML parse. Only a few scalar
  fields are needed.
* No full parse of ``threat-model.yaml``. The file reaches ~500 KB on real
  repositories, where PyYAML's pure-Python loader costs about a second — far
  too much for a startup hook. A single line scan costs ~15 ms.

The hook is registered with ``matcher: "startup"`` on purpose. ``SessionStart``
also fires for ``clear`` and ``compact``, where a plugin-load announcement would
describe a load that never happened.

Keep the status line short. Claude Code prefixes the message with
"SessionStart:startup says: ", which costs the *first* line 27 columns that the
continuation lines get back — an otherwise reasonable line wraps there and
breaks mid-token.

Configuration lives in the ``banner`` block of ``config.json`` (``config.local.json``
wins when present): ``headline`` puts an organization's own name in front of the
status line and ``enabled: false`` silences the banner for a packaged build.
``url`` in the same block is *not* printed here — the help skill prints it, so an
organization points it at an internal repository or runbook. Organizations author
all three in their org profile; packaging resolves them into ``config.json``.

``APPSEC_BANNER`` is the user's own switch and outranks all of it in both
directions — set it in the ``env`` block of ``~/.claude/settings.json``.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Commits since the model was generated, above which it is called out as stale.
STALE_COMMITS = 20

# Wall-clock ceiling for the commit count; a slow repository must not stall
# session start.
GIT_TIMEOUT_SECONDS = 3

# Written with the upstream command namespace on purpose: packaging rewrites it
# to the organization's own namespace across packaged .py files, and
# check_namespace_leaks fails the build if one is missed. Keep the literals
# whole — a namespace assembled at runtime would slip past both.
REVIEW = "/appsec-advisor:review-threat-model"
UPDATE = "/appsec-advisor:update-threat-model"
CREATE = "/appsec-advisor:create-threat-model"
STATUS = "/appsec-advisor:status"
HELP = "/appsec-advisor:help"
REBUILD = f"{CREATE} --full --rebuild"

# Packaged builds may drop skills; only create-threat-model is guaranteed.
# ``update-threat-model`` is an alias for the incremental mode, so it has a
# fallback — the others are simply left out when absent.
INCREMENTAL = f"{CREATE} --incremental"

# A bare "or just ask" does not say what about, so it teaches nothing. A real
# question does, and this one is quoted from ask-threat-model's own description
# so it routes there instead of to show-threat-model.
QUESTION_HINT = 'or ask "what are the critical findings?"'

# One glyph, one claim: can this security picture be relied on right now? Both
# unfixed risk and drift since the scan degrade that, so both feed it. Two
# separate marks were tried and read worse — a green dot beside red "27
# CRITICAL" is taken as an all-clear before anyone parses the distinction.
GLYPH_OK = "🟢"
GLYPH_WARN = "🟠"
GLYPH_ALERT = "🔴"
GLYPH_NONE = "⚪"
GLYPH_BUSY = "🔵"

_TOP_LEVEL_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:")
_META_FIELD = re.compile(r"^  ([a-z_]+): (.*)$")


def _plugin_root() -> Path:
    """Resolve the plugin directory, preferring the runtime-provided root."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return Path(root)
    return Path(__file__).resolve().parent.parent


def _manifest() -> dict:
    try:
        with open(_plugin_root() / ".claude-plugin" / "plugin.json", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _banner_config() -> dict:
    """Read the ``banner`` block; config.local.json wins, as elsewhere in the plugin."""
    root = _plugin_root()
    local = root / "config.local.json"
    path = local if local.is_file() else root / "config.json"
    try:
        with open(path, encoding="utf-8") as fh:
            block = json.load(fh).get("banner")
    except Exception:
        return {}
    return block if isinstance(block, dict) else {}


def _suppressed(config: dict) -> bool:
    """True when the banner must stay silent.

    ``APPSEC_BANNER`` is the user's switch and outranks the packaged config in
    both directions, so a developer can silence a banner the organization
    enabled — and re-enable one it turned off.
    """
    override = os.environ.get("APPSEC_BANNER", "").strip().lower()
    if override in ("0", "false", "off", "no"):
        return True
    if override in ("1", "true", "on", "yes"):
        return False
    return config.get("enabled") is False


def _text(config: dict, key: str) -> str:
    """Return a configured single-line string, or empty when unusable."""
    value = config.get(key)
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:200]


def _in_repository(path: Path) -> bool:
    """True when ``path`` sits inside a git working tree.

    Walked instead of shelled out to: `git rev-parse` would cost a process on
    every session start for a question a directory lookup answers. A worktree
    or submodule carries `.git` as a file, hence ``exists`` rather than
    ``is_dir``.
    """
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return True
    return False


def _has_skill(name: str) -> bool:
    """True when this build still ships the skill.

    ``package_internal_plugin.apply_skill_policy`` deletes excluded skill
    directories, so pointing at one that is gone would advertise a command the
    organization deliberately removed.
    """
    return (_plugin_root() / "skills" / name / "SKILL.md").is_file()


def _skill_command(command: str, fallback: str = "") -> str:
    """Return ``command`` when its skill is packaged, else ``fallback``."""
    skill = command.split(":", 1)[-1].split(" ", 1)[0]
    return command if _has_skill(skill) else fallback


def _identity() -> str:
    """Name and version of the running build, from its own manifest.

    It rides on the action row, not the status line: that line already pays 27
    columns for Claude Code's "SessionStart:startup says: " prefix, and an
    identity in front of it pushed the state into a second visual line.
    """
    manifest = _manifest()
    name = manifest.get("name") or "appsec-advisor"
    version = manifest.get("version")
    return f"{name} {version}" if version else name


def build_actions(command: str) -> str:
    """Compose the action row: the command this state calls for, help, identity.

    One command, not a menu, and it carries no verb label — the command names
    say what they do. Everything else lives on the help page, which is the right
    place for examples and flags; a row shown at every session start earns its
    space by staying short enough to read.
    """
    parts = [command] if command else []
    help_page = _skill_command(HELP)
    if help_page:
        parts.append(help_page)
    parts.append(_identity())
    return " · ".join(parts)


def _blocks(lines: list[str]) -> dict[str, list[str]]:
    """Split YAML lines into top-level blocks, keyed by their unindented key."""
    starts = [(i, line.split(":", 1)[0]) for i, line in enumerate(lines) if _TOP_LEVEL_KEY.match(line)]
    out: dict[str, list[str]] = {}
    for pos, (start, key) in enumerate(starts):
        end = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        out[key] = lines[start + 1 : end]
    return out


def _read_meta(block: list[str]) -> dict[str, str]:
    """Collect the flat scalar fields of the ``meta:`` block.

    Nested and sequence values are skipped — the banner only needs scalars.
    """
    meta: dict[str, str] = {}
    for line in block:
        match = _META_FIELD.match(line)
        if not match:
            continue
        value = match.group(2).strip().strip("'\"")
        if value and value not in ("null", "[]", "{}", "|", ">-"):
            meta[match.group(1)] = value
    return meta


def _count_threats(block: list[str]) -> int:
    """Count top-level sequence items in the ``threats:`` block.

    PyYAML emits those items at the parent's indent level, so they are the only
    lines in the block that start at column 0.
    """
    return sum(1 for line in block if line.startswith("- "))


def _severity_counts(block: list[str]) -> dict[str, int]:
    """Count Critical and High findings in the ``threats:`` block.

    ``effective_severity`` is the displayed severity and carries triage caps and
    boosts; ``risk`` is the pre-adjustment value and only stands in for models
    written before that field existed. Both sit at one line per threat, so
    counting lines matches counting threats.
    """
    counts = {"critical": 0, "high": 0}
    for field in ("effective_severity", "risk"):
        prefix = f"  {field}: "
        seen = False
        for line in block:
            if not line.startswith(prefix):
                continue
            seen = True
            value = line[len(prefix) :].strip().strip("'\"").lower()
            if value in counts:
                counts[value] += 1
        if seen:
            break
    return counts


def _severity_summary(counts: dict[str, int]) -> str:
    """Render "27 CRITICAL, 29 high", omitting the levels that are absent.

    Uppercase, not colour. This line appears at every session start, and an
    emphasis that fires every time stops being one; red text beside a coloured
    glyph is also the classic failure case for red-green colour blindness.
    Capitals in a monospace line carry the weight in every client and theme.
    """
    labels = {"critical": "CRITICAL", "high": "high"}
    return ", ".join(f"{counts[level]} {labels[level]}" for level in ("critical", "high") if counts[level])


def _incompatible_analysis_version(meta: dict[str, str]) -> str | None:
    """Return the model's analysis version when this build can no longer read it.

    The manifest owns the compatibility range, so an unknown or unparseable
    version is treated as compatible rather than guessed at.
    """
    try:
        found = int(meta.get("analysis_version", ""))
    except ValueError:
        return None
    supported = _manifest().get("compatible_analysis_versions")
    if not isinstance(supported, list) or not supported:
        return None
    return None if found in supported else str(found)


def _commits_since(repo: Path, generated: str) -> int | None:
    """Count commits made after ``generated``, or None if that is not knowable."""
    try:
        datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-list", "--count", f"--since={generated}", "HEAD"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _short_date(generated: str) -> str:
    """Render an ISO timestamp as ``27 Jul 2026 10:01 UTC``, or pass it through.

    The zone is spelled out because the stored value is UTC while the reader's
    clock usually is not; a bare time would look wrong by the offset.
    """
    try:
        stamp = datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return generated
    return f"{stamp.day} {stamp:%b %Y %H:%M} UTC"


def _scan_running(output_dir: Path) -> bool:
    """True when a scan is currently live in ``output_dir``.

    Freshness thresholds belong to ``check_state``; this only asks it. If the
    import fails, the banner falls back to reporting the model instead.
    """
    if not (output_dir / ".appsec-lock").is_file():
        return False
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from check_state import classify  # type: ignore
    except Exception:
        return False
    try:
        return classify(output_dir).get("state") == "active"
    except Exception:
        return False


def _line(glyph: str, *segments: str) -> str:
    """Join the non-empty segments of a status line behind its state glyph."""
    body = " · ".join(segment for segment in segments if segment)
    return f"{glyph} {body}" if glyph else body


def _status_line(prefix: str, repo: Path, output_dir: Path) -> tuple[str, str]:
    """Describe the current state.

    Returns the status line and the command this state calls for. The line
    itself stays free of commands so the two
    roles do not compete for the reader's eye — state here, actions on the row
    below.
    """
    if _scan_running(output_dir):
        return _line(GLYPH_BUSY, prefix, "scan in progress"), _skill_command(STATUS)

    try:
        lines = (output_dir / "threat-model.yaml").read_text(encoding="utf-8").splitlines()
    except OSError:
        return _line(GLYPH_NONE, prefix, "no threat model in docs/security/"), CREATE

    blocks = _blocks(lines)
    meta = _read_meta(blocks.get("meta", []))
    project = meta.get("project", repo.name)
    generated = meta.get("generated")
    counts = _severity_counts(blocks.get("threats", []))

    outdated = _incompatible_analysis_version(meta)
    if outdated:
        return (
            _line(GLYPH_ALERT, prefix, f"threat model built with analysis v{outdated}, no longer compatible"),
            REBUILD,
        )

    severity = _severity_summary(counts)
    total = _count_threats(blocks.get("threats", []))
    threats = f"{total} threat" if total == 1 else f"{total} threats"
    if severity:
        threats += f" ({severity})"

    # Name what the numbers are. The project name is only worth the columns when
    # it is not the directory the session is already in — a model produced with
    # --repo / --output describes something else, and that is worth saying.
    label = "threat model" if project == repo.name else f"threat model: {project}"

    # No assessment depth here: it describes how the report was produced, which
    # is a detail of the report, not a decision the reader makes at session start.
    facts = [label, threats]
    if generated:
        facts.append(_short_date(generated))

    # Drift is shown as a number from the first commit on, not only past the
    # staleness threshold. Silence would otherwise mean both "nothing changed"
    # and "could not tell" — no git history, unparseable timestamp.
    commits = _commits_since(repo, generated) if generated else None
    if commits:
        facts.append(f"+{commits} commits")

    stale = commits is not None and commits >= STALE_COMMITS
    if counts["critical"]:
        glyph = GLYPH_ALERT
    elif counts["high"] or stale:
        glyph = GLYPH_WARN
    else:
        glyph = GLYPH_OK

    action = _skill_command(UPDATE, INCREMENTAL) if stale else _skill_command(REVIEW)
    return _line(glyph, prefix, *facts), action


def build_banner(cwd: str) -> str:
    """Return the banner for ``cwd`` — one to three lines, or empty to stay silent."""
    config = _banner_config()
    if _suppressed(config):
        return ""

    # No plugin name or version by default: Claude Code already prefixes the
    # message with "SessionStart:startup says:", the commands below carry the
    # namespace, and that prefix costs the first line 27 columns it does not
    # have. Organizations that want their name there set `headline`.
    prefix = _text(config, "headline")

    repo = Path(cwd)
    output_dir = repo / "docs" / "security"

    # Outside a project there is no state to report, and "no threat model" would
    # be a complaint about a directory nobody meant to scan. Announce the plugin
    # and where to read about it, nothing more.
    if not _in_repository(repo) and not (output_dir / "threat-model.yaml").is_file():
        return " · ".join(filter(None, [_identity(), _skill_command(HELP)]))

    status, action = _status_line(prefix, repo, output_dir)

    banner = [status]
    actions = build_actions(action)
    if actions:
        banner.append(actions)
    return "\n".join(banner)


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        cwd = payload.get("cwd") or os.getcwd()
        banner = build_banner(cwd)
    except Exception:
        return
    if banner:
        print(json.dumps({"systemMessage": banner}))


if __name__ == "__main__":
    main()
