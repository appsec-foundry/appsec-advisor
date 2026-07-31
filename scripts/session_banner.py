#!/usr/bin/env python3
"""SessionStart hook: status banner for the appsec-advisor plugin.

Claude Code has no "plugin loaded" event, so the banner is emitted from the
``SessionStart`` hook and shown to the user through the ``systemMessage`` field.
It reports the state a user would otherwise have to look up — whether this
repository has a threat model, how bad it looks, how old it is — and offers the
one command that state calls for. Outside a repository it shrinks to the plugin
identity and the coding-baseline status: there is no project to report on, and a
missing model is not news about a directory nobody meant to scan.

Layout (see docs/internal/analysis/plan-session-banner-redesign-2026-07-29.md):

1. Who + help — plugin identity (or org ``banner.headline``) and ``help`` when packaged.
2. Threat model — fixed label, severity-first facts, object-local command when needed.
3. Secure coding baseline — id and scope when loaded, otherwise the problem and
   the install command on that same line.

No color glyphs. Commands sit on the domain they act on. A calm, current model
carries facts only — no habitual review link.

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

Keep the status lines short. Claude Code prefixes the message with
"SessionStart:startup says: ", which costs the *first* line 27 columns that the
continuation lines get back — identity + help stays on that taxed line so the
threat-model facts keep full width below.

Configuration lives in the ``banner`` block of ``config.json`` (``config.local.json``
wins when present): ``headline`` puts an organization's own name on the identity
line and ``enabled: false`` silences the banner for a packaged build.
``url`` in the same block is *not* printed here — the help skill prints it, so an
organization points it at an internal repository or runbook. Organizations author
all three in their org profile; packaging resolves them into ``config.json``.

``APPSEC_BANNER`` is the user's own switch and outranks all of it in both
directions — set it in the ``env`` block of ``~/.claude/settings.json``.
"""

from __future__ import annotations

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
INSTALL_BASELINE = "/appsec-advisor:install-baseline"
REBUILD = f"{CREATE} --full --rebuild"

# Packaged builds may drop skills; only create-threat-model is guaranteed.
# ``update-threat-model`` is an alias for the incremental mode, so it has a
# fallback — the others are simply left out when absent.
INCREMENTAL = f"{CREATE} --incremental"

# Fixed domain label. The baseline line is headed by the ``baseline`` block's
# own ``name`` instead, so an organization's baseline appears under its name;
# ``baseline_check.DEFAULT_NAME`` covers a build that sets none.
LABEL_THREAT_MODEL = "threat model"

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
    """Name and version of the running build, from its own manifest."""
    manifest = _manifest()
    name = manifest.get("name") or "appsec-advisor"
    version = manifest.get("version")
    return f"{name} {version}" if version else name


def _identity_line(config: dict) -> str:
    """Who is speaking, plus help when the skill is packaged.

    ``banner.headline`` replaces the plugin name (org product branding) but
    keeps the version so packaged builds stay identifiable. Help is global, so
    it lives here rather than on a domain line.
    """
    headline = _text(config, "headline")
    version = _manifest().get("version")
    if headline:
        head = f"{headline} {version}" if version else headline
    else:
        head = _identity()
    parts = [head]
    help_page = _skill_command(HELP)
    if help_page:
        parts.append(help_page)
    return " · ".join(parts)


def _join(*segments: str) -> str:
    """Join non-empty banner segments with the standard separator."""
    return " · ".join(segment for segment in segments if segment)


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
    """Render an ISO timestamp as ``27 Jul 2026``, or pass it through.

    Session-start drift is a day-scale signal; the clock and zone cost width
    without changing the next step. Unparseable values are shown raw.
    """
    try:
        stamp = datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return generated
    return f"{stamp.day} {stamp:%b %Y}"


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


def _baseline_line(repo: Path | None) -> str:
    """Report the coding-baseline state, or "" when there is nothing to say.

    An installed baseline is named with its id and the scope it loads from, so a
    reader can see which rules are in context without running a command.
    Missing, mismatched, or on-disk-but-unloaded states get a line too, with
    ``install-baseline`` only when that skill is still packaged. A build that
    configures no baseline stays silent — there is nothing to report.

    The line is headed by the baseline's own configured name, so an organization
    that ships its own baseline sees it under that name rather than a generic
    label.

    Failure is silence. ``baseline_check`` is a plain stdlib module, but this is
    a startup hook and a banner that cannot report the baseline must still
    report the threat model.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import baseline_check  # type: ignore

        result = baseline_check.check(repo=repo)
    except Exception:
        return ""

    status = result.get("status")
    if status in (None, "disabled"):
        return ""

    label = _text(result, "name") or baseline_check.DEFAULT_NAME

    if status == "installed":
        ids = ", ".join(sorted({m["id"] for m in result.get("matches") or []}))
        scopes = baseline_check.scope_text(result.get("scopes"))
        # A different baseline loaded beside the configured one. Claude Code
        # loads every instruction file it finds, so a project baseline does not
        # replace the one in ~/.claude/ — both rule sets are in context at once
        # and can contradict each other. Naming only the expected id would call
        # that state healthy.
        others = result.get("other") or []
        beside = ""
        if others:
            found = ", ".join(sorted({item["id"] for item in others}))
            where = baseline_check.scope_text([item["scope"] for item in others])
            beside = f"also {found} in {where}" if where else f"also {found}"
        # No command: which of two rule sets to drop is a decision, not a repair.
        return _join(label, ids, scopes, beside)

    carriers = sorted({Path(item["file"]).name for item in result.get("present_unloaded") or []})
    on_disk = f"on disk in {', '.join(carriers)}" if carriers else ""

    if status == "other":
        expected = result.get("expected_id") or "?"
        found = ", ".join(sorted({m["id"] for m in result.get("other") or []})) or "other"
        facts = _join(f"expected {expected}", f"found {found}", on_disk)
    elif carriers:
        # File exists for another tool or waits to be wired — not "not installed".
        facts = _join("not loaded", on_disk)
    else:
        facts = "not installed"

    return _join(label, facts, _skill_command(INSTALL_BASELINE))


def _threat_model_command(*, stale: bool, pressure: bool) -> str:
    """One primary command for the threat-model line, or empty when calm."""
    if stale:
        return _skill_command(UPDATE, INCREMENTAL)
    if pressure:
        return _skill_command(REVIEW)
    return ""


def _threat_model_line(repo: Path, output_dir: Path) -> str:
    """Describe the threat-model domain, with an object-local command when needed."""
    if _scan_running(output_dir):
        return _join(LABEL_THREAT_MODEL, "scan in progress", _skill_command(STATUS))

    try:
        lines = (output_dir / "threat-model.yaml").read_text(encoding="utf-8").splitlines()
    except OSError:
        return _join(LABEL_THREAT_MODEL, "none in docs/security/", CREATE)

    blocks = _blocks(lines)
    meta = _read_meta(blocks.get("meta", []))
    project = meta.get("project", repo.name)
    generated = meta.get("generated")
    counts = _severity_counts(blocks.get("threats", []))

    outdated = _incompatible_analysis_version(meta)
    if outdated:
        return _join(
            LABEL_THREAT_MODEL,
            f"analysis v{outdated} incompatible",
            REBUILD,
        )

    segments: list[str] = [LABEL_THREAT_MODEL]
    # Name what the numbers are. The project name is only worth the columns when
    # it is not the directory the session is already in — a model produced with
    # --repo / --output describes something else, and that is worth saying.
    if project != repo.name:
        segments.append(project)

    if counts["critical"]:
        segments.append(f"{counts['critical']} CRITICAL")
    if counts["high"]:
        segments.append(f"{counts['high']} high")

    total = _count_threats(blocks.get("threats", []))
    segments.append("no findings" if total == 0 else f"{total} total")

    # No assessment depth here: it describes how the report was produced, which
    # is a detail of the report, not a decision the reader makes at session start.
    if generated:
        segments.append(_short_date(generated))

    # Drift is shown as a number from the first commit on, not only past the
    # staleness threshold. Silence would otherwise mean both "nothing changed"
    # and "could not tell" — no git history, unparseable timestamp.
    commits = _commits_since(repo, generated) if generated else None
    if commits:
        segments.append(f"+{commits} commits")

    stale = commits is not None and commits >= STALE_COMMITS
    pressure = bool(counts["critical"] or counts["high"])
    command = _threat_model_command(stale=stale, pressure=pressure)
    if command:
        segments.append(command)
    return _join(*segments)


def build_banner(cwd: str) -> str:
    """Return the banner for ``cwd`` — one to three lines, or empty to stay silent."""
    config = _banner_config()
    if _suppressed(config):
        return ""

    repo = Path(cwd)
    output_dir = repo / "docs" / "security"
    identity = _identity_line(config)

    # Outside a project there is no threat-model state to report, and "no threat
    # model" would be a complaint about a directory nobody meant to scan.
    # Announce who we are, and coding-baseline status when it needs action.
    if not _in_repository(repo) and not (output_dir / "threat-model.yaml").is_file():
        return "\n".join(filter(None, [identity, _baseline_line(None)]))

    banner = [identity, _threat_model_line(repo, output_dir)]
    baseline = _baseline_line(repo)
    if baseline:
        banner.append(baseline)
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
