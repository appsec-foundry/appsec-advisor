"""Published assessment file names and the one naming set a directory holds.

A run works under the internal ``threat-model.*`` names in its private
workspace and publishes ``security-assessment.*``. Directories written before
the rename hold the legacy ``threat-model.*`` set. Readers take the report and
the model from the same set: a directory holding a model under both names is
ambiguous and refused, because an old report could otherwise be read next to a
new model.
"""

from __future__ import annotations

from pathlib import Path

INTERNAL_STEM = "threat-model"
PUBLISHED_STEM = "security-assessment"
REPORT = f"{PUBLISHED_STEM}.md"
MODEL = f"{PUBLISHED_STEM}.yaml"
LEGACY_REPORT = f"{INTERNAL_STEM}.md"
LEGACY_MODEL = f"{INTERNAL_STEM}.yaml"


class ArtifactSetError(ValueError):
    """A directory holds both naming sets, so neither can be trusted alone."""


def published_name(name: str) -> str:
    """The published name of an internal artifact; other names stay as they are.

    ``threat-model.md`` → ``security-assessment.md``,
    ``threat-model-changelog.jsonl`` → ``security-assessment-changelog.jsonl``.
    A slug-stamped ``threat-model-<slug>.<ext>`` keeps its slug.
    """
    if name.startswith(INTERNAL_STEM + ".") or name.startswith(INTERNAL_STEM + "-"):
        return PUBLISHED_STEM + name[len(INTERNAL_STEM) :]
    return name


def artifact_stem(directory: Path) -> str | None:
    """``security-assessment`` or ``threat-model`` for the set ``directory`` holds, else None."""
    current = (directory / MODEL).is_file() or (directory / REPORT).is_file()
    legacy = (directory / LEGACY_MODEL).is_file() or (directory / LEGACY_REPORT).is_file()
    if current and legacy:
        raise ArtifactSetError(
            f"{directory} holds both {MODEL} and {LEGACY_MODEL} artifacts; move the older set away before reading it"
        )
    if current:
        return PUBLISHED_STEM
    return INTERNAL_STEM if legacy else None


def model_path(directory: Path) -> Path:
    """The model file of the set in ``directory``; the published name when none exists yet."""
    return directory / f"{artifact_stem(directory) or PUBLISHED_STEM}.yaml"


def report_path(directory: Path) -> Path:
    """The report file of the set in ``directory``; the published name when none exists yet."""
    return directory / f"{artifact_stem(directory) or PUBLISHED_STEM}.md"
