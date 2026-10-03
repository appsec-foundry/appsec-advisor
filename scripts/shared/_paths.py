"""shared/_paths.py — the one rule for stripping a leading ``./`` from repo paths.

``str.lstrip`` with ``"./"`` strips a *character set*, not a prefix: it turns
``.github/workflows/ci.yml`` into ``github/workflows/ci.yml`` and ``../x`` into
``x``, so a hidden directory collides with a same-named plain one and a parent
reference with a root file. Every caller that normalizes a repo-relative path
for comparison or identity uses ``strip_dot_slash`` instead:

  * ``model/build_threat_model_yaml.py::_norm_file`` (cross-run finding identity)
  * ``runtime/aggregate_run_issues.py`` (evidence-coverage comparison)
  * ``analyzers/scan_excludes.py::_matches_path_prefix``
"""

from __future__ import annotations


def strip_dot_slash(path: str) -> str:
    """Remove every leading ``./`` segment and nothing else."""
    while path.startswith("./"):
        path = path[2:]
    return path
