"""Structured read of docker-compose files for the §2 deployment figure.

Only what a reader of the deployment needs: services, their image, published
and exposed ports, volumes, networks, dependencies and the source line of each
service. Environment values are never returned — only the keys, plus the value
of a key whose value is a boolean-like switch, so a secret in an ``environment:``
block cannot reach a rendered figure.

Repository content is untrusted: discovery is bounded in depth and file size,
parsing uses ``load_yaml_bounded`` (``safe_load`` with a bound on alias and
merge-key expansion), and files that resolve outside the repository root are
ignored. Every failure degrades to "no services".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_COMPOSE_NAME_RE = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$", re.IGNORECASE)
_MAX_DEPTH = 2
_MAX_BYTES = 512 * 1024
_MAX_FILES = 8
_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "target", "build", "dist", "docs"}
_SWITCH_VALUE_RE = re.compile(r"^(?:0|1|true|false|yes|no|on|off)$", re.IGNORECASE)
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_MAX_EXPANDED_NODES = 200_000  # a 512 KiB file without aliases stays far below; nested aliases exceed it


class YAMLExpansionError(yaml.YAMLError):
    """A document whose aliases or merge keys expand beyond ``_MAX_EXPANDED_NODES``, or refer to themselves."""


def _expanded(node: yaml.Node, memo: dict[int, int], active: set[int]) -> int:
    """Node count of ``node`` with every alias expanded; shared nodes are counted once per reference."""
    key = id(node)
    if key in memo:
        return memo[key]
    if key in active:
        raise YAMLExpansionError("recursive alias")
    if isinstance(node, yaml.ScalarNode):
        return 1
    active.add(key)
    children = [n for pair in node.value for n in pair] if isinstance(node, yaml.MappingNode) else node.value
    total = 1
    for child in children:
        total += _expanded(child, memo, active)
        if total > _MAX_EXPANDED_NODES:
            raise YAMLExpansionError("aliases expand beyond the reader's bound")
    active.discard(key)
    memo[key] = total
    return total


def load_yaml_bounded(text: str, all_documents: bool = False):
    """``yaml.safe_load`` (or a list as ``safe_load_all``) that checks the node graph before building objects.

    Aliases stay shared after loading and expand in any later ``str()`` or walk, and merge keys expand while
    loading, so a file of a few hundred bytes could otherwise stall the scan. Raises ``yaml.YAMLError``.
    """
    loader = yaml.SafeLoader(text)
    try:
        docs, memo, budget = [], {}, 0
        while loader.check_node():
            node = loader.get_node()
            try:
                budget += _expanded(node, memo, set())
            except RecursionError as exc:
                raise YAMLExpansionError("nesting too deep") from exc
            if budget > _MAX_EXPANDED_NODES:
                raise YAMLExpansionError("aliases expand beyond the reader's bound")
            docs.append(loader.construct_document(node))
    finally:
        loader.dispose()
    if all_documents:
        return docs
    if len(docs) > 1:
        raise yaml.YAMLError("expected a single document")
    return docs[0] if docs else None


@dataclass(frozen=True)
class Port:
    host: str  # host port or range; "" when Docker picks one
    container: str
    host_ip: str = ""  # "" = all interfaces

    @property
    def loopback_only(self) -> bool:
        return self.host_ip in _LOOPBACK


@dataclass
class Service:
    name: str
    file: str  # path relative to the repository root
    line: int  # line of the service key
    end_line: int  # last line that belongs to the service
    image: str = ""
    builds: bool = False
    ports: list[Port] = field(default_factory=list)
    expose: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)  # named volume or host path (source side only)
    networks: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    env_switches: dict[str, str] = field(default_factory=dict)  # key -> boolean-like value only
    user: str = ""
    privileged: bool = False

    @property
    def published(self) -> list[Port]:
        return self.ports


def discover_compose_files(repo_root: Path) -> list[Path]:
    """Compose files at most ``_MAX_DEPTH`` levels below the root, inside it."""
    root = repo_root.resolve()
    found: list[Path] = []

    def walk(directory: Path, depth: int) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for entry in entries:
            if len(found) >= _MAX_FILES:
                return
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if depth < _MAX_DEPTH and entry.name not in _SKIP_DIRS and not entry.name.startswith("."):
                    walk(entry, depth + 1)
            elif _COMPOSE_NAME_RE.match(entry.name):
                try:
                    if entry.resolve().is_relative_to(root) and entry.stat().st_size <= _MAX_BYTES:
                        found.append(entry)
                except OSError:
                    continue

    if root.is_dir():
        walk(root, 0)
    return found


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value)
    return [value]


def _parse_port(entry) -> Port | None:
    if isinstance(entry, dict):
        target = str(entry.get("target") or "").strip()
        if not target:
            return None
        return Port(str(entry.get("published") or "").strip(), target, str(entry.get("host_ip") or "").strip())
    if isinstance(entry, (int, float)) and not isinstance(entry, bool):
        return Port("", str(int(entry)))
    if not isinstance(entry, str) or not entry.strip():
        return None
    spec = entry.strip().split("/")[0]
    host_ip = ""
    if spec.startswith("["):  # [::1]:8080:80
        close = spec.find("]")
        host_ip, spec = spec[1:close], spec[close + 2 :]
    parts = spec.split(":")
    if len(parts) == 1:
        return Port("", parts[0])
    if len(parts) == 2:
        return Port(parts[0], parts[1], host_ip)
    return Port(parts[-2], parts[-1], host_ip or ":".join(parts[:-2]))


def _env(value) -> tuple[list[str], dict[str, str]]:
    keys: list[str] = []
    switches: dict[str, str] = {}
    items = (
        value.items()
        if isinstance(value, dict)
        else ((str(e).partition("=")[0], str(e).partition("=")[2]) for e in _as_list(value))
    )
    for key, raw in items:
        key = str(key).strip()
        if not key:
            continue
        keys.append(key)
        text = "" if raw is None else str(raw).strip()
        if isinstance(raw, bool):
            text = "true" if raw else "false"
        if _SWITCH_VALUE_RE.match(text):
            switches[key] = text
    return keys, switches


def _service_lines(text: str, names: list[str]) -> dict[str, tuple[int, int]]:
    """First and last source line of each service key under ``services:``."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(r"^services\s*:", ln)), None)
    if start is None:
        return {}
    heads: list[tuple[int, str]] = []
    indent = None
    for i in range(start + 1, len(lines)):
        ln = lines[i]
        if ln.strip() and not ln.startswith((" ", "\t")) and not ln.lstrip().startswith("#"):
            break  # next top-level key
        m = re.match(r"^(\s+)([\"']?)([^\s:\"'#]+)\2\s*:\s*(?:#.*)?$", ln)
        if m and (indent is None or len(m.group(1)) == indent) and m.group(3) in names:
            indent = len(m.group(1))
            heads.append((i + 1, m.group(3)))
    end_of_block = next(
        (
            i
            for i in range(start + 1, len(lines))
            if lines[i].strip() and not lines[i].startswith((" ", "\t")) and not lines[i].lstrip().startswith("#")
        ),
        len(lines),
    )
    spans = {}
    for k, (line, name) in enumerate(heads):
        nxt = heads[k + 1][0] - 1 if k + 1 < len(heads) else end_of_block
        spans[name] = (line, nxt)
    return spans


def parse_compose_file(path: Path, repo_root: Path) -> list[Service]:
    """Services of one compose file; ``[]`` for anything unreadable."""
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
        data = load_yaml_bounded(text)
    except (OSError, yaml.YAMLError):
        return []
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return []
    try:
        rel = str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return []
    spans = _service_lines(text, [str(n) for n in services])
    out: list[Service] = []
    for name, spec in services.items():
        if not isinstance(spec, dict):
            continue
        name = str(name)
        first, last = spans.get(name, (0, 0))
        keys, switches = _env(spec.get("environment"))
        out.append(
            Service(
                name=name,
                file=rel,
                line=first,
                end_line=last,
                image=str(spec.get("image") or "").strip(),
                builds=bool(spec.get("build")),
                ports=[p for p in (_parse_port(e) for e in _as_list(spec.get("ports"))) if p],
                expose=[str(e) for e in _as_list(spec.get("expose"))],
                volumes=[
                    (str(v.get("source") or "") if isinstance(v, dict) else str(v).split(":")[0]).strip()
                    for v in _as_list(spec.get("volumes"))
                    if (v.get("source") if isinstance(v, dict) else str(v).split(":")[0])
                ],
                networks=[str(n) for n in _as_list(spec.get("networks"))],
                depends_on=[str(n) for n in _as_list(spec.get("depends_on"))],
                env_keys=keys,
                env_switches=switches,
                user=str(spec.get("user") or "").strip(),
                privileged=spec.get("privileged") is True,
            )
        )
    return out


# The names `docker compose` resolves without `-f`, in its own precedence order.
_DEFAULT_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def primary_compose_file(repo_root: Path | None) -> tuple[Path | None, list[Path]]:
    """The file `docker compose` would use at the root (else the first one found) and the other variants."""
    if repo_root is None:
        return None, []
    files = discover_compose_files(repo_root)
    root = repo_root.resolve()
    # The root is checked directly: the bounded walk may stop in nested folders before it reaches a root file.
    primary = next((root / name for name in _DEFAULT_NAMES if _usable(root / name, root)), None)
    primary = primary or (files[0] if files else None)
    return primary, [f for f in files if f != primary]


def _usable(path: Path, root: Path) -> bool:
    try:
        return (
            path.is_file()
            and not path.is_symlink()
            and path.resolve().is_relative_to(root)
            and path.stat().st_size <= _MAX_BYTES
        )
    except OSError:
        return False


def load_services(repo_root: Path | None) -> list[Service]:
    """Services of the primary compose file; variants (override, prod, local) are not merged."""
    primary, _variants = primary_compose_file(repo_root)
    return parse_compose_file(primary, repo_root) if primary else []


def service_at(services: list[Service], file: str, line: int | None) -> Service | None:
    """The service whose block contains ``file:line``."""
    if not line:
        return None
    for svc in services:
        if svc.file == file and svc.line <= line <= svc.end_line:
            return svc
    return None


def compose_networks(repo_root: Path | None) -> dict[str, str]:
    """Declared top-level networks → driver ("" when unset) of the primary compose file."""
    primary, _variants = primary_compose_file(repo_root)
    if primary is None:
        return {}
    try:
        data = load_yaml_bounded(primary.read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError):
        return {}
    nets = data.get("networks") if isinstance(data, dict) else None
    if not isinstance(nets, dict):
        return {}
    return {str(k): str(v.get("driver") or "") if isinstance(v, dict) else "" for k, v in nets.items()}
