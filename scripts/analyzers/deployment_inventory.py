#!/usr/bin/env python3
"""Deterministic deployment inventory for the §2 Deployment and Technology figure.

Reads what the repository declares about where and how it runs — the Dockerfile,
the compose file ``docker compose`` uses without ``-f``, Kubernetes and OpenShift
manifests, Helm chart values, a GitLab Auto Deploy values file, AWS Terraform and
the CI configuration — and writes ``.deployment-inventory.json``. The composer
renders the figure from that file only, so a re-render shows the state of the
scan, not of a later checkout.

Every environment becomes a tree of nodes (cloud, cluster, network, service,
managed, workload). Each node carries at most three short facts chosen by rule:
``weak`` for a setting that weakens a control, ``decision`` for one that needs a
decision, ``neutral`` and ``note`` otherwise. A fact that rests on the absence of
a resource says "in this Terraform" or "in these manifests", because the control
can live in another repository.

``topology`` lists the deployable workloads of the compose file and the Kubernetes manifests with the zones they
sit in — compose networks and namespaces under their declared names, never mapped onto a fixed zone vocabulary —
and the workloads that sit in more than one zone. It never adds or changes an environment of the figure.

Repository content is untrusted. Discovery is bounded in depth, file count and
size, skips symlinks and anything that resolves outside the root, parses YAML with
``safe_load`` and Terraform with a bounded block reader. No environment value,
secret value or file content is ever written: only names, ports, image
references, line numbers and rule-chosen statements.

Usage: analyzers/deployment_inventory.py --repo-root <dir> --output <file>
Exit codes: 0 written, 1 invalid output (nothing written), 2 usage error.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import fnmatch
import json
import os
import re
import sys
from functools import cache
from pathlib import Path
from typing import NamedTuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from renderers.compose_services import load_yaml_bounded, parse_compose_file, primary_compose_file  # noqa: E402
from shared._lib_manifest import discover_manifests, parse_manifest  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "deployment-inventory.schema.json"
VOCAB_PATH = PLUGIN_ROOT / "data" / "deployment-technology.yaml"

MAX_DEPTH = 4
MAX_FILES = 64
MAX_BYTES = 256 * 1024
MAX_WALK_ENTRIES = 50_000
SKIP_DIRS = {
    ".git",
    ".terraform",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "target",
    "build",
    "dist",
    "__pycache__",
    "test",
    "tests",
    "__tests__",
    "fixtures",
    "testdata",
    "examples",
    "docs",
}
# A name is sensitive when one of its words is (`db-credentials.json`, `encryptionkeys/`), never by substring
# (`keycloak/`, `monkeypatch.py`, `tokenizer.py`), or by its extension.
SENSITIVE_WORDS = {
    "key",
    "keys",
    "secret",
    "secrets",
    "cred",
    "creds",
    "credential",
    "credentials",
    "password",
    "passwords",
    "passwd",
    "htpasswd",
    "token",
    "tokens",
    "keystore",
    "truststore",
}
SENSITIVE_WORD_ENDINGS = ("keys", "secrets", "credentials", "passwords", "tokens")
SENSITIVE_SUFFIXES = (".pem", ".p12", ".pfx", ".jks", ".key")
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
    "Cargo.lock",
    "gradle.lockfile",
    "packages.lock.json",
}
RANGE_RE = re.compile(r"^[\^~<>=*]|[*xX]$|\|\||\s-\s|^latest$|^next$|\[|\(|,")
# Kubernetes kinds that run pods; the figure draws one workload node per document of these kinds.
_K8S_WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "DeploymentConfig")
# Every kind the manifest reader keeps; other documents are ignored.
K8S_KINDS = {"Namespace", "Route", "Ingress", "Service", "NetworkPolicy", *_K8S_WORKLOAD_KINDS}

# Output limits. They mirror maxLength / maxItems in schemas/deployment-inventory.schema.json: a value past
# them fails validation and the whole file is not written. Limits used only once stay inline next to their field.
TEXT_MAX = 200  # fact text
NAME_MAX = 120  # node title, service/zone/workload name, path-like label
IMAGE_MAX = 240  # image reference, and any other string attribute of a node
MAX_FACTS = 3  # facts per node or CI system
MAX_CHILDREN = 24  # children per node


# ================================================================ bounded file access
# Every read of repository content goes through these helpers: no symlinks, nothing that resolves outside the
# root, size- and count-bounded. Bypassing them would let a hostile repository point the scan at other files.
def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def _walk(root: Path, accept, max_depth: int = MAX_DEPTH, max_files: int = MAX_FILES) -> list[Path]:
    """Files below root for which accept(path) is true: no symlinks, nothing outside root, bounded."""
    found: list[Path] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not (d.startswith(".") and d not in {".github", ".gitlab", ".circleci"})
            and rel_depth < max_depth
        )
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_WALK_ENTRIES or len(found) >= max_files:
                return found
            p = Path(dirpath) / name
            if p.is_symlink() or not accept(p):
                continue
            try:
                if p.stat().st_size <= MAX_BYTES and _inside(p, root):
                    found.append(p)
            except OSError:
                continue
    return found


def _read(path: Path | None, root: Path) -> str:
    if path is None or path.is_symlink() or not path.is_file() or not _inside(path, root):
        return ""
    try:
        if path.stat().st_size > MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _line_of(text: str, pattern: str, flags: int = 0) -> int | None:
    rx = re.compile(pattern, flags)
    for i, ln in enumerate(text.splitlines(), 1):
        if rx.search(ln):
            return i
    return None


def _clip(s: object, n: int = TEXT_MAX) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


# ================================================================ facts and nodes of the figure
# Tone decides which facts survive the per-node limit: what weakens a control first, plain notes last.
_TONE_ORDER = {"weak": 0, "decision": 1, "neutral": 2, "note": 3}


def _fact(text: str, tone: str, file: str | None = None, line: int | None = None) -> dict:
    """One short statement about a node; ``source`` points at the line that caused it, when known.

    Pass text and tone as literals (or an inline ``a if c else b``) at every call: a test in
    tests/test_iac_resource_checks.py reads each ``weak`` fact from this source and requires a matching
    config finding, so a fact hidden behind a variable fails that test.
    """
    out = {"text": _clip(text), "tone": tone}
    if file and line:
        out["source"] = {"file": file, "line": int(line)}
    return out


def _facts(items: list[dict], limit: int = MAX_FACTS) -> list[dict]:
    """The most important facts first, cut to the limit. The sort is stable, so equal tones keep their order."""
    return sorted(items, key=lambda f: _TONE_ORDER[f["tone"]])[:limit]


def _node(kind: str, title: str, facts=(), children=(), **extra) -> dict:
    """A box of the figure. Extra attributes (image, role, layout, note) are set only when they have a value."""
    node = {
        "kind": kind,
        "title": _clip(title, NAME_MAX) or kind,
        "facts": _facts(list(facts)),
        "children": list(children)[:MAX_CHILDREN],
    }
    for k, v in extra.items():
        if v:
            node[k] = _clip(v, IMAGE_MAX) if isinstance(v, str) else v
    return node


def _floating_image_facts(image: str, file: str | None = None, line: int | None = None) -> list[dict]:
    """A fact for an image without a fixed version (``latest`` or no tag); nothing for a pinned or empty one."""
    if image and image_pin(image) == "floating":
        return [_fact(f"{image.split('/')[-1]} floats", "decision", file, line)]
    return []


# ================================================================ image references
def image_pin(image: str) -> str:
    """digest, version (an exact version tag), tag (a moving major/minor tag) or floating (latest / no tag)."""
    if "@sha256:" in image:
        return "digest"
    last = image.split("/")[-1]
    if ":" not in last:
        return "floating"
    tag = last.split(":", 1)[1]
    if tag in ("latest", "stable", "main", "master", "edge", "lts"):
        return "floating"
    if re.fullmatch(r"v?\d+\.\d+\.\d+([.-][\w.]+)?", tag):
        return "version"
    return "tag"


@cache
def _vocab() -> dict:
    return yaml.safe_load(VOCAB_PATH.read_text(encoding="utf-8")) or {}


def runtime_label(images: list[str]) -> str:
    """Label and version of the first image a vocabulary runtime pattern matches; "" without one."""
    for image in images:
        name = image.split("/")[-1].lower()
        for rule in _vocab().get("runtimes") or []:
            m = re.search(rule["pattern"], name)
            if m:
                version = next((g for g in m.groups()[::-1] if g and re.fullmatch(r"\d+(\.\d+)?", g)), "")
                return f"{rule['label']} {version}".strip()
    return ""


# ================================================================ Dockerfile
# One Dockerfile describes the runtime image: the root one if present, else the first one found near the root.
# The section also reports secrets a `COPY .` would bake into the image.
_DOCKERFILE_RE = re.compile(r"^(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$|^[\w.-]+\.Dockerfile$")


def _dockerfile(root: Path) -> Path | None:
    """Dockerfile or Containerfile at the root, else a variant (Dockerfile.base), else the first one two levels down."""
    for name in ("Dockerfile", "Containerfile"):
        if (root / name).is_file() and not (root / name).is_symlink():
            return root / name
    variants = sorted(p for p in root.iterdir() if _DOCKERFILE_RE.match(p.name) and p.is_file() and not p.is_symlink())
    if variants:
        return variants[0]
    found = _walk(root, lambda p: bool(_DOCKERFILE_RE.match(p.name)), max_depth=2, max_files=1)
    return found[0] if found else None


def scan_runtime(root: Path) -> dict | None:
    """Base image, build stages, USER, EXPOSE and command of the Dockerfile; ``None`` without a parsable FROM.

    ``copies_repository`` lists sensitive root entries a ``COPY .`` sends into the image past .dockerignore;
    it is set only when the Dockerfile sits at the root.
    """
    df = _dockerfile(root)
    text = _read(df, root)
    if not text:
        return None
    lines = text.splitlines()
    # Each FROM starts a stage; the last one is the image that runs. A FROM with a build argument
    # ($BASE) names no image we can judge, so it is skipped.
    stages = []
    for i, ln in enumerate(lines, 1):
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
        if m and "$" not in m.group(1):
            stages.append({"image": _clip(m.group(1), IMAGE_MAX), "pin": image_pin(m.group(1)), "line": i})
    if not stages:
        return None
    users = [(i, m.group(1)) for i, ln in enumerate(lines, 1) if (m := re.match(r"\s*USER\s+(\S+)", ln, re.I))]
    expose = [p for ln in re.findall(r"^\s*EXPOSE\s+(.+)$", text, re.M | re.I) for p in ln.split()][:16]
    return {
        "dockerfile": _rel(df, root),
        "base": stages[-1],
        "build_stages": stages[:-1][:8],
        "user": {"value": _clip(users[-1][1], 64), "line": users[-1][0]} if users else None,
        "expose": [_clip(p, 32) for p in expose],
        "command": _clip(_start_command(text), NAME_MAX),
        "copies_repository": _copied_sensitive_entries(df, text, root),
        "runtime_label": runtime_label([s["image"] for s in stages[::-1]]),
    }


def _start_command(text: str) -> str:
    """The program the last CMD or ENTRYPOINT starts: the first word that looks like a path or file name."""
    cmd = (re.findall(r"^\s*(?:CMD|ENTRYPOINT)\s+(.+)$", text, re.M | re.I) or [""])[-1]
    words = re.sub(r'[\[\]"]', " ", cmd).split()
    return next((Path(w).name for w in words if "/" in w or "." in w), words[0] if words else "")


def _copied_sensitive_entries(df: Path, text: str, root: Path) -> dict | None:
    """Sensitive root entries a ``COPY .`` / ``ADD .`` puts into the image because .dockerignore does not exclude
    them. Only for a Dockerfile at the root, where ``.`` is the repository root."""
    copy_line = _line_of(text, r"^\s*(COPY|ADD)\s+(--\S+\s+)*\.\s")
    if not copy_line or df.parent.resolve() != root:
        return None
    rules = _dockerignore_rules(_read(root / ".dockerignore", root))
    sensitive = sorted(
        p.name + ("/" if p.is_dir() else "")
        for p in root.iterdir()
        if _sensitive(p.name) and not _ignored(p.name, rules) and not p.is_symlink()
    )[:16]
    return {"line": copy_line, "sensitive": [_clip(s, NAME_MAX) for s in sensitive]}


def _sensitive(name: str) -> bool:
    low = name.lower()
    if low.endswith(TEMPLATE_SUFFIXES):
        return False
    if low.endswith(SENSITIVE_SUFFIXES) or low == ".env" or low.startswith(".env."):
        return True
    return any(w in SENSITIVE_WORDS or w.endswith(SENSITIVE_WORD_ENDINGS) for w in re.split(r"[^a-z0-9]+", low))


def _dockerignore_rules(text: str) -> list[tuple[bool, str]]:
    """(negated, pattern) per line, in order; patterns are relative to the build context."""
    rules = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        neg = ln.startswith("!")
        pat = ln[1:].strip() if neg else ln
        pat = re.sub(r"^(\./|/)+", "", pat).rstrip("/")
        if pat:
            rules.append((neg, pat))
    return rules


def _ignored(name: str, rules: list[tuple[bool, str]]) -> bool:
    """Whether a top-level entry is excluded from the build context; the last matching rule wins."""
    ignored = False
    for neg, pat in rules:
        cands = {pat, pat.removesuffix("/**")} | ({pat[3:]} if pat.startswith("**/") else set())
        if any(fnmatch.fnmatchcase(name, c) for c in cands):
            ignored = not neg
    return ignored


# ================================================================ docker compose
# Only the file `docker compose up` uses without -f, and only at the repository root: override and variant files
# are listed by name but not drawn, because which one is used is chosen at deploy time.


def _network_mode(spec) -> str:
    return _clip((spec.get("network_mode") if isinstance(spec, dict) else None) or "", 64)


_COMPOSE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
# A service whose name or image says it forwards traffic is drawn as the entry point of the compose host.
_PROXY_RE = re.compile(r"nginx|traefik|envoy|haproxy|caddy|gateway|proxy|ingress|facade", re.I)


def scan_compose(root: Path) -> tuple[dict | None, dict | None]:
    """The compose file docker compose resolves without -f (root only): services, and an environment tree."""
    primary, variants = primary_compose_file(root)
    if primary is None or primary.parent.resolve() != root or primary.name not in _COMPOSE_NAMES:
        return None, None
    rel = _rel(primary, root)
    services = parse_compose_file(primary, root)
    if not services:
        return None, None
    # parse_compose_file does not keep network_mode or the top-level networks, so read those from the YAML.
    try:
        data = load_yaml_bounded(_read(primary, root)) or {}
    except yaml.YAMLError:
        data = {}
    specs = data.get("services") if isinstance(data, dict) and isinstance(data.get("services"), dict) else {}
    declared = data.get("networks") if isinstance(data, dict) and isinstance(data.get("networks"), dict) else {}
    record = {
        "file": rel,
        "variants": [_rel(v, root) for v in variants][:16],
        "networks": [n for n in (_clip(n, NAME_MAX) for n in declared) if n][:64],
        "services": [_compose_service_record(s, specs.get(s.name)) for s in services][:64],
    }
    nodes = [_compose_service_node(s, rel) for s in services[:MAX_CHILDREN]]
    entry = _compose_entry(nodes, services)
    if entry is not None:
        entry["role"] = "entry"
    nodes.sort(key=lambda n: n.get("role") != "entry")
    tree = _node("cluster", "docker compose host", [], nodes, layout="row", note=rel)
    return record, {"platform": "compose", "label": f"docker compose ({rel})", "source": rel, "tree": tree}


def _compose_service_record(s, spec) -> dict:
    """A service as listed under ``compose.services``; the topology reads its networks from here."""
    return {
        "name": _clip(s.name, NAME_MAX),
        "line": s.line,
        "end_line": s.end_line,
        "image": _clip(s.image, IMAGE_MAX),
        "builds": s.builds,
        "ports": [
            {"host": _clip(p.host, 32), "container": _clip(p.container, 32), "host_ip": _clip(p.host_ip, 64)}
            for p in s.ports
        ][:32],
        "networks": [n for n in (_clip(n, NAME_MAX) for n in s.networks) if n][:16],
        "network_mode": _network_mode(spec),
    }


def _compose_service_node(s, rel: str) -> dict:
    """A service as a box of the figure; a service built from this repository is the workload."""
    facts = []
    open_ports = [p for p in s.ports if p.host and not p.loopback_only]
    if open_ports:
        ports = ", ".join(f":{p.host}" for p in open_ports[:3])
        facts.append(_fact(f"host port {ports} on every interface", "decision", rel, s.line))
    if s.privileged:
        facts.append(_fact("privileged container", "weak", rel, s.line))
    if any("docker.sock" in v for v in s.volumes):
        facts.append(_fact("Docker socket mounted", "weak", rel, s.line))
    facts += _floating_image_facts(s.image, rel, s.line)
    kind = "workload" if s.builds else "service"
    return _node(kind, s.name, facts, image=s.image or ("built from this repository" if s.builds else ""))


def _compose_entry(nodes: list[dict], services) -> dict | None:
    """The node traffic enters through: a proxy published on every interface, else the first service with ports."""
    publicly_published_proxy = next(
        (
            n
            for n, s in zip(nodes, services)
            if any(p.host and not p.loopback_only for p in s.ports) and _PROXY_RE.search(s.name + s.image)
        ),
        None,
    )
    return publicly_published_proxy or next((n for n, s in zip(nodes, services) if s.ports), None)


# ================================================================ Kubernetes and OpenShift manifests
# Plain manifests only: Helm templates and values files are read in the next section. Every document is checked
# for the shape the readers below expect (_k8s_shape_ok), so one malformed document is skipped instead of
# aborting the scan. Each namespace with workloads becomes one environment of the figure.


def _k8s_docs(root: Path) -> list[tuple[str, dict, int]]:
    """(file, document, line of its ``kind:``) for every well-formed document of a kind in K8S_KINDS."""
    out = []
    files = _walk(
        root,
        lambda p: p.suffix in (".yaml", ".yml")
        and "templates" not in p.parts
        and not p.name.startswith(("values", "Chart", "docker-compose", "compose"))
        and ".github" not in p.parts
        and ".gitlab" not in p.parts,
    )
    for p in files:
        text = _read(p, root)
        if "apiVersion" not in text or "kind" not in text:
            continue
        try:
            docs = load_yaml_bounded(text, all_documents=True)
        except yaml.YAMLError:
            continue
        rel = _rel(p, root)
        # The YAML loader gives no line numbers. The n-th top-level `kind:` line belongs to the n-th document
        # that has a kind, so count those documents to find each one's line.
        kind_lines = [i + 1 for i, ln in enumerate(text.splitlines()) if re.match(r"^kind:\s*", ln)]
        k = 0
        for d in docs[:64]:
            if isinstance(d, dict) and _k8s_shape_ok(d) and d["kind"] in K8S_KINDS:
                line = kind_lines[k] if k < len(kind_lines) else 1
                out.append((rel, d, line))
            if isinstance(d, dict) and d.get("kind"):
                k += 1
    return out


_K8S_DICTS = (
    ("metadata",),
    ("metadata", "labels"),
    ("spec",),
    ("spec", "template"),
    ("spec", "template", "metadata"),
    ("spec", "template", "metadata", "labels"),
    ("spec", "template", "spec"),
    ("spec", "selector"),
    ("spec", "to"),
)
_K8S_LISTS = (("spec", "ports"), ("spec", "rules"), ("spec", "template", "spec", "containers"))


def _at(d, path: tuple[str, ...]):
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _k8s_shape_ok(d: dict) -> bool:
    """The fields the readers below walk have the type they expect; a document that does not is skipped alone."""
    if not isinstance(d.get("kind"), str) or not isinstance(d.get("metadata"), dict):
        return False
    if any(_at(d, p) is not None and not isinstance(_at(d, p), dict) for p in _K8S_DICTS):
        return False
    if any(_at(d, p) is not None and not isinstance(_at(d, p), list) for p in _K8S_LISTS):
        return False
    # Ingress rules nest further: rules[].http.paths[].backend.service must be mappings where present.
    for rule in _at(d, ("spec", "rules")) or []:
        http = rule.get("http") if isinstance(rule, dict) else None
        if (rule is not None and not isinstance(rule, dict)) or (http is not None and not isinstance(http, dict)):
            return False
        for path in (http or {}).get("paths") or []:
            backend = path.get("backend") if isinstance(path, dict) else None
            if (path is not None and not isinstance(path, dict)) or (
                backend is not None and not isinstance(backend, dict)
            ):
                return False
            if backend and backend.get("service") is not None and not isinstance(backend["service"], dict):
                return False
    return True


def _pod_facts(spec: dict, rel: str, line: int) -> list[dict]:
    """Hardening gaps of a pod spec. Container securityContext overrides the pod's; each fact appears once."""
    containers = [c for c in (spec.get("containers") or []) if isinstance(c, dict)]
    pod_sc = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
    facts = []
    for c in containers[:4]:
        sc = {**pod_sc, **(c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {})}
        if sc.get("privileged") is True:
            facts.append(_fact("privileged container", "weak", rel, line))
        if sc.get("runAsNonRoot") is not True and not sc.get("runAsUser"):
            facts.append(_fact("runAsNonRoot not set", "decision", rel, line))
        if sc.get("allowPrivilegeEscalation") is not False:
            facts.append(_fact("privilege escalation not blocked", "decision", rel, line))
        if sc.get("readOnlyRootFilesystem") is not True:
            facts.append(_fact("writable root file system", "decision", rel, line))
    if spec.get("hostNetwork") is True:
        facts.append(_fact("host network", "weak", rel, line))
    uniq = {f["text"]: f for f in facts}
    return list(uniq.values())


def scan_manifests(root: Path) -> list[dict]:
    """One Kubernetes or OpenShift environment per namespace with workloads, at most two namespaces.

    The first of up to six workloads is drawn as entry → Service → workload; the others share a row below it.
    """
    docs = _k8s_docs(root)
    if not any(d.get("kind") in _K8S_WORKLOAD_KINDS for _, d, _ in docs):
        return []
    platform = _k8s_platform(docs)
    namespaces = sorted({_namespace(d) for _, d, _ in docs if d.get("kind") != "Namespace"})
    envs = []
    for ns in namespaces[:2]:
        in_ns = [(r, d, ln) for r, d, ln in docs if _namespace(d) == ns]
        workloads = [(r, d, ln) for r, d, ln in in_ns if d.get("kind") in _K8S_WORKLOAD_KINDS]
        if not workloads:
            continue
        services = [(r, d, ln) for r, d, ln in in_ns if d.get("kind") == "Service"]
        routes = [(r, d, ln) for r, d, ln in in_ns if d.get("kind") in ("Route", "Ingress")]
        chains = [_workload_chain(r, w, ln, services, routes) for r, w, ln in workloads[:6]]
        # stack the first chain (entry → service → workload); further workloads join in one row underneath
        first = chains[0]
        if len(first) > 1:
            first[0]["role"] = "entry"
        children = list(first)
        if len(chains) > 1:
            children.append(_node("network", "further workloads", [], [c[-1] for c in chains[1:]], layout="row"))
        ns_facts = []
        if not any(d.get("kind") == "NetworkPolicy" for _, d, _ in in_ns):
            ns_facts.append(
                _fact("no NetworkPolicy in these manifests: any pod in the cluster can reach these pods", "decision")
            )
        src = in_ns[0][0]
        label = f"{'OpenShift' if platform == 'openshift' else 'Kubernetes'} · namespace {ns}"
        envs.append(
            {
                "platform": platform,
                "label": label,
                "source": src,
                "tree": _node("cluster", label, ns_facts, children, note=src),
            }
        )
    return envs


def _k8s_platform(docs: list[tuple[str, dict, int]]) -> str:
    """OpenShift as soon as one document uses an openshift.io API group, else Kubernetes."""
    return "openshift" if any("openshift.io" in str(d.get("apiVersion")) for _, d, _ in docs) else "kubernetes"


def _namespace(d: dict) -> str:
    """The document's namespace; a manifest without one is applied to ``default``."""
    return str(d["metadata"].get("namespace") or "default")


def _workload_chain(rel: str, w: dict, line: int, services: list, routes: list) -> list[dict]:
    """The nodes traffic passes to reach one workload, outermost first: [route,] [service,] workload.

    A Service belongs to the workload when its selector matches the pod labels; a Route or Ingress belongs to
    that Service when it forwards to it by name.
    """
    spec = ((w.get("spec") or {}).get("template") or {}).get("spec") or {}
    labels = (((w.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
    chain = [_workload_node(rel, w, line, spec)]
    svc = next(
        (
            (sr, s, sl)
            for sr, s, sl in services
            if isinstance((s.get("spec") or {}).get("selector"), dict)
            and labels
            and all(labels.get(k) == v for k, v in s["spec"]["selector"].items())
        ),
        None,
    )
    if svc:
        chain.insert(0, _service_node(*svc))
        name = svc[1]["metadata"].get("name")
        route = next(((rr, rt, rl) for rr, rt, rl in routes if _routes_to(rt, name)), None)
        if route:
            chain.insert(0, _route_node(*route))
    return chain


def _workload_node(rel: str, w: dict, line: int, spec: dict) -> dict:
    """A Deployment, StatefulSet, DaemonSet or DeploymentConfig with its first image and hardening gaps.

    Only the names of Secrets loaded via ``envFrom`` are shown, never their values.
    """
    containers = spec.get("containers") or []
    image = next((str(c.get("image")) for c in containers if isinstance(c, dict) and c.get("image")), "")
    replicas = (w.get("spec") or {}).get("replicas", 1)
    secrets = sorted(
        {
            str(e["secretRef"].get("name"))
            for c in containers
            if isinstance(c, dict)
            for e in c.get("envFrom") or []
            if isinstance(e, dict) and isinstance(e.get("secretRef"), dict)
        }
    )
    facts = _pod_facts(spec, rel, line) + _floating_image_facts(image, rel, line)
    if secrets:
        facts.append(_fact("environment from Secret " + ", ".join(secrets[:2]), "note", rel, line))
    title = f"{w['kind']} {w['metadata'].get('name', '')} · {replicas} replica{'s' if replicas != 1 else ''}"
    return _node("workload", title, facts, image=image)


def _service_node(rel: str, s: dict, line: int) -> dict:
    """A Service with its type and first port; NodePort and LoadBalancer reach outside the cluster."""
    spec = s.get("spec") or {}
    typ = spec.get("type", "ClusterIP")
    first_port = (spec.get("ports") or [{}])[0]
    port = first_port if isinstance(first_port, dict) else {}
    fact = _fact(
        f"{typ} :{port.get('port', '?')} → {port.get('targetPort', port.get('port', '?'))}",
        "decision" if typ in ("NodePort", "LoadBalancer") else "neutral",
        rel,
        line,
    )
    return _node("service", f"Service {s['metadata'].get('name', '')}", [fact])


def _routes_to(route: dict, service: str | None) -> bool:
    """Whether an OpenShift Route or an Ingress (current or pre-1.19 backend syntax) forwards to the Service."""
    spec = route.get("spec") or {}
    if route.get("kind") == "Route":
        return (spec.get("to") or {}).get("name") == service
    for rule in spec.get("rules") or []:
        for p in ((rule or {}).get("http") or {}).get("paths") or []:
            backend = (p or {}).get("backend") or {}
            if (backend.get("service") or {}).get("name") == service or backend.get("serviceName") == service:
                return True
    return False


def _route_node(rel: str, route: dict, line: int) -> dict:
    """The entry box of a chain: an OpenShift Route or an Ingress, with whether it terminates TLS."""
    spec = route.get("spec") or {}
    if route.get("kind") == "Route":
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
        facts = []
        if not tls.get("termination"):
            facts.append(_fact("no TLS", "weak", rel, line))
        else:
            facts.append(_fact(f"TLS {tls['termination']} termination at the router", "neutral", rel, line))
            if tls.get("insecureEdgeTerminationPolicy") == "Allow":
                facts.append(
                    _fact("plain HTTP also accepted (insecureEdgeTerminationPolicy: Allow)", "weak", rel, line)
                )
        return _node("service", f"Route {spec.get('host', route['metadata'].get('name', ''))}", facts)
    tls = spec.get("tls")
    host = next((r.get("host") for r in spec.get("rules") or [] if isinstance(r, dict) and r.get("host")), "")
    return _node(
        "service",
        f"Ingress {host or route['metadata'].get('name', '')}",
        [_fact("TLS configured" if tls else "no TLS", "neutral" if tls else "weak", rel, line)],
    )


# ================================================================ Helm values and GitLab Auto Deploy
# Templates are not rendered. The figure is built from the values file alone, using the keys of Helm's default
# chart scaffold (service, ingress, image, securityContext); what a chart sets elsewhere stays unknown.


def _values_env(values: dict, rel: str, text: str, label: str, platform: str, note: str, app_version: str = "") -> dict:
    """An environment of Ingress → Service → Pod from one values file."""
    svc = values.get("service") if isinstance(values.get("service"), dict) else {}
    ing = values.get("ingress") if isinstance(values.get("ingress"), dict) else {}
    img = values.get("image") if isinstance(values.get("image"), dict) else {}
    children = []
    if ing:
        facts = [
            _fact(
                "ingress enabled" if ing.get("enabled") else "no ingress", "neutral", rel, _line_of(text, r"^ingress:")
            )
        ]
        if ing.get("enabled") and not ing.get("tls"):
            facts.append(_fact("no TLS on the ingress", "weak", rel, _line_of(text, r"^ingress:")))
        children.append(_node("service", "Ingress", facts))
    port = svc.get("externalPort") or svc.get("port")
    target = svc.get("internalPort") or svc.get("targetPort") or port
    children.append(
        _node(
            "service",
            f"Service :{port}" if port else "Service",
            [
                _fact(
                    f"{svc.get('type', 'ClusterIP')} :{port} → {target}" if port else "service from chart defaults",
                    "neutral",
                    rel,
                    _line_of(text, r"(externalPort|port):"),
                )
            ],
            note=None if ing else "ingress and TLS from chart defaults",
        )
    )
    # Helm's chart scaffold falls back to the chart's appVersion when the tag is unset or empty; without one the
    # tag is chosen at deploy time, which is unknown here, not floating.
    tag = str(img.get("tag") or "").strip() or app_version
    repo = str(img.get("repository") or "").strip() if img.get("repository") else ""
    image = f"{repo}:{tag}" if repo and tag else ""
    facts = []
    sc = values.get("securityContext") if isinstance(values.get("securityContext"), dict) else None
    if sc is not None and sc.get("privileged") is True:
        facts.append(_fact("privileged container", "weak", rel, _line_of(text, r"securityContext:")))
    facts += _floating_image_facts(image, rel, _line_of(text, r"^image:"))
    children.append(
        _node("workload", "Pod", facts, image=image, note=f"{repo}, tag set at deploy" if repo and not tag else None)
    )
    children[0]["role"] = "entry"
    return {
        "platform": platform,
        "label": label,
        "source": rel,
        "tree": _node("cluster", label, [], children, note=note),
    }


def scan_helm(root: Path) -> list[dict]:
    """One environment per Chart.yaml (at most four), built from the chart's values.yaml."""
    envs = []
    for chart in _walk(root, lambda p: p.name == "Chart.yaml", max_files=4):
        values_path = chart.parent / "values.yaml"
        text = _read(values_path, root)
        try:
            meta = load_yaml_bounded(_read(chart, root)) or {}
            values = load_yaml_bounded(text) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(values, dict) or not isinstance(meta, dict):
            continue
        rel = _rel(values_path, root)
        envs.append(
            _values_env(
                values,
                rel,
                text,
                f"Kubernetes · Helm chart {meta.get('name', chart.parent.name)}",
                "helm",
                rel,
                str(meta.get("appVersion") or "").strip(),
            )
        )
    return envs


def scan_gitlab_auto_deploy(root: Path) -> list[dict]:
    """The GitLab Auto Deploy environment when .gitlab-ci.yml includes Auto-DevOps or its values file exists."""
    ci = _read(root / ".gitlab-ci.yml", root)
    if "Auto-DevOps" not in ci and not (root / ".gitlab" / "auto-deploy-values.yaml").is_file():
        return []
    path = root / ".gitlab" / "auto-deploy-values.yaml"
    text = _read(path, root)
    try:
        values = load_yaml_bounded(text) or {} if text else {}
    except yaml.YAMLError:
        values = {}
    if not isinstance(values, dict):
        values = {}
    rel = _rel(path, root) if text else ".gitlab-ci.yml"
    return [_values_env(values, rel, text, "Kubernetes · GitLab Auto Deploy", "kubernetes", "")]


# ================================================================ Terraform (AWS)
# Steps: group .tf files into root modules (_tf_roots), cut out the resource blocks of each root (_tf_blocks),
# build a node per drawn resource type (_tf_nodes), then place the nodes into VPC → subnet boxes by the subnets
# they reference (_tf_environment). Only AWS resources are drawn. A new resource type needs a builder in
# _TF_NODE_BUILDERS.
#
# iac_resource_checks.py judges some of the same settings for findings; this section only describes the
# deployment for the figure, and the two are not kept in sync automatically.
_TF_LOCAL_MODULE_RE = re.compile(r'^\s*module\s+"[\w-]+"\s*\{[^}]*?\bsource\s*=\s*"(\.\.?/[^"]+)"', re.M | re.S)


def _tf_roots(root: Path) -> dict[Path, list[Path]]:
    """Terraform root directory -> its files plus those of the local modules it calls, transitively.

    Resource addresses are unique only inside one root module, so two roots are separate environments; a
    directory that another one calls through a relative ``source`` is a module of that root, not a root.
    """
    by_dir: dict[Path, list[Path]] = {}
    for p in _walk(root, lambda p: p.suffix == ".tf"):
        by_dir.setdefault(p.parent.resolve(), []).append(p)
    calls: dict[Path, set[Path]] = {d: set() for d in by_dir}
    for d, files in by_dir.items():
        for p in files:
            for src in _TF_LOCAL_MODULE_RE.findall(_read(p, root)):
                target = (d / src).resolve()
                if target in by_dir and target != d:
                    calls[d].add(target)
    called = set().union(*calls.values())
    roots: dict[Path, list[Path]] = {}
    for d in sorted(set(by_dir) - called) or sorted(by_dir):
        seen: set[Path] = set()
        stack = [d]
        while stack:
            x = stack.pop()
            if x not in seen:
                seen.add(x)
                stack.extend(calls[x])
        roots[d] = sorted(p for x in seen for p in by_dir[x])
    return roots


def _tf_blocks(root: Path, files: list[Path]) -> tuple[dict[str, tuple[str, str, int]], str]:
    """resource address -> (body, file, line) within one root. Bounded brace matching; not a full HCL parser."""
    out: dict[str, tuple[str, str, int]] = {}
    region = ""
    for p in files:
        text = _read(p, root)
        rel = _rel(p, root)
        region = (
            region or (re.search(r'provider\s+"aws"\s*\{[^}]*?region\s*=\s*"([\w-]+)"', text, re.S) or [None, ""])[1]
        )
        for m in re.finditer(r'^resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', text, re.M):
            i, depth, limit = m.end(), 1, min(len(text), m.end() + 64 * 1024)
            while depth and i < limit:
                depth += {"{": 1, "}": -1}.get(text[i], 0)
                i += 1
            if len(out) < 400:
                out[f"{m.group(1)}.{m.group(2)}"] = (text[m.end() : i - 1], rel, text.count("\n", 0, m.start()) + 1)
    return out, region


def _attr(body: str, key: str) -> str:
    """The value of a top-level ``key = value`` line in a block body, without quotes; "" when absent."""
    m = re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M)
    return m.group(1).strip() if m else ""


class _TfResource(NamedTuple):
    address: str  # "aws_lb.web"
    rtype: str  # "aws_lb"
    name: str  # "web"
    body: str
    file: str
    line: int


class _TfRoot:
    """The resource blocks of one Terraform root, looked up by address and type.

    Resources link to each other only by reference text such as ``aws_lb.web.arn``; this reader does not
    evaluate HCL, so "refers to" means the address followed by a dot occurs in the other block's body.
    """

    def __init__(self, res: dict[str, tuple[str, str, int]]):
        self.bodies = {k: v[0] for k, v in res.items()}
        self.src = {k: (v[1], v[2]) for k, v in res.items()}

    def resources(self):
        for address, body in self.bodies.items():
            rtype, name = address.split(".", 1)
            yield _TfResource(address, rtype, name, body, *self.src[address])

    def of_type(self, rtype: str) -> list[str]:
        return [k for k in self.bodies if k.split(".", 1)[0] == rtype]

    def referring(self, rtype: str, address: str) -> list[str]:
        """Addresses of ``rtype`` resources whose body refers to ``address``."""
        return [k for k in self.of_type(rtype) if f"{address}." in self.bodies[k]]


# One builder per AWS resource type the figure draws. Each returns a node with at most a few rule-chosen facts;
# a fact about something missing says "in this Terraform", because the control may live in another root.


def _tf_load_balancer(tf: _TfRoot, r: _TfResource) -> dict:
    internal = _attr(r.body, "internal") == "true"
    listeners = [tf.bodies[x] for x in tf.referring("aws_lb_listener", r.address)]
    protos = sorted({(_attr(b, "protocol"), _attr(b, "port")) for b in listeners})
    sgs = [tf.bodies.get(f"aws_security_group.{s}", "") for s in re.findall(r"aws_security_group\.([\w-]+)", r.body)]
    world = any("0.0.0.0/0" in sg for sg in sgs)
    tls = any(p == "HTTPS" for p, _ in protos)
    facts = []
    for proto, port in protos:
        if proto == "HTTP" and not tls:
            facts.append(_fact(f"HTTP :{port}{' from 0.0.0.0/0' if world else ''} — no TLS", "weak", r.file, r.line))
        elif proto == "HTTPS":
            facts.append(_fact(f"HTTPS :{port}", "neutral", r.file, r.line))
    if not internal and not tf.referring("aws_wafv2_web_acl_association", r.address):
        facts.append(_fact("no WAF in this Terraform", "decision", r.file, r.line))
    title = "Load balancer" + (" (internal)" if internal else "")
    return _node("managed", title, facts, role=None if internal else "entry")


def _tf_nat_gateway(tf: _TfRoot, r: _TfResource) -> dict:
    facts = [_fact("outbound traffic of the private subnets", "note", r.file, r.line)]
    return _node("managed", "NAT gateway", facts, role="egress")


def _tf_ecs_service(tf: _TfRoot, r: _TfResource) -> dict:
    """An ECS service, judged together with its task definition and the IAM role policies of that task."""
    facts = []
    if re.search(r"assign_public_ip\s*=\s*true", r.body):
        facts.append(_fact("public IP on the tasks", "weak", r.file, r.line))
    td_names = re.findall(r"aws_ecs_task_definition\.([\w-]+)", r.body)
    td_address = f"aws_ecs_task_definition.{td_names[0]}" if td_names else ""
    td = tf.bodies.get(td_address, "")
    roles = re.findall(r"aws_iam_role\.([\w-]+)", td)
    for pol in tf.of_type("aws_iam_role_policy"):
        if any(f"aws_iam_role.{role}." in tf.bodies[pol] for role in roles):
            act = re.search(r'Action\s*=\s*"([\w-]+:\*|\*)"', tf.bodies[pol])
            if act and re.search(r'Resource\s*=\s*"\*"', tf.bodies[pol]):
                facts.append(_fact(f"task role may use {act.group(1)} on every resource", "weak", *tf.src[pol]))
    if re.search(r"readonlyRootFilesystem\s*=\s*false", td):
        facts.append(_fact("writable root file system", "decision", *tf.src.get(td_address, (r.file, r.line))))
    launch = _attr(r.body, "launch_type") or "EC2"
    count = _attr(r.body, "desired_count") or "1"
    title = f"ECS {'Fargate' if launch == 'FARGATE' else launch} · {count} task{'s' if count != '1' else ''}"
    return _node("workload", title, facts, image=_ecs_image(tf, td))


def _ecs_image(tf: _TfRoot, task_definition: str) -> str:
    """The task's image, with an ECR repository reference shown as ``ECR <name>`` and other interpolations as …"""
    image = (re.search(r'image\s*=\s*"([^"]+)"', task_definition) or [None, ""])[1]
    ecr = re.search(r"\$\{aws_ecr_repository\.([\w-]+)\.repository_url\}", image)
    if ecr:
        repo_name = _attr(tf.bodies.get(f"aws_ecr_repository.{ecr.group(1)}", ""), "name") or ecr.group(1)
        image = image.replace(ecr.group(0), f"ECR {repo_name}")
    return re.sub(r"\$\{[^}]*\}", "…", image)


def _tf_lambda(tf: _TfRoot, r: _TfResource) -> dict:
    facts = [_fact(_attr(r.body, "runtime") or "runtime not set", "note", r.file, r.line)]
    return _node("managed", f"Lambda {_attr(r.body, 'function_name') or r.name}", facts)


def _tf_ec2_instance(tf: _TfRoot, r: _TfResource) -> dict:
    facts = []
    if re.search(r"associate_public_ip_address\s*=\s*true", r.body):
        facts.append(_fact("public IP", "weak", r.file, r.line))
    if not re.search(r'http_tokens\s*=\s*"required"', r.body):
        facts.append(_fact("IMDSv1 allowed", "decision", r.file, r.line))
    return _node("managed", f"EC2 {_attr(r.body, 'instance_type')}".strip(), facts)


def _tf_rds_instance(tf: _TfRoot, r: _TfResource) -> dict:
    facts = []
    if re.search(r"publicly_accessible\s*=\s*true", r.body):
        facts.append(_fact("publicly accessible", "weak", r.file, r.line))
    if not re.search(r"storage_encrypted\s*=\s*true", r.body):
        facts.append(_fact("storage not encrypted", "weak", r.file, r.line))
    facts = facts or [_fact("private, encrypted", "neutral", r.file, r.line)]
    return _node("managed", f"RDS {_attr(r.body, 'engine')}".strip(), facts)


def _tf_ecr_repository(tf: _TfRoot, r: _TfResource) -> dict:
    facts = []
    if _attr(r.body, "image_tag_mutability") != "IMMUTABLE":
        facts.append(_fact("mutable tags", "decision", r.file, r.line))
    if not re.search(r"scan_on_push\s*=\s*true", r.body):
        facts.append(_fact("no scan on push", "decision", r.file, r.line))
    return _node("managed", f"ECR {_attr(r.body, 'name') or r.name}", facts)


def _tf_s3_bucket(tf: _TfRoot, r: _TfResource) -> dict:
    blocked = any(
        re.search(r"block_public_policy\s*=\s*true", tf.bodies[b])
        for b in tf.referring("aws_s3_bucket_public_access_block", r.address)
    )
    if blocked:
        fact = _fact("public access blocked", "neutral", r.file, r.line)
    else:
        fact = _fact("no public access block in this Terraform", "decision", r.file, r.line)
    return _node("managed", f"S3 {_attr(r.body, 'bucket') or r.name}", [fact])


def _tf_secret(tf: _TfRoot, r: _TfResource) -> dict:
    if tf.referring("aws_secretsmanager_secret_rotation", r.address):
        fact = _fact("rotated", "neutral", r.file, r.line)
    else:
        fact = _fact("no rotation in this Terraform", "decision", r.file, r.line)
    return _node("managed", "Secrets Manager", [fact])


def _tf_efs(tf: _TfRoot, r: _TfResource) -> dict:
    encrypted = _attr(r.body, "encrypted") == "true"
    fact = _fact("encrypted" if encrypted else "not encrypted", "neutral" if encrypted else "weak", r.file, r.line)
    return _node("managed", "EFS", [fact])


def _tf_eks_cluster(tf: _TfRoot, r: _TfResource) -> dict:
    # The EKS API endpoint is public unless the configuration turns it off.
    public = not re.search(r"endpoint_public_access\s*=\s*false", r.body)
    if public:
        fact = _fact("public API endpoint", "decision", r.file, r.line)
    else:
        fact = _fact("private API endpoint", "neutral", r.file, r.line)
    return _node("cluster", f"EKS {_attr(r.body, 'name') or r.name}", [fact])


_TF_NODE_BUILDERS = {
    "aws_lb": _tf_load_balancer,
    "aws_nat_gateway": _tf_nat_gateway,
    "aws_ecs_service": _tf_ecs_service,
    "aws_lambda_function": _tf_lambda,
    "aws_instance": _tf_ec2_instance,
    "aws_db_instance": _tf_rds_instance,
    "aws_ecr_repository": _tf_ecr_repository,
    "aws_s3_bucket": _tf_s3_bucket,
    "aws_secretsmanager_secret": _tf_secret,
    "aws_efs_file_system": _tf_efs,
    "aws_eks_cluster": _tf_eks_cluster,
}


def _tf_nodes(res: dict) -> dict[str, dict]:
    """address -> figure node for every resource of a drawn type, in file order. Other resources (listeners,
    policies, subnets, ...) only contribute facts to these nodes or decide where they are placed."""
    tf = _TfRoot(res)
    return {r.address: _TF_NODE_BUILDERS[r.rtype](tf, r) for r in tf.resources() if r.rtype in _TF_NODE_BUILDERS}


def scan_terraform(root: Path) -> list[dict]:
    """One AWS environment per Terraform root; the root directory joins the label when there are several."""
    envs = [(d, env) for d, files in _tf_roots(root).items() if (env := _tf_environment(root, files))]
    if len(envs) > 1:
        for d, env in envs:
            where = _rel(d, root) if d != root else "repository root"
            env["label"] = env["tree"]["title"] = _clip(f"{env['label']} · {where}", NAME_MAX)
    return [env for _, env in envs]


def _tf_environment(root: Path, files: list[Path]) -> dict | None:
    """One AWS environment: cloud → VPC → public then private subnets → nodes; nodes that reference no subnet
    (S3, Lambda, ECR, ...) go into a "regional services" row. ``None`` when the root draws nothing."""
    res, region = _tf_blocks(root, files)
    if not any(k.startswith("aws_") for k in res):
        return None
    nodes = _tf_nodes(res)
    if not nodes:
        return None
    bodies = {k: v[0] for k, v in res.items()}
    subnets = [k for k in res if k.startswith("aws_subnet.")]
    public = {s for s in subnets if _attr(bodies[s], "map_public_ip_on_launch") == "true"}
    placed: dict[str, list[dict]] = {s: [] for s in subnets}
    regional: list[dict] = []
    for k, node in nodes.items():
        refs = [f"aws_subnet.{n}" for n in re.findall(r"aws_subnet\.([\w-]+)", bodies[k])]
        target = next((r for r in refs if r in placed), None)
        (placed[target] if target else regional).append(node)
    for kids in placed.values():  # entry first and egress last in a row: their lines leave through borders only
        kids.sort(key=lambda n: (n.get("role") != "entry", n.get("role") == "egress"))
    nets = []
    for s in sorted(subnets, key=lambda s: (s not in public, s)):
        if placed[s]:
            label = ("public subnet " if s in public else "private subnet ") + _attr(bodies[s], "cidr_block")
            nets.append(_node("network", label, [], placed[s], layout="row" if len(placed[s]) > 1 else None))
    vpc = next((k for k in res if k.startswith("aws_vpc.")), None)
    children = [_node("network", f"VPC {_attr(bodies[vpc], 'cidr_block')}".strip(), [], nets)] if vpc and nets else nets
    if regional:
        children.append(
            _node("network", "regional services", [], sorted(regional, key=lambda n: n["title"])[:8], layout="row")
        )
    src = sorted({v[1] for v in res.values()})[0]
    label = f"AWS · {region}" if region else "AWS"
    return {"platform": "aws", "label": label, "source": src, "tree": _node("cloud", label, [], children, note=src)}


# ================================================================ CI systems
# Which CI systems build and deploy the code, and where they publish to. GitHub Actions and GitLab CI get facts
# (action pinning, disabled scanners); other systems are only recognised by their definition file.
# model/build_plane.py lists the same definition files; keep both in step.
_APPLY_RE = re.compile(
    r"\b(kubectl|oc)\s+apply\b|\bhelm\s+(upgrade|install)\b|\bkustomize\s+build\b|\bargocd\s+app\b|\bterraform\s+apply\b"
)
_REGISTRY_PATTERNS = (
    (r"amazon-ecr-login|\.dkr\.ecr\.", "Amazon ECR"),
    (r"ghcr\.io", "GitHub Container Registry"),
    (r"quay\.io", "Quay"),
    (r"gcr\.io|docker\.pkg\.dev", "Google Artifact Registry"),
    (r"azurecr\.io", "Azure Container Registry"),
)
# CI systems recognised only by their definition file, in the order they are listed.
_OTHER_CI_FILES = (
    ("Jenkinsfile", "Jenkins"),
    (".circleci/config.yml", "CircleCI"),
    ("azure-pipelines.yml", "Azure Pipelines"),
    ("bitbucket-pipelines.yml", "Bitbucket Pipelines"),
    (".travis.yml", "Travis CI"),
)


def scan_ci(root: Path) -> list[dict]:
    """CI systems with their facts and what each publishes to (registries, Kubernetes); at most eight."""
    out = [_github_actions(root), _gitlab_ci(root)]
    for rel, system in _OTHER_CI_FILES:
        text = _read(root / rel, root)
        if text:
            publishes = ["container registry"] if re.search(r"docker push|docker\.build|kaniko|buildah", text) else []
            if _APPLY_RE.search(text):
                publishes.append("Kubernetes (kubectl/Helm)")
            out.append({"system": system, "source": rel, "facts": [], "publishes": publishes})
    return [system for system in out if system][:8]


def _github_actions(root: Path) -> dict | None:
    """GitHub Actions: how many third-party actions are pinned to a commit SHA, and where the workflows push."""
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir() or wf_dir.is_symlink():
        return None
    workflows = [p for p in sorted(wf_dir.iterdir()) if p.suffix in (".yml", ".yaml") and not p.is_symlink()]
    texts = {p.name: _read(p, root) for p in workflows[:MAX_FILES]}
    # Local actions (./) and docker:// images are not versioned by a ref, so they are not counted.
    actions = {
        a
        for t in texts.values()
        for a in re.findall(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", t, re.M)
        if "@" in a and not a.startswith(("./", "docker://"))
    }
    names = {a.split("@")[0] for a in actions}
    pinned = {a.split("@")[0] for a in actions if re.search(r"@[0-9a-f]{40}$", a)}
    facts = []
    if names:
        loose = len(names - pinned)
        if loose:
            facts.append(_fact(f"{loose} of {len(names)} actions not SHA-pinned", "decision"))
        else:
            facts.append(_fact(f"all {len(names)} actions SHA-pinned", "neutral"))
    facts.append(_fact(f"{len(texts)} workflows", "note"))
    pushing = "\n".join(t for t in texts.values() if re.search(r"docker/build-push-action|docker push|podman push", t))
    targets = [label for rx, label in _REGISTRY_PATTERNS if re.search(rx, pushing)]
    if pushing and not targets:
        docker_hub = re.search(r"docker/login-action|DOCKERHUB|docker\.io", pushing, re.I)
        targets.append("Docker Hub" if docker_hub else "container registry")
    if any(_APPLY_RE.search(t) for t in texts.values()):
        targets.append("Kubernetes (kubectl/Helm)")
    return {"system": "GitHub Actions", "source": ".github/workflows", "facts": _facts(facts), "publishes": targets[:4]}


def _gitlab_ci(root: Path) -> dict | None:
    """GitLab CI: the Auto DevOps template, security jobs it disables, and where it publishes."""
    gl = _read(root / ".gitlab-ci.yml", root)
    if not gl:
        return None
    src = ".gitlab-ci.yml"
    facts = []
    off = [
        k.replace("_DISABLED", "").lower()
        for k in re.findall(r"^\s*(\w+_DISABLED):\s*['\"]?(?:true|1|yes)", gl, re.M | re.I)
    ]
    if off:
        facts.append(_fact(f"{', '.join(off)} disabled", "decision", src, _line_of(gl, r"_DISABLED")))
    if "Auto-DevOps" in gl:
        facts.append(_fact("Auto DevOps template", "note", src, _line_of(gl, r"Auto-DevOps")))
    if re.search(r"SAST_EXCLUDED_PATHS", gl):
        facts.append(_fact("SAST excludes paths", "decision", src, _line_of(gl, r"SAST_EXCLUDED_PATHS")))
    if "Auto-DevOps" in gl:
        publishes = ["GitLab registry", "Kubernetes (auto deploy)"]
    else:
        publishes = ["container registry"] if re.search(r"docker push|kaniko|buildah", gl) else []
    if _APPLY_RE.search(gl):
        publishes.append("Kubernetes (kubectl/Helm)")
    return {"system": "GitLab CI", "source": src, "facts": _facts(facts), "publishes": publishes}


# ================================================================ dependencies and packages
# Counts how many declared dependencies use version ranges and whether a lockfile pins them, and lists the
# packages data/deployment-technology.yaml gives a role (framework, database, identity, ...) for the figure.
def scan_dependencies(root: Path) -> tuple[dict, list[dict]]:
    """Dependency counts over up to 40 manifests, and per manifest the packages a vocabulary role matches."""
    vocab = _vocab()
    fw_pkgs = {p.lower() for pkgs in (vocab.get("frameworks") or {}).values() for p in pkgs}
    roles = [
        (role, re.compile("|".join(f"(?:{p})" for p in spec.get("patterns") or []), re.I))
        for role, spec in (vocab.get("roles") or {}).items()
    ]
    manifests = [m for m in discover_manifests(root) if not m.is_symlink() and _inside(m, root)][:40]
    declared = ranges = 0
    lockfile = False
    packages = []
    for m in manifests:
        try:
            if m.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        deps = parse_manifest(m, root)
        declared += len(deps)
        ranges += sum(1 for d in deps if d.version and RANGE_RE.search(d.version.strip()))
        lockfile = lockfile or any((m.parent / name).is_file() for name in LOCKFILES)
        entries = []
        for d in deps:
            name = d.package
            role = "framework" if name.lower() in fw_pkgs else next((r for r, rx in roles if rx.fullmatch(name)), None)
            if role:
                entries.append({"name": _clip(name, 200), "version": _clip(d.version or "", 80), "role": role})
        if entries:
            packages.append({"manifest": _rel(m, root), "entries": entries[:200]})
    return {"manifests": len(manifests), "declared": declared, "ranges": ranges, "lockfile": lockfile}, packages


# ================================================================ topology: zones and the workloads in them
# Not drawn in the figure: the architecture analysis context reads which workload sits in which network zone.
# Zone names are kept exactly as declared; mapping them onto a fixed vocabulary would invent boundaries.
MAX_ZONES = 64
MAX_TOPOLOGY_WORKLOADS = 256


def _compose_topology(compose: dict | None) -> tuple[list[dict], list[dict]]:
    """Compose networks as zones. A service without ``networks`` joins ``default``; a ``network_mode`` replaces
    the networks: ``service:<name>`` shares that service's zones, any other mode (``host``, ``none``,
    ``container:…``) places the service in no compose network."""
    if not compose:
        return [], []
    src = compose["file"]
    services = compose["services"]
    declared = {s["name"]: (s.get("networks") or ["default"]) for s in services if not s.get("network_mode")}
    workloads = []
    for s in services:
        mode = s.get("network_mode") or ""
        zones = declared.get(mode.removeprefix("service:"), []) if mode.startswith("service:") else []
        workload = {
            "name": s["name"],
            "platform": "compose",
            "source": src,
            "line": s["line"],
            "zones": list(declared.get(s["name"], zones)),
        }
        if mode:
            workload["network_mode"] = mode
        workloads.append(workload)
    names = dict.fromkeys(list(compose.get("networks") or []) + [z for w in workloads for z in w["zones"]])
    return [{"name": n, "platform": "compose", "source": src} for n in names], workloads


def _k8s_topology(root: Path) -> tuple[list[dict], list[dict]]:
    """Namespaces as zones, with whether these manifests hold a NetworkPolicy for them."""
    docs = _k8s_docs(root)
    found = [(r, d, ln) for r, d, ln in docs if d.get("kind") in _K8S_WORKLOAD_KINDS]
    if not found:
        return [], []
    platform = _k8s_platform(docs)

    def namespace(d: dict) -> str:
        return _clip(_namespace(d), NAME_MAX)

    policies = {namespace(d) for _, d, _ in docs if d.get("kind") == "NetworkPolicy"}
    zones: dict[str, dict] = {}
    for r, d, ln in docs:
        if d.get("kind") == "Namespace" and d["metadata"].get("name"):
            name = _clip(d["metadata"]["name"], NAME_MAX)
            zones.setdefault(name, {"name": name, "platform": platform, "source": r, "line": ln})
    workloads = []
    for r, d, ln in found:
        ns = namespace(d)
        zones.setdefault(ns, {"name": ns, "platform": platform, "source": r})
        workloads.append(
            {
                "name": _clip(d["metadata"].get("name") or d["kind"], NAME_MAX),
                "platform": platform,
                "kind": d["kind"],
                "source": r,
                "line": ln,
                "zones": [ns],
            }
        )
    for z in zones.values():
        z["network_policy"] = z["name"] in policies
    return list(zones.values()), workloads


def build_topology(root: Path, compose: dict | None) -> dict | None:
    """Deployable workloads with the zones they sit in, as the configuration names them; ``None`` without any.

    Zone names stay as declared (compose network, Kubernetes namespace): they are not mapped onto a fixed zone
    vocabulary. A workload in more than one zone is listed under ``zone_bridging``.
    """
    compose_zones, compose_workloads = _compose_topology(compose)
    k8s_zones, k8s_workloads = _k8s_topology(root)
    workloads = (compose_workloads + k8s_workloads)[:MAX_TOPOLOGY_WORKLOADS]
    if not workloads:
        return None
    return {
        "zones": (compose_zones + k8s_zones)[:MAX_ZONES],
        "workloads": workloads,
        "zone_bridging": [{"name": w["name"], "platform": w["platform"]} for w in workloads if len(w["zones"]) > 1],
    }


# ================================================================ assembly
def build_inventory(root: Path) -> dict:
    """The ``.deployment-inventory.json`` document; ``topology`` only when it finds a deployable workload."""
    root = root.resolve()
    compose, compose_env = scan_compose(root)
    environments = scan_terraform(root) + scan_manifests(root) + scan_helm(root) + scan_gitlab_auto_deploy(root)
    if compose_env:
        environments.append(compose_env)
    deps, packages = scan_dependencies(root)
    doc = {
        "schema_version": 1,
        "runtime": scan_runtime(root),
        "environments": environments[:8],
        "compose": compose,
        "ci": scan_ci(root),
        "dependencies": deps,
        "packages": packages[:40],
    }
    topology = build_topology(root, compose)
    if topology:
        doc["topology"] = topology
    return doc


def validation_errors(doc: dict) -> list[str]:
    from jsonschema import Draft202012Validator  # noqa: PLC0415

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in Draft202012Validator(schema).iter_errors(doc)
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo-root", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args(argv)
    if not args.repo_root.is_dir():
        print(f"deployment_inventory: repository root is not a directory: {args.repo_root.name}", file=sys.stderr)
        return 2
    doc = build_inventory(args.repo_root)
    errors = validation_errors(doc)
    if errors:
        print("deployment_inventory: output does not match the schema: " + "; ".join(errors[:5]), file=sys.stderr)
        return 1
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
