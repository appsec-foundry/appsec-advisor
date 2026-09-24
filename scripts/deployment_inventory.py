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

Repository content is untrusted. Discovery is bounded in depth, file count and
size, skips symlinks and anything that resolves outside the root, parses YAML with
``safe_load`` and Terraform with a bounded block reader. No environment value,
secret value or file content is ever written: only names, ports, image
references, line numbers and rule-chosen statements.

Usage: deployment_inventory.py --repo-root <dir> --output <file>
Exit codes: 0 written, 1 invalid output (nothing written), 2 usage error.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from functools import cache
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib_manifest import discover_manifests, parse_manifest  # noqa: E402
from compose_services import load_yaml_bounded, parse_compose_file, primary_compose_file  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
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
K8S_KINDS = {
    "Namespace",
    "Route",
    "Ingress",
    "Service",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "DeploymentConfig",
    "NetworkPolicy",
}
TEXT_MAX = 200


# ================================================================ bounded file access
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


def _fact(text: str, tone: str, file: str | None = None, line: int | None = None) -> dict:
    out = {"text": _clip(text), "tone": tone}
    if file and line:
        out["source"] = {"file": file, "line": int(line)}
    return out


def _facts(items: list[dict], limit: int = 3) -> list[dict]:
    order = {"weak": 0, "decision": 1, "neutral": 2, "note": 3}
    return sorted(items, key=lambda f: order[f["tone"]])[:limit]


def _node(kind: str, title: str, facts=(), children=(), **extra) -> dict:
    node = {
        "kind": kind,
        "title": _clip(title, 120) or kind,
        "facts": _facts(list(facts)),
        "children": list(children)[:24],
    }
    for k, v in extra.items():
        if v:
            node[k] = _clip(v, 240) if isinstance(v, str) else v
    return node


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
    for image in images:
        name = image.split("/")[-1].lower()
        for rule in _vocab().get("runtimes") or []:
            m = re.search(rule["pattern"], name)
            if m:
                version = next((g for g in m.groups()[::-1] if g and re.fullmatch(r"\d+(\.\d+)?", g)), "")
                return f"{rule['label']} {version}".strip()
    return ""


# ================================================================ Dockerfile
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
    df = _dockerfile(root)
    text = _read(df, root)
    if not text:
        return None
    rel = _rel(df, root)
    stages = []
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
        if m and "$" not in m.group(1):
            stages.append({"image": _clip(m.group(1), 240), "pin": image_pin(m.group(1)), "line": i})
    if not stages:
        return None
    users = [
        (i, m.group(1)) for i, ln in enumerate(text.splitlines(), 1) if (m := re.match(r"\s*USER\s+(\S+)", ln, re.I))
    ]
    expose = [p for ln in re.findall(r"^\s*EXPOSE\s+(.+)$", text, re.M | re.I) for p in ln.split()][:16]
    cmd = (re.findall(r"^\s*(?:CMD|ENTRYPOINT)\s+(.+)$", text, re.M | re.I) or [""])[-1]
    cmd = re.sub(r'[\[\]"]', " ", cmd).split()
    command = next((Path(c).name for c in cmd if "/" in c or "." in c), cmd[0] if cmd else "")
    copy_line = _line_of(text, r"^\s*(COPY|ADD)\s+(--\S+\s+)*\.\s")
    copies = None
    if copy_line and df.parent.resolve() == root:
        rules = _dockerignore_rules(_read(root / ".dockerignore", root))
        sensitive = sorted(
            p.name + ("/" if p.is_dir() else "")
            for p in root.iterdir()
            if _sensitive(p.name) and not _ignored(p.name, rules) and not p.is_symlink()
        )[:16]
        copies = {"line": copy_line, "sensitive": [_clip(s, 120) for s in sensitive]}
    return {
        "dockerfile": rel,
        "base": stages[-1],
        "build_stages": stages[:-1][:8],
        "user": {"value": _clip(users[-1][1], 64), "line": users[-1][0]} if users else None,
        "expose": [_clip(p, 32) for p in expose],
        "command": _clip(command, 120),
        "copies_repository": copies,
        "runtime_label": runtime_label([s["image"] for s in stages[::-1]]),
    }


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


def _root_user(user: dict | None) -> bool:
    return user is None or user["value"].split(":")[0] in ("root", "0")


# ================================================================ docker compose
def scan_compose(root: Path) -> tuple[dict | None, dict | None]:
    """The compose file docker compose resolves without -f (root only): services, and an environment tree."""
    primary, variants = primary_compose_file(root)
    if (
        primary is None
        or primary.parent.resolve() != root
        or primary.name not in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
    ):
        return None, None
    rel = _rel(primary, root)
    services = parse_compose_file(primary, root)
    if not services:
        return None, None
    record = {
        "file": rel,
        "variants": [_rel(v, root) for v in variants][:16],
        "services": [
            {
                "name": _clip(s.name, 120),
                "line": s.line,
                "end_line": s.end_line,
                "image": _clip(s.image, 240),
                "builds": s.builds,
                "ports": [
                    {"host": _clip(p.host, 32), "container": _clip(p.container, 32), "host_ip": _clip(p.host_ip, 64)}
                    for p in s.ports
                ][:32],
            }
            for s in services
        ][:64],
    }
    nodes = []
    for s in services[:24]:
        facts = []
        open_ports = [p for p in s.ports if p.host and not p.loopback_only]
        if open_ports:
            facts.append(
                _fact(
                    "host port " + ", ".join(f":{p.host}" for p in open_ports[:3]) + " on every interface",
                    "decision",
                    rel,
                    s.line,
                )
            )
        if s.privileged:
            facts.append(_fact("privileged container", "weak", rel, s.line))
        if any("docker.sock" in v for v in s.volumes):
            facts.append(_fact("Docker socket mounted", "weak", rel, s.line))
        if s.image and image_pin(s.image) == "floating":
            facts.append(_fact(f"{s.image.split('/')[-1]} floats", "decision", rel, s.line))
        kind = "workload" if s.builds else "service"
        nodes.append(_node(kind, s.name, facts, image=s.image or ("built from this repository" if s.builds else "")))
    entry = next(
        (
            n
            for n, s in zip(nodes, services)
            if any(p.host and not p.loopback_only for p in s.ports)
            and re.search(r"nginx|traefik|envoy|haproxy|caddy|gateway|proxy|ingress|facade", s.name + s.image, re.I)
        ),
        None,
    )
    entry = entry or next((n for n, s in zip(nodes, services) if s.ports), None)
    if entry is not None:
        entry["role"] = "entry"
    nodes.sort(key=lambda n: n.get("role") != "entry")
    tree = _node("cluster", "docker compose host", [], nodes, layout="row", note=rel)
    return record, {"platform": "compose", "label": f"docker compose ({rel})", "source": rel, "tree": tree}


# ================================================================ Kubernetes and OpenShift manifests
def _k8s_docs(root: Path) -> list[tuple[str, dict, int]]:
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
        starts = [i + 1 for i, ln in enumerate(text.splitlines()) if re.match(r"^kind:\s*", ln)]
        k = 0
        for d in docs[:64]:
            if isinstance(d, dict) and _k8s_shape_ok(d) and d["kind"] in K8S_KINDS:
                line = starts[k] if k < len(starts) else 1
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
    for rule in _at(d, ("spec", "rules")) or []:
        http = rule.get("http") if isinstance(rule, dict) else None
        if rule is not None and not isinstance(rule, dict) or http is not None and not isinstance(http, dict):
            return False
        for path in (http or {}).get("paths") or []:
            backend = path.get("backend") if isinstance(path, dict) else None
            if path is not None and not isinstance(path, dict) or backend is not None and not isinstance(backend, dict):
                return False
            if backend and backend.get("service") is not None and not isinstance(backend["service"], dict):
                return False
    return True


def _pod_facts(spec: dict, rel: str, line: int) -> list[dict]:
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
    docs = _k8s_docs(root)
    if not any(d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "DeploymentConfig") for _, d, _ in docs):
        return []
    platform = "openshift" if any("openshift.io" in str(d.get("apiVersion")) for _, d, _ in docs) else "kubernetes"
    namespaces = sorted(
        {str(d["metadata"].get("namespace") or "default") for _, d, _ in docs if d.get("kind") != "Namespace"}
    )
    envs = []
    for ns in namespaces[:2]:
        in_ns = [(r, d, ln) for r, d, ln in docs if str(d["metadata"].get("namespace") or "default") == ns]
        workloads = [
            (r, d, ln)
            for r, d, ln in in_ns
            if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "DeploymentConfig")
        ]
        if not workloads:
            continue
        services = [(r, d, ln) for r, d, ln in in_ns if d.get("kind") == "Service"]
        routes = [(r, d, ln) for r, d, ln in in_ns if d.get("kind") in ("Route", "Ingress")]
        chains = []
        for r, w, ln in workloads[:6]:
            spec = ((w.get("spec") or {}).get("template") or {}).get("spec") or {}
            labels = (((w.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
            image = next(
                (str(c.get("image")) for c in spec.get("containers") or [] if isinstance(c, dict) and c.get("image")),
                "",
            )
            replicas = (w.get("spec") or {}).get("replicas", 1)
            secrets = sorted(
                {
                    str(e["secretRef"].get("name"))
                    for c in spec.get("containers") or []
                    if isinstance(c, dict)
                    for e in c.get("envFrom") or []
                    if isinstance(e, dict) and isinstance(e.get("secretRef"), dict)
                }
            )
            facts = _pod_facts(spec, r, ln)
            if image and image_pin(image) == "floating":
                facts.append(_fact(f"{image.split('/')[-1]} floats", "decision", r, ln))
            if secrets:
                facts.append(_fact("environment from Secret " + ", ".join(secrets[:2]), "note", r, ln))
            workload = _node(
                "workload",
                f"{w['kind']} {w['metadata'].get('name', '')} · {replicas} replica{'s' if replicas != 1 else ''}",
                facts,
                image=image,
            )
            chain = [workload]
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
                sr, s, sl = svc
                sspec = s.get("spec") or {}
                typ = sspec.get("type", "ClusterIP")
                port = (sspec.get("ports") or [{}])[0] if isinstance((sspec.get("ports") or [{}])[0], dict) else {}
                chain.insert(
                    0,
                    _node(
                        "service",
                        f"Service {s['metadata'].get('name', '')}",
                        [
                            _fact(
                                f"{typ} :{port.get('port', '?')} → {port.get('targetPort', port.get('port', '?'))}",
                                "decision" if typ in ("NodePort", "LoadBalancer") else "neutral",
                                sr,
                                sl,
                            )
                        ],
                    ),
                )
                route = next(((rr, rt, rl) for rr, rt, rl in routes if _routes_to(rt, s["metadata"].get("name"))), None)
                if route:
                    chain.insert(0, _route_node(*route))
            chains.append(chain)
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


def _routes_to(route: dict, service: str | None) -> bool:
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
def _values_env(values: dict, rel: str, text: str, label: str, platform: str, note: str, app_version: str = "") -> dict:
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
    if image and image_pin(image) == "floating":
        facts.append(_fact(f"{image.split('/')[-1]} floats", "decision", rel, _line_of(text, r"^image:")))
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
def _tf_blocks(root: Path) -> tuple[dict[str, tuple[str, str, int]], str]:
    """resource address -> (body, file, line). Bounded brace matching; not a full HCL parser."""
    out: dict[str, tuple[str, str, int]] = {}
    region = ""
    for p in _walk(root, lambda p: p.suffix == ".tf"):
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
    m = re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M)
    return m.group(1).strip() if m else ""


def _tf_nodes(res: dict) -> dict[str, dict]:
    bodies = {k: v[0] for k, v in res.items()}
    src = {k: (v[1], v[2]) for k, v in res.items()}
    has = lambda t: [k for k in res if k.split(".", 1)[0] == t]  # noqa: E731
    out: dict[str, dict] = {}
    for k, body in bodies.items():
        rtype, name = k.split(".", 1)
        f, ln = src[k]
        facts: list[dict] = []
        if rtype == "aws_lb":
            internal = _attr(body, "internal") == "true"
            listeners = [bodies[x] for x in has("aws_lb_listener") if f"aws_lb.{name}." in bodies[x]]
            protos = sorted({(_attr(b, "protocol"), _attr(b, "port")) for b in listeners})
            sgs = [bodies.get(f"aws_security_group.{s}", "") for s in re.findall(r"aws_security_group\.([\w-]+)", body)]
            world = any("0.0.0.0/0" in sg for sg in sgs)
            tls = any(p == "HTTPS" for p, _ in protos)
            for proto, port in protos:
                if proto == "HTTP" and not tls:
                    facts.append(_fact(f"HTTP :{port}{' from 0.0.0.0/0' if world else ''} — no TLS", "weak", f, ln))
                elif proto == "HTTPS":
                    facts.append(_fact(f"HTTPS :{port}", "neutral", f, ln))
            if not internal and not any(f"aws_lb.{name}." in bodies[w] for w in has("aws_wafv2_web_acl_association")):
                facts.append(_fact("no WAF in this Terraform", "decision", f, ln))
            out[k] = _node(
                "managed",
                "Load balancer" + (" (internal)" if internal else ""),
                facts,
                role=None if internal else "entry",
            )
        elif rtype == "aws_nat_gateway":
            out[k] = _node(
                "managed",
                "NAT gateway",
                [_fact("outbound traffic of the private subnets", "note", f, ln)],
                role="egress",
            )
        elif rtype == "aws_ecs_service":
            if re.search(r"assign_public_ip\s*=\s*true", body):
                facts.append(_fact("public IP on the tasks", "weak", f, ln))
            td_names = re.findall(r"aws_ecs_task_definition\.([\w-]+)", body)
            td = bodies.get(f"aws_ecs_task_definition.{td_names[0]}", "") if td_names else ""
            roles = re.findall(r"aws_iam_role\.([\w-]+)", td)
            for pol in has("aws_iam_role_policy"):
                if any(f"aws_iam_role.{r}." in bodies[pol] for r in roles):
                    act = re.search(r'Action\s*=\s*"([\w-]+:\*|\*)"', bodies[pol])
                    if act and re.search(r'Resource\s*=\s*"\*"', bodies[pol]):
                        facts.append(
                            _fact(
                                f"task role may use {act.group(1)} on every resource", "weak", src[pol][0], src[pol][1]
                            )
                        )
            if re.search(r"readonlyRootFilesystem\s*=\s*false", td):
                facts.append(
                    _fact(
                        "writable root file system",
                        "decision",
                        *src.get(f"aws_ecs_task_definition.{td_names[0]}", (f, ln)),
                    )
                )
            image = (re.search(r'image\s*=\s*"([^"]+)"', td) or [None, ""])[1]
            ecr = re.search(r"\$\{aws_ecr_repository\.([\w-]+)\.repository_url\}", image)
            if ecr:
                repo_name = _attr(bodies.get(f"aws_ecr_repository.{ecr.group(1)}", ""), "name") or ecr.group(1)
                image = image.replace(ecr.group(0), f"ECR {repo_name}")
            image = re.sub(r"\$\{[^}]*\}", "…", image)
            launch = _attr(body, "launch_type") or "EC2"
            count = _attr(body, "desired_count") or "1"
            out[k] = _node(
                "workload",
                f"ECS {'Fargate' if launch == 'FARGATE' else launch} · {count} task{'s' if count != '1' else ''}",
                facts,
                image=image,
            )
        elif rtype == "aws_lambda_function":
            out[k] = _node(
                "managed",
                f"Lambda {_attr(body, 'function_name') or name}",
                [_fact(_attr(body, "runtime") or "runtime not set", "note", f, ln)],
            )
        elif rtype == "aws_instance":
            if re.search(r"associate_public_ip_address\s*=\s*true", body):
                facts.append(_fact("public IP", "weak", f, ln))
            if not re.search(r'http_tokens\s*=\s*"required"', body):
                facts.append(_fact("IMDSv1 allowed", "decision", f, ln))
            out[k] = _node("managed", f"EC2 {_attr(body, 'instance_type')}".strip(), facts)
        elif rtype == "aws_db_instance":
            if re.search(r"publicly_accessible\s*=\s*true", body):
                facts.append(_fact("publicly accessible", "weak", f, ln))
            if not re.search(r"storage_encrypted\s*=\s*true", body):
                facts.append(_fact("storage not encrypted", "weak", f, ln))
            out[k] = _node(
                "managed",
                f"RDS {_attr(body, 'engine')}".strip(),
                facts or [_fact("private, encrypted", "neutral", f, ln)],
            )
        elif rtype == "aws_ecr_repository":
            if _attr(body, "image_tag_mutability") != "IMMUTABLE":
                facts.append(_fact("mutable tags", "decision", f, ln))
            if not re.search(r"scan_on_push\s*=\s*true", body):
                facts.append(_fact("no scan on push", "decision", f, ln))
            out[k] = _node("managed", f"ECR {_attr(body, 'name') or name}", facts)
        elif rtype == "aws_s3_bucket":
            blocked = any(
                f"aws_s3_bucket.{name}." in bodies[b] and re.search(r"block_public_policy\s*=\s*true", bodies[b])
                for b in has("aws_s3_bucket_public_access_block")
            )
            facts.append(
                _fact(
                    "public access blocked" if blocked else "no public access block in this Terraform",
                    "neutral" if blocked else "decision",
                    f,
                    ln,
                )
            )
            out[k] = _node("managed", f"S3 {_attr(body, 'bucket') or name}", facts)
        elif rtype == "aws_secretsmanager_secret":
            rot = any(
                f"aws_secretsmanager_secret.{name}." in bodies[r] for r in has("aws_secretsmanager_secret_rotation")
            )
            out[k] = _node(
                "managed",
                "Secrets Manager",
                [_fact("rotated" if rot else "no rotation in this Terraform", "neutral" if rot else "decision", f, ln)],
            )
        elif rtype == "aws_efs_file_system":
            enc = _attr(body, "encrypted") == "true"
            out[k] = _node(
                "managed", "EFS", [_fact("encrypted" if enc else "not encrypted", "neutral" if enc else "weak", f, ln)]
            )
        elif rtype == "aws_eks_cluster":
            public = not re.search(r"endpoint_public_access\s*=\s*false", body)
            out[k] = _node(
                "cluster",
                f"EKS {_attr(body, 'name') or name}",
                [
                    _fact(
                        "public API endpoint" if public else "private API endpoint",
                        "decision" if public else "neutral",
                        f,
                        ln,
                    )
                ],
            )
    return out


def scan_terraform(root: Path) -> list[dict]:
    res, region = _tf_blocks(root)
    if not any(k.startswith("aws_") for k in res):
        return []
    nodes = _tf_nodes(res)
    if not nodes:
        return []
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
    return [{"platform": "aws", "label": label, "source": src, "tree": _node("cloud", label, [], children, note=src)}]


# ================================================================ CI systems
_APPLY_RE = re.compile(
    r"\b(kubectl|oc)\s+apply\b|\bhelm\s+(upgrade|install)\b|\bkustomize\s+build\b|\bargocd\s+app\b|\bterraform\s+apply\b"
)


def scan_ci(root: Path) -> list[dict]:
    out = []
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir() and not wf_dir.is_symlink():
        workflows = [p for p in sorted(wf_dir.iterdir()) if p.suffix in (".yml", ".yaml") and not p.is_symlink()][
            :MAX_FILES
        ]
        texts = {p.name: _read(p, root) for p in workflows}
        actions = {
            a
            for t in texts.values()
            for a in re.findall(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", t, re.M)
            if "@" in a and not a.startswith(("./", "docker://"))
        }
        names = {a.split("@")[0] for a in actions}
        pinned = {a.split("@")[0] for a in actions if re.search(r"@[0-9a-f]{40}$", a)}
        pushes = [n for n, t in texts.items() if re.search(r"docker/build-push-action|docker push|podman push", t)]
        facts = [_fact(f"{len(workflows)} workflows", "note")]
        applies = [n for n, t in texts.items() if _APPLY_RE.search(t)]
        if names:
            loose = len(names - pinned)
            facts.insert(
                0,
                _fact(
                    f"{loose} of {len(names)} actions not SHA-pinned"
                    if loose
                    else f"all {len(names)} actions SHA-pinned",
                    "decision" if loose else "neutral",
                ),
            )
        targets = []
        joined = "\n".join(texts[n] for n in pushes)
        for rx, label in (
            (r"amazon-ecr-login|\.dkr\.ecr\.", "Amazon ECR"),
            (r"ghcr\.io", "GitHub Container Registry"),
            (r"quay\.io", "Quay"),
            (r"gcr\.io|docker\.pkg\.dev", "Google Artifact Registry"),
            (r"azurecr\.io", "Azure Container Registry"),
        ):
            if re.search(rx, joined):
                targets.append(label)
        if pushes and not targets:
            targets.append(
                "Docker Hub"
                if re.search(r"docker/login-action|DOCKERHUB|docker\.io", joined, re.I)
                else "container registry"
            )
        if applies:
            targets.append("Kubernetes (kubectl/Helm)")
        out.append(
            {
                "system": "GitHub Actions",
                "source": ".github/workflows",
                "facts": _facts(facts),
                "publishes": targets[:4],
            }
        )
    gl = _read(root / ".gitlab-ci.yml", root)
    if gl:
        facts = []
        if "Auto-DevOps" in gl:
            facts.append(_fact("Auto DevOps template", "note", ".gitlab-ci.yml", _line_of(gl, r"Auto-DevOps")))
        off = [
            k.replace("_DISABLED", "").lower()
            for k in re.findall(r"^\s*(\w+_DISABLED):\s*['\"]?(?:true|1|yes)", gl, re.M | re.I)
        ]
        if off:
            facts.insert(
                0, _fact(f"{', '.join(off)} disabled", "decision", ".gitlab-ci.yml", _line_of(gl, r"_DISABLED"))
            )
        if re.search(r"SAST_EXCLUDED_PATHS", gl):
            facts.append(
                _fact("SAST excludes paths", "decision", ".gitlab-ci.yml", _line_of(gl, r"SAST_EXCLUDED_PATHS"))
            )
        publishes = (
            ["GitLab registry", "Kubernetes (auto deploy)"]
            if "Auto-DevOps" in gl
            else (["container registry"] if re.search(r"docker push|kaniko|buildah", gl) else [])
        )
        if _APPLY_RE.search(gl):
            publishes.append("Kubernetes (kubectl/Helm)")
        out.append({"system": "GitLab CI", "source": ".gitlab-ci.yml", "facts": _facts(facts), "publishes": publishes})
    for rel, system in (
        ("Jenkinsfile", "Jenkins"),
        (".circleci/config.yml", "CircleCI"),
        ("azure-pipelines.yml", "Azure Pipelines"),
        ("bitbucket-pipelines.yml", "Bitbucket Pipelines"),
        (".travis.yml", "Travis CI"),
    ):
        text = _read(root / rel, root)
        if text:
            out.append(
                {
                    "system": system,
                    "source": rel,
                    "facts": [],
                    "publishes": (
                        ["container registry"] if re.search(r"docker push|docker\.build|kaniko|buildah", text) else []
                    )
                    + (["Kubernetes (kubectl/Helm)"] if _APPLY_RE.search(text) else []),
                }
            )
    return out[:8]


# ================================================================ dependencies and packages
def scan_dependencies(root: Path) -> tuple[dict, list[dict]]:
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


# ================================================================ assembly
def build_inventory(root: Path) -> dict:
    root = root.resolve()
    compose, compose_env = scan_compose(root)
    environments = scan_terraform(root) + scan_manifests(root) + scan_helm(root) + scan_gitlab_auto_deploy(root)
    if compose_env:
        environments.append(compose_env)
    deps, packages = scan_dependencies(root)
    return {
        "schema_version": 1,
        "runtime": scan_runtime(root),
        "environments": environments[:8],
        "compose": compose,
        "ci": scan_ci(root),
        "dependencies": deps,
        "packages": packages[:40],
    }


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
