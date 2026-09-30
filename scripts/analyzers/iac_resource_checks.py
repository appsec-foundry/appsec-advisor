#!/usr/bin/env python3
"""Structured evaluators for the Compose, Kubernetes, Helm values and Terraform
checks in the Config/IaC catalog.

The deployment inventory marks some configuration facts ``weak`` for the
deployment figure. Each such fact kind is covered by a check here or listed as
an exception with its reason under ``inventory_weak_facts`` in
``data/config-iac-checks.yaml``, so a weakness never appears only in a figure;
``tests/test_iac_resource_checks.py`` guards that mapping against the inventory
source.

A regex cannot judge these files: a securityContext may sit on the pod or on
the container, a Compose port may be published with or without a host
address, and a secret may be a literal or a reference. Catalog entries with
``expect: structured`` name one evaluator below; each parses the file and
returns ``(line, snippet)`` for the first violation, or ``None``. An
unparsable file yields no violation.

Secret-literal rule, shared by Compose ``environment``, Kubernetes ``env`` and
Terraform attributes and variable defaults: a key whose name denotes a
credential and whose value is a literal string is a violation, placeholder
words such as ``changeme`` included, because the committed value is what runs.
A value is not a literal when it is empty, a number or boolean, or a
reference: interpolation (``${...}``, ``$VAR``), a template expression
(``{{ ... }}``), an angle-bracket marker (``<password>``), a mounted secret
path, a Kubernetes ``valueFrom``, or an unquoted HCL expression. The snippet
names the key and masks the value, so a finding never republishes the secret.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import re
from bisect import bisect_left
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml

MASK = "***"

# Remote administration and data services that must never face every network
# interface or the internet directly. Web ports are deliberately absent.
SENSITIVE_PORTS = frozenset(
    {
        22,
        23,
        135,
        139,
        445,
        1433,
        1521,
        2049,
        2181,
        2375,
        2376,
        2379,
        2380,
        3306,
        3389,
        5432,
        5672,
        5900,
        5984,
        6379,
        6443,
        8200,
        8500,
        9042,
        9092,
        9200,
        9300,
        10250,
        11211,
        15672,
        27017,
        27018,
    }
)
_ALL_INTERFACES = {"", "0.0.0.0", "::", "[::]"}
_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
_WORLD_PREFIXES = {"*", "internet", "any", "0.0.0.0/0", "::/0"}

_SECRET_WORDS = {"password", "passwd", "pwd", "passphrase", "secret", "token", "credential", "credentials", "apikey"}
_SECRET_PAIRS = {
    ("api", "key"),
    ("access", "key"),
    ("private", "key"),
    ("signing", "key"),
    ("secret", "key"),
    ("auth", "key"),
    ("master", "key"),
    ("encryption", "key"),
}
# A trailing word that makes the key describe a secret rather than hold one.
_NON_VALUE_SUFFIXES = {
    "algorithm",
    "arn",
    "audience",
    "backend",
    "count",
    "description",
    "duration",
    "enabled",
    "encoding",
    "endpoint",
    "expiration",
    "expires",
    "expiry",
    "file",
    "format",
    "header",
    "hint",
    "issuer",
    "kind",
    "label",
    "len",
    "length",
    "lifetime",
    "limit",
    "location",
    "max",
    "method",
    "min",
    "mode",
    "mount",
    "name",
    "path",
    "pattern",
    "policy",
    "prefix",
    "provider",
    "ref",
    "regex",
    "rotation",
    "scope",
    "size",
    "source",
    "store",
    "strategy",
    "suffix",
    "template",
    "timeout",
    "ttl",
    "type",
    "units",
    "uri",
    "url",
    "validity",
    "version",
}
_MOUNTED_SECRET = re.compile(r"^/(?:var/)?run/secrets/")

_WORKLOAD_POD_SPEC = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    "DeploymentConfig": ("spec", "template", "spec"),
}


# --------------------------------------------------------------------------- shared rules


def _name_words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word]


def is_secret_name(name: Any) -> bool:
    """Whether a key names a credential value, not a description of one."""
    if not isinstance(name, str):
        return False
    words = _name_words(name)
    if not words or words[-1] in _NON_VALUE_SUFFIXES:
        return False
    return any(word in _SECRET_WORDS for word in words) or any(pair in _SECRET_PAIRS for pair in zip(words, words[1:]))


def is_literal_secret(value: Any) -> bool:
    """Whether a value is a committed literal rather than a reference."""
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or text.lower() in {"true", "false", "null", "none", "yes", "no"}:
        return False
    if "${" in text or text.startswith("$") or ("{{" in text and "}}" in text):
        return False
    if re.fullmatch(r"<[^<>]+>", text) or _MOUNTED_SECRET.match(text):
        return False
    return True


# --------------------------------------------------------------------------- located YAML


class _Map(dict):
    __slots__ = ("line", "key_lines")


class _Seq(list):
    __slots__ = ("line", "item_lines")


class _LineLoader(yaml.SafeLoader):
    """SafeLoader whose mappings and sequences remember their source lines."""


def _construct_map(loader: _LineLoader, node: yaml.MappingNode) -> _Map:
    loader.flatten_mapping(node)
    out = _Map()
    out.line = node.start_mark.line + 1
    out.key_lines = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)):
            continue
        out[key] = loader.construct_object(value_node, deep=True)
        out.key_lines[key] = key_node.start_mark.line + 1
    return out


def _construct_seq(loader: _LineLoader, node: yaml.SequenceNode) -> _Seq:
    out = _Seq()
    out.line = node.start_mark.line + 1
    out.item_lines = []
    for child in node.value:
        out.append(loader.construct_object(child, deep=True))
        out.item_lines.append(child.start_mark.line + 1)
    return out


_LineLoader.add_constructor("tag:yaml.org,2002:map", _construct_map)
_LineLoader.add_constructor("tag:yaml.org,2002:seq", _construct_seq)


def _documents(text: str) -> list[Any]:
    try:
        return list(yaml.load_all(text, Loader=_LineLoader))  # noqa: S506 - SafeLoader subclass
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        return []


def _line_of(container: Any, key: Any = None) -> int:
    if isinstance(container, _Map):
        return container.key_lines.get(key, container.line) if key is not None else container.line
    if isinstance(container, _Seq):
        if isinstance(key, int) and 0 <= key < len(container.item_lines):
            return container.item_lines[key]
        return container.line
    return 1


def _get(node: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


# --------------------------------------------------------------------------- Compose


def _compose_services(text: str) -> Iterator[tuple[str, dict]]:
    docs = _documents(text)
    if len(docs) != 1 or not isinstance(docs[0], dict):
        return
    services = docs[0].get("services")
    if not isinstance(services, dict):
        return
    for name, service in services.items():
        if isinstance(service, dict):
            yield str(name), service


def _environment_entries(env: Any) -> Iterator[tuple[str, Any, int]]:
    if isinstance(env, dict):
        for key, value in env.items():
            yield str(key), value, _line_of(env, key)
    elif isinstance(env, list):
        for index, item in enumerate(env):
            if isinstance(item, str) and "=" in item:
                key, _, value = item.partition("=")
                yield key.strip(), value, _line_of(env, index)


def compose_environment_secret_literal(text: str, path: Path) -> tuple[int, str] | None:
    for service_name, service in _compose_services(text):
        for key, value, line in _environment_entries(service.get("environment")):
            if is_secret_name(key) and is_literal_secret(value):
                return line, f"{service_name} environment {key}: {MASK}"
    return None


def _port_range(spec: Any) -> tuple[int, int] | None:
    if isinstance(spec, int) and not isinstance(spec, bool):
        return spec, spec
    text = str(spec if spec is not None else "").split("/", 1)[0].strip()
    low, _, high = text.partition("-")
    if not low.isdigit() or (high and not high.isdigit()):
        return None
    return int(low), int(high or low)


def _reaches_sensitive_port(port_range: tuple[int, int] | None) -> bool:
    return port_range is not None and any(port_range[0] <= port <= port_range[1] for port in SENSITIVE_PORTS)


def _published_port(item: Any) -> tuple[str | None, tuple[int, int] | None] | None:
    """Host address (``None`` when unbound) and container port range of one
    ``ports`` entry. A long-syntax entry without ``published`` still publishes
    on a random host port, so it counts like a short-syntax container port."""
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        return None, (item, item)
    if isinstance(item, dict):
        host_ip = item.get("host_ip")
        return (str(host_ip) if host_ip is not None else None), _port_range(item.get("target"))
    if not isinstance(item, str):
        return None
    text = item.strip()
    host_ip = None
    if text.startswith("["):
        host_ip, _, text = text[1:].partition("]")
        parts = text.lstrip(":").split(":")
    else:
        parts = text.split(":")
        if len(parts) == 3:
            host_ip = parts[0]
    return host_ip, _port_range(parts[-1])


def compose_sensitive_port_on_all_interfaces(text: str, path: Path) -> tuple[int, str] | None:
    for service_name, service in _compose_services(text):
        ports = service.get("ports")
        if not isinstance(ports, list):
            continue
        for index, item in enumerate(ports):
            parsed = _published_port(item)
            if parsed is None:
                continue
            host_ip, container_range = parsed
            if _reaches_sensitive_port(container_range) and (host_ip is None or host_ip.strip() in _ALL_INTERFACES):
                return _line_of(ports, index), f"{service_name} ports: {item}"
    return None


# --------------------------------------------------------------------------- Kubernetes


def _manifests(text: str) -> Iterator[dict]:
    for doc in _documents(text):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            yield from (item for item in doc["items"] if isinstance(item, dict))
        else:
            yield doc


def _workloads(text: str) -> Iterator[tuple[str, dict, list[dict]]]:
    """``(label, pod spec, containers)`` for every workload manifest."""
    for doc in _manifests(text):
        kind = doc.get("kind")
        if not isinstance(doc.get("apiVersion"), str) or kind not in _WORKLOAD_POD_SPEC:
            continue
        pod = _get(doc, *_WORKLOAD_POD_SPEC[kind])
        if not isinstance(pod, dict):
            continue
        containers = [
            container
            for field in ("initContainers", "containers", "ephemeralContainers")
            if isinstance(pod.get(field), list)
            for container in pod[field]
            if isinstance(container, dict)
        ]
        name = _get(doc, "metadata", "name")
        yield f"{kind}/{name}" if name else str(kind), pod, containers


def kubernetes_privileged_container(text: str, path: Path) -> tuple[int, str] | None:
    for label, _pod, containers in _workloads(text):
        for container in containers:
            context = container.get("securityContext")
            if isinstance(context, dict) and context.get("privileged") is True:
                return _line_of(context, "privileged"), f"{label} container {container.get('name')}: privileged: true"
    return None


def kubernetes_host_namespace(text: str, path: Path) -> tuple[int, str] | None:
    for label, pod, _containers in _workloads(text):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(key) is True:
                return _line_of(pod, key), f"{label}: {key}: true"
    return None


def _effective(container_ctx: dict, pod_ctx: dict, key: str) -> Any:
    return container_ctx[key] if key in container_ctx else pod_ctx.get(key)


def kubernetes_root_not_prevented(text: str, path: Path) -> tuple[int, str] | None:
    for label, pod, containers in _workloads(text):
        if _get(pod, "nodeSelector", "kubernetes.io/os") == "windows":
            continue
        pod_ctx = pod.get("securityContext") if isinstance(pod.get("securityContext"), dict) else {}
        for container in containers:
            ctx = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}
            uid = _effective(ctx, pod_ctx, "runAsUser")
            if _effective(ctx, pod_ctx, "runAsNonRoot") is True and uid != 0:
                continue
            if isinstance(uid, int) and not isinstance(uid, bool) and uid > 0:
                continue
            return _line_of(container), f"{label} container {container.get('name')}: runAsNonRoot not enforced"
    return None


def kubernetes_env_secret_literal(text: str, path: Path) -> tuple[int, str] | None:
    for label, _pod, containers in _workloads(text):
        for container in containers:
            env = container.get("env")
            if not isinstance(env, list):
                continue
            for index, entry in enumerate(env):
                if not isinstance(entry, dict) or "valueFrom" in entry:
                    continue
                if is_secret_name(entry.get("name")) and is_literal_secret(entry.get("value")):
                    return _line_of(
                        env, index
                    ), f"{label} container {container.get('name')} env {entry['name']}: {MASK}"
    return None


def kubernetes_route_without_tls(text: str, path: Path) -> tuple[int, str] | None:
    for doc in _manifests(text):
        kind, name = doc.get("kind"), _get(doc, "metadata", "name")
        if not isinstance(doc.get("apiVersion"), str) or kind not in {"Ingress", "Route"}:
            continue
        spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
        label = f"{kind}/{name}" if name else str(kind)
        if kind == "Ingress":
            if not spec.get("tls"):
                return _line_of(doc, "spec"), f"{label}: no spec.tls"
            continue
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
        if not tls.get("termination"):
            return _line_of(doc, "spec"), f"{label}: no tls.termination"
        if tls.get("insecureEdgeTerminationPolicy") == "Allow":
            return _line_of(tls, "insecureEdgeTerminationPolicy"), f"{label}: insecureEdgeTerminationPolicy: Allow"
    return None


# --------------------------------------------------------------------------- Helm values


def _chart_values(text: str, path: Path) -> dict | None:
    """The values a chart or GitLab Auto Deploy renders its workload from; other YAML is not values."""
    is_chart_values = path.name == "values.yaml" and (path.parent / "Chart.yaml").is_file()
    is_auto_deploy = path.name == "auto-deploy-values.yaml" and path.parent.name == ".gitlab"
    if not (is_chart_values or is_auto_deploy):
        return None
    documents = _documents(text)
    return documents[0] if documents and isinstance(documents[0], dict) else None


def helm_values_privileged_container(text: str, path: Path) -> tuple[int, str] | None:
    context = _get(_chart_values(text, path), "securityContext")
    if isinstance(context, dict) and context.get("privileged") is True:
        return _line_of(context, "privileged"), "securityContext: privileged: true"
    return None


def helm_values_ingress_without_tls(text: str, path: Path) -> tuple[int, str] | None:
    values = _chart_values(text, path)
    ingress = _get(values, "ingress")
    if isinstance(ingress, dict) and ingress.get("enabled") and not ingress.get("tls"):
        return _line_of(values, "ingress"), "ingress enabled without tls"
    return None


# --------------------------------------------------------------------------- Terraform (HCL)


class _Block:
    __slots__ = ("kind", "labels", "lo", "hi", "line", "children", "parent")

    def __init__(self, kind: str, labels: list[str], lo: int, line: int, parent: _Block | None) -> None:
        self.kind, self.labels, self.lo, self.hi, self.line = kind, labels, lo, lo, line
        self.children: list[_Block] = []
        self.parent = parent


_HEREDOC = re.compile(r"<<-?([A-Za-z_]\w*)[ \t]*\n")
_BLOCK_HEADER = re.compile(r'^[ \t]*([A-Za-z_][\w-]*)[ \t]*((?:"[^"\n]*"[ \t]*|[A-Za-z_][\w-]*[ \t]+)*)$')
# No ``^``: ``match(text, pos)`` anchors at ``pos``; a caret would only match offset 0.
_ATTRIBUTE = re.compile(r"[ \t]*([A-Za-z_][\w-]*)[ \t]*=(?!=)[ \t]*")


def _code_offsets(text: str) -> Iterator[int]:
    """Offsets outside strings, comments and heredocs."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] not in '"\n':
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if text.startswith("<<", i):
            m = _HEREDOC.match(text, i)
            if m:
                end = re.compile(rf"(?m)^[ \t]*{re.escape(m.group(1))}[ \t]*$").search(text, m.end())
                i = n if end is None else end.end()
                continue
        yield i
        i += 1


class _Hcl:
    """Block tree plus the offsets whose line starts at a given brace depth."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._newlines = [i for i, c in enumerate(text) if c == "\n"]
        self.root = _Block("", [], 0, 1, None)
        self.root.hi = len(text)
        self.line_depth: dict[int, int] = {0: 0}
        stack: list[tuple[int, _Block | None]] = []
        current = self.root
        depth = 0
        for i in _code_offsets(text):
            c = text[i]
            if c == "{":
                line_start = text.rfind("\n", 0, i) + 1
                header = _BLOCK_HEADER.match(text[line_start:i])
                block = None
                if header and header.group(1) not in {"for", "if"}:
                    labels = re.findall(r'"([^"\n]*)"|([A-Za-z_][\w-]*)', header.group(2) or "")
                    block = _Block(header.group(1), [a or b for a, b in labels], i + 1, self.line_at(i), current)
                    current.children.append(block)
                    current = block
                stack.append((i, block))
                depth += 1
            elif c == "}" and stack:
                _opener, block = stack.pop()
                if block is not None:
                    block.hi = i
                    current = block.parent or self.root
                depth -= 1
            elif c == "\n":
                self.line_depth[i + 1] = depth

    def line_at(self, offset: int) -> int:
        return bisect_left(self._newlines, offset) + 1

    def blocks(self, kind: str | None = None, first_label: str | None = None) -> Iterator[_Block]:
        pending = list(self.root.children)
        while pending:
            block = pending.pop(0)
            if (kind is None or block.kind == kind) and (first_label is None or block.labels[:1] == [first_label]):
                yield block
            pending.extend(block.children)

    def depth_of(self, block: _Block) -> int:
        depth, node = 0, block
        while node.parent is not None:
            depth, node = depth + 1, node.parent
        return depth

    def attributes(self, block: _Block) -> dict[str, tuple[str, int]]:
        """Top-level ``name = value`` pairs of a block with their source lines."""
        target = self.depth_of(block)
        out: dict[str, tuple[str, int]] = {}
        start = block.lo
        while start < block.hi:
            end = self.text.find("\n", start)
            end = block.hi if end < 0 or end > block.hi else end
            if self.line_depth.get(start) == target:
                m = _ATTRIBUTE.match(self.text, start, end)
                if m:
                    out[m.group(1)] = (self._value(m.end(), block.hi).strip(), self.line_at(start))
            start = end + 1
        return out

    def _value(self, start: int, limit: int) -> str:
        """The expression after ``=``, extended over bracketed continuation lines."""
        segment = self.text[start:limit]
        depth = 0
        for i in _code_offsets(segment):
            c = segment[i]
            if c in "[({":
                depth += 1
            elif c in "])}":
                depth -= 1
            elif c == "\n" and depth <= 0:
                return segment[:i]
        return segment


def _quoted(value: str) -> str | None:
    m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', value.strip())
    return m.group(1) if m else None


def _strings(value: str) -> set[str]:
    return set(re.findall(r'"((?:[^"\\]|\\.)*)"', value))


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip().strip('"')
    return int(text) if re.fullmatch(r"-?\d+", text) else None


def _port_range_sensitive(low: int | None, high: int | None, protocol: str | None) -> bool | None:
    """True for a range that reaches a sensitive port, ``None`` when undecidable."""
    if protocol is not None and _quoted(protocol) in {"-1", "all", "*"}:
        return True
    if low is None or high is None:
        return None
    if low <= 0 and high in (0, 65535):
        return True
    return any(low <= port <= high for port in SENSITIVE_PORTS)


def _range_text(value: str | None) -> tuple[int | None, int | None]:
    text = (_quoted(value or "") or "").strip()
    if text == "*":
        return 0, 65535
    low, _, high = text.partition("-")
    if low.isdigit() and (not high or high.isdigit()):
        return int(low), int(high or low)
    return None, None


def _aws_rule_open(attrs: dict[str, tuple[str, int]], cidr_keys: tuple[str, ...], protocol_key: str) -> bool:
    world = any(_strings(attrs[key][0]) & _WORLD_CIDRS for key in cidr_keys if key in attrs)
    if not world:
        return False
    low = _int(attrs.get("from_port", ("", 0))[0])
    high = _int(attrs.get("to_port", ("", 0))[0])
    protocol = attrs.get(protocol_key, (None, 0))[0]
    return bool(_port_range_sensitive(low, high, protocol))


def _open_ingress(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks("resource"):
        rtype = block.labels[0] if block.labels else ""
        attrs = hcl.attributes(block)
        if rtype == "aws_security_group":
            for rule in block.children:
                if rule.kind == "ingress" and _aws_rule_open(
                    hcl.attributes(rule), ("cidr_blocks", "ipv6_cidr_blocks"), "protocol"
                ):
                    yield rule.line, f"{rtype}.{block.labels[1] if len(block.labels) > 1 else ''} ingress"
        elif rtype == "aws_security_group_rule":
            if _quoted(attrs.get("type", ("", 0))[0]) == "ingress" and _aws_rule_open(
                attrs, ("cidr_blocks", "ipv6_cidr_blocks"), "protocol"
            ):
                yield block.line, f"{rtype} ingress"
        elif rtype == "aws_vpc_security_group_ingress_rule":
            if _aws_rule_open(attrs, ("cidr_ipv4", "cidr_ipv6"), "ip_protocol"):
                yield block.line, f"{rtype} ingress"
        elif rtype == "google_compute_firewall":
            direction = _quoted(attrs.get("direction", ('"INGRESS"', 0))[0])
            if direction != "INGRESS" or not (_strings(attrs.get("source_ranges", ("", 0))[0]) & _WORLD_CIDRS):
                continue
            for allow in (child for child in block.children if child.kind == "allow"):
                allow_attrs = hcl.attributes(allow)
                protocol = allow_attrs.get("protocol", (None, 0))[0]
                ports = _strings(allow_attrs["ports"][0]) if "ports" in allow_attrs else None
                if ports is None or _quoted(protocol or "") == "all":
                    yield allow.line, f"{rtype} allow all ports"
                    break
                if any(_port_range_sensitive(*_range_text(f'"{port}"'), None) for port in ports):
                    yield allow.line, f"{rtype} allow {sorted(ports)}"
                    break
        elif rtype in {"azurerm_network_security_rule", "azurerm_network_security_group"}:
            rules = (
                [block]
                if rtype == "azurerm_network_security_rule"
                else [child for child in block.children if child.kind == "security_rule"]
            )
            for rule in rules:
                rule_attrs = hcl.attributes(rule)
                if _quoted(rule_attrs.get("direction", ("", 0))[0]) != "Inbound":
                    continue
                if _quoted(rule_attrs.get("access", ("", 0))[0]) != "Allow":
                    continue
                sources = {s.lower() for s in _strings(rule_attrs.get("source_address_prefix", ("", 0))[0])}
                sources |= {s.lower() for s in _strings(rule_attrs.get("source_address_prefixes", ("", 0))[0])}
                if not sources & _WORLD_PREFIXES:
                    continue
                ranges = [rule_attrs.get("destination_port_range", (None, 0))[0]]
                ranges += [f'"{p}"' for p in _strings(rule_attrs.get("destination_port_ranges", ("", 0))[0])]
                if any(r and _port_range_sensitive(*_range_text(r), None) for r in ranges):
                    yield rule.line, f"{rtype} inbound allow from internet"


def terraform_open_sensitive_ingress(text: str, path: Path) -> tuple[int, str] | None:
    return min(_open_ingress(_Hcl(text)), default=None)


_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_ACCESS_BLOCK_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


def _public_storage(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks("resource"):
        rtype = block.labels[0] if block.labels else ""
        attrs = hcl.attributes(block)
        body = hcl.text[block.lo : block.hi]
        if rtype in {"aws_s3_bucket", "aws_s3_bucket_acl"} and _quoted(attrs.get("acl", ("", 0))[0]) in _PUBLIC_ACLS:
            yield attrs["acl"][1], f"{rtype} acl {attrs['acl'][0]}"
        elif rtype == "aws_s3_bucket_public_access_block":
            for flag in _ACCESS_BLOCK_FLAGS:
                if attrs.get(flag, ("", 0))[0] == "false":
                    yield attrs[flag][1], f"{rtype} {flag} = false"
                    break
        elif (
            rtype in {"aws_s3_bucket_policy", "aws_s3_bucket"}
            and re.search(r'"?Effect"?\s*[=:]\s*"Allow"', body)
            # A Condition may narrow a wildcard principal (VPC endpoint, org id);
            # without statement-level evaluation that grant is undecidable.
            and not re.search(r'"?Condition"?\s*[=:]', body)
        ):
            m = re.search(r'"?(?:Principal|AWS)"?\s*[=:]\s*"\*"', body)
            if m:
                yield hcl.line_at(block.lo + m.start()), f"{rtype} grants Principal *"
        elif rtype.startswith("google_storage_bucket_") and any(member in body for member in _PUBLIC_MEMBERS):
            yield block.line, f"{rtype} grants {'/'.join(sorted(m for m in _PUBLIC_MEMBERS if m in body))}"
        elif rtype == "azurerm_storage_container" and _quoted(attrs.get("container_access_type", ("", 0))[0]) in {
            "blob",
            "container",
        }:
            yield (
                attrs["container_access_type"][1],
                f"{rtype} container_access_type {attrs['container_access_type'][0]}",
            )
        elif rtype == "azurerm_storage_account":
            for flag in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
                if attrs.get(flag, ("", 0))[0] == "true":
                    yield attrs[flag][1], f"{rtype} {flag} = true"
                    break


def terraform_public_storage(text: str, path: Path) -> tuple[int, str] | None:
    return min(_public_storage(_Hcl(text)), default=None)


_ENCRYPTION_FLAGS = {
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
    "aws_docdb_cluster": "storage_encrypted",
    "aws_neptune_cluster": "storage_encrypted",
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
    "aws_redshift_cluster": "encrypted",
    "aws_elasticache_replication_group": "at_rest_encryption_enabled",
}
# Resources whose provider default is unencrypted, so an absent flag is a violation.
_UNENCRYPTED_BY_DEFAULT = {"aws_db_instance", "aws_rds_cluster"}


def _unencrypted_storage(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks("resource"):
        rtype = block.labels[0] if block.labels else ""
        attrs = hcl.attributes(block)
        flag = _ENCRYPTION_FLAGS.get(rtype)
        if flag:
            value = attrs.get(flag, (None, 0))
            if value[0] == "false":
                yield value[1], f"{rtype} {flag} = false"
            elif (
                value[0] is None
                and rtype in _UNENCRYPTED_BY_DEFAULT
                and "replicate_source_db" not in attrs
                and _quoted(attrs.get("engine_mode", ('""', 0))[0]) != "serverless"
            ):
                yield block.line, f"{rtype} without {flag}"
        elif rtype == "aws_opensearch_domain" or rtype == "aws_elasticsearch_domain":
            for child in block.children:
                if child.kind == "encrypt_at_rest" and hcl.attributes(child).get("enabled", ("", 0))[0] == "false":
                    yield child.line, f"{rtype} encrypt_at_rest disabled"


def terraform_unencrypted_storage(text: str, path: Path) -> tuple[int, str] | None:
    return min(_unencrypted_storage(_Hcl(text)), default=None)


def _credential_literals(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in (hcl.root, *hcl.blocks()):
        attrs = hcl.attributes(block)
        if block.kind == "variable":
            name = block.labels[0] if block.labels else ""
            default = attrs.get("default")
            if default and is_secret_name(name) and is_literal_secret(_quoted(default[0])):
                yield default[1], f'variable "{name}" default = "{MASK}"'
            continue
        for key, (value, line) in attrs.items():
            if is_secret_name(key) and is_literal_secret(_quoted(value)):
                yield line, f'{key} = "{MASK}"'


def terraform_credential_literal(text: str, path: Path) -> tuple[int, str] | None:
    return min(_credential_literals(_Hcl(text)), default=None)


_LB_REFERENCE = re.compile(r"\baws_(?:lb|alb)\.([\w-]+)\.")


def _plaintext_listeners(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    """HTTP listeners of a load balancer that has no HTTPS listener in the same file."""
    by_lb: dict[str, list[tuple[str | None, int]]] = {}
    for block in hcl.blocks("resource"):
        if block.labels[:1] not in (["aws_lb_listener"], ["aws_alb_listener"]):
            continue
        attrs = hcl.attributes(block)
        target = _LB_REFERENCE.search(attrs.get("load_balancer_arn", ("", 0))[0])
        by_lb.setdefault(target.group(1) if target else f"?{block.line}", []).append(
            (_quoted(attrs.get("protocol", ("", 0))[0]), attrs.get("protocol", ("", block.line))[1])
        )
    for lb, listeners in by_lb.items():
        if any(protocol == "HTTPS" for protocol, _ in listeners):
            continue
        for protocol, line in listeners:
            if protocol == "HTTP":
                yield line, f"load balancer {lb.lstrip('?')} listener protocol HTTP without an HTTPS listener"


def terraform_plaintext_load_balancer(text: str, path: Path) -> tuple[int, str] | None:
    return min(_plaintext_listeners(_Hcl(text)), default=None)


def _public_addresses(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks("resource"):
        rtype = block.labels[0] if block.labels else ""
        if rtype == "aws_instance":
            value = hcl.attributes(block).get("associate_public_ip_address", ("", 0))
            if value[0] == "true":
                yield value[1], f"{rtype} associate_public_ip_address = true"
        elif rtype == "aws_ecs_service":
            for child in block.children:
                value = hcl.attributes(child).get("assign_public_ip", ("", 0))
                if child.kind == "network_configuration" and value[0] == "true":
                    yield value[1], f"{rtype} assign_public_ip = true"


def terraform_public_compute_address(text: str, path: Path) -> tuple[int, str] | None:
    return min(_public_addresses(_Hcl(text)), default=None)


_PUBLICLY_ACCESSIBLE = {"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"}


def _public_databases(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks("resource"):
        rtype = block.labels[0] if block.labels else ""
        value = hcl.attributes(block).get("publicly_accessible", ("", 0))
        if rtype in _PUBLICLY_ACCESSIBLE and value[0] == "true":
            yield value[1], f"{rtype} publicly_accessible = true"


def terraform_publicly_accessible_database(text: str, path: Path) -> tuple[int, str] | None:
    return min(_public_databases(_Hcl(text)), default=None)


_IAM_POLICY_RESOURCES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
# ``Action = "*"`` / ``"Action": "s3:*"`` inside jsonencode(...) or a heredoc JSON document.
_WILDCARD_ACTION = re.compile(r'"?Action"?\s*[=:]\s*\[?\s*"(\*|[\w-]+:\*)"')
_WILDCARD_RESOURCE = re.compile(r'"?Resource"?\s*[=:]\s*\[?\s*"\*"')


def _wildcard_policies(hcl: _Hcl) -> Iterator[tuple[int, str]]:
    for block in hcl.blocks():
        kind = block.labels[0] if block.labels else ""
        if block.kind == "resource" and kind in _IAM_POLICY_RESOURCES:
            body = hcl.text[block.lo : block.hi]
            action = _WILDCARD_ACTION.search(body)
            if action and _WILDCARD_RESOURCE.search(body):
                yield hcl.line_at(block.lo + action.start()), f'{kind} Action "{action.group(1)}" on Resource "*"'
        elif block.kind == "data" and kind == "aws_iam_policy_document":
            for statement in (child for child in block.children if child.kind == "statement"):
                attrs = hcl.attributes(statement)
                actions = _strings(attrs.get("actions", ("", 0))[0])
                wildcard = sorted(a for a in actions if a == "*" or a.endswith(":*"))
                if (
                    wildcard
                    and "*" in _strings(attrs.get("resources", ("", 0))[0])
                    and _quoted(attrs.get("effect", ('"Allow"', 0))[0]) != "Deny"
                ):
                    yield attrs["actions"][1], f'{kind} actions "{wildcard[0]}" on resources "*"'


def terraform_wildcard_iam_policy(text: str, path: Path) -> tuple[int, str] | None:
    return min(_wildcard_policies(_Hcl(text)), default=None)


EVALUATORS: dict[str, Callable[[str, Path], tuple[int, str] | None]] = {
    "compose_environment_secret_literal": compose_environment_secret_literal,
    "compose_sensitive_port_on_all_interfaces": compose_sensitive_port_on_all_interfaces,
    "kubernetes_privileged_container": kubernetes_privileged_container,
    "kubernetes_host_namespace": kubernetes_host_namespace,
    "kubernetes_root_not_prevented": kubernetes_root_not_prevented,
    "kubernetes_env_secret_literal": kubernetes_env_secret_literal,
    "kubernetes_route_without_tls": kubernetes_route_without_tls,
    "helm_values_privileged_container": helm_values_privileged_container,
    "helm_values_ingress_without_tls": helm_values_ingress_without_tls,
    "terraform_open_sensitive_ingress": terraform_open_sensitive_ingress,
    "terraform_public_storage": terraform_public_storage,
    "terraform_unencrypted_storage": terraform_unencrypted_storage,
    "terraform_credential_literal": terraform_credential_literal,
    "terraform_plaintext_load_balancer": terraform_plaintext_load_balancer,
    "terraform_public_compute_address": terraform_public_compute_address,
    "terraform_publicly_accessible_database": terraform_publicly_accessible_database,
    "terraform_wildcard_iam_policy": terraform_wildcard_iam_policy,
}
