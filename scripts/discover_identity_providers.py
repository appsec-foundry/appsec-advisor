"""Reconcile evidenced OAuth/OIDC/SAML clients with the architecture inventory.

This offline architecture producer inspects outbound calls and declarative client
configuration, not dependency names or vulnerability signals. It emits no findings
and assigns no CWE or severity. Its only persisted output is the existing,
schema-validated data-flow fragment. Unknown dynamic addresses remain for semantic
discovery; a concrete integration without a unique owner fails the handoff.
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from reclassify_components import _glob_to_regex
from recon_patterns import _walk_repo

MAX_FILES = 20000
MAX_BYTES = 32_000_000
MAX_FILE_BYTES = 1_000_000
_SOURCE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".cs", ".go", ".rb", ".php"}
_CONFIG_EXT = {".json", ".yaml", ".yml", ".properties"}
_NON_RUNTIME = re.compile(
    r"(?:^|/)(?:tests?|__tests__|fixtures?|examples?|docs?|samples?|mocks?)(?:/|$)|(?:\.test|\.spec|_test|Test)\.", re.I
)
_LEX = re.compile(
    r"'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*"
)
_CALL = re.compile(
    r"\b(?:[\w.]+\.)?(?:fetch|get|post|request|replace|assign|open|urlopen|discover|fromIssuerLocation|UserManager|PublicClientApplication|ConfidentialClientApplication|OAuth2Session|OAuth2|OpenIDConnect|Saml2Client|SAMLStrategy|Strategy|register)\s*\("
)
_CLIENT = re.compile(
    r"(?:UserManager|ClientApplication|OAuth2?(?:Session)?|OpenIDConnect|Saml2Client|SAMLStrategy|Strategy|register)\s*\("
)
_CONFIG_CONTEXT = re.compile(r"oauth|oidc|openid|saml|sso|singlesignon|relyingparty", re.I)


@dataclass(frozen=True)
class Integration:
    file: str
    line: int
    use_line: int
    authority: str
    host: str
    protocol: str
    role: str
    configured: bool = False
    browser: bool = False


def _address(value: str, *, issuer: bool = False) -> tuple[str, str, str] | None:
    """Canonical identity only: never publish credentials, query strings or tokens."""
    if len(value) > 2048 or re.search(r'[\s\\${}<>"]', value):
        return None
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return None
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+|[a-f0-9:]+", host):
        return None
    display_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{display_host}"
    if port and port != {"http": 80, "https": 443}[parsed.scheme]:
        origin += f":{port}"
    # Realm/tenant paths distinguish independent authorities on one host.
    realm = re.search(r"/(?:realms|tenants)/[A-Za-z0-9._-]+", parsed.path)
    scope = (
        parsed.path.removesuffix("/.well-known/openid-configuration").rstrip("/")
        if issuer
        else (realm.group() if realm else "")
    )
    if scope and not re.fullmatch(r"/[A-Za-z0-9._~/-]*", scope):
        return None
    return origin + scope, host, parsed.scheme.upper()


def _field_role(key: str) -> str | None:
    key = re.sub(r"[^a-z]", "", key.lower())
    if key in {
        "issuer",
        "issueruri",
        "issuerurl",
        "authority",
        "metadataurl",
        "metadatauri",
        "servermetadataurl",
        "wellknown",
    }:
        return "OIDC discovery"
    if key in {"authorizationurl", "authorizationuri", "authorizationendpoint", "authorizeurl"}:
        return "OAuth authorization"
    if key in {"tokenurl", "tokenuri", "tokenendpoint", "accesstokenurl"}:
        return "OAuth token exchange"
    if key in {"userinfo", "userinfourl", "userinfouri", "userinfoendpoint"}:
        return "OAuth profile request"
    if key in {"entrypoint", "singlesignonserviceurl", "ssourl", "idpssourl", "ssoendpoint"}:
        return "SAML sign-in"
    return None


def _url_role(value: str) -> str | None:
    path = urlsplit(value).path.lower()
    if "/.well-known/openid-configuration" in path:
        return "OIDC discovery"
    if re.search(r"/(?:saml2?|sso)/(?:login|sso|signin)(?:/|$)", path):
        return "SAML sign-in"
    if re.search(r"/(?:oauth2?|oidc|openid)(?:/[^/]+)*/(?:auth|authorize|authorization)(?:/|$)", path):
        return "OAuth authorization"
    if re.search(r"/(?:oauth2?|oidc|openid)(?:/[^/]+)*/token(?:/|$)", path):
        return "OAuth token exchange"
    if re.search(r"/(?:oauth2?|oidc|openid)(?:/[^/]+)*/userinfo(?:/|$)", path):
        return "OAuth profile request"
    return None


def _source_integrations(text: str, rel: str) -> list[Integration]:
    code = list(text)
    strings = []
    for token in _LEX.finditer(text):
        raw = token.group()
        if raw[0] in "'\"`" and not raw.startswith(("'''", '"""')):
            strings.append((token.start(), token.end(), raw[1:-1]))
        code[token.start() : token.end()] = ["\n" if c == "\n" else " " for c in raw]
    masked = "".join(code)
    calls = []
    for call in _CALL.finditer(masked):
        method = call.group()
        if re.search(r"(?:replace|assign)\s*\(", method) and not re.search(r"\blocation\.", method):
            continue
        if re.search(r"\bopen\s*\(", method) and not re.search(r"(?:window|Window)\.open", method):
            continue
        if re.search(r"(?:get|post|request)\s*\(", method) and not re.search(
            r"\b(?:http|https|httpClient|http_client|axios|requests|session|client)\.", method
        ):
            continue
        depth, end = 1, call.end()
        while end < min(len(masked), call.end() + 4096) and depth:
            depth += (masked[end] == "(") - (masked[end] == ")")
            end += 1
        if depth == 0:
            calls.append((call, end))
    result = []
    for start, end, value in strings:
        address = _address(value)
        if not address:
            continue
        binding = re.search(r"([A-Za-z_$][\w$]*)\s*[:=]\s*$", masked[max(0, start - 120) : start])
        name = binding.group(1) if binding else ""
        for call, call_end in calls:
            # A literal argument or an explicitly referenced local URL binding.
            used = call.end() <= start < call_end
            if name and end <= call.start():
                if re.search(r"\b" + re.escape(name) + r"\s*=(?!=)", masked[end : call.start()]):
                    continue
                used = bool(re.search(r"\b" + re.escape(name) + r"\b", masked[call.end() : call_end])) or any(
                    call.end() <= a < call_end and "${" + name + "}" in s for a, _b, s in strings
                )
            if not used:
                continue
            role = _url_role(value)
            if _CLIENT.search(call.group()):
                role = _field_role(name) or role
                if role == "OIDC discovery" and re.search(r"SAML|Saml", call.group()):
                    role = "SAML metadata"
            if re.search(r"(?:Issuer\.discover|JwtDecoders\.fromIssuerLocation)\s*\(", call.group()):
                role = "OIDC discovery"
            if not role:
                continue
            address = _address(value, issuer=role == "OIDC discovery")
            if not address:
                continue
            result.append(
                Integration(
                    rel,
                    text.count("\n", 0, start) + 1,
                    text.count("\n", 0, call.start()) + 1,
                    *address,
                    role,
                    browser=bool(re.search(r"\blocation\.(?:assign|replace)|(?:window|Window)\.open", call.group())),
                )
            )
            break
    return result


def _config_integrations(text: str, rel: str) -> list[Integration]:
    if rel.endswith(".properties"):
        # Resource servers also consume an external issuer's discovery metadata.
        text = re.sub(r"(?m)^\s*[#!].*$", "", text)
        result = []
        for number, line in enumerate(text.splitlines(), 1):
            match = re.match(
                r"\s*(spring\.security\.oauth2\.(?:client|resourceserver\.jwt)\.[\w.-]+)\s*=\s*(https?://\S+)\s*$",
                line,
            )
            if (
                match
                and (role := _field_role(match[1].split(".")[-1]))
                and (address := _address(match[2], issuer=role == "OIDC discovery"))
            ):
                result.append(Integration(rel, number, number, *address, role, True))
        return result
    # YAML's node tree preserves evidence line numbers for JSON as well. Reject
    # aliases rather than expanding recursive or exponential configuration data.
    try:
        if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(text)):
            return []
        root = yaml.compose(text)
    except (yaml.YAMLError, RecursionError):
        return []
    result = []

    def walk(node, path=(), depth=0):
        if depth > 40:
            return
        if isinstance(node, yaml.MappingNode):
            values = {k.value: v for k, v in node.value if isinstance(k, yaml.ScalarNode)}
            if any(
                isinstance(values.get(k), yaml.ScalarNode) and values[k].value.lower() in {"false", "0", "off"}
                for k in ("enabled", "active")
            ):
                return
            for key, value in values.items():
                context = ".".join((*path, key))
                role = _field_role(key.split(".")[-1])
                if key == "url" and path:
                    role = _field_role(path[-1] + key) or role
                if role == "OIDC discovery" and re.search(r"saml|relyingparty", context, re.I):
                    role = "SAML metadata"
                if (
                    role
                    and _CONFIG_CONTEXT.search(context)
                    and not re.search(r"(?:^|[._-])(?:authorizationserver|server)(?:[._-]|$)", context, re.I)
                ):
                    if isinstance(value, yaml.ScalarNode) and (
                        address := _address(value.value, issuer=role == "OIDC discovery")
                    ):
                        line = value.start_mark.line + 1
                        result.append(Integration(rel, line, line, *address, role, True))
                walk(value, (*path, key), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                walk(value, path, depth + 1)

    walk(root)
    return result


def discover(repo_root: Path) -> list[Integration]:
    """Find bounded, source-backed client integrations without fetching URLs."""
    root = repo_root.resolve()
    total, count, result = 0, 0, []
    for path in _walk_repo(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix not in _SOURCE_EXT | _CONFIG_EXT or _NON_RUNTIME.search(rel):
            continue
        if not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        total, count = total + size, count + 1
        if total > MAX_BYTES or count > MAX_FILES:
            raise ValueError("identity-provider discovery exceeded its source budget")
        text = path.read_text(encoding="utf-8", errors="replace")
        if "http" not in text:
            continue
        result.extend(
            _config_integrations(text, rel) if path.suffix in _CONFIG_EXT else _source_integrations(text, rel)
        )
    return sorted(set(result), key=lambda c: (c.file, c.line, c.authority, c.role))


def _owner(file: str, components: list[dict], *, browser: bool = False) -> str:
    matches = []
    for component in components:
        # A browser navigation cannot originate from a server-side auth component,
        # even when its functional inventory also claims the login UI's files.
        if browser and component.get("tier") != "client":
            continue
        for pattern in component.get("paths") or []:
            if _glob_to_regex(pattern).fullmatch(file) or (
                not re.search(r"[*?\[]", pattern) and file.startswith(pattern.rstrip("/") + "/")
            ):
                specificity = len(re.split(r"[*?\[]", pattern)[0])
                matches.append((specificity, component["id"]))
    if matches:
        best = max(score for score, _cid in matches)
        owners = {cid for score, cid in matches if score == best}
        if len(owners) == 1:
            return owners.pop()
    raise ValueError(f"identity integration in {file} needs a unique component owner")


def reconcile(repo_root: Path, components: list[dict], document: dict) -> dict:
    """Fill omitted providers/flows before boundary assessment; retain authored topology."""
    result = copy.deepcopy(document)
    integrations = discover(repo_root)
    if not integrations:
        return result
    entities = result.setdefault("external_entities", [])
    flows = result.setdefault("data_flows", [])
    next_flow = max((int(f["id"][3:]) for f in flows), default=0) + 1
    for integration in integrations:
        owner = _owner(integration.file, components, browser=integration.browser)
        evidence = [
            {"file": integration.file, "line": line} for line in sorted({integration.line, integration.use_line})
        ]

        def same_evidence(row):
            return any(e in (row.get("evidence") or []) for e in evidence)

        unambiguous_line = (
            len({c.authority for c in integrations if c.file == integration.file and c.line == integration.line}) == 1
        )
        # Explicit internal topology is stronger than an absolute URL hint.
        if any(f.get("from") == owner and f.get("to") != "external" and same_evidence(f) for f in flows):
            if not unambiguous_line:
                raise ValueError(
                    f"ambiguous internal identity-server evidence at {integration.file}:{integration.line}"
                )
            continue
        digest = hashlib.sha256(integration.authority.encode()).hexdigest()[:16]
        entity_id = f"ext-idp-{digest}"

        def represents(entity):
            if not same_evidence(entity):
                return False
            urls = re.findall(r"https?://[^\s)]+", entity.get("description", ""))
            if urls:
                return any(
                    (address := _address(url.rstrip(".,"), issuer=True)) and address[0] == integration.authority
                    for url in urls
                )
            # Compact JSON may configure several authorities on one line.
            return unambiguous_line

        matching = [
            e for e in entities if e["id"] == entity_id or (e.get("kind") == "identity-provider" and represents(e))
        ]
        if len(matching) > 1:
            raise ValueError(f"ambiguous identity-provider representation at {integration.file}:{integration.line}")
        if matching:
            entity_id = matching[0]["id"]
            if matching[0].get("kind") not in {"identity-provider", "external-service"}:
                raise ValueError(f"identity-provider ID collides with another entity: {entity_id}")
            if (
                entity_id == f"ext-idp-{digest}"
                and matching[0].get("kind") == "external-service"
                and integration.role != "OAuth profile request"
            ):
                matching[0]["kind"] = "identity-provider"
                matching[0]["name"] = f"Identity provider · {integration.host}"[:80]
        else:
            profile = integration.role == "OAuth profile request"
            entities.append(
                {
                    "id": entity_id,
                    "name": f"{'OAuth profile service' if profile else 'Identity provider'} · {integration.host}"[:80],
                    "kind": "external-service" if profile else "identity-provider",
                    "description": f"{integration.role}: {integration.authority}. Activation depends on deployment configuration."[
                        :240
                    ],
                    "evidence": evidence,
                }
            )
        existing = [f for f in flows if f.get("from") == owner and f.get("to") == "external" and same_evidence(f)]
        label = ("Configured " if integration.configured else "") + integration.role
        if any(
            f.get("to_entity") == entity_id and (f.get("provenance") != "recon" or f.get("label") == label)
            for f in existing
        ):
            continue
        generic = [f for f in existing if not f.get("to_entity")]
        if len(generic) == 1 and unambiguous_line:
            generic[0]["to_entity"] = entity_id
            continue
        flows.append(
            {
                "id": f"df-{next_flow:03d}",
                "from": owner,
                "to": "external",
                "to_entity": entity_id,
                "label": label,
                "protocol": integration.protocol,
                "data_classification": "Public"
                if integration.role in {"OIDC discovery", "SAML metadata"}
                else "Confidential",
                "direction": "unidirectional"
                if integration.role in {"OAuth authorization", "SAML sign-in"}
                else "request-response",
                "evidence": evidence,
                "provenance": "recon",
            }
        )
        next_flow += 1
    return result
