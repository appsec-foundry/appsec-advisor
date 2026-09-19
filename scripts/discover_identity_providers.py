"""Reconcile evidenced OAuth/OIDC/SAML clients with the architecture inventory.

This offline architecture producer inspects outbound calls and declarative client
configuration, not dependency names or vulnerability signals. It emits no findings
and assigns no CWE or severity. Its only persisted output is the existing,
schema-validated data-flow fragment. Unknown dynamic addresses remain for semantic
discovery; a concrete integration without a unique owner fails the handoff.

A flow to an identity provider takes its authentication from the protocol step
the integration performs (``integration_authentication``): the provider
authenticates the user at a sign-in step, checks the access token of a profile
request, and authenticates the client at a token request only as its call or
configuration proves. Only an unknown scheme is filled (FE-14); an authored
`none` on a sign-in or profile step is a self-check error instead. A client
configured with its ID and secret whose library hides the token endpoint gains
the token request to its sign-in provider (``reconcile_confidential_clients``).
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
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
# Function headers across the supported source languages: `def`/`function`/`func`/`fun`
# declarations, functions bound to a name, and methods with a brace body.
_DEFINITION = re.compile(
    r"(?:\b(?:def|function|func|fun)\s+(?:\([^()\n]*\)\s*)?(?P<keyword>[A-Za-z_$][\w$]*)\s*\("
    r"|(?<![\w$.])(?P<bound>[A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^()]*\)[^=;{\n]*=>|[A-Za-z_$][\w$]*\s*=>)"
    r"|(?<![\w$.])(?P<method>[A-Za-z_$][\w$]*)\s*\([^()]*\)\s*(?::[^{;=\n]+|throws[\w.,\s]+)?\{)"
)
_NOT_FUNCTIONS = frozenset({"if", "for", "while", "switch", "catch", "return", "with", "new", "else", "do", "try"})
_MAX_DEFINITIONS = 200


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
    # The call expression or configuration block; protocol markers are read here only.
    window: str = field(default="", compare=False)


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


_ROLES = frozenset(
    {
        "OIDC discovery",
        "OAuth authorization",
        "OAuth token exchange",
        "OAuth profile request",
        "SAML sign-in",
        "SAML metadata",
    }
)


_TRANSPORT = {"HTTPS": "protected", "HTTP": "cleartext"}
# Steps whose receiver always authenticates its caller; `none` there is a modelling error.
_CALLER_CHECKED = frozenset({"OAuth authorization", "SAML sign-in", "OAuth profile request"})


def _grant(window: str) -> str | None:
    """The OAuth grant a sign-in request states; nothing is inferred from names."""
    if re.search(r"code[-_]?challenge", window, re.I):
        return "authorization-code-pkce"
    if re.search(r"response[-_]?type\W{0,6}(?:id_token\W+)?token\b", window, re.I):
        return "implicit"
    if re.search(r"response[-_]?type\W{0,6}code\b", window, re.I):
        return "authorization-code"
    return None


def _client_authentication(window: str) -> dict | None:
    """How a token request authenticates the client, only as its call or configuration shows."""
    if re.search(r"client[-_]?assertion|private[-_]?key[-_]?jwt", window, re.I):
        return {"scheme": "private-key", "scope": "The client signs a JWT assertion with its private key"}
    if re.search(r"tls[-_]client[-_]auth", window, re.I):
        return {"scheme": "mtls", "scope": "The client authenticates with its TLS client certificate"}
    if re.search(r"client[-_]?secret", window, re.I):
        return {"scheme": "client-secret", "scope": "The client presents its OAuth client ID and client secret"}
    if re.search(r"code[-_]?verifier", window, re.I):
        return {
            "scheme": "oauth2",
            "flow": "authorization-code-pkce",
            "scope": "A public client proves the PKCE code verifier",
        }
    return None


def integration_authentication(integration: Integration, evidence: list[dict]) -> dict | None:
    """The authentication the provider applies to this protocol step, or None when unproven."""
    window, role = integration.window, integration.role
    if role == "OAuth authorization":
        auth = {
            "scheme": "oidc" if re.search(r"\bopenid\b", window) else "oauth2",
            "scope": "The identity provider authenticates the user at its sign-in endpoint",
        }
        if grant := _grant(window):
            auth["flow"] = grant
    elif role == "SAML sign-in":
        auth = {"scheme": "saml", "scope": "The identity provider authenticates the user and issues a SAML assertion"}
    elif role == "OAuth profile request":
        auth = {"scheme": "bearer", "scope": "The provider checks the OAuth access token sent with the request"}
    elif role == "OAuth token exchange":
        auth = _client_authentication(window)
    else:  # OIDC discovery, SAML metadata
        auth = {"scheme": "none", "scope": "Public provider metadata; the provider checks no caller"}
    if auth is None:
        return None
    if transport := _TRANSPORT.get(integration.protocol):
        auth["transport"] = transport
    auth["evidence"] = evidence
    return auth


def _service_role(integration: Integration) -> str:
    if integration.role == "OAuth profile request":
        return "oauth-resource-server"
    if integration.role.startswith("SAML"):
        return "saml-identity-provider"
    if integration.role == "OIDC discovery" or re.search(r"\bopenid\b", integration.window):
        return "oidc-provider"
    return "oauth-authorization-server"


def _fill_authentication(flow: dict, integration: Integration, evidence: list[dict]) -> None:
    """FE-14: only an unknown scheme is filled; an authored scheme stays."""
    if flow.get("interaction") or (flow.get("authentication") or {}).get("scheme", "unknown") != "unknown":
        return
    if auth := integration_authentication(integration, evidence):
        flow["authentication"] = auth


def identity_authentication_errors(repo_root: Path, flows: list) -> list[str]:
    """Self-check: a flow citing a sign-in or profile step cannot claim that the provider checks nothing."""
    try:
        steps = [i for i in discover(repo_root) if i.role in _CALLER_CHECKED]
    except ValueError:
        return []
    errors = []
    for flow in flows or []:
        auth = flow.get("authentication") if isinstance(flow, dict) else None
        if not isinstance(auth, dict) or auth.get("scheme") != "none" or flow.get("to") != "external":
            continue
        rows = [*(flow.get("evidence") or []), *(auth.get("evidence") or [])]
        cited = {(row.get("file"), row.get("line")) for row in rows if isinstance(row, dict)}
        for step in steps:
            if {(step.file, step.line), (step.file, step.use_line)} & cited:
                expected = integration_authentication(step, [])
                errors.append(
                    f"{flow.get('id')}: it cites the {step.role} at {step.file}:{step.use_line}, where the provider "
                    f"authenticates the caller; use scheme `{expected['scheme']}` instead of `none`"
                )
                break
    return errors


def _written_by_reconcile(flow: dict) -> bool:
    """Only a recon flow carrying a role label came from here; any other flow is authored."""
    label = str(flow.get("label") or "")
    return flow.get("provenance") == "recon" and label.removeprefix("Configured ") in _ROLES


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
                    window=value + "\n" + text[call.start() : call_end],
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
                result.append(Integration(rel, number, number, *address, role, True, window=line))
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
                        block = text[node.start_mark.index : node.end_mark.index]
                        result.append(Integration(rel, line, line, *address, role, True, window=block))
                walk(value, (*path, key), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                walk(value, path, depth + 1)

    walk(root)
    return result


def _runtime_files(repo_root: Path):
    """Runtime source and configuration files within the discovery budget, as (rel, suffix, text)."""
    root = repo_root.resolve()
    total, count = 0, 0
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
        yield rel, path.suffix, path.read_text(encoding="utf-8", errors="replace")


def discover(repo_root: Path) -> list[Integration]:
    """Find bounded, source-backed client integrations without fetching URLs."""
    result = []
    for rel, suffix, text in _runtime_files(repo_root):
        if "http" not in text:
            continue
        result.extend(_config_integrations(text, rel) if suffix in _CONFIG_EXT else _source_integrations(text, rel))
    return sorted(set(result), key=lambda c: (c.file, c.line, c.authority, c.role))


@dataclass(frozen=True)
class ConfidentialClient:
    """An OAuth/OIDC client configured with its ID and secret; its library performs the token request."""

    file: str
    line: int
    window: str = field(default="", compare=False)


_CLIENT_ID = re.compile(r"client[-_]?id", re.I)
_CLIENT_SECRET = re.compile(r"client[-_]?secret", re.I)
# Constructors whose name alone does not say OAuth (`Strategy`, `register`) need protocol context.
_OAUTH_CONSTRUCTOR = re.compile(r"OAuth|OpenIDConnect|ClientApplication|Saml", re.I)
_OAUTH_CALL_CONTEXT = re.compile(r"oauth|oidc|openid|callback[-_]?ur[il]|redirect[-_]?ur[il]|authoriz", re.I)


def _source_confidential_clients(text: str, rel: str) -> list[ConfidentialClient]:
    masked = _masked(text)
    result = []
    for call in _CLIENT.finditer(masked):
        depth, end = 1, call.end()
        while end < min(len(masked), call.end() + 4096) and depth:
            depth += (masked[end] == "(") - (masked[end] == ")")
            end += 1
        window = text[call.start() : end]
        if depth or not (_CLIENT_ID.search(window) and _CLIENT_SECRET.search(window)):
            continue
        if not (_OAUTH_CONSTRUCTOR.search(call.group()) or _OAUTH_CALL_CONTEXT.search(window)):
            continue
        result.append(ConfidentialClient(rel, text.count("\n", 0, call.start()) + 1, window))
    return result


def _config_confidential_clients(text: str, rel: str) -> list[ConfidentialClient]:
    """A client-secret key under an OAuth/OIDC configuration path; its value is never read out."""
    if rel.endswith(".properties"):
        text = re.sub(r"(?m)^\s*[#!].*$", "", text)
        return [
            ConfidentialClient(rel, number, line)
            for number, line in enumerate(text.splitlines(), 1)
            if (match := re.match(r"\s*([\w.-]+)\s*[=:]\s*\S", line))
            and _CLIENT_SECRET.search(match[1].split(".")[-1])
            and _CONFIG_CONTEXT.search(match[1])
        ]
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
            # A client ID beside the secret identifies an OAuth client registration as well.
            sibling_id = any(isinstance(k, yaml.ScalarNode) and _CLIENT_ID.search(k.value) for k, _v in node.value)
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    continue
                context = ".".join((*path, key.value))
                if (
                    _CLIENT_SECRET.search(key.value.split(".")[-1])
                    and (_CONFIG_CONTEXT.search(context) or sibling_id)
                    and isinstance(value, yaml.ScalarNode)
                    and value.value.strip()
                ):
                    block = text[node.start_mark.index : node.end_mark.index]
                    result.append(ConfidentialClient(rel, key.start_mark.line + 1, block))
                walk(value, (*path, key.value), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                walk(value, path, depth + 1)

    walk(root)
    return result


def discover_confidential_clients(repo_root: Path) -> list[ConfidentialClient]:
    """OAuth/OIDC clients configured with an ID and secret, found without fetching anything."""
    result = []
    for rel, suffix, text in _runtime_files(repo_root):
        if not _CLIENT_SECRET.search(text):
            continue
        result.extend(
            _config_confidential_clients(text, rel)
            if suffix in _CONFIG_EXT
            else _source_confidential_clients(text, rel)
        )
    return sorted(set(result), key=lambda c: (c.file, c.line))


def _masked(text: str) -> str:
    """Blank strings and comments, keeping offsets and line numbers."""
    code = list(text)
    for token in _LEX.finditer(text):
        code[token.start() : token.end()] = ["\n" if c == "\n" else " " for c in token.group()]
    return "".join(code)


def _balanced(masked: str, index: int) -> int:
    """Offset after the bracket that closes the one at `index`; -1 when it never closes."""
    depth = 0
    for i in range(index, len(masked)):
        if masked[i] in "({[":
            depth += 1
        elif masked[i] in ")}]":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _statement_end(masked: str, index: int) -> int:
    depth = 0
    for i in range(index, len(masked)):
        depth += (masked[i] in "({[") - (masked[i] in ")}]")
        if depth <= 0 and masked[i] in ";\n":
            return i
    return len(masked)


def _definitions(masked: str) -> list[tuple[str, re.Match]]:
    return [
        (name, match)
        for match in _DEFINITION.finditer(masked)
        if (name := match.group(match.lastgroup)) not in _NOT_FUNCTIONS
    ]


def _body_end(masked: str, match: re.Match) -> int:
    """End offset of a definition's body; -1 when the header has no delimitable body."""
    header = match.group()
    if header.startswith("def "):
        close = _balanced(masked, match.end() - 1)
        line_start = masked.rfind("\n", 0, match.start()) + 1
        indent = match.start() - line_start
        pos = masked.find("\n", close) if close != -1 else -1
        while pos != -1:
            nxt = masked.find("\n", pos + 1)
            line = masked[pos + 1 : nxt if nxt != -1 else len(masked)]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                return pos + 1
            pos = nxt
        return len(masked) if close != -1 else -1
    if header.endswith("{"):
        return _balanced(masked, match.end() - 1)
    index = match.end()
    if header.endswith("("):
        index = _balanced(masked, index - 1)
    elif header.endswith("function"):
        paren = masked.find("(", index)
        index = _balanced(masked, paren) if paren != -1 else -1
    if index == -1:
        return -1
    if header.endswith("=>"):
        index += len(masked[index:]) - len(masked[index:].lstrip())
        return _balanced(masked, index) if masked[index : index + 1] == "{" else _statement_end(masked, index)
    # Return types and `throws` clauses may precede the brace; `=` starts an expression body.
    brace = re.compile(r"[^{;=]*\{").match(masked, index)
    return _balanced(masked, brace.end() - 1) if brace else -1


def _enclosing_function(masked: str, line: int) -> str | None:
    """Name of the innermost function whose body contains the line."""
    offset = 0
    for _ in range(line - 1):
        offset = masked.find("\n", offset) + 1
        if not offset:
            return None
    offset += len(masked[offset:].split("\n", 1)[0]) - len(masked[offset:].split("\n", 1)[0].lstrip())
    before = [(name, match) for name, match in _definitions(masked) if match.start() <= offset]
    for name, match in reversed(before[-_MAX_DEFINITIONS:]):
        end = _body_end(masked, match)
        if end != -1 and offset < end:
            return name
    return None


def _call_lines(masked: str, name: str) -> list[tuple[int, int]]:
    """Line spans of calls to `name`, including member calls chained onto their result."""
    headers = {match.start(match.lastgroup) for found, match in _definitions(masked) if found == name}
    spans = []
    for call in re.finditer(r"(?<![\w$])" + re.escape(name) + r"\s*\(", masked):
        if call.start() in headers:
            continue
        end = _balanced(masked, call.end() - 1)
        while end != -1 and (chained := re.compile(r"\s*\??\.\s*[A-Za-z_$][\w$]*\s*\(").match(masked, end)):
            end = _balanced(masked, chained.end() - 1)
        if end != -1:
            spans.append((masked.count("\n", 0, call.start()) + 1, masked.count("\n", 0, end) + 1))
    return spans


def _read_source(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


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


def _authored_callers(integration: Integration, owner: str, flows: list[dict], root: Path, masked: dict) -> list[dict]:
    """Authored outbound flows of the owner whose evidence calls the function that makes this request."""
    if integration.configured or Path(integration.file).suffix not in _SOURCE_EXT:
        return []

    def source(rel: str) -> str:
        if rel not in masked:
            masked[rel] = _masked(_read_source(root, rel))
        return masked[rel]

    name = _enclosing_function(source(integration.file), integration.line)
    if not name:
        return []
    spans: dict[str, list[tuple[int, int]]] = {}
    covering = []
    for flow in flows:
        if flow.get("from") != owner or flow.get("to") != "external" or not flow.get("to_entity"):
            continue
        if _written_by_reconcile(flow):
            continue
        for row in flow.get("evidence") or []:
            rel, line = str(row.get("file") or ""), row.get("line")
            if Path(rel).suffix not in _SOURCE_EXT or not isinstance(line, int):
                continue
            if rel not in spans:
                spans[rel] = _call_lines(source(rel), name)
            if any(first <= line <= last for first, last in spans[rel]):
                covering.append(flow)
                break
    return covering


_SIGN_IN_SCHEMES = frozenset({"oauth2", "oidc", "saml"})


def _sign_in_flows(flows: list[dict], entities: list[dict]) -> list[dict]:
    """Flows in which a component sends the user to an identity provider to sign in."""
    providers = {e["id"] for e in entities if e.get("kind") == "identity-provider"}
    return [
        f
        for f in flows
        if f.get("to") == "external"
        and f.get("to_entity") in providers
        and not f.get("interaction")
        and (f.get("authentication") or {}).get("scheme") in _SIGN_IN_SCHEMES
    ]


def _sign_in_provider(owner: str, flows: list[dict], entities: list[dict]) -> dict | None:
    """The one identity provider this component, or else the whole system, signs users in at.

    A profile request presents the access token that provider issued, so it
    calls that provider's API rather than an unrelated third party. Several
    candidate providers stay ambiguous and keep their own entities.
    """
    sign_ins = _sign_in_flows(flows, entities)
    for candidates in (
        {f["to_entity"] for f in sign_ins if f.get("from") == owner},
        {f["to_entity"] for f in sign_ins},
    ):
        if len(candidates) == 1:
            provider = candidates.pop()
            return next(e for e in entities if e["id"] == provider)
    return None


def reconcile_sign_in_results(flows: list[dict], entities: list[dict]) -> list[str]:
    """Give the provider's redirect back to the client the sign-in step's protocol.

    The authorization response (or SAML assertion post) completes the sign-in:
    the provider has authenticated the user and delivers the result to the
    client's registered redirect URI. `none` or `unknown` there contradicts the
    sign-in step drawn beside it, so the step takes the sign-in's scheme and
    grant with its own evidence. Any other authored scheme stays (FE-15).
    """
    changed = []
    sign_ins = _sign_in_flows(flows, entities)
    for flow in flows:
        auth = flow.get("authentication") or {}
        if (
            flow.get("from") != "external"
            or flow.get("interaction")
            or auth.get("scheme", "unknown")
            not in {
                "none",
                "unknown",
            }
        ):
            continue
        matches = [
            s
            for s in sign_ins
            if s.get("to_entity") == flow.get("from_entity")
            and s.get("from") == flow.get("to")
            and (s.get("protocol_group") or None) == (flow.get("protocol_group") or None)
        ]
        schemes = {
            ((s.get("authentication") or {}).get("scheme"), (s.get("authentication") or {}).get("flow"))
            for s in matches
        }
        if len(schemes) != 1:
            continue
        scheme, grant = schemes.pop()
        sign_in = matches[0]["authentication"]
        evidence = flow.get("evidence") or auth.get("evidence") or sign_in.get("evidence") or []
        flow["authentication"] = {
            "scheme": scheme,
            **({"flow": grant} if grant else {}),
            "scope": "Completes the sign-in: the provider returns its result to the client's registered redirect URI",
            **({"transport": sign_in["transport"]} if sign_in.get("transport") else {}),
            "evidence": evidence,
        }
        changed.append(flow["id"])
    return changed


def reconcile_confidential_clients(
    repo_root: Path, components: list[dict], flows: list[dict], entities: list[dict]
) -> list[str]:
    """Draw the token request a library performs for a client configured with its ID and secret.

    The request goes to the provider the component, or else the system, signs
    users in at (`_sign_in_provider`); without one provider, or when the
    component already models a token request to it, nothing is added. The
    client authentication is what the configuration shows, the protocol and
    group those of the sign-in.
    """
    added = []
    for client in discover_confidential_clients(repo_root):
        try:
            owner = _owner(client.file, components)
        except ValueError:
            continue
        provider = _sign_in_provider(owner, flows, entities)
        auth = _client_authentication(client.window)
        if provider is None or auth is None:
            continue
        # A token request the component already draws, for instance from a token
        # URL in the same call, represents the client; a sign-in flow does not.
        if any(
            f.get("from") == owner
            and f.get("to") == "external"
            and (
                str(f.get("label") or "").removeprefix("Configured ") == "OAuth token exchange"
                or (f.get("authentication") or {}).get("scheme") in {"client-secret", "private-key", "mtls"}
            )
            for f in flows
        ):
            continue
        sign_ins = [f for f in _sign_in_flows(flows, entities) if f["to_entity"] == provider["id"]]
        protocol = next((f.get("protocol") for f in sign_ins if f.get("protocol")), "HTTPS")
        groups = {f.get("protocol_group") for f in sign_ins if f.get("protocol_group")}
        evidence = [{"file": client.file, "line": client.line}]
        if transport := _TRANSPORT.get(protocol):
            auth["transport"] = transport
        flow_id = f"df-{max((int(f['id'][3:]) for f in flows), default=0) + 1:03d}"
        flows.append(
            {
                "id": flow_id,
                "from": owner,
                "to": "external",
                "to_entity": provider["id"],
                "label": "OAuth token exchange",
                "protocol": protocol,
                "data_classification": "Confidential",
                "direction": "request-response",
                "evidence": evidence,
                "authentication": {**auth, "evidence": evidence},
                **({"protocol_group": groups.pop()} if len(groups) == 1 else {}),
                "provenance": "recon",
            }
        )
        added.append(flow_id)
    return added


def reconcile(repo_root: Path, components: list[dict], document: dict) -> dict:
    """Fill omitted providers/flows before boundary assessment; retain authored topology."""
    result = copy.deepcopy(document)
    integrations = discover(repo_root)
    if not integrations:
        flows, entities = result.get("data_flows") or [], result.get("external_entities") or []
        reconcile_sign_in_results(flows, entities)
        if flows and entities:
            reconcile_confidential_clients(repo_root, components, flows, entities)
        return result
    entities = result.setdefault("external_entities", [])
    flows = result.setdefault("data_flows", [])
    next_flow = max((int(f["id"][3:]) for f in flows), default=0) + 1
    root = repo_root.resolve()
    masked: dict[str, str] = {}
    # Sign-in providers first, so a profile request can join the provider it calls.
    for integration in sorted(integrations, key=lambda i: i.role == "OAuth profile request"):
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
        covering = _authored_callers(integration, owner, flows, root, masked)
        if len({f["to_entity"] for f in covering}) == 1:
            # The author modelled this request where its wrapper is called; record the URL there.
            covering[0]["evidence"] = (covering[0].get("evidence") or []) + [
                e for e in evidence if e not in (covering[0].get("evidence") or [])
            ]
            _fill_authentication(covering[0], integration, evidence)
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
        profile = integration.role == "OAuth profile request"
        provider = _sign_in_provider(owner, flows, entities) if profile and not matching else None
        if provider is not None:
            roles = provider.setdefault("service_roles", [])
            if not any(r.get("role") == "oauth-resource-server" for r in roles):
                roles.append({"role": "oauth-resource-server", "evidence": evidence})
            matching = [provider]
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
            entities.append(
                {
                    "id": entity_id,
                    "name": f"{'OAuth profile service' if profile else 'Identity provider'} · {integration.host}"[:80],
                    "kind": "external-service" if profile else "identity-provider",
                    "description": f"{integration.role}: {integration.authority}. Activation depends on deployment configuration."[
                        :240
                    ],
                    "evidence": evidence,
                    "service_roles": [{"role": _service_role(integration), "evidence": evidence}],
                }
            )
        existing = [f for f in flows if f.get("from") == owner and f.get("to") == "external" and same_evidence(f)]
        label = ("Configured " if integration.configured else "") + integration.role
        # An authored flow with this evidence already represents the integration,
        # whatever provenance its author chose; a generated one covers only its role.
        represented = [
            f
            for f in existing
            if f.get("to_entity") == entity_id and (not _written_by_reconcile(f) or f.get("label") == label)
        ]
        if represented:
            for flow in represented:
                _fill_authentication(flow, integration, evidence)
            continue
        generic = [f for f in existing if not f.get("to_entity")]
        if len(generic) == 1 and unambiguous_line:
            generic[0]["to_entity"] = entity_id
            _fill_authentication(generic[0], integration, evidence)
            continue
        authentication = integration_authentication(integration, evidence)
        groups = {
            f.get("protocol_group")
            for f in _sign_in_flows(flows, entities)
            if f.get("to_entity") == entity_id and f.get("from") == owner and f.get("protocol_group")
        }
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
                **({"authentication": authentication} if authentication else {}),
                **({"protocol_group": groups.pop()} if len(groups) == 1 else {}),
                "provenance": "recon",
            }
        )
        next_flow += 1
    reconcile_sign_in_results(flows, entities)
    reconcile_confidential_clients(repo_root, components, flows, entities)
    return result
