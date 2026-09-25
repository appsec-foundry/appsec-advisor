"""Tests for scripts/deployment_inventory.py — the scan-time input of the §2.2 deployment figure.

Every source reader gets a neutral repository, a variant with different names and a negative case. Repository
content is untrusted: values from `environment:` blocks, secret files and anything outside the root never reach
the inventory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import deployment_inventory as DI
import pytest

SHA = "0123456789abcdef0123456789abcdef01234567"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _dump(doc: dict) -> str:
    return json.dumps(doc)


# ---------------------------------------------------------------- Dockerfile
@pytest.mark.parametrize(
    "base,build,runtime",
    [("node:24-slim", "node:24", "Node.js 24"), ("eclipse-temurin:21-jre", "gradle:8.10-jdk21", "Java 21")],
    ids=["node", "java"],
)
def test_dockerfile_runtime_base_user_and_copied_secrets(tmp_path: Path, base: str, build: str, runtime: str):
    _write(
        tmp_path,
        "Dockerfile",
        f'FROM {build} AS b\nRUN make\nFROM {base}\nCOPY . /srv\nUSER 1001\nEXPOSE 8080\nCMD ["/srv/run.sh"]\n',
    )
    _write(tmp_path, "signing.key", "not a real key")
    _write(tmp_path, "vault-token.txt", "x")
    _write(tmp_path, ".dockerignore", "vault-token.txt\n")
    rt = DI.scan_runtime(tmp_path)
    assert rt["base"] == {"image": base, "pin": "tag", "line": 3}
    assert rt["build_stages"][0]["image"] == build
    assert rt["user"] == {"value": "1001", "line": 5}
    assert rt["expose"] == ["8080"] and rt["command"] == "run.sh" and rt["runtime_label"] == runtime
    # The name of a sensitive file copied into the image is reported; an ignored one is not; no content ever.
    assert rt["copies_repository"] == {"line": 4, "sensitive": ["signing.key"]}
    assert "not a real key" not in _dump(rt)


def test_dockerfile_variant_name_and_no_dockerfile(tmp_path: Path):
    assert DI.scan_runtime(tmp_path) is None
    _write(tmp_path, "Dockerfile.base", "FROM python:3.12\n")
    rt = DI.scan_runtime(tmp_path)
    assert rt["dockerfile"] == "Dockerfile.base" and rt["user"] is None and rt["runtime_label"] == "Python 3.12"


def test_dockerfile_symlink_outside_the_root_is_ignored(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "Dockerfile", "FROM secret-base:1.0.0\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside / "Dockerfile", repo / "Dockerfile")
    assert DI.scan_runtime(repo) is None


@pytest.mark.parametrize(
    "image,pin",
    [
        ("a/b@sha256:" + "a" * 64, "digest"),
        ("a/b:1.2.3", "version"),
        ("a/b:1.2", "tag"),
        ("a/b:latest", "floating"),
        ("a/b", "floating"),
    ],
)
def test_image_pin(image: str, pin: str):
    assert DI.image_pin(image) == pin


# ---------------------------------------------------------------- docker compose
@pytest.mark.parametrize("names", [("gateway", "api"), ("front-door", "catalog")], ids=["neutral", "renamed"])
def test_compose_default_file_services_ports_and_no_environment_values(tmp_path: Path, names):
    gw, app = names
    _write(
        tmp_path,
        "compose.yaml",
        f'services:\n  {gw}:\n    image: nginx:1.27.0\n    ports:\n      - "80:80"\n'
        f'  {app}:\n    build: .\n    privileged: true\n    ports:\n      - "127.0.0.1:9000:9000"\n'
        "    environment:\n      DB_PASSWORD: hunter2-value\n",
    )
    record, env = DI.scan_compose(tmp_path)
    assert record["file"] == "compose.yaml" and [s["name"] for s in record["services"]] == [gw, app]
    assert env["platform"] == "compose" and env["tree"]["children"][0]["role"] == "entry"
    facts = {n["title"]: [f["text"] for f in n["facts"]] for n in env["tree"]["children"]}
    assert facts[gw] == ["host port :80 on every interface"]
    assert facts[app] == ["privileged container"]  # the loopback-only port is not reported
    assert [n["kind"] for n in env["tree"]["children"]] == ["service", "workload"]
    assert "hunter2-value" not in _dump(record) + _dump(env)


def test_compose_variant_only_is_not_the_deployment(tmp_path: Path):
    """Negative: a test compose file is not what `docker compose` runs without -f."""
    _write(tmp_path, "docker-compose.test.yml", "services:\n  sut:\n    image: example/sut:latest\n")
    assert DI.scan_compose(tmp_path) == (None, None)


# ---------------------------------------------------------------- Kubernetes and OpenShift
MANIFESTS = """apiVersion: route.openshift.io/v1
kind: Route
metadata: {{name: web, namespace: {ns}}}
spec:
  host: {host}
  to: {{kind: Service, name: {svc}}}
  tls: {{termination: edge, insecureEdgeTerminationPolicy: Allow}}
---
apiVersion: v1
kind: Service
metadata: {{name: {svc}, namespace: {ns}}}
spec:
  selector: {{app: {app}}}
  ports: [{{port: 8080, targetPort: 3000}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {app}, namespace: {ns}}}
spec:
  replicas: 2
  template:
    metadata: {{labels: {{app: {app}}}}}
    spec:
      containers:
        - name: {app}
          image: registry.example/{app}:latest
          securityContext: {{runAsNonRoot: true, allowPrivilegeEscalation: false}}
          envFrom: [{{secretRef: {{name: {app}-keys}}}}]
          env: [{{name: TOKEN, value: plain-secret-value}}]
"""


@pytest.mark.parametrize(
    "names",
    [("shop", "web-svc", "storefront", "shop.example.test"), ("billing", "pay-svc", "ledger", "pay.example.test")],
    ids=["neutral", "renamed"],
)
def test_openshift_route_service_workload_chain(tmp_path: Path, names):
    ns, svc, app, host = names
    _write(tmp_path, "deploy/app.yaml", MANIFESTS.format(ns=ns, svc=svc, app=app, host=host))
    [env] = DI.scan_manifests(tmp_path)
    assert env["platform"] == "openshift" and env["label"] == f"OpenShift · namespace {ns}"
    route, service, workload = env["tree"]["children"]
    assert route["role"] == "entry" and route["title"] == f"Route {host}"
    assert route["facts"][0]["text"].startswith("plain HTTP also accepted") and route["facts"][0]["tone"] == "weak"
    assert service["facts"][0]["text"] == "ClusterIP :8080 → 3000"
    assert workload["kind"] == "workload" and workload["image"] == f"registry.example/{app}:latest"
    texts = [f["text"] for f in workload["facts"]]
    assert "writable root file system" in texts and "runAsNonRoot not set" not in texts
    assert env["tree"]["facts"][0]["text"].startswith("no NetworkPolicy in these manifests")
    assert "plain-secret-value" not in _dump(env)


def test_network_policy_and_ingress_tls(tmp_path: Path):
    """Negative: with a NetworkPolicy the namespace fact disappears; an Ingress without TLS is weak."""
    text = MANIFESTS.format(ns="shop", svc="web-svc", app="storefront", host="h").replace(
        "route.openshift.io/v1", "networking.k8s.io/v1"
    )
    text = text.replace("kind: Route", "kind: Ingress").replace(
        "  to: {kind: Service, name: web-svc}\n",
        "  rules: [{http: {paths: [{backend: {service: {name: web-svc}}}]}}]\n",
    )
    text = text.replace("  tls: {termination: edge, insecureEdgeTerminationPolicy: Allow}\n", "")
    text += "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny, namespace: shop}\nspec: {}\n"
    _write(tmp_path, "k8s/app.yaml", text)
    [env] = DI.scan_manifests(tmp_path)
    assert env["platform"] == "kubernetes" and env["tree"]["facts"] == []
    assert env["tree"]["children"][0]["facts"] == [
        {"text": "no TLS", "tone": "weak", "source": {"file": "k8s/app.yaml", "line": 2}}
    ]


def test_helm_templates_are_not_read_as_manifests(tmp_path: Path):
    _write(tmp_path, "chart/Chart.yaml", "name: web\n")
    _write(
        tmp_path,
        "chart/values.yaml",
        "image:\n  repository: example/web\n  tag: latest\nservice:\n  port: 80\ningress:\n  enabled: true\n",
    )
    _write(
        tmp_path,
        "chart/templates/deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: {{ .Release.Name }}}\n",
    )
    assert DI.scan_manifests(tmp_path) == []
    [env] = DI.scan_helm(tmp_path)
    assert env["label"] == "Kubernetes · Helm chart web"
    ingress, service, pod = env["tree"]["children"]
    assert [f["text"] for f in ingress["facts"]] == ["no TLS on the ingress", "ingress enabled"]
    assert pod["image"] == "example/web:latest" and pod["facts"][0]["text"] == "web:latest floats"


def test_gitlab_auto_deploy_and_ci_facts(tmp_path: Path):
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        'include:\n  - template: Auto-DevOps.gitlab-ci.yml\nvariables:\n  TEST_DISABLED: "true"\n  DAST_DISABLED: "true"\n',
    )
    _write(tmp_path, ".gitlab/auto-deploy-values.yaml", "service:\n  internalPort: 3000\n  externalPort: 3000\n")
    [env] = DI.scan_gitlab_auto_deploy(tmp_path)
    assert env["label"] == "Kubernetes · GitLab Auto Deploy" and env["tree"]["children"][0]["title"] == "Service :3000"
    [ci] = DI.scan_ci(tmp_path)
    assert ci["system"] == "GitLab CI" and ci["facts"][0]["text"] == "test, dast disabled"
    assert ci["publishes"] == ["GitLab registry", "Kubernetes (auto deploy)"]


def test_github_actions_pinning_and_publish_target(tmp_path: Path):
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: example/scan@{SHA}\n"
        "      - uses: aws-actions/amazon-ecr-login@v2\n      - run: docker push 1.dkr.ecr.eu-west-1.amazonaws.com/app\n",
    )
    [ci] = DI.scan_ci(tmp_path)
    assert ci["facts"][0] == {"text": "2 of 3 actions not SHA-pinned", "tone": "decision"}
    assert ci["publishes"] == ["Amazon ECR"]


# ---------------------------------------------------------------- Terraform (AWS)
TF = """provider "aws" {{
  region = "eu-west-1"
}}
resource "aws_vpc" "{p}" {{
  cidr_block = "10.1.0.0/16"
}}
resource "aws_subnet" "{p}_pub" {{
  vpc_id = aws_vpc.{p}.id
  cidr_block = "10.1.1.0/24"
  map_public_ip_on_launch = true
}}
resource "aws_subnet" "{p}_priv" {{
  vpc_id = aws_vpc.{p}.id
  cidr_block = "10.1.2.0/24"
}}
resource "aws_security_group" "{p}_lb" {{
  ingress {{
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
resource "aws_lb" "{p}" {{
  internal = false
  subnets = [aws_subnet.{p}_pub.id]
  security_groups = [aws_security_group.{p}_lb.id]
}}
resource "aws_lb_listener" "{p}" {{
  load_balancer_arn = aws_lb.{p}.arn
  port = {port}
  protocol = "{proto}"
}}
resource "aws_ecr_repository" "{p}" {{
  name = "{p}-image"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {{
    scan_on_push = true
  }}
}}
resource "aws_iam_role" "{p}_task" {{
  name = "{p}-task"
}}
resource "aws_iam_role_policy" "{p}_task" {{
  role = aws_iam_role.{p}_task.id
  policy = jsonencode({{ Statement = [{{ Effect = "Allow", Action = "dynamodb:*", Resource = "*" }}] }})
}}
resource "aws_ecs_task_definition" "{p}" {{
  task_role_arn = aws_iam_role.{p}_task.arn
  container_definitions = jsonencode([{{ image = "${{aws_ecr_repository.{p}.repository_url}}:1.4.0" }}])
}}
resource "aws_ecs_service" "{p}" {{
  task_definition = aws_ecs_task_definition.{p}.arn
  launch_type = "FARGATE"
  desired_count = 3
  network_configuration {{
    subnets = [aws_subnet.{p}_priv.id]
  }}
}}
"""


@pytest.mark.parametrize("prefix", ["shop", "ledger"], ids=["neutral", "renamed"])
def test_terraform_places_resources_and_states_rule_facts(tmp_path: Path, prefix: str):
    _write(tmp_path, "infra/main.tf", TF.format(p=prefix, port=80, proto="HTTP"))
    [env] = DI.scan_terraform(tmp_path)
    assert env["label"] == "AWS · eu-west-1" and env["source"] == "infra/main.tf"
    [vpc] = env["tree"]["children"][:1]
    public, private = vpc["children"]
    assert public["title"] == "public subnet 10.1.1.0/24" and private["title"] == "private subnet 10.1.2.0/24"
    [lb] = public["children"]
    assert lb["role"] == "entry"
    assert [f["text"] for f in lb["facts"]] == ["HTTP :80 from 0.0.0.0/0 — no TLS", "no WAF in this Terraform"]
    [ecs] = private["children"]
    assert ecs["kind"] == "workload" and ecs["title"] == "ECS Fargate · 3 tasks"
    assert ecs["image"] == f"ECR {prefix}-image:1.4.0"
    assert ecs["facts"][0] == {
        "text": "task role may use dynamodb:* on every resource",
        "tone": "weak",
        "source": {"file": "infra/main.tf", "line": 41},
    }
    regional = env["tree"]["children"][-1]
    assert [n["title"] for n in regional["children"]] == [f"ECR {prefix}-image"] and regional["children"][0][
        "facts"
    ] == []


def test_terraform_tls_and_waf_remove_the_facts(tmp_path: Path):
    """Negative: an HTTPS listener and a WAF association leave nothing to flag."""
    text = TF.format(p="shop", port=443, proto="HTTPS")
    text += 'resource "aws_wafv2_web_acl_association" "shop" {\n  resource_arn = aws_lb.shop.arn\n}\n'
    _write(tmp_path, "main.tf", text)
    [env] = DI.scan_terraform(tmp_path)
    lb = env["tree"]["children"][0]["children"][0]["children"][0]
    assert lb["facts"] == [{"text": "HTTPS :443", "tone": "neutral", "source": {"file": "main.tf", "line": 21}}]


def test_terraform_without_aws_resources_is_no_environment(tmp_path: Path):
    _write(tmp_path, "main.tf", 'resource "null_resource" "x" {\n}\n')
    assert DI.scan_terraform(tmp_path) == []


# ---------------------------------------------------------------- dependencies, bounds, CLI
def test_dependencies_ranges_lockfile_and_roles(tmp_path: Path):
    _write(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"express": "^4.21.0", "jsonwebtoken": "9.0.2", "left-pad": "1.3.0"}}),
    )
    deps, packages = DI.scan_dependencies(tmp_path)
    assert deps == {"manifests": 1, "declared": 3, "ranges": 1, "lockfile": False}
    assert packages == [
        {
            "manifest": "package.json",
            "entries": [
                {"name": "express", "version": "^4.21.0", "role": "framework"},
                {"name": "jsonwebtoken", "version": "9.0.2", "role": "identity"},
            ],
        }
    ]
    _write(tmp_path, "package-lock.json", "{}")
    assert DI.scan_dependencies(tmp_path)[0]["lockfile"] is True


def test_oversize_and_deep_files_are_skipped(tmp_path: Path):
    _write(tmp_path, "a/b/c/d/e/deep.tf", 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
    _write(tmp_path, "big.tf", 'resource "aws_s3_bucket" "b" {\n' + "#" * (DI.MAX_BYTES + 1) + "\n}\n")
    assert DI._tf_blocks(tmp_path)[0] == {}


def test_cli_writes_a_schema_valid_inventory(tmp_path: Path):
    repo = tmp_path / "repo"
    _write(repo, "Dockerfile", "FROM node:24\n")
    _write(repo, "main.tf", TF.format(p="shop", port=80, proto="HTTP"))
    out = tmp_path / ".deployment-inventory.json"
    assert DI.main(["--repo-root", str(repo), "--output", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert DI.validation_errors(doc) == [] and doc["environments"][0]["platform"] == "aws"
    assert str(tmp_path) not in out.read_text()  # no absolute local path


def test_cli_writes_nothing_when_the_output_breaks_the_schema(tmp_path: Path, monkeypatch):
    """Negative: an invalid inventory is never written, so the composer keeps the Mermaid diagram."""
    monkeypatch.setattr(DI, "build_inventory", lambda root: {"schema_version": 2})
    out = tmp_path / ".deployment-inventory.json"
    assert DI.main(["--repo-root", str(tmp_path), "--output", str(out)]) == 1
    assert not out.exists()
    assert DI.main(["--repo-root", str(tmp_path / "missing"), "--output", str(out)]) == 2


# ---------------------------------------------------------------- regressions: copied secrets, Helm tags, malformed manifests
@pytest.mark.parametrize(
    "ignore,reported",
    [
        ("*.key\n", ["db-credentials.json", "encryptionkeys/"]),
        ("**/*.key\n!ci.key\n/db-credentials.json\n", ["ci.key", "encryptionkeys/"]),
    ],
    ids=["glob", "negation"],
)
def test_copied_secrets_follow_dockerignore_patterns_and_whole_words(tmp_path: Path, ignore: str, reported: list):
    _write(tmp_path, "Dockerfile", "FROM node:24-slim\nCOPY . /app\n")
    for name in ("server.key", "ci.key", "db-credentials.json", "encryptionkeys/a", "keycloak/realm.json"):
        _write(tmp_path, name, "x")
    for name in ("monkeypatch.py", "tokenizer.py", "credits.md"):
        _write(tmp_path, name, "x")
    _write(tmp_path, ".dockerignore", ignore)
    assert DI.scan_runtime(tmp_path)["copies_repository"]["sensitive"] == reported


def test_a_copied_env_file_is_reported_unless_ignored(tmp_path: Path):
    _write(tmp_path, "Dockerfile", "FROM node:24-slim\nCOPY . /app\n")
    _write(tmp_path, ".env", "X=1")
    _write(tmp_path, ".env.example", "X=")
    assert DI.scan_runtime(tmp_path)["copies_repository"]["sensitive"] == [".env"]
    _write(tmp_path, ".dockerignore", ".env*\n")
    assert DI.scan_runtime(tmp_path)["copies_repository"]["sensitive"] == []


@pytest.mark.parametrize("tag_line", ["", '  tag: ""\n'], ids=["missing", "empty"])
def test_helm_image_without_tag_uses_the_chart_app_version(tmp_path: Path, tag_line: str):
    _write(tmp_path, "chart/Chart.yaml", 'name: web\nappVersion: "2.4.1"\n')
    _write(tmp_path, "chart/values.yaml", f"image:\n  repository: example/web\n{tag_line}service:\n  port: 80\n")
    [env] = DI.scan_helm(tmp_path)
    pod = env["tree"]["children"][-1]
    assert pod["image"] == "example/web:2.4.1" and not [f for f in pod["facts"] if "floats" in f["text"]]
    # Negative: without an appVersion the tag is unknown, which is not the same as floating.
    _write(tmp_path, "chart/Chart.yaml", "name: web\n")
    pod = DI.scan_helm(tmp_path)[0]["tree"]["children"][-1]
    assert "image" not in pod and not [f for f in pod["facts"] if "floats" in f["text"]]
    assert "example/web" in pod["note"]
    assert DI.validation_errors(DI.build_inventory(tmp_path)) == []


@pytest.mark.parametrize(
    "bad",
    [
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: odd}\nspec:\n  template:\n    metadata:\n      labels: [x]\n",
        "apiVersion: v1\nkind: [Service]\nmetadata: {name: odd}\n",
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: odd}\nspec:\n  rules: [plain]\n",
    ],
    ids=["labels-list", "kind-list", "rule-string"],
)
def test_one_malformed_manifest_does_not_drop_the_others(tmp_path: Path, bad: str):
    _write(tmp_path, "k8s/app.yaml", MANIFESTS.format(ns="shop", svc="web-svc", app="web", host="web.example.test"))
    _write(tmp_path, "k8s/odd.yaml", bad)
    [env] = DI.scan_manifests(tmp_path)
    assert "Deployment web" in json.dumps(env)
    assert DI.validation_errors(DI.build_inventory(tmp_path)) == []


def test_manifest_alias_expansion_is_bounded(tmp_path: Path):
    lines = ['x0: &a0 ["v1"]'] + [f"x{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 7)]
    _write(tmp_path, "k8s/bomb.yaml", "\n".join(lines) + "\napiVersion: *a6\nkind: Deployment\nmetadata: {name: b}\n")
    _write(tmp_path, "k8s/app.yaml", MANIFESTS.format(ns="shop", svc="web-svc", app="web", host="web.example.test"))
    [env] = DI.scan_manifests(tmp_path)
    assert "Deployment b" not in json.dumps(env) and "Deployment web" in json.dumps(env)
