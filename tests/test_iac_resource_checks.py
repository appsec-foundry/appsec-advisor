"""Rule semantics of the Compose, Kubernetes, Helm values and Terraform
evaluators, and the rule that every weak deployment-inventory fact has a check."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import analyzers.config_iac_scanner as scanner
import analyzers.deployment_inventory as di
import analyzers.iac_resource_checks as irc
import pytest
import yaml

P = Path("x")
ROOT = Path(__file__).resolve().parents[1]
CATALOG = yaml.safe_load((ROOT / "data" / "config-iac-checks.yaml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- shared rules


@pytest.mark.parametrize(
    "name",
    [
        "DB_PASSWORD",
        "POSTGRES_PASSWORD",
        "jwtSigningKey",
        "AWS_SECRET_ACCESS_KEY",
        "api_key",
        "API-KEY",
        "service_token",
        "VAULT_DEV_ROOT_TOKEN_ID",
        "master_password",
        "client_secret",
        "passphrase",
    ],
)
def test_credential_names_are_recognised(name):
    assert irc.is_secret_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "POSTGRES_PASSWORD_FILE",
        "SECRET_NAME",
        "TOKEN_URL",
        "token_endpoint_auth_method",
        "password_length",
        "JWT_SECRET_ROTATION",
        "kms_key_id",
        "SERVICE_NAME",
        "MAX_TOKENS",
        "username",
        "public_key",
    ],
)
def test_names_that_describe_or_locate_a_secret_are_not_credentials(name):
    assert not irc.is_secret_name(name)


@pytest.mark.parametrize("value", ["hunter2", "changeme", "AKIAIOSFODNN7EXAMPLE", "fixture-local-admin-token"])
def test_committed_strings_are_literals_placeholder_words_included(value):
    assert irc.is_literal_secret(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "${DB_PASSWORD}",
        "$DB_PASSWORD",
        "${VAR:-fallback}",
        "{{ .Values.password }}",
        "<password>",
        "/run/secrets/db_password",
        "true",
        None,
        1234,
        False,
    ],
)
def test_references_empty_and_non_strings_are_not_literals(value):
    assert not irc.is_literal_secret(value)


# --------------------------------------------------------------------------- Compose


COMPOSE_ENV_MAP = """
x-base: &base
  image: app
services:
  api:
    <<: *base
    environment:
      SERVICE_NAME: api
      DB_PASSWORD: s3cr3t-value
"""


@pytest.mark.parametrize(
    "text,line",
    [
        (COMPOSE_ENV_MAP, 9),
        ("services:\n  api:\n    environment:\n      - SERVICE_NAME=api\n      - API_KEY=abc123xyz\n", 5),
    ],
)
def test_compose_environment_literal_is_found_and_masked(text, line):
    found = irc.compose_environment_secret_literal(text, P)
    assert found is not None and found[0] == line
    assert "s3cr3t-value" not in found[1] and "abc123xyz" not in found[1]
    assert irc.MASK in found[1]


@pytest.mark.parametrize(
    "text",
    [
        "services:\n  api:\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n",
        "services:\n  api:\n    environment:\n      - DB_PASSWORD\n      - DB_PASSWORD_FILE=/run/secrets/db\n",
        "services:\n  api:\n    image: app\n",
        "not: [valid",
        "- a\n- b\n",
    ],
)
def test_compose_environment_without_literal_is_clean(text):
    assert irc.compose_environment_secret_literal(text, P) is None


@pytest.mark.parametrize(
    "ports",
    [
        '["5432:5432"]',
        '["0.0.0.0:6379:6379"]',
        '["27017"]',
        '["${PORT}:5432"]',
        '["5000-5500:5000-5500"]',
        "[{target: 3306, published: 3306}]",
        '["22/tcp"]',
    ],
)
def test_compose_sensitive_port_on_every_interface_is_found(ports):
    text = f"services:\n  db:\n    image: db\n    ports: {ports}\n"
    assert irc.compose_sensitive_port_on_all_interfaces(text, P) is not None


@pytest.mark.parametrize(
    "ports",
    [
        '["127.0.0.1:5432:5432"]',
        '["[::1]:6379:6379"]',
        '["8080:8080", "443:443"]',
        "[{target: 3306, host_ip: 127.0.0.1}]",
    ],
)
def test_compose_loopback_or_web_ports_are_clean(ports):
    text = f"services:\n  db:\n    image: db\n    ports: {ports}\n"
    assert irc.compose_sensitive_port_on_all_interfaces(text, P) is None


# --------------------------------------------------------------------------- Kubernetes


def _deployment(pod_extra: str = "", container_extra: str = "", kind: str = "Deployment") -> str:
    body = f"""apiVersion: apps/v1
kind: {kind}
metadata:
  name: web
spec:
  template:
    spec:
{pod_extra}      containers:
        - name: web
          image: nginx
{container_extra}"""
    return body


HARDENED_POD = "      securityContext:\n        runAsNonRoot: true\n        runAsUser: 10001\n"


def test_kubernetes_hardened_workload_has_no_violation():
    text = _deployment(HARDENED_POD) + "---\napiVersion: v1\nkind: Service\nmetadata: {name: web}\n"
    for name, evaluator in irc.EVALUATORS.items():
        if name.startswith("kubernetes"):
            assert evaluator(text, P) is None, name


def test_kubernetes_privileged_container():
    text = _deployment(HARDENED_POD, "          securityContext:\n            privileged: true\n")
    assert irc.kubernetes_privileged_container(text, P) == (15, "Deployment/web container web: privileged: true")


@pytest.mark.parametrize("key", ["hostNetwork", "hostPID", "hostIPC"])
def test_kubernetes_host_namespace(key):
    found = irc.kubernetes_host_namespace(_deployment(HARDENED_POD + f"      {key}: true\n"), P)
    assert found is not None and key in found[1]


@pytest.mark.parametrize(
    "pod,container,violates",
    [
        ("", "", True),
        (HARDENED_POD, "", False),
        ("", "          securityContext:\n            runAsUser: 1000\n", False),
        (HARDENED_POD, "          securityContext:\n            runAsNonRoot: false\n            runAsUser: 0\n", True),
        ("      securityContext:\n        runAsNonRoot: true\n", "", False),
    ],
)
def test_kubernetes_root_prevention_follows_pod_and_container_context(pod, container, violates):
    assert (irc.kubernetes_root_not_prevented(_deployment(pod, container), P) is not None) is violates


def test_kubernetes_cronjob_and_list_wrappers_are_evaluated():
    cron = """apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{name: job, image: x, securityContext: {privileged: true}}]
"""
    listed = "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: p}\n    spec: {hostPID: true, containers: [{name: c, image: x}]}\n"
    assert irc.kubernetes_privileged_container(cron, P) is not None
    assert irc.kubernetes_host_namespace(listed, P) is not None


def test_kubernetes_env_literal_is_found_masked_and_references_are_clean():
    env = (
        "          env:\n"
        "            - name: DB_PASSWORD\n"
        "              valueFrom: {secretKeyRef: {name: db, key: password}}\n"
        "            - name: API_TOKEN\n"
        "              value: tok-123456\n"
    )
    found = irc.kubernetes_env_secret_literal(_deployment(HARDENED_POD, env), P)
    assert found is not None and "API_TOKEN" in found[1] and "tok-123456" not in found[1]


@pytest.mark.parametrize(
    "text",
    [
        "services:\n  api:\n    privileged: true\n",
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {password: x}\n",
        "{{- if .Values.enabled }}\napiVersion: apps/v1\nkind: Deployment\n{{- end }}\n",
    ],
)
def test_non_workload_yaml_and_helm_templates_are_not_judged(text):
    for name, evaluator in irc.EVALUATORS.items():
        if name.startswith("kubernetes"):
            assert evaluator(text, P) is None, name


# --------------------------------------------------------------------------- Terraform


def _sg(ingress: str) -> str:
    return f'resource "aws_security_group" "app" {{\n  name = "app"\n  ingress {{\n{ingress}  }}\n}}\n'


@pytest.mark.parametrize(
    "text",
    [
        _sg('    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'),
        _sg('    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    ipv6_cidr_blocks = ["::/0"]\n'),
        _sg(
            '    from_port = 5000\n    to_port = 6000\n    protocol = "tcp"\n    cidr_blocks = [\n      "10.0.0.0/8",\n      "0.0.0.0/0",\n    ]\n'
        ),
        'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 3389\n  to_port = 3389\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
        'resource "aws_vpc_security_group_ingress_rule" "r" {\n  cidr_ipv4 = "0.0.0.0/0"\n  from_port = 6379\n  to_port = 6379\n  ip_protocol = "tcp"\n}\n',
        'resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22", "80"]\n  }\n}\n',
        'resource "azurerm_network_security_rule" "r" {\n  direction = "Inbound"\n  access = "Allow"\n  source_address_prefix = "Internet"\n  destination_port_range = "3389"\n}\n',
    ],
)
def test_terraform_internet_ingress_to_sensitive_ports_is_found(text):
    assert irc.terraform_open_sensitive_ingress(text, P) is not None


@pytest.mark.parametrize(
    "text",
    [
        _sg('    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'),
        _sg('    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = [var.admin_cidr]\n'),
        _sg(
            '    from_port = var.port\n    to_port = var.port\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        ),
        'resource "aws_security_group" "app" {\n  egress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        'resource "google_compute_firewall" "f" {\n  direction = "EGRESS"\n  source_ranges = ["0.0.0.0/0"]\n  allow { protocol = "all" }\n}\n',
    ],
)
def test_terraform_web_restricted_egress_or_undecidable_ingress_is_clean(text):
    assert irc.terraform_open_sensitive_ingress(text, P) is None


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_s3_bucket_acl" "a" {\n  acl = "public-read"\n}\n',
        'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = true\n  restrict_public_buckets = false\n}\n',
        'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject" }]\n  })\n}\n',
        'resource "google_storage_bucket_iam_member" "m" {\n  member = "allUsers"\n}\n',
        'resource "azurerm_storage_container" "c" {\n  container_access_type = "blob"\n}\n',
    ],
)
def test_terraform_public_storage_is_found(text):
    assert irc.terraform_public_storage(text, P) is not None


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n',
        'resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Principal = "*", Condition = { StringEquals = { "aws:SourceVpce" = "vpce-1" } } }]\n  })\n}\n',
        'resource "aws_s3_bucket_acl" "a" {\n  acl = "private"\n}\n',
    ],
)
def test_terraform_private_or_condition_narrowed_storage_is_clean(text):
    assert irc.terraform_public_storage(text, P) is None


@pytest.mark.parametrize(
    "text,violates",
    [
        ('resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}\n', True),
        ('resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n', True),
        ('resource "aws_db_instance" "d" {\n  storage_encrypted = true\n}\n', False),
        ('resource "aws_db_instance" "r" {\n  replicate_source_db = aws_db_instance.d.id\n}\n', False),
        ('resource "aws_ebs_volume" "v" {\n  size = 10\n}\n', False),
        ('resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n', True),
        ('resource "aws_opensearch_domain" "o" {\n  encrypt_at_rest {\n    enabled = false\n  }\n}\n', True),
    ],
)
def test_terraform_unencrypted_storage(text, violates):
    assert (irc.terraform_unencrypted_storage(text, P) is not None) is violates


@pytest.mark.parametrize(
    "text,line",
    [
        ('variable "db_password" {\n  type = string\n  default = "hunter2"\n}\n', 3),
        ('locals {\n  service_token = "changeme"\n}\n', 2),
        ('provider "aws" {\n  secret_key = "abcDEF123"\n}\n', 2),
        ('db_password = "from-tfvars"\n', 1),
        ('resource "aws_db_instance" "d" {\n  # password = "commented"\n  password = "inline-pass"\n}\n', 3),
    ],
)
def test_terraform_credential_literal_is_found_and_masked(text, line):
    found = irc.terraform_credential_literal(text, P)
    assert found is not None and found[0] == line
    assert irc.MASK in found[1]
    assert not any(secret in found[1] for secret in ("hunter2", "changeme", "abcDEF123", "from-tfvars", "inline-pass"))


@pytest.mark.parametrize(
    "text",
    [
        'variable "db_password" {\n  type = string\n  sensitive = true\n}\n',
        'variable "db_username" {\n  default = "admin"\n}\n',
        'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n',
        'resource "x" "y" {\n  token = "${var.prefix}-suffix"\n}\n',
        'resource "aws_instance" "i" {\n  user_data = <<-EOF\n    password = "in-heredoc"\n  EOF\n}\n',
    ],
)
def test_terraform_references_and_non_credentials_are_clean(text):
    assert irc.terraform_credential_literal(text, P) is None


CLEAN_TERRAFORM = """
resource "aws_security_group" "database" {
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "database" {
  username          = var.database_username
  password          = var.database_password
  storage_encrypted = true
  tags = merge(local.common_tags, {
    Name = "db"
  })
}

resource "aws_s3_bucket_public_access_block" "exports" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

variable "database_password" {
  type      = string
  sensitive = true
}
"""


def test_hardened_terraform_has_no_violation():
    for name, evaluator in irc.EVALUATORS.items():
        if name.startswith("terraform"):
            assert evaluator(CLEAN_TERRAFORM, P) is None, name


def test_nested_block_attributes_do_not_leak_into_the_parent():
    text = 'resource "aws_db_instance" "d" {\n  lifecycle {\n    storage_encrypted = true\n  }\n}\n'
    assert irc.terraform_unencrypted_storage(text, P) == (1, "aws_db_instance without storage_encrypted")


# --------------------------------------------------------------------------- routes, chart values, more Terraform


@pytest.mark.parametrize(
    "text,violates",
    [
        ("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  rules: []\n", True),
        (
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n"
            "  tls:\n  - hosts: [a.example]\n    secretName: web-tls\n",
            False,
        ),
        ("apiVersion: route.openshift.io/v1\nkind: Route\nmetadata:\n  name: web\nspec:\n  to:\n    name: web\n", True),
        (
            "apiVersion: route.openshift.io/v1\nkind: Route\nmetadata:\n  name: web\nspec:\n"
            "  tls:\n    termination: edge\n    insecureEdgeTerminationPolicy: Allow\n",
            True,
        ),
        (
            "apiVersion: route.openshift.io/v1\nkind: Route\nmetadata:\n  name: web\nspec:\n"
            "  tls:\n    termination: edge\n    insecureEdgeTerminationPolicy: Redirect\n",
            False,
        ),
        ("kind: Ingress\nspec: {}\n", False),
    ],
)
def test_kubernetes_route_without_tls(text, violates):
    assert (irc.kubernetes_route_without_tls(text, P) is not None) is violates


def test_deployment_config_is_a_workload():
    text = (
        "apiVersion: apps.openshift.io/v1\nkind: DeploymentConfig\nmetadata:\n  name: api\nspec:\n  template:\n"
        "    spec:\n      containers:\n      - name: api\n        securityContext:\n          privileged: true\n"
    )
    assert irc.kubernetes_privileged_container(text, P) == (11, "DeploymentConfig/api container api: privileged: true")


VALUES = "securityContext:\n  privileged: true\ningress:\n  enabled: true\n"


@pytest.mark.parametrize("relative", ["charts/api/values.yaml", "helm/renamed-chart/values.yaml"])
def test_chart_values_next_to_a_chart_are_judged(tmp_path, relative):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    (path.parent / "Chart.yaml").write_text("apiVersion: v2\nname: api\n", encoding="utf-8")
    assert irc.helm_values_privileged_container(VALUES, path) == (2, "securityContext: privileged: true")
    assert irc.helm_values_ingress_without_tls(VALUES, path) == (3, "ingress enabled without tls")
    hardened = "securityContext:\n  privileged: false\ningress:\n  enabled: true\n  tls:\n  - secretName: api\n"
    assert irc.helm_values_privileged_container(hardened, path) is None
    assert irc.helm_values_ingress_without_tls(hardened, path) is None


def test_values_file_without_a_chart_is_not_chart_values(tmp_path):
    path = tmp_path / "config" / "values.yaml"
    path.parent.mkdir(parents=True)
    assert irc.helm_values_privileged_container(VALUES, path) is None
    auto_deploy = tmp_path / ".gitlab" / "auto-deploy-values.yaml"
    assert irc.helm_values_ingress_without_tls(VALUES, auto_deploy) == (3, "ingress enabled without tls")


@pytest.mark.parametrize(
    "text,violates",
    [
        (
            'resource "aws_lb_listener" "http" {\n  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTP"\n}\n',
            True,
        ),
        (
            'resource "aws_lb_listener" "http" {\n  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTP"\n}\n'
            'resource "aws_lb_listener" "https" {\n  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTPS"\n}\n',
            False,
        ),
        (
            'resource "aws_lb_listener" "http" {\n  load_balancer_arn = aws_lb.edge.arn\n  protocol = "HTTP"\n}\n'
            'resource "aws_lb_listener" "https" {\n  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTPS"\n}\n',
            True,
        ),
    ],
)
def test_terraform_plaintext_load_balancer(text, violates):
    assert (irc.terraform_plaintext_load_balancer(text, P) is not None) is violates


@pytest.mark.parametrize(
    "text,violates",
    [
        ('resource "aws_instance" "i" {\n  associate_public_ip_address = true\n}\n', True),
        ('resource "aws_instance" "i" {\n  associate_public_ip_address = false\n}\n', False),
        ('resource "aws_ecs_service" "s" {\n  network_configuration {\n    assign_public_ip = true\n  }\n}\n', True),
        ('resource "aws_ecs_service" "s" {\n  network_configuration {\n    subnets = var.private\n  }\n}\n', False),
    ],
)
def test_terraform_public_compute_address(text, violates):
    assert (irc.terraform_public_compute_address(text, P) is not None) is violates


@pytest.mark.parametrize(
    "text,violates",
    [
        ('resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n', True),
        ('resource "aws_rds_cluster_instance" "d" {\n  publicly_accessible = true\n}\n', True),
        ('resource "aws_db_instance" "d" {\n  publicly_accessible = false\n}\n', False),
        ('resource "aws_db_instance" "d" {\n  publicly_accessible = var.public\n}\n', False),
    ],
)
def test_terraform_publicly_accessible_database(text, violates):
    assert (irc.terraform_publicly_accessible_database(text, P) is not None) is violates


@pytest.mark.parametrize(
    "text,violates",
    [
        (
            'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n'
            '    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]\n  })\n}\n',
            True,
        ),
        (
            'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement": [{"Effect": "Allow", '
            '"Action": "*", "Resource": "*"}]}\nEOF\n}\n',
            True,
        ),
        (
            'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n'
            '    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]\n  })\n}\n',
            False,
        ),
        (
            'resource "aws_iam_role_policy" "p" {\n  policy = jsonencode({\n'
            '    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = aws_s3_bucket.b.arn }]\n  })\n}\n',
            False,
        ),
        (
            'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n    resources = ["*"]\n  }\n}\n',
            True,
        ),
        (
            'data "aws_iam_policy_document" "d" {\n  statement {\n    effect = "Deny"\n'
            '    actions = ["*"]\n    resources = ["*"]\n  }\n}\n',
            False,
        ),
    ],
)
def test_terraform_wildcard_iam_policy(text, violates):
    assert (irc.terraform_wildcard_iam_policy(text, P) is not None) is violates


# --------------------------------------------------------------------------- weak inventory facts
# The deployment figure draws inventory facts with a `weak` tone. Each such fact
# must also be a config finding on the same file, or a listed exception, so a
# weakness never exists only in a figure.

WEAK_ENTRIES = CATALOG["inventory_weak_facts"]


def _weak_templates() -> list[str]:
    """Every fact text scripts/analyzers/deployment_inventory.py can emit with the weak tone; interpolations read as X."""

    def text(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(v.value if isinstance(v, ast.Constant) else "X" for v in node.values)
        return None

    def weak_text(message: ast.expr, tone: ast.expr) -> str | None:
        if isinstance(tone, ast.Constant):
            return text(message) if tone.value == "weak" else ""
        if isinstance(tone, ast.IfExp) and all(isinstance(t, ast.Constant) for t in (tone.body, tone.orelse)):
            messages = (message.body, message.orelse) if isinstance(message, ast.IfExp) else (message, message)
            pairs = zip(messages, (tone.body, tone.orelse))
            return next((text(m) for m, t in pairs if t.value == "weak"), "")
        return None

    tree = ast.parse((ROOT / "scripts" / "analyzers/deployment_inventory.py").read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_fact" and len(node.args) >= 2:
            found = weak_text(node.args[0], node.args[1])
            assert found is not None, f"line {node.lineno}: weak fact text or tone is not a literal the guard can read"
            if found:
                out.append(found)
    return out


def _entry(fact: str, entries: list[dict]) -> dict | None:
    return next((e for e in entries if re.fullmatch(e["fact"], fact)), None)


def _weak_facts(inventory: dict) -> set[tuple[str, str | None]]:
    out: set[tuple[str, str | None]] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for fact in node.get("facts") or []:
                if isinstance(fact, dict) and fact.get("tone") == "weak":
                    out.add((fact["text"], (fact.get("source") or {}).get("file")))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(inventory)
    return out


def _uncovered(weak: set, findings: list[dict], entries: list[dict]) -> list[tuple[str, str | None]]:
    """Weak facts without an entry, or whose entry's checks raised nothing on the fact's file."""
    missing = []
    for text, file in sorted(weak, key=str):
        entry = _entry(text, entries)
        if entry is None:
            missing.append((text, file))
        elif not entry.get("exception") and not any(
            f["check_id"] in entry["checks"] and f["file"] == file for f in findings
        ):
            missing.append((text, file))
    return missing


def _scan(tmp_path: Path, files: dict[str, str]) -> tuple[set, list[dict]]:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    for relative, content in files.items():
        (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (repo / relative).write_text(content, encoding="utf-8")
    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "scan.json")
    return _weak_facts(di.build_inventory(repo)), result["findings"]


_K8S_APP = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  template:
    metadata:
      labels:
        app: {name}
    spec:
      hostNetwork: true
      containers:
      - name: {name}
        image: registry.example/{name}:1.0
        securityContext:
          privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
spec:
  selector:
    app: {name}
  ports:
  - port: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {name}
spec:
  rules:
  - http:
      paths:
      - path: /
        backend:
          service:
            name: {name}
"""

_OPENSHIFT_APP = """apiVersion: apps.openshift.io/v1
kind: DeploymentConfig
metadata:
  name: {name}
spec:
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: {name}
        image: registry.example/{name}:1.0
        securityContext:
          privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
spec:
  selector:
    app: {name}
  ports:
  - port: 8080
---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: {name}
spec:
  to:
    name: {name}
{tls}"""

_TERRAFORM = """resource "aws_security_group" "{lb}" {{
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

resource "aws_lb" "{lb}" {{
  internal        = false
  security_groups = [aws_security_group.{lb}.id]
}}

resource "aws_lb_listener" "{lb}_http" {{
  load_balancer_arn = aws_lb.{lb}.arn
  port              = 80
  protocol          = "HTTP"
}}

resource "aws_iam_role" "{app}" {{
  name = "{app}"
}}

resource "aws_iam_role_policy" "{app}" {{
  role = aws_iam_role.{app}.id
  policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Action = "s3:*", Resource = "*" }}]
  }})
}}

resource "aws_ecs_task_definition" "{app}" {{
  task_role_arn = aws_iam_role.{app}.arn
}}

resource "aws_ecs_service" "{app}" {{
  task_definition = aws_ecs_task_definition.{app}.arn
  network_configuration {{
    assign_public_ip = true
  }}
}}

resource "aws_instance" "{app}_bastion" {{
  associate_public_ip_address = true
}}

resource "aws_db_instance" "{app}_db" {{
  publicly_accessible = true
}}

resource "aws_efs_file_system" "{app}_share" {{
  encrypted = false
}}
"""

_CHART_VALUES = "image:\n  repository: registry.example/api\n  tag: '1.0'\nsecurityContext:\n  privileged: true\ningress:\n  enabled: true\n"

WEAK_FACT_SHAPES = {
    "compose": {
        "docker-compose.yml": "services:\n  web:\n    image: nginx:1.25\n    privileged: true\n    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
    },
    "compose-renamed": {
        "compose.yaml": "services:\n  edge-proxy:\n    image: traefik:3\n    privileged: true\n    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock:ro\n",
    },
    "kubernetes": {"k8s/app.yaml": _K8S_APP.format(name="web")},
    "kubernetes-renamed": {"manifests/prod/storefront.yml": _K8S_APP.format(name="storefront")},
    "openshift-without-tls": {"deploy/api.yaml": _OPENSHIFT_APP.format(name="api", tls="")},
    "openshift-plain-http-allowed": {
        "deploy/api.yaml": _OPENSHIFT_APP.format(
            name="api", tls="  tls:\n    termination: edge\n    insecureEdgeTerminationPolicy: Allow\n"
        )
    },
    "helm": {"charts/api/Chart.yaml": "apiVersion: v2\nname: api\n", "charts/api/values.yaml": _CHART_VALUES},
    "gitlab-auto-deploy": {
        ".gitlab-ci.yml": "include:\n  - template: Auto-DevOps.gitlab-ci.yml\n",
        ".gitlab/auto-deploy-values.yaml": "ingress:\n  enabled: true\n",
    },
    "terraform": {"infra/main.tf": _TERRAFORM.format(lb="web", app="app")},
    "terraform-renamed": {"platform/aws/stack.tf": _TERRAFORM.format(lb="edge-lb", app="orders")},
}


@pytest.mark.parametrize("shape", sorted(WEAK_FACT_SHAPES))
def test_weak_inventory_facts_are_findings_on_the_same_file(tmp_path, shape):
    weak, findings = _scan(tmp_path, WEAK_FACT_SHAPES[shape])
    assert weak, f"{shape} no longer produces a weak inventory fact; the guard would pass vacuously"
    assert _uncovered(weak, findings, WEAK_ENTRIES) == []


def test_repository_without_deployment_config_has_no_weak_fact_and_nothing_uncovered(tmp_path):
    weak, findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert weak == set()
    assert not [f for f in findings if f["iac_type"] in {"docker_compose", "kubernetes", "helm_values", "terraform"}]
    assert _uncovered(weak, findings, WEAK_ENTRIES) == []


def test_an_excepted_weak_fact_needs_no_finding_but_an_unlisted_one_is_uncovered():
    weak = {("public IP", "main.tf")}
    excepted = [{"fact": "public IP", "exception": "no file-level signal"}]
    assert _uncovered(weak, [], excepted) == []
    assert _uncovered(weak, [], [{"fact": "publicly accessible", "checks": ["IAC-096"]}]) == [("public IP", "main.tf")]
    covered_elsewhere = [{"check_id": "IAC-095", "file": "other.tf"}]
    assert _uncovered(weak, covered_elsewhere, [{"fact": "public IP", "checks": ["IAC-095"]}]) == [
        ("public IP", "main.tf")
    ]


def test_every_weak_fact_the_inventory_can_emit_has_an_entry():
    templates = _weak_templates()
    assert templates
    assert [t for t in templates if _entry(t, WEAK_ENTRIES) is None] == []


def test_every_entry_names_catalog_checks_or_a_reason_and_matches_an_emittable_fact():
    check_ids = {check["id"] for check in CATALOG["checks"]}
    templates = _weak_templates()
    for entry in WEAK_ENTRIES:
        assert bool(entry.get("checks")) != bool(entry.get("exception")), entry
        assert set(entry.get("checks") or []) <= check_ids, entry
        assert any(re.fullmatch(entry["fact"], t) for t in templates), f"stale entry {entry['fact']!r}"


def test_every_checked_entry_is_proven_by_a_shape(tmp_path):
    proven = set()
    for index, files in enumerate(WEAK_FACT_SHAPES.values()):
        weak, _findings = _scan(tmp_path / str(index), files)
        proven.update(_entry(text, WEAK_ENTRIES)["fact"] for text, _file in weak if _entry(text, WEAK_ENTRIES))
    assert {e["fact"] for e in WEAK_ENTRIES if e.get("checks")} <= proven


# --------------------------------------------------------------------------- GitHub Actions permissions

ON = "on: push\n"
JOB_A = "  build:\n    runs-on: ubuntu-latest\n    steps: [{run: make}]\n"
JOB_B = "  deploy:\n    runs-on: ubuntu-latest\n    steps: [{run: make}]\n"
JOB_A_PERMS = "  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps: [{run: make}]\n"
JOB_B_PERMS = (
    "  deploy:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps: [{run: make}]\n"
)


@pytest.mark.parametrize(
    ("text", "missing_line", "broad_line"),
    [
        pytest.param(ON + "jobs:\n" + JOB_A + JOB_B, 3, None, id="no-permissions-anywhere"),
        pytest.param(ON + "permissions:\n  contents: read\njobs:\n" + JOB_A, None, None, id="root-read"),
        pytest.param(ON + "permissions: read-all\njobs:\n" + JOB_A, None, None, id="root-read-all"),
        pytest.param(ON + "permissions: {}\njobs:\n" + JOB_A, None, None, id="root-empty"),
        pytest.param(
            ON + "permissions:\n  issues: write\n  pull-requests: write\njobs:\n" + JOB_A,
            None,
            None,
            id="explicit-without-contents",
        ),
        pytest.param(ON + "jobs:\n" + JOB_A_PERMS + JOB_B_PERMS, None, None, id="every-job-declares"),
        pytest.param(ON + "jobs:\n" + JOB_A_PERMS + JOB_B, 8, None, id="partial-job-level"),
        pytest.param(ON + "permissions:\n  contents: write\njobs:\n" + JOB_A, None, 3, id="root-contents-write"),
        pytest.param(ON + "permissions: write-all\njobs:\n" + JOB_A, None, 2, id="root-write-all"),
        pytest.param(ON + "jobs: [", None, None, id="unparsable"),
    ],
)
def test_github_workflow_permission_checks(text, missing_line, broad_line):
    missing = irc.github_workflow_permissions_missing(text, P)
    broad = irc.github_workflow_token_scope_broad(text, P)
    assert (missing[0] if missing else None) == missing_line
    assert (broad[0] if broad else None) == broad_line


def test_catalog_judges_workflow_permissions_structurally():
    checks = {c["id"]: c for c in yaml.safe_load(scanner.DEFAULT_CHECKS.read_text(encoding="utf-8"))["checks"]}
    assert checks["IAC-010"]["evaluator"] == "github_workflow_permissions_missing"
    assert checks["IAC-015"]["evaluator"] == "github_workflow_token_scope_broad"
