"""Rule semantics of the Compose, Kubernetes and Terraform evaluators."""

from __future__ import annotations

from pathlib import Path

import iac_resource_checks as irc
import pytest

P = Path("x")


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
