"""Tests for scripts/compose_services.py — the bounded docker-compose reader."""

from __future__ import annotations

from pathlib import Path

import compose_services as C

COMPOSE = """\
version: "3.9"
services:
  edge:
    image: nginx:1.27.0
    ports:
      - "8080:80"
      - "127.0.0.1:9901:9901"
    depends_on:
      - api
  api:
    image: example/orders:latest
    ports:
      - target: 9000
        published: 9000
        host_ip: 127.0.0.1
      - 3000
    expose:
      - "5000"
    environment:
      SECRET_TOKEN: do-not-leak-this
      ORDERS_DEBUG: "true"
      TLS_VERIFY: false
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - orders_data:/var/lib/orders
      - type: bind
        source: ./conf
        target: /etc/orders
  db:
    image: postgres@sha256:0123456789abcdef
networks:
  backend:
    driver: bridge
volumes:
  orders_data:
"""


def _repo(tmp_path: Path, text: str = COMPOSE, name: str = "docker-compose.yml") -> Path:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_services_ports_env_and_line_spans(tmp_path: Path):
    services = {s.name: s for s in C.load_services(_repo(tmp_path))}
    assert list(services) == ["edge", "api", "db"]
    edge, api = services["edge"], services["api"]
    assert [(p.host, p.container, p.loopback_only) for p in edge.ports] == [
        ("8080", "80", False),
        ("9901", "9901", True),
    ]
    # Long syntax keeps the bind address; a bare container port gets a random host port.
    assert [(p.host, p.container, p.host_ip) for p in api.ports] == [("9000", "9000", "127.0.0.1"), ("", "3000", "")]
    assert api.expose == ["5000"] and api.depends_on == ["db"]
    assert api.volumes == ["orders_data", "./conf"]
    # Only boolean-like switch values survive; a secret value never leaves the parser.
    assert api.env_switches == {"ORDERS_DEBUG": "true", "TLS_VERIFY": "false"}
    assert "SECRET_TOKEN" in api.env_keys and "do-not-leak-this" not in repr(api)
    assert (edge.line, edge.end_line) == (3, 9)
    assert C.service_at(list(services.values()), "docker-compose.yml", 20).name == "api"
    assert C.compose_networks(tmp_path) == {"backend": "bridge"}


def test_primary_file_follows_docker_compose_precedence(tmp_path: Path):
    """Variant: several files — `docker compose` without -f picks compose.yaml first; variants are not merged."""
    _repo(tmp_path, "services:\n  a:\n    image: x:latest\n", "docker-compose.yml")
    _repo(tmp_path, "services:\n  b:\n    image: y:latest\n", "compose.yaml")
    _repo(tmp_path, "services:\n  c:\n    image: z:latest\n", "docker-compose.prod.yml")
    primary, variants = C.primary_compose_file(tmp_path)
    assert primary.name == "compose.yaml"
    assert sorted(v.name for v in variants) == ["docker-compose.prod.yml", "docker-compose.yml"]
    assert [s.name for s in C.load_services(tmp_path)] == ["b"]


def test_unreadable_oversized_and_escaping_files_yield_no_services(tmp_path: Path):
    """Negative: repository content cannot break or steer the reader."""
    assert C.load_services(None) == []
    _repo(tmp_path, "services: [unclosed\n")
    assert C.load_services(tmp_path) == []
    (tmp_path / "docker-compose.yml").write_text("services:\n  a:\n    image: x\n" + "#" * (C._MAX_BYTES + 1))
    assert C.load_services(tmp_path) == []
    outside = tmp_path.parent / "outside-compose"
    outside.mkdir(exist_ok=True)
    (outside / "docker-compose.yml").write_text("services:\n  leak:\n    image: x\n")
    (tmp_path / "docker-compose.yml").unlink()
    (tmp_path / "sub").symlink_to(outside, target_is_directory=True)
    assert C.load_services(tmp_path) == []


def _laughs(levels: int, merge: bool = False) -> str:
    """Nested aliases (or merge keys) that expand to 9**levels nodes from a few hundred bytes."""
    if merge:
        lines = ["x-m0: &m0 {" + ", ".join(f"k{j}: 1" for j in range(9)) + "}"]
        lines += [f"x-m{i}: &m{i} {{<<: [{', '.join([f'*m{i - 1}'] * 9)}]}}" for i in range(1, levels + 1)]
        return "\n".join(lines) + f"\nservices:\n  web:\n    image: nginx:1.27.0\n    labels: *m{levels}\n"
    lines = ['x-a0: &a0 ["lol"]']
    lines += [f"x-a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, levels + 1)]
    return "\n".join(lines) + f"\nservices:\n  web:\n    image: *a{levels}\n"


def test_root_compose_file_wins_over_many_nested_ones(tmp_path: Path):
    for name, nested in (("docker-compose.yml", "apps"), ("compose.yaml", "a-services")):
        root = tmp_path / name
        for i in range(10):
            (root / nested / f"svc{i}").mkdir(parents=True)
            (root / nested / f"svc{i}" / "docker-compose.yml").write_text("services:\n  x:\n    image: a:1\n")
        (root / name).write_text(COMPOSE)
        primary, _ = C.primary_compose_file(root)
        assert primary == root / name
    # Negative: without a root file the first nested one is still found.
    primary, _ = C.primary_compose_file(tmp_path / "compose.yaml" / "a-services")
    assert primary is not None and primary.name == "docker-compose.yml"


def test_alias_expansion_is_bounded(tmp_path: Path):
    for merge in (False, True):
        p = tmp_path / f"docker-compose-{merge}.yml"
        p.write_text(_laughs(6 if not merge else 7, merge), encoding="utf-8")
        assert len(p.read_bytes()) < 2048
        assert C.parse_compose_file(p, tmp_path) == []  # treated as unreadable, not expanded
    # Negative: ordinary anchors and merge keys still load.
    p = tmp_path / "docker-compose.yml"
    p.write_text(
        "x-common: &common\n  restart: always\n  image: nginx:1.27.0\n"
        "services:\n  web:\n    <<: *common\n  api:\n    <<: *common\n    image: example/api:2.0.0\n",
        encoding="utf-8",
    )
    assert [(s.name, s.image) for s in C.parse_compose_file(p, tmp_path)] == [
        ("web", "nginx:1.27.0"),
        ("api", "example/api:2.0.0"),
    ]
