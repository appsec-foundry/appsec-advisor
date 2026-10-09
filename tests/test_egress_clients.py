"""Outbound client detection: fixed external hosts and request-chosen destinations."""

from __future__ import annotations

from pathlib import Path

import pytest
from analyzers.egress_clients import scan


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _summary(rows):
    return [(r["kind"], r["host"], r["transport"], [(e["file"], e["line"]) for e in r["evidence"]]) for r in rows]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (
            {
                "src/chain.ts": "const p = new WebSocketProvider(`wss://node.chainhost.net/v2/${key}`)\n",
                "src/upload.ts": "const target = req.body.pictureUrl\nconst body = '1'\nconst res = await fetch(target)\n",
            },
            [
                ("user-controlled", None, "http", [("src/upload.ts", 3)]),
                ("fixed-host", "node.chainhost.net", "rpc", [("src/chain.ts", 1)]),
            ],
        ),
        (
            # The same mechanism under other languages, clients and names.
            {
                "svc/proxy.py": "def go():\n    return requests.get(request.args.get('next'))\n",
                "svc/rates.go": 'resp, err := http.Get("https://rates.feedco.example2.org/today")\n',
            },
            [
                ("user-controlled", None, "http", [("svc/proxy.py", 2)]),
                ("fixed-host", "rates.feedco.example2.org", "http", [("svc/rates.go", 1)]),
            ],
        ),
    ],
    ids=["typescript", "python-and-go"],
)
def test_fixed_hosts_and_request_chosen_urls_are_destinations(tmp_path, files, expected):
    assert _summary(scan(_repo(tmp_path, files))) == expected


def test_one_host_called_from_two_files_is_one_destination(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "a/wallet.ts": "const p = new JsonRpcProvider('https://rpc.ledgerco.io')\n",
            "b/mint.ts": "\nconst q = new JsonRpcProvider('https://rpc.ledgerco.io/x')\n",
        },
    )
    (row,) = scan(repo)
    assert row["clients"] == ["rpc-provider"]
    assert [(e["file"], e["line"]) for e in row["evidence"]] == [("a/wallet.ts", 1), ("b/mint.ts", 2)]


@pytest.mark.parametrize(
    "line",
    [
        "fetch('/api/orders')",  # same-origin call of a client to its own backend
        "fetch(`${base}/api/orders`)",  # configured, neither literal nor request-derived
        "fetch('http://localhost:3000/health')",
        "axios.get('https://api.example.com/v1')",  # reserved example domain
        "this.http.get('https://api.vendor.io')",  # framework client method, not Node http
        "const reply = 'see https://docs.vendor.io for details'",  # a URL without a client call
    ],
)
def test_calls_that_name_no_external_destination_are_ignored(tmp_path, line):
    assert scan(_repo(tmp_path, {"src/app.ts": line + "\n"})) == []


def test_excluded_and_minified_code_is_not_scanned(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "test/fixtures/call.ts": "fetch('https://api.vendor.io')\n",
            "node_modules/lib/index.js": "fetch('https://api.vendor.io')\n",
            "public/bundle.js": "x".ljust(2100, "x") + "fetch('https://api.vendor.io')\n",
        },
    )
    assert scan(repo) == []
