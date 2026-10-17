"""A published repository remote never carries credentials."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from shared._remote_url import public_remote_url


@pytest.mark.parametrize(
    ("url", "public"),
    [
        ("https://deploy:t0ken@example.invalid/org/api.git", "https://example.invalid/org/api.git"),
        ("https://token@example.invalid:8443/org/api", "https://example.invalid:8443/org/api"),
        ("ssh://git@example.invalid/org/api.git", "ssh://example.invalid/org/api.git"),
        ("https://user:pw@[::1]:8443/org/api", "https://[::1]:8443/org/api"),
    ],
)
def test_user_information_is_removed(url, public):
    assert public_remote_url(url) == public


@pytest.mark.parametrize(
    "url",
    ["git" + "@example.invalid:org/api.git", "https://example.invalid/org/api.git", "/srv/git/api.git"],
)
def test_a_remote_without_credentials_is_kept_unchanged(url):
    assert public_remote_url(url) == url


@pytest.mark.parametrize("url", ["", "   ", "bad\nurl", "https://", None, 42])
def test_an_unusable_value_is_not_published(url):
    assert public_remote_url(url) is None
