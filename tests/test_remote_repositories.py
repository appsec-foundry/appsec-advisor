"""Remote provisioning exercises real Git with an offline SSH transport fixture."""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import remote_repositories as remote

ROOT = Path(__file__).resolve().parents[1]


def git(*args, cwd=None, env=None, input=None):
    return subprocess.run(["git", *args], cwd=cwd, env=env, input=input, text=True, capture_output=True, check=True)


@pytest.fixture
def transport(tmp_path, monkeypatch):
    """Keep Git's clone and checkout real; replace only the network transport."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(remote.tempfile, "gettempdir", lambda: str(scratch))
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    monkeypatch.delenv("APPSEC_GIT_SSH_KEY_FILE", raising=False)
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    sources = {}
    for name in ("storefront", "ledger"):
        root = tmp_path / name
        root.mkdir()
        git("init", "-q", cwd=root)
        git("config", "user.name", "Fixture", cwd=root)
        git("config", "user.email", "fixture@example.invalid", cwd=root)
        (root / "source.txt").write_text(f"source for {name}\n")
        (root / ".gitattributes").write_text("*.txt filter=untrusted\n")
        git("add", ".", cwd=root)
        git("commit", "-qm", "fixture", cwd=root)
        sources[f"team/{name}.git"] = str(root)
        sources[f"/team/{name}.git"] = str(root)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ssh = bin_dir / "ssh"
    ssh.write_text(
        f"#!{sys.executable}\nimport os, sys, json, shlex\n"
        "command = shlex.split(sys.argv[-1])\n"
        "assert command[0] == 'git-upload-pack'\n"
        "source = json.loads(os.environ['FIXTURE_SOURCES'])[command[1]]\n"
        "os.execvp('git-upload-pack', ['git-upload-pack', source])\n"
    )
    ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FIXTURE_SOURCES", json.dumps(sources))
    return scratch


@pytest.mark.parametrize(
    "url",
    [
        "https://git.example/team/storefront.git",
        "ssh://git@git.example/team/ledger.git",
        "git@git.example:team/storefront.git",
        "ssh://git@git.example:2222/team/storefront.git",
        "ssh://git@[2001:db8::1]/team/storefront.git",
    ],
)
def test_supported_urls(url):
    selected = remote.parse_remote(url)
    assert selected.scheme in {"https", "ssh"}
    assert selected.name in {"storefront", "ledger"}
    if url.startswith("git@"):
        assert selected.url == url


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@git.example/team/a.git",
        "https://secret@git.example/team/a.git",
        "ssh://git:secret@git.example/team/a.git",
        "file:///tmp/a",
        "git://git.example/a",
        "ext::sh -c bad",
        "ssh://-option/a",
        "ssh://git@git.example/a/../b",
        "https://git.example/%2e%2e/a",
        "https://git.example/a?token=secret",
        "https://git.example/a#secret",
        "https://git.example/a\nforged",
        "git@git.example:team/$(bad)",
        "ssh://git@git.example:0/a",
        "https://git.example:99999/a",
    ],
)
def test_malformed_or_credential_urls_fail_without_echo(url):
    with pytest.raises(remote.RemoteError) as error:
        remote.parse_remote(url)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("url", ["git@git.example:team/storefront.git", "ssh://git@git.example/team/ledger.git"])
def test_real_checkout_and_cleanup_with_stable_identity(transport, tmp_path, url):
    args = ["--repo", url, "--output", str(tmp_path / "reports"), "--full"]
    paths = []
    for _ in range(2):
        with remote.checkout_arguments(args) as resolved:
            root = Path(resolved[1])
            paths.append(root)
            assert (root / "source.txt").read_text().startswith("source for ")
            assert len(git("rev-parse", "HEAD", cwd=root).stdout.strip()) == 40
            output = Path(resolved[3])
            output.mkdir(exist_ok=True)
            (output / "state.json").write_text("preserved")
        assert not root.exists()
        assert (output / "state.json").read_text() == "preserved"
    assert paths[0] == paths[1]


def test_multiple_urls_and_local_paths_share_one_invocation(transport, tmp_path):
    local = tmp_path / "local"
    local.mkdir()
    args = [
        "--repo",
        "git@git.example:team/storefront.git",
        "--repo",
        str(local),
        "--repo",
        "ssh://git@git.example/team/ledger.git",
        "--output",
        str(tmp_path / "report"),
    ]
    with remote.checkout_arguments(args) as result:
        roots = [Path(result[i]) for i in (1, 3, 5)]
        assert all(root.is_dir() for root in roots)
        assert result[3] == str(local)
    assert local.is_dir()
    assert not roots[0].exists() and not roots[2].exists()


def test_concurrent_output_is_refused_and_existing_checkout_preserved(transport, tmp_path):
    args = ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "report")]
    with remote.checkout_arguments(args) as result:
        with pytest.raises(remote.RemoteError, match="Another remote assessment"):
            with remote.checkout_arguments(args):
                pass
        assert (Path(result[1]) / "source.txt").is_file()


def test_local_only_does_not_clone_or_require_output(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "clone", lambda *_: pytest.fail("local checkout must not be cloned"))
    args = ["--repo", str(tmp_path / "local")]
    with remote.checkout_arguments(args) as result:
        assert result == args


def test_checkout_failure_cleans_earlier_and_partial_roots(transport, tmp_path, monkeypatch):
    original = remote.clone
    roots = []

    def fail_second(selected, root, token_env=None):
        roots.append(root)
        if len(roots) == 2:
            root.mkdir()
            raise remote.RemoteError("fixture failure")
        original(selected, root, token_env)

    monkeypatch.setattr(remote, "clone", fail_second)
    args = [
        "--repo",
        "git@git.example:team/storefront.git",
        "--repo",
        "git@git.example:team/ledger.git",
        "--output",
        str(tmp_path / "report"),
    ]
    with pytest.raises(remote.RemoteError, match="fixture failure"):
        with remote.checkout_arguments(args):
            pass
    assert len(roots) == 2 and all(not r.exists() for r in roots)
    assert not (tmp_path / "report").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["--repo", "https://git.example/a"],
        ["--repo", "https://git.example/a", "--repo", "https://git.example/a", "--output", "reports"],
        ["--repo", "https://git.example/a"] * 17 + ["--output", "reports"],
    ],
)
def test_admission_precedes_network(args, monkeypatch):
    monkeypatch.setattr(remote, "clone", lambda *_: pytest.fail("must reject before cloning"))
    with pytest.raises(remote.RemoteError):
        with remote.checkout_arguments(args):
            pass


def config(env):
    return [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(int(env["GIT_CONFIG_COUNT"]))]


def test_environment_token_reaches_git_helper_without_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("APPSEC_GIT_USERNAME", "fixture-user")
    selected = remote.parse_remote("https://git.example/team/source.git")
    env = remote._git_env(selected, tmp_path)
    result = git(
        "credential", "fill", cwd=tmp_path, env=env, input="protocol=https\nhost=git.example\npath=team/source.git\n\n"
    )
    assert "password=synthetic-test-token" in result.stdout
    assert "username=fixture-user" in result.stdout
    assert all("synthetic-test-token" not in v for _, v in config(env))
    assert not list(tmp_path.iterdir())


def test_operator_helper_and_username_configuration_is_preserved(tmp_path, monkeypatch):
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text('[credential "https://git.example"]\n helper = cache\n username = fixture\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    result = remote._credentials(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    assert ("credential.helper", "cache") in result
    assert ("credential.username", "fixture") in result


def test_transport_pinning_authentication_and_configuration_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "true")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/fixture/agent.sock")
    key = tmp_path / "key with spaces"
    key.write_text("synthetic, not a private key")
    monkeypatch.setenv("APPSEC_GIT_SSH_KEY_FILE", str(key))
    env = remote._git_env(remote.parse_remote("ssh://git@git.example:2222/team/a.git"), tmp_path)
    command = shlex.split(env["GIT_SSH_COMMAND"])
    assert "BatchMode=yes" in command and "StrictHostKeyChecking=yes" in command
    assert "Hostname=192.0.2.10" in command and "HostKeyAlias=[git.example]:2222" in command
    assert "ProxyCommand=none" in command and "ControlPath=none" in command
    assert command[-1] == str(key) and env["SSH_AUTH_SOCK"] == "/fixture/agent.sock"
    assert "GIT_SSL_NO_VERIFY" not in env
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    https = remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    cfg = dict(config(https))
    assert cfg["http.curloptResolve"] == "git.example:443:192.0.2.10"
    assert cfg["http.followRedirects"] == "false" and cfg["http.sslVerify"] == "true"
    assert cfg["protocol.allow"] == "never" and cfg["core.hooksPath"] == os.devnull


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_prohibited_network_destinations_fail_before_transport(monkeypatch, address):
    monkeypatch.delenv("APPSEC_URL_ALLOWLIST", raising=False)
    monkeypatch.setattr(remote.socket, "getaddrinfo", lambda *_a, **_k: [(0, 0, 0, "", (address, 443))])
    with pytest.raises(remote.RemoteError, match="prohibited"):
        remote._address(remote.parse_remote("https://git.example/team/a.git"))


def test_private_operator_destination_and_host_allowlist(monkeypatch):
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "git.example")
    monkeypatch.setattr(remote.socket, "getaddrinfo", lambda *_a, **_k: [(0, 0, 0, "", ("10.2.3.4", 443))])
    assert remote._address(remote.parse_remote("https://git.example/team/a.git")) == "10.2.3.4"
    with pytest.raises(remote.RemoteError, match="allowlist|ALLOWLIST"):
        remote._address(remote.parse_remote("https://other.example/team/a.git"))


def test_oversized_checkout_fails_and_cleans(transport, tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "MAX_BYTES", 1)
    with pytest.raises(remote.RemoteError, match="limit"):
        with remote.checkout_arguments(
            ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")]
        ):
            pass
    assert not list(transport.rglob("source.txt"))


def test_insecure_or_symlinked_temporary_directory_is_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    with pytest.raises(remote.RemoteError, match="private"):
        remote._private_directory(target)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        remote._private_directory(link)


def test_headless_routes_urls_before_authentication_and_preserves_argv(tmp_path):
    plugin = tmp_path / "plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin/plugin.json").write_text("{}")
    scripts = plugin / "scripts/runtime"
    scripts.mkdir(parents=True)
    (scripts / "remote_repositories.py").write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    args = ["--repo", "git@git.example:team/a.git", "--repo", "/local with spaces", "--output", "/reports with spaces"]
    proc = subprocess.run(
        [str(ROOT / "scripts/run-headless.sh"), *args],
        env={**os.environ, "CLAUDE_PLUGIN_DIR": str(plugin)},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == args


def test_headless_hands_the_token_variable_name_to_the_url_owner(tmp_path):
    plugin = tmp_path / "plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin/plugin.json").write_text("{}")
    (plugin / "scripts/runtime").mkdir(parents=True)
    (plugin / "scripts/runtime/remote_repositories.py").write_text(
        "import json, sys\nprint(json.dumps(sys.argv[1:]))\n"
    )
    args = ["--git-token-env", "CUSTOM_CI_PAT", "--repo", "https://git.example/team/a.git", "--output", "/reports"]
    proc = subprocess.run(
        [str(ROOT / "scripts/run-headless.sh"), *args],
        env={**os.environ, "CLAUDE_PLUGIN_DIR": str(plugin)},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == args


@pytest.mark.parametrize("exit_code", [0, 7, -15])
def test_runner_exit_cleanup_and_secret_removal(transport, tmp_path, monkeypatch, exit_code):
    scripts = tmp_path / "plugin/scripts"
    (scripts / "runtime").mkdir(parents=True)
    monkeypatch.setattr(remote, "__file__", str(scripts / "runtime/remote_repositories.py"))
    runner = scripts / "run-headless.sh"
    runner.write_text(
        f"#!{sys.executable}\nimport json, os, sys, pathlib, signal\n"
        f"pathlib.Path({str(tmp_path / 'received.json')!r}).write_text(json.dumps([sys.argv[1:], 'APPSEC_GIT_TOKEN' in os.environ]))\n"
        + ("os.kill(os.getpid(), signal.SIGTERM)\n" if exit_code < 0 else f"sys.exit({exit_code})\n")
    )
    runner.chmod(0o700)
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "synthetic-test-token")
    result = remote.main(["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")])
    assert result == (3 if exit_code < 0 else exit_code)
    args, token_present = json.loads((tmp_path / "received.json").read_text())
    assert not token_present and not Path(args[1]).exists()


def test_fetch_timeout_kills_transport_and_cleans(transport, tmp_path, monkeypatch):
    ssh = tmp_path / "bin/ssh"
    ssh.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
    monkeypatch.setattr(remote, "FETCH_SECONDS", 0.05)
    start = time.monotonic()
    with pytest.raises(remote.RemoteError, match="timed out"):
        with remote.checkout_arguments(
            ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")]
        ):
            pass
    assert time.monotonic() - start < 10
    assert not list(transport.rglob("storefront"))


def test_sigterm_stops_runner_and_removes_checkouts(transport, tmp_path):
    scripts = tmp_path / "plugin/scripts"
    (scripts / "runtime").mkdir(parents=True)
    ready = tmp_path / "ready"
    runner = scripts / "run-headless.sh"
    runner.write_text(
        f"#!{sys.executable}\nimport pathlib,time,sys\npathlib.Path({str(ready)!r}).write_text(sys.argv[2])\ntime.sleep(60)\n"
    )
    runner.chmod(0o700)
    harness = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "from runtime import remote_repositories as r\n"
        "r._address = lambda _: '192.0.2.10'\n"
        f"r.__file__ = {str(scripts / 'runtime/remote_repositories.py')!r}\n"
        f"raise SystemExit(r.main(['--repo','git@git.example:team/storefront.git','--output',{str(tmp_path / 'reports')!r}]))\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", harness], env={**os.environ, "TMPDIR": str(transport)})
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists()
        checkout = Path(ready.read_text())
        assert checkout.exists()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 3
        assert not checkout.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def test_clone_does_not_execute_operator_filters_or_hooks(transport, tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n")
    hook.chmod(0o700)
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text(f'[core]\n hooksPath = {hooks}\n[filter "untrusted"]\n smudge = touch {marker}\n required = true\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    with remote.checkout_arguments(
        ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "report")]
    ) as args:
        assert (Path(args[1]) / "source.txt").is_file()
    assert not marker.exists()


@pytest.mark.parametrize("token", ["", "synthetic\npassword=injected"])
def test_empty_or_multiline_token_is_rejected(tmp_path, monkeypatch, token):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setenv("APPSEC_GIT_TOKEN", token)
    with pytest.raises(remote.RemoteError, match="single lines"):
        remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)


def test_missing_credentials_fail_without_prompting(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    env = remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    proc = subprocess.run(
        ["git", "credential", "fill"],
        cwd=tmp_path,
        env=env,
        input="protocol=https\nhost=git.example\n\n",
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert proc.returncode != 0 and "password=" not in proc.stdout


def test_git_failure_is_redacted_and_partial_clone_is_removed(transport, tmp_path, capsys):
    code = remote.main(["--repo", "git@git.example:team/nonexistent.git", "--output", str(tmp_path / "reports")])
    assert code == 1
    diagnostic = capsys.readouterr().err
    assert "Git checkout failed" in diagnostic
    assert "APPSEC_GIT_SSH_KEY_FILE" in diagnostic and "known_hosts" in diagnostic
    assert "Traceback" not in diagnostic and "nonexistent.git" not in diagnostic
    assert not list(transport.rglob("nonexistent"))


def _https_env(tmp_path, monkeypatch, url="https://git.example/team/a.git", token_env=None):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    return remote._git_env(remote.parse_remote(url), tmp_path, token_env)


def _filled(env, tmp_path, host):
    return git("credential", "fill", cwd=tmp_path, env=env, input=f"protocol=https\nhost={host}\n\n").stdout


@pytest.fixture
def no_token_env(monkeypatch):
    for name in (
        "APPSEC_GIT_TOKEN",
        "GIT_TOKEN",
        "GITLAB_TOKEN",
        "GITLAB_HOST",
        "APPSEC_GIT_USERNAME",
        "CUSTOM_CI_PAT",
    ):
        monkeypatch.delenv(name, raising=False)


def test_token_variables_are_tried_in_order(tmp_path, monkeypatch, no_token_env):
    monkeypatch.setenv("GITLAB_TOKEN", "from-gitlab")
    monkeypatch.setenv("GIT_TOKEN", "from-git")
    assert "password=from-git" in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "from-appsec")
    assert "password=from-appsec" in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")
    monkeypatch.setenv("CUSTOM_CI_PAT", "from-custom")
    env = _https_env(tmp_path, monkeypatch, token_env="CUSTOM_CI_PAT")
    assert "password=from-custom" in _filled(env, tmp_path, "git.example")


def test_gitlab_token_reaches_only_gitlab_hosts(tmp_path, monkeypatch, no_token_env):
    monkeypatch.setenv("GITLAB_TOKEN", "from-gitlab")
    other = _https_env(tmp_path, monkeypatch)
    assert "password" not in _filled_or_empty(other, tmp_path, "git.example")
    com = _https_env(tmp_path, monkeypatch, "https://gitlab.com/team/a.git")
    assert "password=from-gitlab" in _filled(com, tmp_path, "gitlab.com")
    monkeypatch.setenv("GITLAB_HOST", "https://git.example/")
    own = _https_env(tmp_path, monkeypatch)
    assert "password=from-gitlab" in _filled(own, tmp_path, "git.example")


def _filled_or_empty(env, tmp_path, host):
    proc = subprocess.run(
        ["git", "credential", "fill"],
        cwd=tmp_path,
        env=env,
        input=f"protocol=https\nhost={host}\n\n",
        text=True,
        capture_output=True,
        timeout=5,
    )
    return proc.stdout


def test_named_variable_must_be_set_and_is_not_checked_against_host(tmp_path, monkeypatch, no_token_env):
    with pytest.raises(remote.RemoteError, match="CUSTOM_CI_PAT is not set"):
        _https_env(tmp_path, monkeypatch, token_env="CUSTOM_CI_PAT")
    monkeypatch.setenv("GITLAB_TOKEN", "explicit")
    env = _https_env(tmp_path, monkeypatch, token_env="GITLAB_TOKEN")
    assert "password=explicit" in _filled(env, tmp_path, "git.example")


def test_token_flag_is_stripped_and_validated(monkeypatch):
    assert remote._split_token_env(["--repo", "a", "--git-token-env", "X_1", "--output", "o"]) == (
        "X_1",
        ["--repo", "a", "--output", "o"],
    )
    for bad in (["--git-token-env"], ["--git-token-env", "a b"], ["--git-token-env", "A", "--git-token-env", "B"]):
        with pytest.raises(remote.RemoteError, match="git-token-env"):
            remote._split_token_env(bad)


def test_failure_hint_names_tried_variables_or_the_one_that_failed(monkeypatch, no_token_env):
    https = remote.parse_remote("https://git.example/team/a.git")
    hint = remote._failure_hint(https, None)
    assert all(n in hint for n in ("APPSEC_GIT_TOKEN", "GIT_TOKEN", "GITLAB_TOKEN", "--git-token-env"))
    monkeypatch.setenv("GITLAB_TOKEN", "ambient-secret")
    assert "GITLAB_TOKEN was not accepted" not in remote._failure_hint(https, None)
    monkeypatch.setenv("GIT_TOKEN", "ambient-secret")
    failed = remote._failure_hint(https, None)
    assert "GIT_TOKEN was not accepted" in failed and "ambient-secret" not in failed
    with pytest.raises(remote.RemoteError) as raised:
        remote._git(["no-such-subcommand"], Path("/nonexistent-root"), dict(os.environ), failed)
    assert "GIT_TOKEN was not accepted" in str(raised.value)
