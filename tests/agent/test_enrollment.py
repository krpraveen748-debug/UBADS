"""Stage 4D: agent-side enrollment with a one-time code.

The backend is mocked here (requests.request is replaced) so every failure category can be
produced on demand; tests/backend/test_agent_enrollment_e2e.py runs the same agent code against
the REAL backend application. All state lives in throwaway folders - never the real agent state."""

import base64
import json
import logging
import os
import pickle
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import requests

import agent as agent_module
import credential_store
import enrollment
import identity as identity_module
import user_config

SECRET = "S3cr3tS3cr3tS3cr3tS3cr3tS3cr3tS3cr3tS3cr3tAB"[:43]
assert len(SECRET) == 43
ENDPOINT_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
CREDENTIAL = "cred-" + "x" * 38  # 43 chars, token_urlsafe-shaped


def make_code(url="https://ubads.example.com", secret=SECRET):
    hint = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"ubads1.{hint}.{secret}"


CODE = make_code()


class FakeResponse:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body, text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def ok_body(**over):
    body = {
        "endpoint_id": ENDPOINT_ID,
        "agent_credential": CREDENTIAL,
        "credential_issued_at": "2026-10-03T12:00:00+00:00",
        "monitoring_scope": ["authentication"],
        "backend": "https://ubads.example.com",
    }
    body.update(over)
    return body


def err_body(code, message="m"):
    return {"detail": {"code": code, "message": message}}


@pytest.fixture()
def env(agent_tmp_dir, monkeypatch):
    monkeypatch.setattr(credential_store, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(credential_store, "CREDENTIAL_FILE", agent_tmp_dir / "credentials.json")
    monkeypatch.setattr(identity_module, "STATE_DIR", agent_tmp_dir)
    monkeypatch.setattr(identity_module, "IDENTITY_FILE", agent_tmp_dir / "identity.json")
    monkeypatch.setattr(user_config, "get_user_config_path", lambda: agent_tmp_dir / "agent.env")
    return agent_tmp_dir


class Backend:
    """Replaces requests.request; records calls; returns/raises what the test says."""

    def __init__(self, monkeypatch):
        self.calls = []
        self.action = FakeResponse(200, ok_body())
        monkeypatch.setattr(requests, "request", self._request)

    def _request(self, method, url, json=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "json": json, "headers": headers or {}})
        if isinstance(self.action, Exception):
            raise self.action
        return self.action


@pytest.fixture()
def backend(monkeypatch):
    return Backend(monkeypatch)


class Capture:
    def __init__(self):
        self.out, self.err = [], []
        self.io = enrollment._Out(out=self.out.append, err=self.err.append)

    @property
    def text(self):
        return "\n".join(self.out + self.err)


def enroll(code=CODE, **kw):
    cap = Capture()
    secret = enrollment.SecretCode(code)
    rc = enrollment.run_enrollment(secret, io=cap.io, **kw)
    return rc, cap, secret


# ---------------------------------------------------------------- 1. success


def test_successful_redemption_stores_everything_and_sends_no_shared_secret(env, backend):
    ident = identity_module.load_or_create_identity()
    rc, cap, secret = enroll()
    assert rc == enrollment.EXIT_OK
    assert len(backend.calls) == 1  # one attempt, never retried
    call = backend.calls[0]
    assert call["url"] == "https://ubads.example.com/api/agent/enrollment/redeem" and call["method"] == "POST"
    assert call["json"]["code"] == CODE and call["json"]["endpoint_id"] == ident.endpoint_id
    assert not any(h.lower() in ("x-agent-api-key", "x-agent-credential", "x-endpoint-id", "authorization") for h in call["headers"])  # no fallback secret, no auth header

    stored = credential_store.load_credential()
    assert stored.endpoint_id == ENDPOINT_ID and stored.agent_credential == CREDENTIAL
    cfg = user_config.read_user_config()
    assert cfg["BACKEND_URL"] == "https://ubads.example.com" and cfg["CATEGORIES"] == "authentication"
    assert "AGENT_API_KEY" not in cfg and CODE not in (env / "agent.env").read_text()
    assert ENDPOINT_ID in cap.text and "authentication" in cap.text
    assert CREDENTIAL not in cap.text and CODE not in cap.text and SECRET not in cap.text
    assert identity_module.load_or_create_identity().display_name == ident.display_name  # identity preserved apart from the id


def test_server_assigned_endpoint_id_is_adopted_keeping_the_rest_of_the_identity(env, backend):
    ident = identity_module.load_or_create_identity()
    backend.action = FakeResponse(200, ok_body(endpoint_id="11111111-1111-4111-8111-111111111111"))
    assert enroll()[0] == 0
    after = identity_module.load_or_create_identity()
    assert after.endpoint_id == "11111111-1111-4111-8111-111111111111"
    assert (after.display_name, after.operating_system, after.created_at) == (ident.display_name, ident.operating_system, ident.created_at)


def test_a_local_server_needs_an_explicit_flag_and_https_is_required_otherwise(env, backend):
    local = make_code("http://127.0.0.1:8000")
    rc, cap, _ = enroll(local)
    assert rc == enrollment.EXIT_BACKEND_CONFIG and backend.calls == []  # loopback only with --allow-local
    assert enroll(local, allow_local=True)[0] == 0
    (env / "credentials.json").unlink()  # un-enroll so the next check isolates the URL policy
    (env / "agent.env").unlink()
    # plain http to a remote host is refused even with the code pointing there
    rc2, _, _ = enroll(make_code("http://192.168.1.20:8000"))
    assert rc2 == enrollment.EXIT_BACKEND_CONFIG


def test_a_different_configured_server_is_never_silently_replaced(env, backend):
    user_config.write_user_config({"BACKEND_URL": "https://other.example.org"})
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_BACKEND_CONFIG and backend.calls == []
    assert not (env / "credentials.json").exists()


# ---------------------------------------------------------------- 2-8. failure categories


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (401, err_body("invalid_code"), enrollment.EXIT_INVALID_CODE),
        (410, err_body("expired"), enrollment.EXIT_EXPIRED),
        (410, err_body("superseded"), enrollment.EXIT_EXPIRED),
        (409, err_body("already_used"), enrollment.EXIT_ALREADY_USED),
        (403, err_body("revoked"), enrollment.EXIT_REVOKED),
        (403, err_body("request_not_approved"), enrollment.EXIT_NOT_AUTHORISED),
        (403, err_body("scope_mismatch"), enrollment.EXIT_NOT_AUTHORISED),
        (403, err_body("request_mismatch"), enrollment.EXIT_NOT_AUTHORISED),
        (403, err_body("account_unavailable"), enrollment.EXIT_NOT_AUTHORISED),
        (429, err_body("rate_limited"), enrollment.EXIT_RATE_LIMITED),
        (409, err_body("endpoint_id_in_use"), enrollment.EXIT_ENDPOINT_ID_IN_USE),
        (503, err_body("server_busy"), enrollment.EXIT_SERVER_ERROR),
        (500, {"detail": "Internal server error."}, enrollment.EXIT_SERVER_ERROR),
        (400, {"detail": "weird"}, enrollment.EXIT_SERVER_ERROR),
    ],
)
def test_backend_rejections_map_to_distinct_exit_codes_and_store_nothing(env, backend, status, body, expected):
    backend.action = FakeResponse(status, body)
    rc, cap, secret = enroll()
    assert rc == expected
    assert len(backend.calls) == 1  # never retried, even for 5xx
    assert not (env / "credentials.json").exists() and not (env / "agent.env").exists()
    assert CODE not in cap.text and SECRET not in cap.text
    assert not secret  # wiped


@pytest.mark.parametrize("exc", [requests.exceptions.ConnectionError("getaddrinfo failed"), requests.exceptions.Timeout()])
def test_network_failure_is_reported_once_without_state_change(env, backend, exc):
    backend.action = exc
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_NETWORK and len(backend.calls) == 1
    assert not (env / "credentials.json").exists()
    assert "internet connection" in cap.text


def test_tls_failure_has_its_own_exit_code(env, backend):
    backend.action = requests.exceptions.SSLError("certificate verify failed: self signed")
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_TLS and len(backend.calls) == 1
    assert "certificate" in cap.text.lower() and CODE not in cap.text
    assert not (env / "credentials.json").exists()


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(200, None, text="<html>not json</html>"),
        FakeResponse(200, ["list", "not", "dict"]),
        FakeResponse(200, {}),
        FakeResponse(200, ok_body(agent_credential=None)),
        FakeResponse(200, ok_body(agent_credential="short")),
        FakeResponse(200, ok_body(agent_credential="has spaces " + "x" * 40)),
        FakeResponse(200, ok_body(endpoint_id="not-a-uuid")),
        FakeResponse(200, ok_body(endpoint_id=None)),
        FakeResponse(200, ok_body(monitoring_scope=[])),
        FakeResponse(200, ok_body(monitoring_scope=["authentication", "keystrokes"])),
        FakeResponse(200, ok_body(monitoring_scope="authentication")),
        FakeResponse(200, ok_body(credential_issued_at=12345)),
    ],
)
def test_malformed_success_responses_are_rejected_before_anything_is_stored(env, backend, response):
    backend.action = response
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_MALFORMED_RESPONSE
    assert not (env / "credentials.json").exists() and not (env / "agent.env").exists()
    assert "fresh installer" in cap.text  # tells the user what to do, since the code may have been spent
    assert CODE not in cap.text and CREDENTIAL not in cap.text


def test_malformed_code_never_reaches_the_server(env, backend):
    for bad in ("", "nonsense", "ubads1.aaa.bbb", "ubads2.aHR0cHM6Ly94.%s" % SECRET, CODE + "A", CODE[:-1]):
        rc, cap, _ = enroll(bad)
        assert rc == enrollment.EXIT_USAGE
    assert backend.calls == []


# ---------------------------------------------------------------- 9-11. DPAPI


def test_credential_is_stored_with_dpapi_and_never_as_plaintext(env, backend):
    assert enroll()[0] == 0
    raw = (env / "credentials.json").read_text()
    data = json.loads(raw)
    assert data["protection"] == "dpapi-user" and "agent_credential" not in data
    assert CREDENTIAL not in raw and CODE not in raw and SECRET not in raw


def test_the_intended_windows_user_can_decrypt_what_enrollment_stored(env, backend):
    import win32crypt

    assert enroll()[0] == 0
    blob = base64.b64decode(json.loads((env / "credentials.json").read_text())["agent_credential_protected"])
    _desc, plain = win32crypt.CryptUnprotectData(blob, credential_store._ENTROPY, None, None, 0)
    assert plain.decode() == CREDENTIAL  # decrypted by THIS Windows user
    assert credential_store.load_credential().agent_credential == CREDENTIAL


def test_dpapi_blob_is_bound_to_this_applications_entropy(env, backend):
    import win32crypt

    assert enroll()[0] == 0
    blob = base64.b64decode(json.loads((env / "credentials.json").read_text())["agent_credential_protected"])
    with pytest.raises(Exception):
        win32crypt.CryptUnprotectData(blob, b"some-other-application", None, None, 0)
    with pytest.raises(Exception):
        win32crypt.CryptUnprotectData(blob, None, None, None, 0)


@pytest.mark.skip(reason="NOT EXECUTED: proving isolation between Windows USERS needs a second Windows account "
                         "(and a logon for it). Covered only by the OS DPAPI guarantee plus the entropy-binding test above. "
                         "Manual check: copy credentials.json to another Windows user's profile and run --status there; "
                         "the credential must be reported as unreadable / not enrolled.")
def test_another_windows_user_cannot_decrypt_the_credential():
    raise AssertionError("not run")


def test_preflight_failure_does_not_contact_the_server_or_spend_the_code(env, backend, monkeypatch):
    monkeypatch.setattr(credential_store, "protection_self_test", lambda: False)
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_LOCAL_STORAGE and backend.calls == []
    assert "code was not used" in cap.text


def test_credential_that_cannot_be_verified_after_saving_is_preserved_and_reported(env, backend, monkeypatch):
    real_save = credential_store.save_credential
    monkeypatch.setattr(credential_store, "save_credential", lambda *a, **k: real_save(a[0], "different-" + "y" * 30, *a[2:]))
    rc, cap, _ = enroll()
    assert rc == enrollment.EXIT_POST_REDEMPTION_FAILURE
    assert credential_store.load_credential().agent_credential == "different-" + "y" * 30
    assert "revoke" in cap.text and CREDENTIAL not in cap.text


# ---------------------------------------------------------------- 12-13. existing state


def test_existing_credential_is_never_overwritten_or_re_enrolled(env, backend):
    credential_store.save_credential("existing-endpoint", "existing-secret-value", "2026-01-01")
    before = (env / "credentials.json").read_bytes()
    rc, cap, secret = enroll()
    assert rc == enrollment.EXIT_ALREADY_ENROLLED
    assert backend.calls == []  # the code was not even sent
    assert (env / "credentials.json").read_bytes() == before
    assert credential_store.load_credential().agent_credential == "existing-secret-value"
    assert not secret


def test_an_unreadable_existing_credential_file_is_also_left_alone(env, backend):
    (env / "credentials.json").write_text("{this is not valid", encoding="utf-8")
    identity_file = env / "identity.json"
    identity_file.write_text(
        json.dumps(
            {
                "endpoint_id": "synthetic-existing-id",
                "display_name": "synthetic",
                "operating_system": "synthetic",
                "agent_version": "synthetic",
                "created_at": "synthetic",
            }
        ),
        encoding="utf-8",
    )
    identity_before = identity_file.read_bytes()
    rc, output, _ = enroll()
    assert rc == enrollment.EXIT_ALREADY_ENROLLED
    assert (env / "credentials.json").read_text() == "{this is not valid" and backend.calls == []
    assert identity_file.read_bytes() == identity_before
    assert "Administrator recovery is required" in output.text


def test_inaccessible_credential_does_not_trigger_enrollment_or_modify_identity(
    env, backend, monkeypatch
):
    identity_file = env / "identity.json"
    identity_file.write_text(
        json.dumps(
            {
                "endpoint_id": "synthetic-existing-id",
                "display_name": "synthetic",
                "operating_system": "synthetic",
                "agent_version": "synthetic",
                "created_at": "synthetic",
            }
        ),
        encoding="utf-8",
    )
    identity_before = identity_file.read_bytes()
    credential_file = env / "credentials.json"
    credential_file.write_text('{"endpoint_id":"synthetic"}', encoding="utf-8")
    real_read_text = credential_file.__class__.read_text

    def deny_credential_read(path, *args, **kwargs):
        if path == credential_file:
            raise PermissionError("synthetic access denial")
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(credential_file.__class__, "read_text", deny_credential_read)
    rc, output, _ = enroll()

    assert rc == enrollment.EXIT_ALREADY_ENROLLED
    assert backend.calls == []
    assert identity_file.read_bytes() == identity_before
    assert "inaccessible" in output.text


def test_a_failed_enrollment_leaves_identity_checkpoints_buffer_and_logs_untouched(env, backend):
    ident = identity_module.load_or_create_identity()
    files = {
        "checkpoint.json": '{"Security": {"authentication": 41}}',
        "pending_events.jsonl": '{"event_id": 4624}\n',
        "runtime_state.json": '{"last_successful_upload_at": "2026-10-03T00:00:00+00:00"}',
        "logs.txt": "agent log line\n",
    }
    for name, content in files.items():
        (env / name).write_text(content, encoding="utf-8")
    identity_before = (env / "identity.json").read_bytes()
    for status, body in [(401, err_body("invalid_code")), (410, err_body("expired")), (409, err_body("already_used"))]:
        backend.action = FakeResponse(status, body)
        enroll()
    backend.action = requests.exceptions.ConnectionError("down")
    enroll()
    for name, content in files.items():
        assert (env / name).read_text(encoding="utf-8") == content
    assert (env / "identity.json").read_bytes() == identity_before
    assert identity_module.load_or_create_identity().endpoint_id == ident.endpoint_id


def test_a_successful_enrollment_also_preserves_checkpoints_and_the_pending_buffer(env, backend):
    for name, content in {"checkpoint.json": '{"Security": {"authentication": 41}}', "pending_events.jsonl": '{"event_id": 4624}\n'}.items():
        (env / name).write_text(content, encoding="utf-8")
    assert enroll()[0] == 0
    assert (env / "checkpoint.json").read_text() == '{"Security": {"authentication": 41}}'
    assert (env / "pending_events.jsonl").read_text() == '{"event_id": 4624}\n'


# ---------------------------------------------------------------- 14. no leakage


def test_no_code_or_credential_in_logs_output_or_exceptions(env, backend, caplog):
    scenarios = [
        FakeResponse(200, ok_body()),
        FakeResponse(401, err_body("invalid_code", f"bad {SECRET}")),  # even a server echoing the secret is not printed
        requests.exceptions.SSLError(f"verify failed for {CODE}"),
        requests.exceptions.ConnectionError(f"cannot reach {CODE}"),
    ]
    with caplog.at_level(logging.DEBUG):
        for action in scenarios:
            for f in (env / "credentials.json", env / "agent.env"):
                f.unlink(missing_ok=True)
            backend.action = action
            rc, cap, _ = enroll()
            assert CODE not in cap.text and SECRET not in cap.text and CREDENTIAL not in cap.text
    assert CODE not in caplog.text and SECRET not in caplog.text and CREDENTIAL not in caplog.text


def test_secret_code_object_cannot_leak_through_repr_str_pickle_or_after_wipe():
    secret = enrollment.SecretCode(CODE)
    assert CODE not in repr(secret) and CODE not in str(secret) and CODE not in f"{secret}"
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    assert secret.reveal() == CODE and secret
    secret.wipe()
    assert not secret and secret.reveal() == ""


def test_the_code_is_wiped_even_when_enrollment_fails_early(env, backend):
    for code in ("garbage", CODE):
        credential_store.save_credential("x", "y" * 20) if code == CODE else None
        secret = enrollment.SecretCode(code)
        enrollment.run_enrollment(secret, io=Capture().io)
        assert not secret
        (env / "credentials.json").unlink(missing_ok=True)


def test_passing_the_code_on_the_command_line_is_refused_without_echoing_it(capsys):
    rc = agent_module.main(["--enroll", CODE])
    captured = capsys.readouterr()
    assert rc == enrollment.EXIT_USAGE
    assert CODE not in captured.out + captured.err and SECRET not in captured.out + captured.err


def test_the_enroll_flags_take_no_code_value():
    with pytest.raises(SystemExit):
        agent_module.main(["--enroll", "--enroll-stdin"])  # mutually exclusive, and neither accepts a value


# ---------------------------------------------------------------- code sources


def test_stdin_source_reads_one_line_and_hidden_prompt_is_used_interactively(monkeypatch):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO(CODE + "\nsecond line ignored\n"))
    assert enrollment.read_code_stdin().reveal() == CODE
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    with pytest.raises(enrollment.CodeInputError):
        enrollment.read_code_stdin()

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Tty())
    asked = {}
    monkeypatch.setattr(enrollment.getpass, "getpass", lambda prompt: asked.setdefault("prompt", prompt) and CODE)
    assert enrollment.read_code_interactive().reveal() == CODE
    assert "hidden" in asked["prompt"]
    monkeypatch.setattr(sys, "stdin", io.StringIO(CODE))  # not a terminal
    with pytest.raises(enrollment.CodeInputError):
        enrollment.read_code_interactive()


def test_end_to_end_through_the_cli_with_piped_stdin(env, backend, monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO(CODE + "\n"))
    assert agent_module.main(["--enroll-stdin"]) == 0
    out = capsys.readouterr()
    assert ENDPOINT_ID in out.out and CODE not in out.out + out.err and CREDENTIAL not in out.out + out.err
    assert credential_store.load_credential().agent_credential == CREDENTIAL


@pytest.mark.parametrize(
    "name,ok",
    [
        (f"UBADS-Agent-Setup--{CODE}.exe", True),
        (f"UBADS-Agent-Setup--{CODE} (1).exe", True),
        (f"UBADS-Agent-Setup--{CODE}.tmp", True),
        (f"ubads-agent-setup--{CODE}.EXE", True),
        ("UBADS-Agent-Setup.exe", False),
        (f"Other-Setup--{CODE}.exe", False),
        (f"UBADS-Agent-Setup--{CODE[:-3]}.exe", False),
        (f"UBADS-Agent-Setup--{CODE}.zip", False),
    ],
)
def test_installer_file_name_parsing(name, ok, monkeypatch):
    monkeypatch.setattr(enrollment, "ancestor_pids", lambda pid=None: [4242])
    monkeypatch.setattr(enrollment, "image_path", lambda pid: "C:\\Users\\x\\Downloads\\" + name)
    if ok:
        assert enrollment.read_code_from_process(4242).reveal() == CODE
    else:
        with pytest.raises(enrollment.CodeInputError):
            enrollment.read_code_from_process(4242)


def test_process_source_rejects_a_pid_that_is_not_an_ancestor(monkeypatch):
    monkeypatch.setattr(enrollment, "image_path", lambda pid: f"C:\\x\\UBADS-Agent-Setup--{CODE}.exe")
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        with pytest.raises(enrollment.CodeInputError):
            enrollment.read_code_from_process(unrelated.pid)
        with pytest.raises(enrollment.CodeInputError):
            enrollment.read_code_from_process(0)
    finally:
        unrelated.kill()


def test_windows_process_helpers_see_the_real_process_tree():
    parent = os.getppid()
    assert parent in enrollment.ancestor_pids()
    assert enrollment.ancestor_pids()[0] == parent
    path = enrollment.image_path(os.getpid())
    # inside a venv sys.executable is a launcher; the running image is the base interpreter
    expected = {os.path.normcase(os.path.realpath(p)) for p in (sys.executable, getattr(sys, "_base_executable", sys.executable))}
    assert path and os.path.normcase(os.path.realpath(path)) in expected
    assert enrollment.image_path(2**31 - 5) is None  # nonexistent process


def test_real_installer_style_parent_process_hands_over_the_code(tmp_path):
    """A REAL parent process whose executable is named like the installer launches a child
    that reads the code through the --enroll-from-process mechanism (no argv/env/file)."""
    base = Path(sys.base_prefix)
    renamed = tmp_path / f"UBADS-Agent-Setup--{CODE}.exe"
    shutil.copy2(base / "python.exe", renamed)
    agent_dir = str(Path(__file__).resolve().parents[2] / "agent")
    child = (
        "import sys, os; sys.path.insert(0, sys.argv[1]); import enrollment; "
        "c = enrollment.read_code_from_process(int(sys.argv[2])); "
        f"print('MATCH' if c.reveal() == {CODE!r} else 'MISMATCH')"
    )
    parent = (
        "import subprocess, sys, os; "
        f"r = subprocess.run([{str(Path(sys.executable).resolve())!r}, '-c', {child!r}, {agent_dir!r}, str(os.getpid())], capture_output=True, text=True); "
        "print(r.stdout.strip() or r.stderr.strip()[-300:])"
    )
    env = {**os.environ, "PYTHONHOME": str(base)}
    done = subprocess.run([str(renamed), "-c", parent], capture_output=True, text=True, env=env, timeout=60)
    assert done.stdout.strip() == "MATCH", (done.stdout, done.stderr[-400:])


# ---------------------------------------------------------------- 15. existing commands


def test_existing_commands_and_help_still_work(env, capsys):
    with pytest.raises(SystemExit) as helped:
        agent_module.main(["--help"])
    assert helped.value.code == 0
    text = capsys.readouterr().out
    for flag in ("--identity", "--status", "--collect", "--setup", "--run", "--background", "--start", "--stop", "--restart",
                 "--install-task", "--uninstall-task", "--enroll", "--enroll-stdin", "--enroll-from-process"):
        assert flag in text
    assert "--enrollment-code" not in text and "--code" not in text  # no way to type a code as an argument
    assert agent_module.main(["--identity"]) == 0
    assert json.loads(capsys.readouterr().out)["endpoint_id"]
    assert agent_module.main(["--stop"]) == 0  # not running: reports so and exits cleanly
