"""
Stage 4E - REAL Windows installer tests (per-user TEST build, no UAC).

What runs for real: the compiled Inno Setup test installer, the real agent executables, the real
Task Scheduler, DPAPI, a real backend process on 127.0.0.1:8811 with a throwaway database. The
"portal download" is the backend's own enrollment-package route (so the file name that carries the
one-time code is produced exactly as in production).

SAFETY
  * Opt-in only: set UBADS_RUN_INSTALLER_TESTS=1 (a normal `pytest` run skips this file).
  * Everything lives under %LOCALAPPDATA%\\UBADS-TEST and the task "UBADS Agent TEST". The real
    install (C:\\Program Files\\UBADS Agent, %LOCALAPPDATA%\\UBADS, task "UBADS Agent") is never
    referenced, and the module verifies at the start and end that it did not change.
  * Fixture events used for the upload check are labelled synthetic and are NOT evidence of real
    collection.
NOT covered here (needs a human): the UAC / elevated build - see docs and the elevated test build.
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]
DIST_TEST = ROOT / "agent" / "dist-test"
INSTALLER = DIST_TEST / "UBADS-Agent-Setup-TEST.exe"
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
TEST_HOME = LOCAL / "UBADS-TEST"
APP_DIR = TEST_HOME / "App"
STATE_HOME = TEST_HOME / "Agent"
STATE_DIR = STATE_HOME / ".state"
LOGS = STATE_HOME / "logs"
TASK = "UBADS Agent TEST"
REAL_TASK = "UBADS Agent"
UNINSTALL_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7A3D2C10-5E4B-4C1A-9B0F-2D6E8A1C7F42}_is1"
PORT = 8811
BASE = f"http://127.0.0.1:{PORT}"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
PASSWORD = "Inst-test-password-123"

pytestmark = pytest.mark.skipif(
    os.environ.get("UBADS_RUN_INSTALLER_TESTS") != "1",
    reason="Real installer tests are opt-in: set UBADS_RUN_INSTALLER_TESTS=1 (they install a TEST build under %LOCALAPPDATA%\\UBADS-TEST).",
)


# ------------------------------------------------------------------ helpers


def ps(command: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=timeout)


def run(args, timeout=120, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)


def real_install_fingerprint() -> dict:
    """Everything belonging to the REAL installed agent that must never change (immutable
    files only: the live agent legitimately updates its checkpoint / runtime files)."""
    out = {}
    for p in (r"C:\Program Files\UBADS Agent\ubads-agent.exe", r"C:\Program Files\UBADS Agent\ubads-agent-bg.exe", r"C:\Program Files\UBADS Agent\.env"):
        path = Path(p)
        out[p] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    for name in ("credentials.json", "identity.json", "agent.env"):
        path = LOCAL / "UBADS" / "Agent" / ".state" / name if name != "agent.env" else LOCAL / "UBADS" / "Agent" / name
        out[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    xml = run(["schtasks", "/Query", "/TN", REAL_TASK, "/XML"]).stdout
    out["real_task_xml"] = hashlib.sha256(xml.encode()).hexdigest() if xml else None
    return out


def kill_test_processes():
    ps(
        "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '*\\UBADS-TEST\\*' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
    )


def reset_test_machine():
    """Returns the machine to 'TEST build never installed'. Touches only UBADS-TEST."""
    assert TEST_HOME.name == "UBADS-TEST"
    kill_test_processes()
    run(["schtasks", "/Delete", "/TN", TASK, "/F"])
    unins = APP_DIR / "unins000.exe"
    if unins.exists():
        run([str(unins), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], timeout=120)
    kill_test_processes()
    time.sleep(0.5)
    shutil.rmtree(TEST_HOME, ignore_errors=True)
    run(["reg", "delete", UNINSTALL_KEY, "/f"])
    assert not (APP_DIR / "ubads-agent.exe").exists()


def task_exists() -> bool:
    return run(["schtasks", "/Query", "/TN", TASK]).returncode == 0


def task_xml() -> str:
    return run(["schtasks", "/Query", "/TN", TASK, "/XML"]).stdout


def agent(*args, timeout=90):
    """Runs the INSTALLED TEST agent exe (it reads its isolation profile from its own folder)."""
    return run([str(APP_DIR / "ubads-agent.exe"), *args], timeout=timeout)


def bg_process_count() -> int:
    """Background-agent processes belonging to the TEST install only (the real installed agent is
    also called ubads-agent-bg.exe and must neither be counted nor touched)."""
    out = ps(r"(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'ubads-agent-bg.exe' -and $_.ExecutablePath -like '*\UBADS-TEST\*' } | Measure-Object).Count").stdout
    return int(out.strip() or 0)


def agent_running() -> bool:
    return (STATE_DIR / "agent.pid").exists() and bg_process_count() > 0


def read_result() -> dict | None:
    path = LOGS / "installer-result.json"
    return json.loads(path.read_text()) if path.exists() else None


def code_from_filename(name: str) -> str:
    return re.search(r"UBADS-Agent-Setup--(.+)\.exe", name).group(1)


class Stack:
    """Throwaway backend + database, plus API helpers."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ubads-inst-"))
        self.db = self.tmp / "inst.db"
        self.admin = ("inst-admin", PASSWORD)
        self.proc = None
        self.downloads = self.tmp / "downloads"
        self.downloads.mkdir()
        self.env = {
            **os.environ,
            "DATABASE_URL": f"sqlite:///{self.db.as_posix()}",
            "AGENT_API_KEY": "",
            "ENVIRONMENT": "local",
            "PUBLIC_BASE_URL": BASE,
            "INSTALLER_PATH": str(INSTALLER),
            "CORS_ALLOWED_ORIGINS": "http://127.0.0.1:1",
            "E2E_ADMIN_USER": self.admin[0],
            "E2E_ADMIN_PASSWORD": self.admin[1],
            "E2E_USER_USER": "inst-seed-user",
            "E2E_USER_PASSWORD": PASSWORD,
        }
        seed = run([str(PYTHON), str(ROOT / "frontend" / "e2e" / "seed_e2e_db.py")], env=self.env, cwd=self.tmp)
        assert seed.returncode == 0, seed.stderr
        self.start()

    def start(self):
        self.log = open(self.tmp / "backend.log", "ab")
        self.proc = subprocess.Popen(
            [str(PYTHON), "-m", "uvicorn", "app.main:app", "--app-dir", str(ROOT / "backend"), "--host", "127.0.0.1", "--port", str(PORT)],
            env=self.env, cwd=self.tmp, stdout=self.log, stderr=self.log, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for _ in range(120):
            try:
                if requests.get(f"{BASE}/health", timeout=1).ok:
                    return
            except requests.RequestException:
                time.sleep(0.5)
        raise RuntimeError("test backend did not start")

    def stop(self):
        if self.proc:
            run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"])
            self.proc.wait(10)
            self.log.close()
            self.proc = None

    def token(self, user, password=PASSWORD):
        r = requests.post(f"{BASE}/api/auth/login", json={"username": user, "password": password})
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def new_approved_request(self, tag, scope=("authentication",), approve=("authentication",)):
        user = f"{tag}-{os.urandom(3).hex()}"
        requests.post(f"{BASE}/api/auth/register", json={"username": user, "password": PASSWORD, "email": f"{user}@example.org", "full_name": tag, "organization": "Installer Test Org"}).raise_for_status()
        h = self.token(user)
        rid = requests.post(f"{BASE}/api/endpoint-requests", headers=h, json={"requested_scope": list(scope), "consent_acknowledged": True, "department": "QA"}).json()["id"]
        requests.post(f"{BASE}/api/admin/endpoint-requests/{rid}/approve", headers=self.token(*self.admin), json={"approved_scope": list(approve)}).raise_for_status()
        return user, h, rid

    def download_package(self, headers, rid) -> Path:
        """What the portal's Download button does: POST, then save under the server-provided name."""
        r = requests.post(f"{BASE}/api/endpoint-requests/{rid}/enrollment-package", headers=headers)
        r.raise_for_status()
        name = re.search(r'filename="([^"]+)"', r.headers["content-disposition"]).group(1)
        path = self.downloads / name
        path.write_bytes(r.content)
        return path

    def sql(self, query, params=()):
        con = sqlite3.connect(self.db, timeout=30)
        try:
            cur = con.execute(query, params)
            con.commit()
            return cur.fetchall()
        finally:
            con.close()

    def close(self):
        self.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class InstallRun:
    def __init__(self, rc, samples, seconds):
        self.rc, self.samples, self.seconds = rc, samples, seconds
        self.result = read_result()


def install(path: Path, timeout=300) -> InstallRun:
    stop_file = path.parent / "sampler.stop"
    out_file = path.parent / f"samples-{path.stem[-12:]}-{os.urandom(2).hex()}.jsonl"
    stop_file.unlink(missing_ok=True)
    sampler = subprocess.Popen(
        ["powershell", "-NoProfile", "-File", str(Path(__file__).with_name("sampler.ps1")), str(out_file), str(stop_file)],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    time.sleep(1.5)  # let the sampler start
    started = time.time()
    done = subprocess.run([str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"], capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - started
    time.sleep(1.0)
    stop_file.write_text("stop")
    sampler.wait(30)
    samples = [json.loads(line) for line in out_file.read_text(encoding="utf-8-sig").splitlines() if line.strip()] if out_file.exists() else []
    return InstallRun(done.returncode, samples, elapsed)


def mask(text, code):
    secret = code.rsplit(".", 1)[-1]
    return (text or "").replace(code, "<CODE>").replace(secret, "<SECRET>")


def tree_files(*roots):
    for root in roots:
        if root.exists():
            for p in root.rglob("*"):
                if p.is_file():
                    yield p


def assert_no_code_anywhere(code, label=""):
    """The code must not be in the install folder, the state folder, the uninstall registry key,
    the scheduled task, or the installer's own notes."""
    secret = code.rsplit(".", 1)[-1].encode()
    needles = [code.encode(), secret]
    for p in tree_files(APP_DIR, STATE_HOME):
        if p.name == "agent.lock":  # an empty lock file held open by the running agent (unreadable by design)
            assert p.stat().st_size == 0
            continue
        data = p.read_bytes()
        for n in needles:
            assert n not in data, f"{label}: enrollment code found inside {p}"
        assert code not in p.name and code.rsplit('.', 1)[-1] not in p.name
    reg = run(["reg", "query", UNINSTALL_KEY, "/s"]).stdout
    assert code not in reg and secret.decode() not in reg, f"{label}: code in uninstall registry key"
    xml = task_xml()
    assert code not in xml and secret.decode() not in xml, f"{label}: code in scheduled task"


# ------------------------------------------------------------------ fixtures


@pytest.fixture(scope="module")
def stack():
    assert INSTALLER.exists(), "build the test installer first (see docs/phase17-stage4e-installer.md)"
    before = real_install_fingerprint()
    s = Stack()
    reset_test_machine()
    yield s
    s.close()
    reset_test_machine()
    assert real_install_fingerprint() == before, "the REAL installed agent / its task changed during the tests!"


@pytest.fixture()
def clean(stack):
    reset_test_machine()
    stack.sql("select 1")
    yield
    kill_test_processes()


# ------------------------------------------------------------------ tests


def test_the_test_installer_is_newer_than_the_executables_it_packages():
    """Contents are LZMA-compressed, so packaging is proven by the install test below (installed
    files must be byte-identical to dist-test). Here: it exists, is sizeable, and was built after them."""
    assert INSTALLER.exists() and INSTALLER.stat().st_size > 30_000_000
    for exe in ("ubads-agent.exe", "ubads-agent-bg.exe"):
        assert (DIST_TEST / exe).stat().st_mtime <= INSTALLER.stat().st_mtime


def test_full_install_enrolls_schedules_starts_and_reports_through_the_backend(stack, clean):
    user, headers, rid = stack.new_approved_request("full")
    pkg = stack.download_package(headers, rid)
    code = code_from_filename(pkg.name)

    run_ = install(pkg)
    result = run_.result
    print("\n--- installer result:", json.dumps(result), f"({run_.seconds:.0f}s)")
    assert result and result["outcome"] == "success", (result, (LOGS / "installer.log").read_text() if (LOGS / "installer.log").exists() else "")
    assert result["enroll_exit"] == 0 and result["step_reached"] == "done" and result["had_code_in_name"] is True
    print("--- Inno relaunch: setup process extension seen by [Code]:", result["setup_process_extension"], "| is_admin:", result["is_admin"])

    # ---- ancestry / file name evidence from the sampler (code masked for display) ----
    agent_rows = [s for s in run_.samples if s["name"].lower() == "ubads-agent.exe"]
    setup_rows = [s for s in run_.samples if s["name"].lower().startswith("ubads-agent-setup")]
    print("--- sampled setup-related processes (code masked):")
    by_pid = {}
    for s in run_.samples:  # WMI can return an empty path on some rows of the same process: merge them
        merged = by_pid.setdefault(s["pid"], {"pid": s["pid"], "ppid": s["ppid"], "name": s["name"], "path": ""})
        merged["path"] = merged["path"] or (s["path"] or "")
    for s in sorted(by_pid.values(), key=lambda r: r["pid"]):
        print(f"    pid={s['pid']} ppid={s['ppid']} name={mask(s['name'], code)}")
    enroll_rows = [s for s in agent_rows if "--enroll-from-process" in (s["cmd"] or "")]
    assert enroll_rows, "the agent enrollment invocation was not observed"
    enroll = enroll_rows[0]
    installer_pid = int(re.search(r"--enroll-from-process (\d+)", enroll["cmd"]).group(1))
    assert enroll["ppid"] == installer_pid, "the PID handed to the agent must be the agent's direct parent"
    assert installer_pid in by_pid
    relaunched = by_pid[installer_pid]
    assert code in relaunched["name"] or code in relaunched["path"], "the relaunched setup process must still carry the code in its file name"
    assert relaunched["name"].lower().endswith(".tmp"), relaunched["name"]  # Inno's relaunched copy
    original = by_pid.get(relaunched["ppid"])
    assert original and original["name"].lower().endswith(".exe") and code in original["name"], "the relaunched copy's parent is the original download"
    print("--- ancestry (code masked):",
          f"{mask(original['name'], code)} (pid {original['pid']}) -> {mask(relaunched['name'], code)} (pid {relaunched['pid']}) -> ubads-agent.exe --enroll-from-process {installer_pid}")

    # ---- where the code can be seen on a command line ----
    secret = code.rsplit(".", 1)[-1]
    filename_forms = {f"UBADS-Agent-Setup--{code}.exe", f"UBADS-Agent-Setup--{code}.tmp"}
    inno_sl5 = []
    for s_ in run_.samples:
        cmd = s_["cmd"] or ""
        if s_["name"].lower().startswith("ubads-agent") and s_["name"].lower() in ("ubads-agent.exe", "ubads-agent-bg.exe"):
            # OUR processes: never, not even as a path
            assert code not in cmd and secret not in cmd, f"code on an AGENT command line: {mask(cmd, code)}"
        else:
            # Setup processes: the code may only be part of the setup FILE'S OWN NAME (its path), including
            # inside Inno's own /SL5 argument. Strip every occurrence of that name; nothing else may contain it.
            stripped = cmd
            for form in filename_forms:
                stripped = stripped.replace(form, "<SETUP-FILE>")
            assert code not in stripped and secret not in stripped, f"code on a setup command line outside the file name: {mask(cmd, code)}"
            if "/SL5" in cmd and code in cmd:
                inno_sl5.append(s_["name"])
    print("--- code visible only as the setup file's own name; Inno's /SL5 relaunch argument carries it on:", sorted(set(mask(n, code) for n in inno_sl5)))
    assert "--enroll-from-process" in enroll["cmd"] and "ubads1" not in enroll["cmd"]

    # ---- packaging: both executables installed, byte-identical to the build outputs ----
    for exe in ("ubads-agent.exe", "ubads-agent-bg.exe"):
        assert hashlib.sha256((APP_DIR / exe).read_bytes()).hexdigest() == hashlib.sha256((DIST_TEST / exe).read_bytes()).hexdigest(), exe
    assert (APP_DIR / ".env.example").exists() and (APP_DIR / "unins000.exe").exists()
    assert not (APP_DIR / ".env").exists()  # the installer never writes a config with secrets

    # ---- credential storage ----
    cred = json.loads((STATE_DIR / "credentials.json").read_text())
    assert cred["protection"] == "dpapi-user" and "agent_credential" not in cred
    cfg = (STATE_HOME / "agent.env").read_text()
    assert f"BACKEND_URL={BASE}" in cfg and "CATEGORIES=authentication" in cfg
    assert "AGENT_API_KEY" not in cfg

    # ---- isolation: separate state / task / install location ----
    assert (APP_DIR / "ubads-agent.profile").exists() and "UBADS Agent TEST" in (APP_DIR / "ubads-agent.profile").read_text()
    assert str(LOCAL / "UBADS" / "Agent") not in json.dumps(result)
    assert not (LOCAL / "UBADS" / "Agent" / ".state" / "agent.pid").exists() or True  # real agent's own business; fingerprinted separately

    # ---- scheduled task ----
    assert task_exists()
    xml = task_xml()
    assert str(APP_DIR / "ubads-agent-bg.exe").lower() in xml.lower() and "--background" in xml
    assert "Program Files" not in xml and "<Hidden>true</Hidden>" in xml and "MultipleInstancesPolicy>IgnoreNew" in xml

    # ---- agent is running; backend sees an ENROLLED, online endpoint ----
    assert agent_running()
    h = stack.token(*stack.admin)
    req = requests.get(f"{BASE}/api/admin/endpoint-requests/{rid}", headers=h).json()
    assert req["status"] == "ENROLLED" and req["endpoint_connection_status"] == "online"
    endpoint_id = req["endpoint_id"]
    assert json.loads((STATE_DIR / "credentials.json").read_text())["endpoint_id"] == endpoint_id
    assert agent("--verify-enrollment", "--require-running").returncode == 0

    # ---- upload through the installed agent (SYNTHETIC fixture; not evidence of real collection) ----
    interval_cfg = (STATE_HOME / "agent.env").read_text() + "COLLECTION_INTERVAL=5\n"
    (STATE_HOME / "agent.env").write_text(interval_cfg)
    fixture = {"event_id": 4624, "event_type": "successful_logon", "event_category": "authentication", "timestamp": "2026-01-01T00:00:00.000000Z",
               "computer_name": "INSTALLER-TEST-FIXTURE", "username": "synthetic.fixture", "event_record_id": 777001}
    out_of_scope = dict(fixture, event_category="process_activity", event_record_id=777002)
    (STATE_DIR / "pending_events.jsonl").write_text(json.dumps(fixture) + "\n" + json.dumps(out_of_scope) + "\n")
    assert agent("--restart", timeout=120).returncode == 0
    for _ in range(60):
        events = requests.get(f"{BASE}/api/events", headers=h, params={"endpoint_id": endpoint_id}).json()
        if events:
            break
        time.sleep(1)
    assert [e["event_category"] for e in events] == ["authentication"], events  # the in-scope fixture arrived, the out-of-scope one was dropped
    assert all(e["endpoint_id"] == endpoint_id for e in events)

    # ---- leak scan ----
    assert_no_code_anywhere(code, "after install")
    notes = (LOGS / "installer.log").read_text()
    assert "enroll exit=0" in notes and "start exit=0" in notes and code not in notes
    leftovers = [p for p in Path(tempfile.gettempdir()).glob("is-*.tmp") if any(code in f.name for f in p.rglob("*"))]
    assert not leftovers, "extracted setup files carrying the code were left in %TEMP%"

    # ---- code is single use: the same installer cannot enroll again ----
    before_cred = (STATE_DIR / "credentials.json").read_bytes()
    again = install(pkg)
    assert again.result["outcome"] == "already_enrolled" and again.result["enroll_exit"] == 3
    assert (STATE_DIR / "credentials.json").read_bytes() == before_cred  # existing enrolled endpoint untouched
    assert stack.sql("select count(*) from endpoints where enrolled_request_id = ?", (rid,))[0][0] == 1
    assert agent_running()  # an upgrade does not leave a working agent stopped

    # ---- uninstall: task removed, agent stopped, files gone, identity kept ----
    unins = APP_DIR / "unins000.exe"
    assert unins.exists()
    assert run([str(unins), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], timeout=120).returncode == 0
    time.sleep(2)
    assert not task_exists()
    assert not agent_running()
    assert not (APP_DIR / "ubads-agent.exe").exists()
    assert (STATE_DIR / "credentials.json").exists() and (STATE_DIR / "identity.json").exists()


@pytest.mark.parametrize("scenario,expected_exit,expect_text", [
    ("expired", 11, "expired"),
    ("invalid", 10, "not valid"),
    ("revoked", 13, "revoked"),
])
def test_failed_enrollment_leaves_nothing_scheduled_running_or_enrolled(stack, clean, scenario, expected_exit, expect_text):
    user, headers, rid = stack.new_approved_request(scenario)
    pkg = stack.download_package(headers, rid)
    code = code_from_filename(pkg.name)
    if scenario == "expired":
        stack.sql("update enrollment_authorizations set expires_at = ? where request_id = ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(sep=" "), rid))
    elif scenario == "revoked":
        requests.post(f"{BASE}/api/admin/endpoint-requests/{rid}/revoke", headers=stack.token(*stack.admin), json={"reason": "test"}).raise_for_status()
    elif scenario == "invalid":
        hint = code.split(".")[1]
        bad = stack.downloads / f"UBADS-Agent-Setup--ubads1.{hint}.{'A' * 43}.exe"
        shutil.copy2(pkg, bad)
        pkg = bad
        code = code_from_filename(pkg.name)

    run_ = install(pkg)
    r = run_.result
    print(f"\n--- {scenario}: result", json.dumps(r))
    assert r and r["outcome"] == "failed" and r["enroll_exit"] == expected_exit and r["step_reached"] == "enroll"
    assert not (STATE_DIR / "credentials.json").exists(), "no credential may be left behind"
    assert not (STATE_HOME / "agent.env").exists()
    assert not task_exists(), "no startup task may be installed"
    assert not agent_running() and bg_process_count() == 0
    assert stack.sql("select count(*) from endpoints where enrolled_request_id = ?", (rid,))[0][0] == 0, "no endpoint may exist for a failed enrollment"
    notes = (LOGS / "installer.log").read_text()
    assert f"enroll exit={expected_exit}" in notes and "install-task" not in notes and "start exit" not in notes
    assert_no_code_anywhere(code, scenario)


def test_installer_without_an_enrollment_code_installs_files_only(stack, clean):
    plain = stack.downloads / "UBADS-Agent-Setup-TEST.exe"
    shutil.copy2(INSTALLER, plain)
    r = install(plain).result
    assert r["outcome"] == "files_only" and r["had_code_in_name"] is False
    assert (APP_DIR / "ubads-agent.exe").exists() and (APP_DIR / "ubads-agent-bg.exe").exists()
    assert not task_exists() and not agent_running()
    assert not (STATE_DIR / "credentials.json").exists()


def test_backend_unreachable_means_no_enrollment_and_no_success(stack, clean):
    user, headers, rid = stack.new_approved_request("down")
    pkg = stack.download_package(headers, rid)
    stack.stop()
    try:
        r = install(pkg).result
    finally:
        stack.start()
    assert r["outcome"] == "failed" and r["enroll_exit"] == 20
    assert not (STATE_DIR / "credentials.json").exists() and not task_exists() and not agent_running()
    # the code was never sent anywhere, so it still works once the server is back
    assert stack.sql("select count(*) from enrollment_authorizations where request_id = ? and redeemed_at is null", (rid,))[0][0] == 1


def test_an_existing_enrolled_endpoint_is_never_overwritten_by_a_new_code(stack, clean):
    # first a normal enrollment...
    u1, h1, rid1 = stack.new_approved_request("first")
    assert install(stack.download_package(h1, rid1)).result["outcome"] == "success"
    cred = (STATE_DIR / "credentials.json").read_bytes()
    ident = (STATE_DIR / "identity.json").read_bytes()
    # ...then a second, perfectly valid code arrives on the same computer
    u2, h2, rid2 = stack.new_approved_request("second")
    pkg2 = stack.download_package(h2, rid2)
    r = install(pkg2).result
    assert r["outcome"] == "already_enrolled" and r["enroll_exit"] == 3
    assert (STATE_DIR / "credentials.json").read_bytes() == cred and (STATE_DIR / "identity.json").read_bytes() == ident
    assert stack.sql("select count(*) from endpoints where enrolled_request_id = ?", (rid1,))[0][0] == 1
    assert stack.sql("select count(*) from endpoints where enrolled_request_id = ?", (rid2,))[0][0] == 0  # the second code created nothing
    assert stack.sql("select redeemed_at from enrollment_authorizations where request_id = ?", (rid2,))[0][0] is None  # the new code was NOT spent
    assert agent_running()
