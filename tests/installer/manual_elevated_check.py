"""
MANUAL elevated (UAC) check of the Stage 4E installer. A human must approve the UAC prompt.

    python tests/installer/manual_elevated_check.py prepare   # sets up an isolated test backend + a real elevated test package
    ... double-click the package it prints, approve the Windows (UAC) prompt, let setup finish ...
    python tests/installer/manual_elevated_check.py verify    # reads the installer's non-secret diagnostics and checks the result
    python tests/installer/manual_elevated_check.py cleanup   # stops the test backend and removes the test install (see notes)

Uses ONLY the isolated TEST build (AppId 7A3D2C10-..., task "UBADS Agent TEST", %LOCALAPPDATA%\\UBADS-TEST,
"Program Files\\UBADS Agent TEST") and a throwaway backend on 127.0.0.1:8811. The real installed agent, its
task and its database are never referenced.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

os.environ["UBADS_RUN_INSTALLER_TESTS"] = "1"
sys.path.insert(0, str(Path(__file__).parent))
import test_installer_e2e as t  # noqa: E402

ELEVATED = t.DIST_TEST / "UBADS-Agent-Setup-TEST-ELEVATED.exe"
STATE_FILE = Path(os.environ["TEMP"]) / "ubads-elevated-test-state.json"
ELEVATED_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "UBADS Agent TEST"


def prepare():
    if STATE_FILE.exists():
        sys.exit(f"A previous run is still set up ({STATE_FILE}). Run 'cleanup' first.")
    assert ELEVATED.exists(), "build the elevated test installer first"
    t.reset_test_machine()
    t.INSTALLER = ELEVATED  # the test backend serves the ELEVATED installer under the code file name
    stack = t.Stack()
    user, headers, rid = stack.new_approved_request("uac")
    pkg = stack.download_package(headers, rid)
    STATE_FILE.write_text(json.dumps({"backend_pid": stack.proc.pid, "tmp": str(stack.tmp), "request_id": rid, "package": str(pkg), "admin": stack.admin[0]}))
    stack.proc = None  # keep the backend running after this script exits (cleanup stops it)
    print("\nELEVATED TEST PACKAGE READY (isolated test server is running on 127.0.0.1:8811)\n")
    print("  1. Double-click this file in File Explorer:\n     " + str(pkg))
    print("  2. Approve the Windows (UAC) prompt, then let setup finish (it can take 2-3 minutes).")
    print("  3. Run:  python tests/installer/manual_elevated_check.py verify\n")


def verify():
    state = json.loads(STATE_FILE.read_text())
    result = t.read_result()
    print("installer-result.json:", json.dumps(result, indent=2) if result else "NOT FOUND - the installer did not run to its end")
    if not result:
        sys.exit(1)
    checks = {
        "elevated build ran with administrator rights (is_admin)": result.get("is_admin") is True,
        "Inno relaunched copy kept the code-bearing name (.tmp)": result.get("setup_process_extension", "").lower() in (".tmp", ".exe") and result.get("had_code_in_name") is True,
        "enrollment exit code 0": result.get("enroll_exit") == 0,
        "outcome == success": result.get("outcome") == "success",
        "credential stored with DPAPI": (t.STATE_DIR / "credentials.json").exists() and "dpapi-user" in (t.STATE_DIR / "credentials.json").read_text(),
        "task 'UBADS Agent TEST' exists": t.task_exists(),
    }
    xml = t.task_xml()
    checks["task runs with highest available privileges"] = "HighestAvailable" in xml
    import requests

    login = requests.post(f"{t.BASE}/api/auth/login", json={"username": state["admin"], "password": t.PASSWORD})
    if login.ok:
        req = requests.get(f"{t.BASE}/api/admin/endpoint-requests/{state['request_id']}", headers={"Authorization": f"Bearer {login.json()['access_token']}"}).json()
        checks["backend shows the request ENROLLED"] = req.get("status") == "ENROLLED"
        checks["backend sees the endpoint online"] = req.get("endpoint_connection_status") == "online"
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    sys.exit(0 if all(checks.values()) else 1)


def cleanup():
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        subprocess.run(["taskkill", "/PID", str(state["backend_pid"]), "/T", "/F"], capture_output=True)
        import shutil

        shutil.rmtree(state["tmp"], ignore_errors=True)
        STATE_FILE.unlink()
    subprocess.run(["schtasks", "/Delete", "/TN", t.TASK, "/F"], capture_output=True)
    t.kill_test_processes()
    unins = ELEVATED_DIR / "unins000.exe"
    if unins.exists():
        print("The elevated TEST app is still installed. Remove it via Windows Settings > Apps > "
              "'UBADS Windows Endpoint Agent [TEST BUILD]' > Uninstall (approve the UAC prompt), or run:\n  " + str(unins))
    t.shutil.rmtree(t.TEST_HOME, ignore_errors=True)
    print("Test backend stopped and test data removed.")


if __name__ == "__main__":
    {"prepare": prepare, "verify": verify, "cleanup": cleanup}[sys.argv[1] if len(sys.argv) > 1 else "prepare"]()
