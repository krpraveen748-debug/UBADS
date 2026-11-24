"""
Windows Task Scheduler integration for automatic start.

The task runs under the INSTALLING USER's own account (never SYSTEM): the
agent only needs to read event logs that user may read (Administrator, or
Event Log Readers membership for the Security log), and its credential is
DPAPI-protected for that same user. It starts at that user's logon (with a
short delay for the network), hidden, restarts itself on failure, never
times out, and ignores a second start while one instance is running.

Elevation: if --install-task is run from an elevated prompt the task is
created with "run with highest available privileges" (an administrator's
task then runs elevated with no UAC prompt, which reading the Security log
normally needs). From a non-elevated prompt it is created un-elevated.

Trade-off: a user-account task cannot run before that user signs in. See
agent/README.md "Automatic operation" for why SYSTEM was not chosen.
"""

from __future__ import annotations

import ctypes
import getpass
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

import paths

TASK_NAME = paths.get_task_name()  # "UBADS Agent" unless an isolated test install overrides it
BACKGROUND_EXE_NAME = "ubads-agent-bg.exe"


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_user() -> str:
    domain = os.environ.get("USERDOMAIN") or os.environ.get("COMPUTERNAME") or "."
    return f"{domain}\\{getpass.getuser()}"


def background_command() -> tuple[str, str, str]:
    """(program, arguments, working_directory) that runs the agent with no window."""
    if paths.is_frozen():
        exe_dir = Path(sys.executable).resolve().parent
        return str(exe_dir / BACKGROUND_EXE_NAME), "--background", str(exe_dir)
    # From source: pythonw.exe never opens a console window.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    program = str(pythonw if pythonw.exists() else sys.executable)
    agent_py = Path(__file__).resolve().parent / "agent.py"
    return program, f'"{agent_py}" --background', str(agent_py.parent)


def build_task_xml(*, user: str, program: str, arguments: str, workdir: str, elevated: bool) -> str:
    run_level = "HighestAvailable" if elevated else "LeastPrivilege"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>UBADS endpoint agent: collects authorized Windows activity logs and sends them to the UBADS server.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId><Delay>PT30S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>{run_level}</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{escape(program)}</Command><Arguments>{escape(arguments)}</Arguments><WorkingDirectory>{escape(workdir)}</WorkingDirectory></Exec>
  </Actions>
</Task>
"""


@dataclass
class TaskResult:
    ok: bool
    output: str


def _schtasks(*args: str) -> TaskResult:
    proc = subprocess.run(
        ["schtasks", *args], capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    return TaskResult(proc.returncode == 0, (proc.stdout + proc.stderr).strip())


def install_task() -> TaskResult:
    program, arguments, workdir = background_command()
    if not Path(program).exists():
        return TaskResult(False, f"Cannot find the agent program to schedule: {program}")
    xml = build_task_xml(
        user=current_user(), program=program, arguments=arguments, workdir=workdir, elevated=is_elevated()
    )
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-16") as handle:
        handle.write(xml)
        xml_path = handle.name
    try:
        return _schtasks("/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F")
    finally:
        os.unlink(xml_path)


def uninstall_task() -> TaskResult:
    return _schtasks("/Delete", "/TN", TASK_NAME, "/F")


def run_task() -> TaskResult:
    return _schtasks("/Run", "/TN", TASK_NAME)


def end_task() -> TaskResult:
    return _schtasks("/End", "/TN", TASK_NAME)


def task_info() -> dict:
    """installed flag plus state / last run / last result when installed."""
    result = _schtasks("/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V")
    if not result.ok:
        return {"installed": False}
    fields = {}
    for line in result.output.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return {
        "installed": True,
        "state": fields.get("Status") or fields.get("Scheduled Task State"),
        "last_run": fields.get("Last Run Time"),
        "last_result": fields.get("Last Result"),
        "run_as": fields.get("Run As User"),
    }
