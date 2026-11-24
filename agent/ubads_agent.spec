# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller build spec for the UBADS Windows Endpoint Agent (Phase 13).
#
# LOCAL / DEVELOPMENT ARTIFACT ONLY — see agent/README.md "Building a local
# Windows executable" for the exact build command, where the resulting
# .exe is produced, how to configure it, and why it is explicitly NOT a
# signed, production release artifact.
#
# This spec changes NOTHING about the agent's behavior — it only tells
# PyInstaller how to find and bundle:
#   - agent.py itself and every agent/*.py module (identity, config,
#     credential_store, checkpoint, state, runtime_state, paths,
#     backend_client, pipeline_bridge) — found automatically via normal
#     Python import analysis, since PyInstaller runs from this directory.
#   - log-collector's collector.py / event_parser.py / validation.py /
#     storage.py, which agent/pipeline_bridge.py imports as plain
#     top-level modules (see that file's docstring for why). `pathex`
#     below adds log-collector/ so PyInstaller's static analysis can find
#     and bundle them like any other local dependency; `datas` ALSO copies
#     the raw log-collector/*.py source into the executable as a fallback
#     extraction path, matching how pipeline_bridge.py resolves paths at
#     runtime when frozen (see paths.py).
#   - pywin32's win32evtlog/win32timezone/pywintypes, which PyInstaller's
#     built-in pywin32 hooks handle, plus a couple of hidden imports that
#     hook is known to sometimes miss.
#
# No log-collector or backend code is modified or duplicated by this file.

import sys
from pathlib import Path

SPEC_DIR = Path(SPECPATH)  # PyInstaller injects SPECPATH into the spec's globals
PROJECT_ROOT = SPEC_DIR.parent
LOG_COLLECTOR_DIR = PROJECT_ROOT / "log-collector"

block_cipher = None

a = Analysis(
    [str(SPEC_DIR / "agent.py")],
    pathex=[str(SPEC_DIR), str(LOG_COLLECTOR_DIR)],
    binaries=[],
    datas=[
        # Raw log-collector source, for pipeline_bridge.py's frozen-mode
        # sys.path fallback (see paths.py / pipeline_bridge.py). Only the
        # four modules the agent actually imports — not scripts/, not
        # log-collector's own README/tests.
        (str(LOG_COLLECTOR_DIR / "collector.py"), "log-collector"),
        (str(LOG_COLLECTOR_DIR / "event_parser.py"), "log-collector"),
        (str(LOG_COLLECTOR_DIR / "validation.py"), "log-collector"),
        (str(LOG_COLLECTOR_DIR / "storage.py"), "log-collector"),
        (str(LOG_COLLECTOR_DIR / "event_sanitizer.py"), "log-collector"),
    ],
    hiddenimports=[
        "win32timezone",  # commonly required by pywin32 but not always auto-detected
        "pydantic_settings.sources",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ubads-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # this is a CLI tool (--identity/--status/--collect/--run) — never a silent background process
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # NOT CODE-SIGNED — see agent/README.md. Do not distribute this
    # artifact as if it were a signed release build.
)

# Phase 16: the SAME program built as a Windows-subsystem (windowless)
# executable. This is what Task Scheduler launches (`--background`): it can
# never open a console window, and logs to a file instead (agent.py
# _configure_logging). The console build above stays for interactive CLI use.
exe_bg = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ubads-agent-bg",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
