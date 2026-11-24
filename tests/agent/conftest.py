"""
Shared fixtures for agent tests.

`agent_tmp_dir` replaces pytest's built-in `tmp_path` for these tests: on
this project's Windows development machine, `tmp_path` setup consistently
took ~32s per test (an environmental delay inside pytest's temp-dir
machinery, unrelated to agent code). A plain `tempfile.mkdtemp()` gives the
same isolation — every agent test still writes only to a throwaway
directory, never to the real agent/.state/.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def agent_tmp_dir():
    path = Path(tempfile.mkdtemp(prefix="ubads_agent_test_"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
