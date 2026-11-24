"""
Regression guard for log-collector/scripts/*.ps1.

Background: both audit-policy setup scripts originally contained UTF-8
em-dash characters (U+2014) in unmarked (no byte-order-mark) .ps1 files.
Windows PowerShell 5.1 reads a BOM-less script file using the system's
legacy ANSI code page rather than UTF-8; the em-dash's multi-byte UTF-8
encoding was then misread as several separate legacy-codepage characters,
one of which happened to be a "smart quote" character that PowerShell's
parser accepts as an alternate string-literal delimiter. That silently
terminated a `Write-Host "..."` string early and corrupted how the rest of
the script tokenized:

  - enable_process_and_device_audit.ps1 failed with "The string is missing
    the terminator", reported at the END of the file.
  - enable_file_activity_audit.ps1 failed with "Unexpected token '}'" at
    its next closing brace after the corrupted string.

Both are different-looking symptoms of the exact same root cause.

This test does not require PowerShell to be installed or exercise either
script's actual behavior (auditpol calls, Administrator elevation, ACL
changes) — it only guards against reintroducing non-ASCII characters into
these files, and checks that specific, previously-verified-by-hand
behaviors remain textually present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "log-collector" / "scripts"
PROCESS_DEVICE_SCRIPT = SCRIPTS_DIR / "enable_process_and_device_audit.ps1"
FILE_ACTIVITY_SCRIPT = SCRIPTS_DIR / "enable_file_activity_audit.ps1"
AUTHENTICATION_SCRIPT = SCRIPTS_DIR / "enable_authentication_audit.ps1"
ALL_SCRIPTS = [PROCESS_DEVICE_SCRIPT, FILE_ACTIVITY_SCRIPT, AUTHENTICATION_SCRIPT]


@pytest.mark.parametrize("script_path", ALL_SCRIPTS, ids=lambda p: p.name)
def test_script_exists(script_path):
    assert script_path.exists()


@pytest.mark.parametrize("script_path", ALL_SCRIPTS, ids=lambda p: p.name)
def test_script_is_ascii_only(script_path):
    """No non-ASCII byte (e.g. an em-dash) may appear in either file — see
    module docstring for why that specific class of character previously
    broke both scripts under Windows PowerShell 5.1."""
    raw = script_path.read_bytes()
    non_ascii_offsets = [i for i, b in enumerate(raw) if b > 127]
    assert non_ascii_offsets == [], f"non-ASCII byte(s) found at offset(s): {non_ascii_offsets}"


@pytest.mark.parametrize("script_path", ALL_SCRIPTS, ids=lambda p: p.name)
def test_script_has_no_byte_order_mark(script_path):
    """Documents the current, intentional state (plain ASCII, no BOM
    needed) rather than silently depending on it."""
    raw = script_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")


@pytest.mark.parametrize("script_path", ALL_SCRIPTS, ids=lambda p: p.name)
def test_script_still_requires_administrator(script_path):
    text = script_path.read_text(encoding="ascii")
    assert text.startswith("#Requires -RunAsAdministrator")


@pytest.mark.parametrize("script_path", ALL_SCRIPTS, ids=lambda p: p.name)
def test_script_preserves_should_process_confirmation(script_path):
    text = script_path.read_text(encoding="ascii")
    assert "SupportsShouldProcess = $true" in text
    assert "$PSCmdlet.ShouldProcess(" in text


def test_process_device_script_does_not_enable_command_line_auditing():
    """This project deliberately never turns on "include command line in
    process creation events" - see log-collector/README.md Privacy."""
    text = PROCESS_DEVICE_SCRIPT.read_text(encoding="ascii")
    assert "ProcessCreationIncludesCmdLine" not in text
    assert "Include command line" not in text or "does not enable" in text


def test_process_device_script_only_targets_its_two_documented_subcategories():
    """The script builds its `auditpol /set /subcategory:` calls from the
    $actions list rather than a literal string, so this checks that list's
    two Subcategory entries instead of grepping for a literal
    `/subcategory:"..."` (which never appears verbatim in the code)."""
    text = PROCESS_DEVICE_SCRIPT.read_text(encoding="ascii")
    subcategory_entries = {
        line.split("Subcategory = ")[1].split(";")[0].strip('"')
        for line in text.splitlines()
        if "Subcategory = " in line
    }
    assert subcategory_entries == {"Process Creation", "Plug and Play Events"}
    # And the actual auditpol invocation is parameterized off that list,
    # not a hard-coded third subcategory.
    assert 'auditpol /set /subcategory:"$($a.Subcategory)"' in text


def test_file_activity_script_path_parameter_is_mandatory():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    # The [Parameter(Mandatory = $true)] attribute must immediately precede
    # the $Path parameter declaration, not $Principal (which is optional).
    param_block = text.split("param(", 1)[1].split(")\n", 1)[0]
    path_decl_index = param_block.index("[string]$Path")
    principal_decl_index = param_block.index("[string]$Principal")
    assert "Mandatory = $true" in param_block[:path_decl_index]
    assert "Mandatory = $true" not in param_block[path_decl_index:principal_decl_index]


def test_file_activity_script_verifies_path_exists_and_is_a_directory():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    assert "Test-Path -Path $Path -PathType Container" in text


def test_file_activity_script_preserves_principal_parameter_default():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    assert '[string]$Principal = "Everyone"' in text


def test_file_activity_script_enables_only_file_system_subcategory():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    subcategory_targets = {
        line.split('/subcategory:"')[1].split('"')[0] for line in text.splitlines() if '/subcategory:"' in line
    }
    assert subcategory_targets == {"File System"}


def test_file_activity_script_enables_success_and_failure_auditing():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    assert "/success:enable /failure:enable" in text
    assert 'AuditFlags]"Success,Failure"' in text
    # And the reversal instructions correctly turn both back off.
    assert "/success:disable /failure:disable" in text


def test_file_activity_script_applies_sacl_only_to_the_supplied_resolved_path():
    text = FILE_ACTIVITY_SCRIPT.read_text(encoding="ascii")
    assert "Get-Acl -Path $resolvedPath -Audit" in text
    assert "Set-Acl -Path $resolvedPath -AclObject $acl" in text
    # No second, unrelated path is ever touched.
    assert text.count("Set-Acl") == 1


def test_authentication_script_enables_logon_success_and_failure():
    """4624 (successful logon) needs Success; 4625 (failed logon) needs
    Failure - both come from the same "Logon" subcategory."""
    text = AUTHENTICATION_SCRIPT.read_text(encoding="ascii")
    assert 'Subcategory = "Logon"' in text
    assert "/success:enable /failure:enable" in text


def test_authentication_script_enables_logoff_success_only():
    """4634/4647 (logoff) only have a Success case - Windows does not
    define a "failed logoff" event."""
    text = AUTHENTICATION_SCRIPT.read_text(encoding="ascii")
    assert 'Subcategory = "Logoff"' in text


def test_authentication_script_only_targets_logon_and_logoff():
    text = AUTHENTICATION_SCRIPT.read_text(encoding="ascii")
    subcategory_entries = {
        line.split("Subcategory = ")[1].split(";")[0].strip('"')
        for line in text.splitlines()
        if "Subcategory = " in line
    }
    assert subcategory_entries == {"Logon", "Logoff"}


def test_authentication_script_has_reversal_instructions_for_both_subcategories():
    text = AUTHENTICATION_SCRIPT.read_text(encoding="ascii")
    assert 'auditpol /set /subcategory:`"Logon`" /success:disable /failure:disable' in text
    assert 'auditpol /set /subcategory:`"Logoff`" /success:disable' in text
