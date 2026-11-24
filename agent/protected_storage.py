"""Create and verify the installed agent's machine-wide Windows storage ACLs."""

from __future__ import annotations

import os
from pathlib import Path

import paths


class ProtectedStorageError(RuntimeError):
    """Protected agent storage could not be established or verified."""


def _reject_reparse_point(path: Path) -> None:
    if path.is_symlink():
        raise ProtectedStorageError("Protected agent storage contains a reparse point.")
    if os.name == "nt":
        try:
            import win32con
            import win32file

            attributes = win32file.GetFileAttributes(str(path))
        except Exception as exc:
            raise ProtectedStorageError("Could not verify protected agent storage paths.") from exc
        if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ProtectedStorageError("Protected agent storage contains a reparse point.")


def _windows_security_modules():
    if os.name != "nt":
        raise ProtectedStorageError("Windows ACL support is required for installed agent storage.")
    try:
        import ntsecuritycon
        import win32security
    except ImportError as exc:
        raise ProtectedStorageError("Windows ACL support is unavailable; agent startup was refused.") from exc
    return win32security, ntsecuritycon


def _apply_acl(path: Path, *, directory: bool) -> None:
    import win32api

    win32security, ntsecuritycon = _windows_security_modules()
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    administrators_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
    dacl = win32security.ACL()
    inheritance = (
        win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE if directory else 0
    )
    for sid in (system_sid, administrators_sid):
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inheritance, ntsecuritycon.FILE_ALL_ACCESS, sid)
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    )
    previous = None
    try:
        privilege = win32security.LookupPrivilegeValue(None, "SeRestorePrivilege")
        win32api.SetLastError(0)
        previous = win32security.AdjustTokenPrivileges(
            token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)]
        )
        if win32api.GetLastError() == 1300:
            raise ProtectedStorageError("Required Windows storage-security privileges are unavailable.")
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION
            | win32security.OWNER_SECURITY_INFORMATION,
            administrators_sid,
            None,
            dacl,
            None,
        )
    finally:
        if previous is not None:
            win32security.AdjustTokenPrivileges(token, False, previous)
        win32api.CloseHandle(token)


def _verify_acl(path: Path, *, directory: bool) -> bool:
    win32security, ntsecuritycon = _windows_security_modules()
    descriptor = win32security.GetFileSecurity(
        str(path), win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
    )
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        return False
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() != 2:
        return False

    expected_sids = (
        win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None),
        win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None),
    )
    owner_sid = descriptor.GetSecurityDescriptorOwner()
    if not any(expected == owner_sid for expected in expected_sids):
        return False
    expected_flags = (
        win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE if directory else 0
    )
    actual_sids = []
    for index in range(dacl.GetAceCount()):
        header, access_mask, sid = dacl.GetAce(index)
        ace_type, ace_flags = header
        if (
            ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE
            or ace_flags != expected_flags
            or access_mask != ntsecuritycon.FILE_ALL_ACCESS
        ):
            return False
        actual_sids.append(sid)
    return all(
        any(expected == actual for actual in actual_sids) for expected in expected_sids
    )


def _secure_path(path: Path, *, directory: bool) -> None:
    _reject_reparse_point(path)
    try:
        _apply_acl(path, directory=directory)
        if not _verify_acl(path, directory=directory):
            raise ProtectedStorageError("Protected agent storage ACL verification failed.")
    except ProtectedStorageError:
        raise
    except Exception as exc:
        raise ProtectedStorageError("Protected agent storage could not be secured.") from exc


def _check_path(path: Path, *, directory: bool) -> None:
    _reject_reparse_point(path)
    if not _verify_acl(path, directory=directory):
        raise ProtectedStorageError("Protected agent storage ACL verification failed.")


def verify_protected_storage(root: Path | None = None) -> None:
    """Verify existing storage without changing ACLs or file contents."""
    root = Path(root) if root is not None else paths.get_agent_root()
    required = (root.parent, root, root / "config", root / "state", root / "logs")
    try:
        for directory in required:
            if not directory.is_dir():
                raise ProtectedStorageError("Protected agent storage is incomplete.")
            _check_path(directory, directory=True)
        for directory in required[2:]:
            for descendant in directory.rglob("*"):
                _check_path(descendant, directory=descendant.is_dir())
    except ProtectedStorageError:
        raise
    except Exception as exc:
        raise ProtectedStorageError("Protected agent storage could not be verified.") from exc


def secure_storage_file(path: Path) -> None:
    """Apply the protected owner and DACL to a newly written production file."""
    if paths.is_frozen_production():
        _secure_path(Path(path), directory=False)


def ensure_protected_storage(root: Path | None = None) -> tuple[Path, Path, Path]:
    """Secure the agent root, config, state, logs, and existing descendants.

    The optional root is intended for isolated tests. Production callers use
    the canonical ProgramData location resolved by ``paths``.
    """
    root = Path(root) if root is not None else paths.get_agent_root()
    config_dir, state_dir, log_dir = root / "config", root / "state", root / "logs"
    protected_parent = root.parent
    try:
        expected = (protected_parent, root, config_dir, state_dir, log_dir)
        existed = {directory for directory in expected if directory.exists()}
        existing_data = any(
            child.is_file() or child.is_symlink()
            for directory in expected[1:]
            if directory.exists()
            for child in directory.rglob("*")
        )
        protected_parent.mkdir(parents=True, exist_ok=True)
        for directory in expected:
            directory.mkdir(exist_ok=True)
            if existing_data and directory in existed:
                _check_path(directory, directory=True)
            else:
                _secure_path(directory, directory=True)
        for directory in expected[1:]:
            for descendant in directory.rglob("*"):
                is_directory = descendant.is_dir()
                if existing_data:
                    _check_path(descendant, directory=is_directory)
                else:
                    _secure_path(descendant, directory=is_directory)
    except ProtectedStorageError:
        raise
    except Exception as exc:
        raise ProtectedStorageError("Protected agent storage is unavailable.") from exc
    return config_dir, state_dir, log_dir
