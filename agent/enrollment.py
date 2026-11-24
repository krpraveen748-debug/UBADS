"""
Stage 4D - enrollment of THIS computer with a one-time code from an approved request.
See docs/phase17-stage4d-agent-enrollment.md for the design.

Rules this module enforces:
  * the code lives only in a SecretCode (never in argv, env, files or logs) and is
    zero-filled right after the single redemption request;
  * the shared enrollment key is NEVER used here (no fallback);
  * pre-flight checks run BEFORE the server is contacted, so a code is not spent when
    this machine could not store the result;
  * the response is validated BEFORE anything is stored; the credential goes through the
    existing DPAPI store and is verified by a decrypt round-trip;
  * an already-enrolled machine is never re-enrolled or overwritten.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import getpass
import hmac
import os
import re
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable

import credential_store
import identity as identity_module
import user_config
import paths
from backend_client import BackendClient, BackendResult
from connection import InvalidBackendUrl, validate_backend_url
from protected_storage import secure_storage_file

# ------------------------------------------------------------------ exit codes
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ALREADY_ENROLLED = 3
EXIT_INVALID_CODE = 10
EXIT_EXPIRED = 11
EXIT_ALREADY_USED = 12
EXIT_REVOKED = 13
EXIT_NOT_AUTHORISED = 14
EXIT_RATE_LIMITED = 15
EXIT_ENDPOINT_ID_IN_USE = 16
EXIT_NETWORK = 20
EXIT_TLS = 21
EXIT_SERVER_ERROR = 22
EXIT_MALFORMED_RESPONSE = 23
EXIT_BACKEND_CONFIG = 24
EXIT_LOCAL_STORAGE = 30
EXIT_POST_REDEMPTION_FAILURE = 31

KNOWN_CATEGORIES = ("authentication", "file_activity", "process_activity", "device_activity")

_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
CODE_PREFIX = "ubads1"
# The installer's own file name carries the code. Inno Setup re-launches a copy of itself
# with a .tmp extension, so both are accepted. Windows may append " (1)" to duplicates.
_INSTALLER_NAME_RE = re.compile(
    r"^UBADS-Agent-Setup--(?P<code>ubads1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43})(?: \(\d+\))?\.(?:exe|tmp)$", re.IGNORECASE
)


class CodeInputError(Exception):
    """The code could not be obtained. The message is always safe to display."""


# ------------------------------------------------------------------ secret holder


class SecretCode:
    """Holds the enrollment code in a mutable buffer so it can be zero-filled.
    repr/str never reveal it, so it cannot leak through logs or tracebacks.
    (Python cannot guarantee that every transient str copy is erased - best effort.)"""

    __slots__ = ("_buf",)

    def __init__(self, value: str) -> None:
        self._buf = bytearray(value.encode("utf-8"))

    def reveal(self) -> str:
        return self._buf.decode("utf-8")

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()

    def __bool__(self) -> bool:
        return bool(self._buf)

    def __repr__(self) -> str:
        return "<SecretCode redacted>"

    __str__ = __repr__

    def __reduce__(self):  # never pickled/copied into another process by accident
        raise TypeError("SecretCode cannot be serialised")


def parse_server_hint(code: SecretCode) -> str | None:
    """Validates the code's shape and returns the server address embedded in it, or
    None. Does not keep or return the secret part."""
    parts = code.reveal().strip().split(".")
    if len(parts) != 3 or parts[0] != CODE_PREFIX or not _SECRET_RE.match(parts[2]):
        return None
    try:
        url = base64.urlsafe_b64decode((parts[1] + "=" * (-len(parts[1]) % 4)).encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeError, ValueError):
        return None
    return url if url.startswith(("http://", "https://")) else None


def redact(text: str | None, *secrets: str) -> str:
    out = text or ""
    for secret in secrets:
        if secret and len(secret) >= 8:
            out = out.replace(secret, "<redacted>")
    return out


# ------------------------------------------------------------------ code sources


def read_code_interactive() -> SecretCode:
    if not sys.stdin or not sys.stdin.isatty():
        raise CodeInputError("No interactive terminal is available. Pipe the code with --enroll-stdin instead.")
    value = getpass.getpass("Enrollment code (input is hidden): ").strip()
    if not value:
        raise CodeInputError("No enrollment code was entered.")
    return SecretCode(value)


def read_code_stdin() -> SecretCode:
    line = sys.stdin.readline(1024) if sys.stdin else ""
    value = line.strip()
    if not value:
        raise CodeInputError("No enrollment code was received on standard input.")
    return SecretCode(value)


# --- Windows process helpers (ctypes; no extra dependency) ---

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TH32CS_SNAPPROCESS = 0x2


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def _parent_map() -> dict[int, int]:
    k = _kernel32()
    snapshot = k.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        return {}
    parents: dict[int, int] = {}
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = k.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            ok = k.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k.CloseHandle(snapshot)
    return parents


def ancestor_pids(pid: int | None = None) -> list[int]:
    """Process ids of this process's parent, grandparent, ... (nearest first)."""
    parents = _parent_map()
    chain: list[int] = []
    seen: set[int] = set()
    current = pid or os.getpid()
    while current in parents and current not in seen and len(chain) < 16:
        seen.add(current)
        current = parents[current]
        if current:
            chain.append(current)
    return chain


def image_path(pid: int) -> str | None:
    k = _kernel32()
    handle = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value
    finally:
        k.CloseHandle(handle)


def read_code_from_process(pid: int) -> SecretCode:
    """The installer interface: the installer passes ITS OWN process id (not a secret).
    The id is accepted only if it is an ancestor of this process (the installer that
    launched us); the code is then read from that process's executable file name, so it
    never appears on a command line, in the environment, in a file or in a log."""
    if pid not in ancestor_pids():
        raise CodeInputError("The given process is not the program that started this one.")
    path = image_path(pid)
    match = _INSTALLER_NAME_RE.match(os.path.basename(path or ""))
    if not match:
        raise CodeInputError("The installer's file name does not carry an enrollment code. Download a fresh installer from the UBADS portal.")
    return SecretCode(match.group("code"))


# ------------------------------------------------------------------ flow


@dataclass
class _Out:
    out: Callable[[str], None] = print
    err: Callable[[str], None] = lambda m: print(m, file=sys.stderr)


def _classify_failure(result: BackendResult) -> tuple[int, str]:
    """(exit code, user-facing message). Messages are fixed text, never the code."""
    if result.error_kind == "tls":
        return EXIT_TLS, "The server's security certificate could not be verified, so enrollment was stopped. Nothing was changed."
    if result.error_kind in ("network", "timeout"):
        return EXIT_NETWORK, "Could not reach the UBADS server. Check the internet connection and try again. Nothing was changed."
    if result.error_kind == "config":
        return EXIT_BACKEND_CONFIG, "The server address is not acceptable (HTTPS is required for remote servers)."
    code = result.error_code
    table = {
        "invalid_code": (EXIT_INVALID_CODE, "This enrollment code is not valid. Download a fresh installer from the UBADS portal."),
        "expired": (EXIT_EXPIRED, "This enrollment code has expired. Download a fresh installer from the UBADS portal."),
        "superseded": (EXIT_EXPIRED, "A newer installer was issued for this request. Use the most recently downloaded installer."),
        "already_used": (EXIT_ALREADY_USED, "This enrollment code was already used. Download a fresh installer from the UBADS portal."),
        "revoked": (EXIT_REVOKED, "An administrator revoked this authorization."),
        "request_not_approved": (EXIT_NOT_AUTHORISED, "This request is not approved for enrollment."),
        "request_mismatch": (EXIT_NOT_AUTHORISED, "This enrollment code does not match its approved request."),
        "account_unavailable": (EXIT_NOT_AUTHORISED, "The account that owns this request is no longer available."),
        "scope_mismatch": (EXIT_NOT_AUTHORISED, "The approved monitoring scope does not match this enrollment code."),
        "rate_limited": (EXIT_RATE_LIMITED, "Too many failed attempts. Wait a few minutes and try again."),
        "endpoint_id_in_use": (EXIT_ENDPOINT_ID_IN_USE, "This computer's identity is already registered on the server. Ask an administrator for help."),
    }
    if code in table:
        return table[code]
    if result.status_code == 401:
        return table["invalid_code"]
    if result.status_code == 429:
        return table["rate_limited"]
    if result.error_kind == "server" or (result.status_code or 0) >= 500:
        return EXIT_SERVER_ERROR, "The UBADS server had a problem. Nothing was changed on this computer; try again later."
    return EXIT_SERVER_ERROR, "The server did not accept the enrollment request. Nothing was changed on this computer."


def _validate_response(data: object) -> tuple[str, str, str | None, list[str]] | None:
    """(endpoint_id, credential, issued_at, scope) or None if anything looks wrong."""
    if not isinstance(data, dict):
        return None
    endpoint_id, credential = data.get("endpoint_id"), data.get("agent_credential")
    scope, issued = data.get("monitoring_scope"), data.get("credential_issued_at")
    try:
        endpoint_id = str(uuid.UUID(str(endpoint_id)))
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(credential, str) or not _CREDENTIAL_RE.match(credential):
        return None
    if not isinstance(scope, list) or not scope or any(s not in KNOWN_CATEGORIES for s in scope):
        return None
    if issued is not None and not isinstance(issued, str):
        return None
    return endpoint_id, credential, issued, list(dict.fromkeys(scope))


def _preflight() -> str | None:
    """Can this machine store the result? Checked BEFORE the server is contacted."""
    try:
        if paths.is_frozen_production():
            from protected_storage import ensure_protected_storage

            ensure_protected_storage()
        credential_store.STATE_DIR.mkdir(parents=True, exist_ok=True)
        probe = credential_store.STATE_DIR / ".enroll-write-test"
        probe.touch(exist_ok=True)
        credential_store.secure_storage_file(probe)
        probe.write_text("x", encoding="ascii")
        probe.unlink()
        if not credential_store.protection_self_test():
            return "Windows credential protection (DPAPI) is not working for this user."
        config_path = user_config.get_user_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        probe = config_path.parent / ".enroll-config-test"
        probe.touch(exist_ok=True)
        secure_storage_file(probe)
        probe.write_text("x", encoding="ascii")
        probe.unlink()
    except Exception as exc:  # noqa: BLE001 - any failure means "cannot store"
        return f"The agent's data folder is not writable ({type(exc).__name__})."
    return None


def run_enrollment(
    code: SecretCode,
    *,
    backend_url: str | None = None,
    allow_insecure_http: bool = False,
    allow_local: bool = False,
    client_factory: Callable[..., BackendClient] = BackendClient,
    io: _Out | None = None,
) -> int:
    """Redeems `code` and stores the result. Returns an exit code (see module top).
    The code is wiped before returning, whatever the outcome."""
    io = io or _Out()
    revealed: str | None = None
    try:
        hint = parse_server_hint(code)
        if hint is None:
            io.err("That is not a valid enrollment code. Download a fresh installer from the UBADS portal.")
            return EXIT_USAGE

        # Only an absent credential permits first-time enrollment. Corrupt or
        # inaccessible state must be recovered explicitly, not replaced.
        try:
            existing = credential_store.load_credential()
        except credential_store.CredentialStateError as exc:
            io.err(
                f"{exc} Administrator recovery is required; nothing was changed."
            )
            return EXIT_ALREADY_ENROLLED
        if existing is not None:
            io.err("This computer is already enrolled; nothing was changed. (Remove the existing enrollment first if you really intend to re-enroll.)")
            return EXIT_ALREADY_ENROLLED

        # Which server? The one in the code unless explicitly overridden; never silently switch servers.
        try:
            url = validate_backend_url(backend_url or hint, allow_insecure_http=allow_insecure_http, allow_loopback=allow_local)
            configured = user_config.read_user_config().get("BACKEND_URL")
            if configured:
                normalised = validate_backend_url(configured, allow_insecure_http=True, allow_loopback=True)
                if normalised != url:
                    io.err("This computer is already set up for a different UBADS server than the one in this enrollment code. Nothing was changed.")
                    return EXIT_BACKEND_CONFIG
        except InvalidBackendUrl as exc:
            io.err(f"Enrollment stopped: {exc}")
            return EXIT_BACKEND_CONFIG

        problem = _preflight()
        if problem:
            io.err(f"Enrollment was not attempted and the code was not used: {problem}")
            return EXIT_LOCAL_STORAGE

        ident = identity_module.load_or_create_identity()
        client = client_factory(url, allow_insecure_http=allow_insecure_http)
        revealed = code.reveal()
        result = client.redeem_enrollment(
            code=revealed,
            display_name=ident.display_name,
            operating_system=ident.operating_system,
            agent_version=ident.agent_version,
            endpoint_id=ident.endpoint_id,
        )
        code.wipe()
        revealed = None

        if not result.ok:
            exit_code, message = _classify_failure(result)
            io.err(message)
            return exit_code

        parsed = _validate_response(result.data)
        if parsed is None:
            io.err(
                "The server's answer was not in the expected format, so nothing was stored. "
                "The one-time code may have been used: download a fresh installer from the UBADS portal "
                "(an administrator may need to revoke and re-approve the request)."
            )
            return EXIT_MALFORMED_RESPONSE
        endpoint_id, credential, issued_at, scope = parsed

        # ---- the server has enrolled this machine: from here on storage MUST succeed ----
        try:
            credential_store.save_credential(endpoint_id, credential, issued_at)
            stored = credential_store.load_credential()
            if stored is None or stored.endpoint_id != endpoint_id or not hmac.compare_digest(
                stored.agent_credential.encode(), credential.encode()
            ):
                raise RuntimeError("credential verification failed")
        except Exception:  # noqa: BLE001
            io.err(
                "The server enrolled this computer but the credential could not be stored securely here. "
                "The local credential state was preserved. Ask an administrator to verify or revoke this enrollment."
            )
            return EXIT_POST_REDEMPTION_FAILURE
        finally:
            credential = ""  # drop our reference

        try:
            if endpoint_id != ident.endpoint_id:
                identity_module.adopt_endpoint_id(endpoint_id)
            user_config.write_user_config(
                {
                    "BACKEND_URL": url,
                    "CATEGORIES": ",".join(scope),
                    "ALLOW_INSECURE_HTTP": "true" if allow_insecure_http else "false",
                }
            )
        except Exception:  # noqa: BLE001
            io.err(
                "Enrolled and the credential is stored, but the agent settings could not be saved. "
                "Run 'ubads-agent --setup' with the server address, or contact an administrator."
            )
            return EXIT_POST_REDEMPTION_FAILURE

        io.out(f"Enrolled successfully. Endpoint ID: {endpoint_id}. Approved monitoring scope: {', '.join(scope)}.")
        return EXIT_OK
    finally:
        code.wipe()
        revealed = None  # noqa: F841


def cli_enroll(
    mode: str,
    *,
    pid: int | None = None,
    backend_url: str | None = None,
    allow_insecure_http: bool = False,
    allow_local: bool = False,
    io: _Out | None = None,
) -> int:
    """Entry used by agent.py. mode: "prompt" | "stdin" | "process"."""
    io = io or _Out()
    try:
        if mode == "stdin":
            code = read_code_stdin()
        elif mode == "process":
            code = read_code_from_process(int(pid or 0))
        else:
            code = read_code_interactive()
    except CodeInputError as exc:
        io.err(str(exc))
        return EXIT_USAGE
    return run_enrollment(code, backend_url=backend_url, allow_insecure_http=allow_insecure_http, allow_local=allow_local, io=io)
