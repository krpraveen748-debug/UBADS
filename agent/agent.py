"""
UBADS Windows Endpoint Agent — CLI entry point.

    Authorized Windows Endpoint
            |
            v
    Windows Event Collector (reused: log-collector/collector.py)
            |  normalize (event_parser.normalize_event, inside collect_events)
            v
    Local validation (validation.validate_event — reused, same rules
    log-collector's own CLI enforces)
            |
            v
    Endpoint identity (identity.py — stable UUID4, persisted locally)
            |
            v
    Per-agent credential (credential_store.py — this endpoint's own
    secret, obtained once via enrollment, never the shared enrollment key)
            |
            v
    Backend client (backend_client.py — authenticates with
    X-Endpoint-Id + X-Agent-Credential)
            |
            v
    POST /api/ingest/events  (backend validates+stores again; see
    backend/app/services/ingestion_service.py) — only on success does the
    collection cursor (checkpoint.py) advance.

Commands:
    python agent.py --identity   Show local endpoint identity (safe fields only).
    python agent.py --setup      First-time setup (server address + enrollment).
    python agent.py --status     Check configuration + backend connectivity.
    python agent.py --collect    Run one collection-and-submit cycle.
    python agent.py --background Like --run but with no console window; logs to a file.
    python agent.py --install-task / --uninstall-task   Start automatically at sign-in.
    python agent.py --start / --stop / --restart        Control the background agent.
    python agent.py --run        Run continuously (collect every
                                  COLLECTION_INTERVAL seconds; Ctrl+C to stop).

Does NOT install as a Windows service in this phase — `--run` is a
foreground process only (a future Windows service design is PLANNED, see
agent/README.md — this phase never installs one automatically).

Delivery ordering (Phase 11), see checkpoint.py for the full rationale:

    collect (candidate cursor per category)
        -> validate
        -> send (previously-buffered events + newly collected ones)
        -> confirm (backend accepted the batch)
        -> advance checkpoint (only now, and only for categories with a
           confirmed candidate in THIS batch)

If the send fails, nothing is lost: unsent events are buffered locally
(state.py, bounded) and the checkpoint is left untouched, so the next
cycle naturally retries the same range instead of skipping it.
"""

from __future__ import annotations

import argparse
import config as config_module
import getpass
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import checkpoint
import credential_store
import enrollment
import process_control
import runtime_state
import state
import task_scheduler
from backend_client import BackendClient
from config import settings
from connection import InvalidBackendUrl, validate_backend_url
from user_config import write_user_config
from identity import IdentityStateError, load_or_create_identity
from paths import get_log_dir, is_frozen, is_frozen_production
from pipeline_bridge import collector, validation
from protected_storage import ProtectedStorageError, ensure_protected_storage, secure_storage_file

logger = logging.getLogger("ubads_agent")


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def log_file_path():
    return get_log_dir() / "agent.log"


class ProtectedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def _open(self):
        stream = super()._open()
        try:
            secure_storage_file(Path(self.baseFilename))
        except Exception:
            stream.close()
            raise
        return stream


def _configure_logging(background: bool = False) -> None:
    if not background:
        logging.basicConfig(level=settings.log_level.upper(), format=LOG_FORMAT, stream=sys.stderr)
        return
    # Background mode has no console (the windowed exe has no stdout/stderr
    # at all): log to a rotating file instead, and make stray prints harmless.
    for stream_name in ("stdout", "stderr"):
        if getattr(sys, stream_name) is None:
            setattr(sys, stream_name, open(os.devnull, "w", encoding="utf-8"))
    path = log_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    secure_storage_file(path)
    handler = ProtectedRotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.basicConfig(level=settings.log_level.upper(), handlers=[handler], force=True)


def cmd_identity(_args: argparse.Namespace) -> int:
    identity = load_or_create_identity()
    print(
        json.dumps(
            {
                "endpoint_id": identity.endpoint_id,
                "display_name": identity.display_name,
                "operating_system": identity.operating_system,
                "agent_version": identity.agent_version,
                "created_at": identity.created_at,
            },
            indent=2,
        )
    )
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    identity = load_or_create_identity()
    client = BackendClient()
    stored_cred = credential_store.load_credential()
    rstate = runtime_state.load_runtime_state()

    health = client.check_health()
    ready = client.check_ready()

    checkpoints = {
        f"{category}": checkpoint.get_cursor(settings.log_channel, category) for category in settings.category_list
    }

    report = {
        "endpoint_id": identity.endpoint_id,
        "display_name": identity.display_name,
        "backend_url": settings.backend_url,
        "enrollment_key_configured": bool(settings.agent_api_key),
        "agent_credential_enrolled": stored_cred is not None,
        "categories": settings.category_list,
        "log_channel": settings.log_channel,
        "collection_checkpoints": checkpoints,
        "pywin32_available": collector.PYWIN32_AVAILABLE,
        "backend_health": "reachable" if health.ok else f"unreachable ({health.error})",
        "backend_ready": "ready" if ready.ok else f"not ready ({ready.error})",
        "pending_events_buffered_locally": len(state.load_pending()),
        "last_successful_collection_at": rstate.last_successful_collection_at,
        "last_successful_upload_at": rstate.last_successful_upload_at,
        "agent_process": _process_report(),
        "scheduled_task": task_scheduler.task_info(),
        "log_file": str(log_file_path()),
    }
    print(json.dumps(report, indent=2))
    return 0 if health.ok else 1


def _event_key(event: dict) -> tuple:
    """Identity used to avoid re-buffering an event that's already pending
    (e.g. after a failed send whose checkpoint therefore wasn't advanced,
    causing the same Windows events to be re-collected next cycle).
    Mirrors storage.build_event_uid's own preference order: real
    EventRecordID first, then a same fallback tuple."""
    record_id = event.get("event_record_id")
    if record_id is not None:
        return ("rid", event.get("computer_name"), record_id)
    return ("fallback", event.get("computer_name"), event.get("event_id"), event.get("timestamp"))


@dataclass
class CollectionResult:
    events: list[dict] = field(default_factory=list)
    # category -> highest validated EventRecordID collected this cycle
    # (the checkpoint value to advance to, IF this batch is confirmed sent).
    cursor_candidates: dict[str, int] = field(default_factory=dict)
    # category -> a collector.STATUS_* code, only present for categories
    # that did NOT complete normally this cycle (access denied, log
    # unavailable, pywin32 missing, unknown category).
    category_status: dict[str, str] = field(default_factory=dict)


def _collect_one_cycle() -> CollectionResult:
    """Collects real events across every configured category using the
    persisted per-category cursor, validating each one locally before it's
    ever considered for transmission. Invalid events are logged and
    dropped, never sent. Permission/availability problems are reported
    honestly per category (never silently treated as "zero events") — see
    log-collector/collector.py's STATUS_* codes."""
    result = CollectionResult()

    newest_record_id: int | None = None
    try:
        newest_record_id = collector.get_newest_record_id(settings.log_channel)
    except RuntimeError:
        pass  # pywin32 missing or channel unavailable — reported below per category instead.

    for category in settings.category_list:
        event_ids = collector.CATEGORY_EVENT_IDS.get(category)
        if event_ids is None:
            logger.warning("Unknown category '%s' in configuration — skipping.", category)
            result.category_status[category] = "UNKNOWN_CATEGORY"
            continue

        checkpoint.check_for_rollover(settings.log_channel, category, newest_record_id)
        after_record_id = checkpoint.get_cursor(settings.log_channel, category)

        try:
            events = collector.collect_events(
                limit=settings.batch_size,
                event_ids=event_ids,
                log_name=settings.log_channel,
                after_record_id=after_record_id,
                raise_errors=True,
            )
        except collector.EventLogAccessDenied as exc:
            logger.error(
                "%s for category '%s' on channel '%s': %s",
                collector.STATUS_ACCESS_DENIED,
                category,
                settings.log_channel,
                exc,
            )
            result.category_status[category] = collector.STATUS_ACCESS_DENIED
            continue
        except collector.EventLogUnavailable as exc:
            logger.error("Cannot collect '%s' events (log unavailable): %s", category, exc)
            result.category_status[category] = collector.STATUS_LOG_UNAVAILABLE
            continue
        except RuntimeError as exc:
            # pywin32 not installed — a real, honest limitation, not silently ignored.
            logger.error("Cannot collect '%s' events: %s", category, exc)
            result.category_status[category] = collector.STATUS_PYWIN32_MISSING
            continue

        max_record_id: int | None = None
        for event in events:
            validation_result = validation.validate_event(event)
            if validation_result.is_valid:
                result.events.append(event)
                record_id = event.get("event_record_id")
                if isinstance(record_id, int):
                    max_record_id = record_id if max_record_id is None else max(max_record_id, record_id)
            else:
                logger.warning(
                    "Dropping invalid %s event (event_id=%s): %s",
                    category,
                    event.get("event_id"),
                    validation_result.errors,
                )
        if max_record_id is not None:
            result.cursor_candidates[category] = max_record_id

    return result


def _ensure_enrolled(
    client: BackendClient, identity, enrollment_key: str | None = None
) -> credential_store.AgentCredential | None:
    """Returns this endpoint's credential, enrolling with the shared
    enrollment key first if none is stored yet. Never overwrites an
    existing stored credential — enrollment happens at most once per
    endpoint (see backend's 409-on-already-enrolled rule)."""
    stored = credential_store.load_credential()
    if stored is not None:
        return stored

    if not (enrollment_key or settings.agent_api_key):
        logger.warning(
            "No agent credential stored and no enrollment key (AGENT_API_KEY) configured — "
            "cannot enroll with the backend."
        )
        return None

    enroll_result = client.enroll_endpoint(
        endpoint_id=identity.endpoint_id,
        display_name=identity.display_name,
        operating_system=identity.operating_system,
        agent_version=identity.agent_version,
        enrollment_key=enrollment_key,
    )
    if not enroll_result.ok or not enroll_result.data or not enroll_result.data.get("agent_credential"):
        logger.warning("Could not enroll with backend: %s", enroll_result.error)
        return None

    endpoint_id = enroll_result.data.get("endpoint_id") or identity.endpoint_id
    credential_store.save_credential(
        endpoint_id=endpoint_id,
        agent_credential=enroll_result.data["agent_credential"],
        issued_at=enroll_result.data.get("credential_issued_at"),
    )
    logger.info("Enrolled endpoint %s with backend and stored its credential.", endpoint_id)
    return credential_store.load_credential()


def cmd_setup(args: argparse.Namespace) -> int:
    """First-time setup: validate the server address, prove the server is a
    reachable UBADS backend, enroll THIS computer, and save only the server
    address. The enrollment key is used once, in memory — never written to
    disk. Nothing is saved if the address fails validation or the server
    cannot be reached."""
    url_text = args.backend_url or input("UBADS server address (e.g. https://ubads.example.com): ")
    try:
        backend_url = validate_backend_url(
            url_text, allow_insecure_http=args.allow_insecure_http, allow_loopback=args.allow_local
        )
    except InvalidBackendUrl as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 2

    client = BackendClient(backend_url, allow_insecure_http=args.allow_insecure_http)
    print(f"Checking {backend_url} ...")
    health = client.check_health()
    if not health.ok:
        print(f"Setup failed: cannot reach the UBADS server. {health.error}", file=sys.stderr)
        return 1

    identity = load_or_create_identity()
    stored = credential_store.load_credential()
    if stored is None:
        key = args.enrollment_key or settings.agent_api_key or getpass.getpass("Enrollment key (from your UBADS administrator): ")
        if not key:
            print("Setup failed: an enrollment key is required.", file=sys.stderr)
            return 2
        stored = _ensure_enrolled(client, identity, enrollment_key=key)
        if stored is None:
            print(
                "Setup failed: the server rejected enrollment (wrong enrollment key, or enrollment is closed on the server).",
                file=sys.stderr,
            )
            return 1
    else:
        print("This computer is already enrolled; keeping its existing credential.")

    write_user_config(
        {"BACKEND_URL": backend_url, "ALLOW_INSECURE_HTTP": "true" if args.allow_insecure_http else "false"}
    )
    print(
        json.dumps(
            {"status": "ready", "backend_url": backend_url, "endpoint_id": stored.endpoint_id, "display_name": identity.display_name},
            indent=2,
        )
    )
    return 0


def cmd_collect(_args: argparse.Namespace) -> int:
    identity = load_or_create_identity()
    client = BackendClient()

    stored_cred = _ensure_enrolled(client, identity)
    if stored_cred is not None:
        register_result = client.register(
            endpoint_id=stored_cred.endpoint_id,
            agent_credential=stored_cred.agent_credential,
            display_name=identity.display_name,
            operating_system=identity.operating_system,
            agent_version=identity.agent_version,
        )
        if not register_result.ok:
            logger.warning("Could not refresh registration with backend: %s", register_result.error)
        # Liveness signal for the dashboard's online/stale/offline status.
        heartbeat_result = client.heartbeat(
            endpoint_id=stored_cred.endpoint_id, agent_credential=stored_cred.agent_credential
        )
        if not heartbeat_result.ok:
            logger.warning("Heartbeat failed: %s", heartbeat_result.error)

    collection = _collect_one_cycle()
    now_iso = datetime.now(timezone.utc).isoformat()
    runtime_state.record_successful_collection(now_iso)

    pending = state.load_pending()
    pending_keys = {_event_key(e) for e in pending}
    new_events = [e for e in collection.events if _event_key(e) not in pending_keys]
    to_send = pending + new_events

    logger.info(
        "Collected %d new real event(s) this cycle (%d previously buffered, unsent).",
        len(new_events),
        len(pending),
    )

    has_category_errors = bool(collection.category_status)

    if not to_send:
        print(
            json.dumps(
                {"collected": 0, "sent": 0, "buffered": 0, "category_status": collection.category_status},
                indent=2,
            )
        )
        return 1 if has_category_errors else 0

    if stored_cred is None:
        kept = state.append_pending(new_events)
        logger.error("Cannot submit events: this endpoint has no agent credential (enrollment did not complete).")
        print(
            json.dumps(
                {
                    "collected": len(new_events),
                    "sent": 0,
                    "buffered": kept,
                    "reason": "not_enrolled",
                    "category_status": collection.category_status,
                },
                indent=2,
            )
        )
        return 1

    result = client.ingest_events(
        endpoint_id=stored_cred.endpoint_id,
        agent_credential=stored_cred.agent_credential,
        log_name=settings.log_channel,
        events=to_send,
    )
    if result.ok:
        state.clear_pending()
        # Only now — after a CONFIRMED successful backend response for
        # exactly this batch — does the cursor move forward.
        checkpoint.commit(settings.log_channel, collection.cursor_candidates)
        runtime_state.record_successful_upload(now_iso)
        print(
            json.dumps(
                {
                    "collected": len(new_events),
                    "sent": len(to_send),
                    "backend_response": result.data,
                    "category_status": collection.category_status,
                },
                indent=2,
            )
        )
        return 1 if has_category_errors else 0

    # Backend unavailable or ingestion not enabled — never pretend the
    # events were uploaded, and never advance the checkpoint for a batch
    # that was not confirmed. Buffer them (bounded) for the next attempt.
    kept = state.append_pending(new_events)
    logger.error(
        "Could not submit events to backend (%s). %d event(s) buffered locally (capped at %d). "
        "Collection checkpoint NOT advanced — these events will be retried.",
        result.error,
        kept,
        state.MAX_PENDING_EVENTS,
    )
    print(
        json.dumps(
            {
                "collected": len(new_events),
                "sent": 0,
                "buffered": kept,
                "reason": result.error,
                "status_code": result.status_code,
                "category_status": collection.category_status,
            },
            indent=2,
        )
    )
    return 1


def _process_report() -> dict:
    pid = process_control.running_pid()
    return {"running": pid is not None, "pid": pid if pid not in (None, -1) else None}


def _sleep_unless_stopped(seconds: float) -> bool:
    """Sleeps up to `seconds`; returns True as soon as a stop is requested."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process_control.stop_requested():
            return True
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    return process_control.stop_requested()


def cmd_run(_args: argparse.Namespace) -> int:
    logger.info(
        "Starting continuous collection: interval=%ds, categories=%s",
        settings.collection_interval,
        settings.category_list,
    )
    try:
        while True:
            try:
                cmd_collect(_args)
            except Exception:
                # One bad cycle (network down, disk hiccup, ...) must never
                # end the agent: log it and try again next interval. Unsent
                # events stay buffered and the checkpoint is untouched.
                logger.exception("Collection cycle failed; will retry in %ds.", settings.collection_interval)
            if _sleep_unless_stopped(settings.collection_interval):
                logger.info("Stop requested; shutting down cleanly.")
                return 0
    except KeyboardInterrupt:
        logger.info("Stopped by user (Ctrl+C).")
        return 0


def _run_single_instance(args: argparse.Namespace) -> int:
    lock = process_control.acquire_instance_lock()
    if lock is None:
        message = "Another UBADS agent instance is already running; not starting a second one."
        logger.warning(message)
        print(message)
        return 3
    try:
        return cmd_run(args)
    finally:
        lock.release()


def cmd_collect_guarded(args: argparse.Namespace) -> int:
    """--collect must not race a running agent (both would read/advance the
    same checkpoint)."""
    lock = process_control.acquire_instance_lock()
    if lock is None:
        print("The UBADS agent is already running and collecting on its own; nothing to do.")
        return 0
    try:
        return cmd_collect(args)
    finally:
        lock.release()


# --verify-enrollment exit codes (used by the installer to decide whether to show success)
EXIT_VERIFY_NOT_ENROLLED = 40
EXIT_VERIFY_BACKEND_UNREACHABLE = 41
EXIT_VERIFY_CREDENTIAL_REJECTED = 42
EXIT_VERIFY_NOT_RUNNING = 43


def cmd_verify_enrollment(args: argparse.Namespace) -> int:
    """Confirms, for real, that this computer is enrolled and working: a credential is stored
    and decrypts, the server accepts it (authenticated heartbeat) and - with --require-running -
    the background agent is alive. Prints no secrets."""
    try:
        stored = credential_store.load_credential()
    except credential_store.CredentialProtectionUnavailable:
        stored = None
    if stored is None:
        print("Not enrolled: no usable credential is stored on this computer.", file=sys.stderr)
        return EXIT_VERIFY_NOT_ENROLLED
    result = BackendClient().heartbeat(endpoint_id=stored.endpoint_id, agent_credential=stored.agent_credential)
    if not result.ok:
        if result.status_code == 401:
            print("The server rejected this computer's credential (it may have been revoked).", file=sys.stderr)
            return EXIT_VERIFY_CREDENTIAL_REJECTED
        print(f"Could not confirm with the server: {result.error}", file=sys.stderr)
        return EXIT_VERIFY_BACKEND_UNREACHABLE
    if args.require_running and process_control.running_pid() is None:
        print("The background agent is not running.", file=sys.stderr)
        return EXIT_VERIFY_NOT_RUNNING
    print(f"Enrollment verified. Endpoint ID: {stored.endpoint_id}. Server accepted the credential.")
    return 0


def cmd_install_task(_args: argparse.Namespace) -> int:
    if credential_store.load_credential() is None:
        print("Warning: this computer is not enrolled yet. Run --setup first, or the agent will have nothing to send.")
    result = task_scheduler.install_task()
    if not result.ok:
        print(f"Could not create the startup task: {result.output}", file=sys.stderr)
        return 1
    mode = "with administrator rights" if task_scheduler.is_elevated() else "WITHOUT administrator rights"
    print(f"Startup task '{task_scheduler.TASK_NAME}' created for {task_scheduler.current_user()} {mode}.")
    if not task_scheduler.is_elevated():
        print(
            "Note: reading the Security log needs administrator rights (or Event Log Readers membership). "
            "Re-run --install-task from an Administrator prompt to start the agent elevated."
        )
    print("It starts automatically at this user's next sign-in. Use --start to start it now.")
    return 0


def cmd_uninstall_task(_args: argparse.Namespace) -> int:
    cmd_stop(_args)
    result = task_scheduler.uninstall_task()
    print("Startup task removed." if result.ok else f"Could not remove the startup task: {result.output}")
    return 0 if result.ok else 1


def _wait_for_task_to_settle(timeout: float = 45.0) -> None:
    """Task Scheduler ignores a new run (MultipleInstancesPolicy=IgnoreNew) while the previous
    run is still winding down - the one-file exe's launcher outlives the agent for a moment.
    Without this, `--stop` followed at once by `--start` (i.e. `--restart`) silently did nothing."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if task_scheduler.task_info().get("state") != "Running":
            return
        if process_control.running_pid() is not None:  # a run that is already up is not "winding down"
            return
        time.sleep(1.0)


def cmd_start(_args: argparse.Namespace) -> int:
    pid = process_control.running_pid()
    if pid is not None:
        print(f"The agent is already running (pid {pid}).")
        return 0
    if task_scheduler.task_info().get("installed"):
        _wait_for_task_to_settle()
        if process_control.running_pid() is not None:
            print("The agent is running.")
            return 0
        result = task_scheduler.run_task()
        if not result.ok:
            print(f"Could not start the scheduled task: {result.output}", file=sys.stderr)
            return 1
    else:
        program, _arguments, workdir = task_scheduler.background_command()
        command = [program, "--background"] if is_frozen() else [program, str(Path(__file__).resolve()), "--background"]
        subprocess.Popen(
            command,
            cwd=workdir,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            close_fds=True,
        )
    for _ in range(80):  # a frozen one-file exe can take 10-20s to unpack and start
        if process_control.running_pid() is not None:
            print("The agent is running.")
            return 0
        time.sleep(0.5)
    print("The agent did not start. See the log file shown by --status.", file=sys.stderr)
    return 1


def cmd_stop(_args: argparse.Namespace) -> int:
    if process_control.running_pid() is None:
        print("The agent is not running.")
        return 0
    process_control.request_stop()
    if process_control.wait_until_stopped(settings.request_timeout * 3 + 5):
        print("The agent stopped.")
        return 0
    # Did not stop in time (e.g. stuck mid-request): fall back to the scheduler.
    task_scheduler.end_task()
    if process_control.wait_until_stopped(10):
        print("The agent was force-stopped.")
        return 0
    print("The agent is still running. Stop it from Task Manager (ubads-agent).", file=sys.stderr)
    return 1


def cmd_restart(args: argparse.Namespace) -> int:
    return cmd_stop(args) or cmd_start(args)


def _dispatch(args: argparse.Namespace) -> int:
    if args.enroll or args.enroll_stdin or args.enroll_from_process is not None:
        mode = "stdin" if args.enroll_stdin else "process" if args.enroll_from_process is not None else "prompt"
        return enrollment.cli_enroll(
            mode,
            pid=args.enroll_from_process,
            backend_url=args.backend_url,
            allow_insecure_http=args.allow_insecure_http,
            allow_local=args.allow_local,
        )
    if args.verify_enrollment:
        return cmd_verify_enrollment(args)
    if args.setup:
        return cmd_setup(args)
    if args.identity:
        return cmd_identity(args)
    if args.status:
        return cmd_status(args)
    if args.collect:
        return cmd_collect_guarded(args)
    if args.install_task:
        return cmd_install_task(args)
    if args.uninstall_task:
        return cmd_uninstall_task(args)
    if args.start:
        return cmd_start(args)
    if args.stop:
        return cmd_stop(args)
    if args.restart:
        return cmd_restart(args)
    return _run_single_instance(args)


def main(argv: list[str] | None = None) -> int:
    # parsed first so --background can switch logging to a file before anything logs

    # An enrollment code must never travel on a command line (it would sit in process
    # listings/shell history, and argparse would echo it in its error text). Refuse early,
    # without printing the offending value.
    if any(str(arg).strip().lower().startswith("ubads1.") for arg in (argv if argv is not None else sys.argv[1:])):
        print(
            "Do not pass an enrollment code on the command line. Use --enroll (hidden prompt) or --enroll-stdin.",
            file=sys.stderr,
        )
        return enrollment.EXIT_USAGE

    parser = argparse.ArgumentParser(description="UBADS Windows Endpoint Agent")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--identity", action="store_true", help="Show local endpoint identity.")
    group.add_argument("--status", action="store_true", help="Check configuration and backend connectivity.")
    group.add_argument("--collect", action="store_true", help="Run one collection-and-submit cycle.")
    group.add_argument("--setup", action="store_true", help="First-time setup: set server address and enroll.")
    group.add_argument("--enroll", action="store_true", help="Enroll with a one-time code from an approved request (hidden prompt).")
    group.add_argument("--enroll-stdin", action="store_true", help="Enroll with a one-time code read from one line of standard input.")
    group.add_argument(
        "--enroll-from-process",
        type=int,
        metavar="PID",
        help="Installer interface: PID of the installer that launched this agent (its file name carries the code).",
    )
    group.add_argument("--verify-enrollment", action="store_true", help="Check enrollment end to end (credential, server, optionally the running agent).")
    group.add_argument("--run", action="store_true", help="Run continuously until Ctrl+C.")
    group.add_argument("--background", action="store_true", help="Run continuously with no console (logs to a file).")
    group.add_argument("--install-task", action="store_true", help="Start the agent automatically at sign-in (Task Scheduler).")
    group.add_argument("--uninstall-task", action="store_true", help="Remove the automatic-start task.")
    group.add_argument("--start", action="store_true", help="Start the agent in the background now.")
    group.add_argument("--stop", action="store_true", help="Stop the background agent cleanly.")
    group.add_argument("--restart", action="store_true", help="Stop then start the background agent.")
    setup = parser.add_argument_group("--setup / --enroll options")
    setup.add_argument("--backend-url", help="UBADS server address, e.g. https://ubads.example.com")
    setup.add_argument("--enrollment-key", help="Enrollment key (prompted for if omitted; avoid shell history).")
    setup.add_argument("--allow-insecure-http", action="store_true", help="Permit http:// to a non-local host (trusted LAN trials only).")
    setup.add_argument("--require-running", action="store_true", help="With --verify-enrollment: also require the background agent to be running.")
    setup.add_argument("--allow-local", action="store_true", help="Permit localhost (same-computer testing).")
    args = parser.parse_args(argv)

    if is_frozen_production():
        try:
            ensure_protected_storage()
        except ProtectedStorageError:
            print("Agent storage security could not be verified; the agent was not started.", file=sys.stderr)
            return 1
        is_enrollment = args.enroll or args.enroll_stdin or args.enroll_from_process is not None
        is_recovery = args.stop or args.uninstall_task
        allowed_without_config = is_recovery or (config_module.PRODUCTION_CONFIG_MISSING and is_enrollment)
        if config_module.PRODUCTION_CONFIG_ERROR and not allowed_without_config:
            print(config_module.PRODUCTION_CONFIG_ERROR, file=sys.stderr)
            return 1

    try:
        _configure_logging(background=args.background)
        return _dispatch(args)
    except credential_store.CredentialStateError as exc:
        logger.error("Agent stopped because stored credentials are unsafe (%s).", type(exc).__name__)
        print(
            "Stored agent credentials are corrupt or inaccessible; enrollment was stopped. "
            "Administrator recovery is required.",
            file=sys.stderr,
        )
        return 1
    except (IdentityStateError, ProtectedStorageError, state.PendingStateError, OSError) as exc:
        logger.error("Agent stopped because local protected storage is unavailable (%s).", type(exc).__name__)
        print(
            "The agent could not safely read or update local state. No replacement endpoint identity was created.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
