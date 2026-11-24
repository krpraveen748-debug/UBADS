"""
Local operator CLI for the Phase 11 per-agent credential model.

This is a manual, explicit local-development/admin tool — it is never run
automatically by the backend or the agent. It talks directly to the same
`endpoints` table the API uses (via the same DATABASE_URL / SQLAlchemy
Base as backend/app/db/database.py), never over HTTP.

Commands:
    python manage_endpoints.py --list
        Show every registered endpoint (safe fields only — never a
        credential hash or the raw secret, which isn't stored anyway).

    python manage_endpoints.py --revoke-credential ENDPOINT_ID
        Clears that endpoint's stored credential verifier, so its old
        credential stops being accepted immediately, and marks the endpoint
        REVOKED. Revocation is final: the shared AGENT_API_KEY can NOT enroll
        it again. Deliberately a manual, explicit action, never something the
        API itself can trigger.

    python manage_endpoints.py --reinstate ENDPOINT_ID
        Operator recovery for a revoked endpoint that does NOT belong to an
        approved request (e.g. to rotate a legacy credential: revoke, then
        reinstate, then run the agent's setup again). Refused for endpoints
        enrolled through the portal: those need a new request.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.db.database import SessionLocal  # noqa: E402
from app.services import endpoint_identity_service  # noqa: E402


def cmd_list(_args: argparse.Namespace) -> int:
    with SessionLocal() as session:
        endpoints = endpoint_identity_service.list_endpoints(session)
    print(json.dumps(endpoints, indent=2))
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    with SessionLocal() as session:
        found = endpoint_identity_service.revoke_credential(session, args.endpoint_id)
    if not found:
        print(f"No such endpoint: {args.endpoint_id}", file=sys.stderr)
        return 1
    print(f"Revoked endpoint {args.endpoint_id}. Its credential no longer works, and it cannot be re-enrolled with the shared key.")
    print("To allow a legacy (non-portal) endpoint to enroll again, run --reinstate; portal endpoints need a new request.")
    return 0


def cmd_reinstate(args: argparse.Namespace) -> int:
    with SessionLocal() as session:
        outcome = endpoint_identity_service.reinstate_endpoint(session, args.endpoint_id)
    messages = {
        "reinstated": f"Endpoint {args.endpoint_id} may now be enrolled again with the shared key.",
        "unknown": f"No such endpoint: {args.endpoint_id}",
        "not_revoked": f"Endpoint {args.endpoint_id} is not revoked; nothing to do.",
        "request_linked": f"Endpoint {args.endpoint_id} belongs to an approved request and cannot be reinstated; a new request is required.",
    }
    print(messages[outcome], file=sys.stderr if outcome != "reinstated" else sys.stdout)
    return 0 if outcome == "reinstated" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UBADS backend endpoint management (local operator tool)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List all registered endpoints.")
    group.add_argument("--revoke-credential", metavar="ENDPOINT_ID", help="Revoke one endpoint's credential (final).")
    group.add_argument("--reinstate", metavar="ENDPOINT_ID", help="Allow a revoked, non-portal endpoint to enroll again.")
    args = parser.parse_args(argv)

    if args.list:
        return cmd_list(args)
    if args.reinstate:
        return cmd_reinstate(argparse.Namespace(endpoint_id=args.reinstate))
    return cmd_revoke(argparse.Namespace(endpoint_id=args.revoke_credential))


if __name__ == "__main__":
    sys.exit(main())
