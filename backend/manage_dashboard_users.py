"""
Local operator CLI for dashboard logins (never exposed over HTTP).

    python manage_dashboard_users.py --create-user NAME   (prompts for password)
    python manage_dashboard_users.py --list
    python manage_dashboard_users.py --delete-user NAME

--create-user on an existing name resets its password and signs it out.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.db.database import SessionLocal  # noqa: E402
from app.models.dashboard_auth import DashboardSession, DashboardUser  # noqa: E402
from app.security import dashboard_auth  # noqa: E402

def main() -> int:
    parser = argparse.ArgumentParser(description="Manage UBADS dashboard logins")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create-user", metavar="NAME")
    group.add_argument("--list", action="store_true")
    group.add_argument("--delete-user", metavar="NAME")
    args = parser.parse_args()

    with SessionLocal() as session:
        if args.list:
            for user in session.query(DashboardUser).order_by(DashboardUser.username):
                print(user.username)
            return 0
        if args.delete_user:
            deleted = session.query(DashboardUser).filter_by(username=args.delete_user).delete()
            session.query(DashboardSession).filter_by(username=args.delete_user).delete()
            session.commit()
            print("Deleted." if deleted else "No such user.")
            return 0 if deleted else 1
        password = getpass.getpass("New password (min 12 chars): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 2
        try:
            dashboard_auth.create_user(session, args.create_user, password)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"Dashboard user '{args.create_user}' saved.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
