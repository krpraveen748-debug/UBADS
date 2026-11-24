"""Seeds the ISOLATED browser-test database (never data/app.db).

Refuses to run unless DATABASE_URL points inside the system temp directory, so
a misconfiguration cannot seed - or touch - a real database.
"""

import os
import sys
import tempfile
from pathlib import Path

url = os.environ.get("DATABASE_URL", "")
prefix = "sqlite:///"
if not url.startswith(prefix):
    sys.exit("seed_e2e_db: DATABASE_URL must be a sqlite file URL")
db_path = Path(url[len(prefix):]).resolve()
if Path(tempfile.gettempdir()).resolve() not in db_path.parents:
    sys.exit(f"seed_e2e_db: refusing to seed {db_path} - not inside the temp directory")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.db.database import Base, SessionLocal, engine  # noqa: E402
from app.models import dashboard_auth as _d, enrollment as _e  # noqa: E402,F401
from app.security import dashboard_auth  # noqa: E402

Base.metadata.create_all(bind=engine)
with SessionLocal() as session:
    dashboard_auth.create_user(
        session, os.environ["E2E_ADMIN_USER"], os.environ["E2E_ADMIN_PASSWORD"], role="admin", full_name="E2E Admin"
    )
    dashboard_auth.create_user(
        session,
        os.environ["E2E_USER_USER"],
        os.environ["E2E_USER_PASSWORD"],
        role="user",
        email="e2e-user@example.org",
        full_name="E2E Requester",
        organization="E2E Org",
    )
print("seeded", db_path.name)
