"""Manual stress tool (not collected by pytest): many fresh databases, many threads
redeeming ONE code at once; every round must have exactly one winner.
Run from the project root:  .venv\Scripts\python.exe tests/backend/stress_redeem.py"""
import sys, tempfile, threading, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path[:0] = ["backend", "log-collector"]
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.database import Base
from app.models import dashboard_auth, endpoint, enrollment  # noqa: F401
from app.models.dashboard_auth import DashboardUser
from app.models.endpoint import EndpointRecord
from app.models.enrollment import EndpointRequest, EnrollmentAuthorization
from app.services import enrollment_service
from app.security import rate_limit

ROUNDS, THREADS = 40, 16
tmp = Path(tempfile.mkdtemp(prefix="stress-"))
stub = tmp / "UBADS-Agent-Setup.exe"
stub.write_bytes(b"x")
settings.installer_path = str(stub)
bad = 0
try:
    for rnd in range(ROUNDS):
        rate_limit.reset_all()
        engine = create_engine(f"sqlite:///{tmp / f'r{rnd}.db'}", connect_args={"check_same_thread": False, "timeout": 30})
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)
        now = datetime.now(timezone.utc)
        with Session() as s:
            s.add(DashboardUser(username="racer", password_hash="x", created_at=now, role="user"))
            s.add(EndpointRequest(id="r1", username="racer", organization="Org", requested_scope="authentication", approved_scope="authentication",
                                  consent_version="v", consent_acknowledged_at=now, status="APPROVED", created_at=now, updated_at=now,
                                  approval_expires_at=now + timedelta(days=1)))
            s.commit()
            code = enrollment_service.mint_package(s, s.get(DashboardUser, "racer"), "r1").code
        outcomes, barrier = [], threading.Barrier(THREADS)

        def attempt(n):
            with Session() as s:
                barrier.wait()
                try:
                    r = enrollment_service.redeem(s, code=code, display_name="x", operating_system="w", agent_version="t",
                                                  endpoint_id=f"{n:08d}-0000-4000-8000-000000000000", ip=f"203.0.113.{n}")
                    outcomes.append(("ok", r["endpoint_id"]))
                except HTTPException as e:
                    outcomes.append((e.status_code, e.detail["code"] if isinstance(e.detail, dict) else str(e.detail)))
                except Exception as e:
                    outcomes.append(("exception", f"{type(e).__name__}: {str(e)[:150]}"))

        ts = [threading.Thread(target=attempt, args=(n,)) for n in range(THREADS)]
        [t.start() for t in ts]; [t.join(90) for t in ts]
        wins = [o for o in outcomes if o[0] == "ok"]
        others = {o for o in outcomes if o[0] != "ok"}
        with Session() as s:
            endpoints = s.query(EndpointRecord).count()
        if len(outcomes) != THREADS or len(wins) != 1 or endpoints != 1 or others - {(409, "already_used")}:
            bad += 1
            print("ROUND", rnd, "unexpected:", len(outcomes), len(wins), endpoints, sorted(others)[:5])
        engine.dispose()
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print(f"rounds={ROUNDS} threads={THREADS} unexpected={bad}")
