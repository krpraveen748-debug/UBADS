from __future__ import annotations

from pydantic import BaseModel


class UserSummary(BaseModel):
    """One human-candidate account, from
    user_classification_diagnostics.generate_user_classification_report()
    (Phase 6A.1) — reused as-is, not re-derived. `sid_present` is a
    boolean rather than the raw SID, matching that module's existing
    privacy stance."""

    username: str | None = None
    domain: str | None = None
    account_type: str
    event_count: int
    sid_present: bool
    is_human_candidate: bool
    exclusion_reason: str | None = None


class UserBaseline(BaseModel):
    """One user's behavioral baseline summary for GET /api/users/baselines.
    Field names are camelCase to match the frontend's existing Users &
    Baselines page (built against this exact shape in Phase 8A)."""

    username: str | None = None
    endpoint: str | None = None
    observedDays: int
    events: int
    typicalLoginWindow: str
    typicalActivityHours: str
    commonCategories: list[str]
    baselineStatus: str  # "insufficient_data" | "building" | "ready"
    mlReadiness: str
