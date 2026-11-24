from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint

from app.repositories.pipeline_bridge import storage


class AnomalyDetection(storage.Base):
    __tablename__ = "anomaly_detections"
    __table_args__ = (
        UniqueConstraint(
            "profile_id",
            "window_start",
            "window_size",
            "model_version",
            name="uq_anomaly_profile_window_model",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id = Column(String, nullable=False, index=True)
    profile_id = Column(String, nullable=False, index=True)
    username = Column(String, nullable=True)
    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    window_end = Column(DateTime(timezone=True), nullable=False)
    window_size = Column(String, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    severity = Column(String, nullable=False)
    explanation_json = Column(Text, nullable=False)
    explanation_method = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    training_data_source = Column(String, nullable=False)
    detected_at = Column(DateTime(timezone=True), nullable=False, index=True)
    is_anomaly = Column(Boolean, nullable=False, default=True)
