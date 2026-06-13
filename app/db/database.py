import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    create_engine, Column, String, Integer, Boolean,
    Float, Text, DateTime, JSON
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text

from app.config import get_settings


def _build_engine():
    settings = get_settings()
    url = settings.database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True, echo=False)


engine = _build_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(String, primary_key=True, index=True)
    api_key_hint = Column(String, nullable=True)          # first 8 chars only
    user_id = Column(String, nullable=True, index=True)
    user_query_hash = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    blocked = Column(Boolean, nullable=False)
    chunks_received = Column(Integer, nullable=False)
    chunks_passed = Column(Integer, nullable=False)
    threats_detected = Column(Integer, nullable=False)
    processing_time_ms = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, nullable=False, index=True)
    threat_type = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    source = Column(String, nullable=False)
    matched_pattern = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


class RiskScoreAudit(Base):
    __tablename__ = "risk_score_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, nullable=False, index=True)
    component_scores = Column(JSON, nullable=False)
    final_score = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


def init_db() -> None:
    # Import every ORM model so SQLAlchemy registers them with Base.metadata
    # before create_all(). Missing imports = missing tables in test & prod.
    from app.payments.models import Subscription, PaymentEvent  # noqa: F401
    from app.auth.users import User  # noqa: F401
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_request(
    db: Session,
    request_id: str,
    user_id: Optional[str],
    query_hash: str,
    risk_score: int,
    blocked: bool,
    chunks_received: int,
    chunks_passed: int,
    threats_detected: int,
    processing_time_ms: float,
    api_key_hint: Optional[str] = None,
) -> None:
    entry = RequestLog(
        id=request_id,
        api_key_hint=api_key_hint,
        user_id=user_id,
        user_query_hash=query_hash,
        risk_score=risk_score,
        blocked=blocked,
        chunks_received=chunks_received,
        chunks_passed=chunks_passed,
        threats_detected=threats_detected,
        processing_time_ms=processing_time_ms,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()


def save_threats(db: Session, request_id: str, threats: list) -> None:
    for t in threats:
        entry = ThreatLog(
            request_id=request_id,
            threat_type=t["threat_type"],
            description=t["description"],
            severity=t["severity"],
            source=t["source"],
            matched_pattern=t.get("matched_pattern"),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(entry)
    db.commit()


def save_score_audit(db: Session, request_id: str, component_scores: dict, final_score: int) -> None:
    entry = RiskScoreAudit(
        request_id=request_id,
        component_scores=component_scores,
        final_score=final_score,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()


def check_db_connection() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False


# ── Demo usage table ──────────────────────────────────────────────────────────

class DemoUsageLog(Base):
    """One row per IP hash. scans_used never resets — hard lifetime limit."""
    __tablename__ = "demo_usage"

    ip_hash    = Column(String, primary_key=True, index=True)
    scans_used = Column(Integer, nullable=False, default=0)
    first_scan_at = Column(DateTime, nullable=False)
    last_scan_at  = Column(DateTime, nullable=False)


DEMO_LIMIT = 3


def get_demo_usage(db: Session, ip_hash: str) -> int:
    row = db.query(DemoUsageLog).filter(DemoUsageLog.ip_hash == ip_hash).first()
    return row.scans_used if row else 0


def increment_demo_usage(db: Session, ip_hash: str) -> int:
    now = datetime.now(timezone.utc)
    row = db.query(DemoUsageLog).filter(DemoUsageLog.ip_hash == ip_hash).first()
    if row:
        row.scans_used += 1
        row.last_scan_at = now
    else:
        row = DemoUsageLog(
            ip_hash=ip_hash, scans_used=1,
            first_scan_at=now, last_scan_at=now,
        )
        db.add(row)
    db.commit()
    return row.scans_used
