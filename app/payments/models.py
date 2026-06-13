"""
payments/models.py — SQLAlchemy models and CRUD for subscriptions.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import Column, String, Integer, Boolean, DateTime, Float
from sqlalchemy.orm import Session

from app.db.database import Base


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False, unique=True, index=True)
    api_key = Column(String, nullable=False, unique=True, index=True)
    plan_id = Column(String, nullable=False)                 # starter / growth / enterprise
    status = Column(String, nullable=False, default="active")  # active / cancelled / past_due
    requests_used = Column(Integer, nullable=False, default=0)
    requests_limit = Column(Integer, nullable=False)
    rate_limit_per_min = Column(Integer, nullable=False)
    amount_ils = Column(Float, nullable=False)
    tranzilla_conf_num = Column(String, nullable=True)       # last successful transaction ID
    current_period_start = Column(DateTime, nullable=False)
    current_period_end = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class PaymentEvent(Base):
    __tablename__ = "payment_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False)   # charge / refund / webhook
    plan_id = Column(String, nullable=True)
    amount_ils = Column(Float, nullable=True)
    tranzilla_conf_num = Column(String, nullable=True)
    success = Column(Boolean, nullable=False)
    error_message = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


# ── CRUD helpers ──────────────────────────────────────────────────────────────

def create_subscription(
    db: Session,
    user_id: str,
    api_key: str,
    plan_id: str,
    requests_limit: int,
    rate_limit_per_min: int,
    amount_ils: float,
    conf_num: Optional[str] = None,
) -> Subscription:
    now = datetime.now(timezone.utc)
    sub = Subscription(
        user_id=user_id,
        api_key=api_key,
        plan_id=plan_id,
        status="active",
        requests_used=0,
        requests_limit=requests_limit,
        rate_limit_per_min=rate_limit_per_min,
        amount_ils=amount_ils,
        tranzilla_conf_num=conf_num,
        current_period_start=now,
        current_period_end=now + timedelta(days=30),
        created_at=now,
        updated_at=now,
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub


def get_subscription_by_api_key(db: Session, api_key: str) -> Optional[Subscription]:
    return db.query(Subscription).filter(Subscription.api_key == api_key).first()


def get_subscription_by_user(db: Session, user_id: str) -> Optional[Subscription]:
    return db.query(Subscription).filter(Subscription.user_id == user_id).first()


def increment_usage(db: Session, api_key: str) -> None:
    sub = get_subscription_by_api_key(db, api_key)
    if sub:
        sub.requests_used += 1
        sub.updated_at = datetime.now(timezone.utc)
        db.commit()


def cancel_subscription(db: Session, user_id: str) -> bool:
    sub = get_subscription_by_user(db, user_id)
    if not sub:
        return False
    sub.status = "cancelled"
    sub.updated_at = datetime.now(timezone.utc)
    db.commit()
    return True


def log_payment_event(
    db: Session,
    user_id: str,
    event_type: str,
    success: bool,
    plan_id: Optional[str] = None,
    amount_ils: Optional[float] = None,
    conf_num: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    event = PaymentEvent(
        user_id=user_id,
        event_type=event_type,
        plan_id=plan_id,
        amount_ils=amount_ils,
        tranzilla_conf_num=conf_num,
        success=success,
        error_message=error_message,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
