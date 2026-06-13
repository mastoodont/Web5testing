"""
auth/users.py — User account management.

Separate from subscription — a user account exists independently of payment.
Flow:
  1. POST /auth/register  — create account (name + email + password)
  2. POST /auth/login     — verify credentials, return user info
  3. GET  /auth/me        — get own account info (requires X-API-Key)

Password: bcrypt direct (falls back to sha256 if bcrypt not installed).
"""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.orm import Session

from app.db.database import Base, get_db

logger = logging.getLogger("securerag.auth")
user_router = APIRouter(prefix="/auth", tags=["auth"])


# ── DB model ──────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    user_id       = Column(String, primary_key=True, index=True)
    email         = Column(String, nullable=False, unique=True, index=True)
    password_hash = Column(String, nullable=False)
    created_at    = Column(DateTime, nullable=False, default=datetime.utcnow)
    is_active     = Column(Boolean, nullable=False, default=True)


# ── Password hashing (bcrypt preferred, sha256 fallback) ─────────────────────

def _hash_password(plain: str) -> str:
    """Hash password with bcrypt (direct) or sha256 fallback."""
    try:
        import bcrypt
        return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except Exception:
        salt = secrets.token_hex(16)
        h = hashlib.sha256((salt + plain).encode()).hexdigest()
        return f"sha256${salt}${h}"


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify password against stored hash."""
    try:
        if hashed.startswith("sha256$"):
            _, salt, digest = hashed.split("$", 2)
            return hashlib.sha256((salt + plain).encode()).hexdigest() == digest
        import bcrypt
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── Schemas ───────────────────────────────────────────────────────────────────

_VALID_USER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{1,48}[a-zA-Z0-9]$")


class RegisterRequest(BaseModel):
    user_id:  str
    email:    str
    password: str

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        v = v.strip()
        if not _VALID_USER_ID.match(v):
            raise ValueError(
                "Account name must be 3–50 characters, "
                "letters/numbers/hyphens, not starting or ending with a hyphen."
            )
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class RegisterResponse(BaseModel):
    success:    bool
    user_id:    str
    email:      str
    message:    str


class LoginRequest(BaseModel):
    user_id:  str
    password: str


class LoginResponse(BaseModel):
    success:       bool
    user_id:       str
    email:         str
    has_active_sub: bool
    plan_id:       Optional[str]
    message:       str


class MeResponse(BaseModel):
    user_id:        str
    email:          str
    has_active_sub: bool
    plan_id:        Optional[str]
    requests_used:  Optional[int]
    requests_limit: Optional[int]
    period_end:     Optional[datetime]
    created_at:     datetime


# ── CRUD helpers ──────────────────────────────────────────────────────────────

def get_user(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.user_id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.lower()).first()


def create_user(db: Session, user_id: str, email: str, password: str) -> User:
    user = User(
        user_id=user_id,
        email=email.lower(),
        password_hash=_hash_password(password),
        created_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── Routes ────────────────────────────────────────────────────────────────────

@user_router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create a new user account.
    The account name (user_id) and email must both be unique.
    No payment required at this step.
    """
    # Check uniqueness
    if get_user(db, body.user_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Account name '{body.user_id}' is already taken. Please choose another.",
        )
    if get_user_by_email(db, body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = create_user(db, body.user_id, body.email, body.password)
    logger.info("New user registered: %s (%s)", user.user_id, user.email)

    return RegisterResponse(
        success=True,
        user_id=user.user_id,
        email=user.email,
        message=(
            f"Account '{user.user_id}' created. "
            "Choose a plan below to get your API key."
        ),
    )


@user_router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, db: Session = Depends(get_db)):
    """
    Verify credentials. Returns user info and subscription status.
    Not a token-based auth — the API key IS the auth token for API calls.
    This endpoint is for the dashboard UI to look up account state.
    """
    user = get_user(db, body.user_id)
    if not user or not _verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid account name or password.",
        )

    # Check subscription
    try:
        from app.payments.models import Subscription
        sub = (
            db.query(Subscription)
            .filter(
                Subscription.user_id == body.user_id,
                Subscription.status == "active",
            )
            .first()
        )
    except Exception:
        sub = None

    return LoginResponse(
        success=True,
        user_id=user.user_id,
        email=user.email,
        has_active_sub=sub is not None,
        plan_id=sub.plan_id if sub else None,
        message="Login successful.",
    )


@user_router.get("/check/{user_id}")
async def check_user_id(user_id: str, db: Session = Depends(get_db)):
    """
    Check if a user_id is available (for real-time validation in the signup form).
    Public endpoint — no auth required.
    """
    taken = get_user(db, user_id) is not None
    return {"user_id": user_id, "available": not taken}
