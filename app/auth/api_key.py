"""
auth/api_key.py

Two-tier API key validation:
  1. Static keys from settings (env var API_KEYS) — for dev/testing
  2. Subscription keys from the database (sk-... keys issued at subscribe time)

This means a key obtained via POST /billing/subscribe works immediately
without restarting the server or editing .env.
"""
import logging
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.database import get_db

logger = logging.getLogger("securerag.auth")

_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    raw_key: str = Security(_api_key_scheme),
    db: Session = Depends(get_db),
) -> str:
    settings = get_settings()

    if not raw_key:
        logger.warning("Request missing API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Supply it in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Tier 1: static keys from env (dev / admin)
    if raw_key in settings.get_api_keys():
        return raw_key

    # Tier 2: subscription keys from DB
    try:
        from app.payments.models import Subscription
        sub = db.query(Subscription).filter(
            Subscription.api_key == raw_key,
            Subscription.status == "active",
        ).first()
        if sub:
            return raw_key
    except Exception:
        pass  # DB unavailable — fall through to 403

    logger.warning("Invalid API key presented: %s…", raw_key[:8])
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key.",
    )
