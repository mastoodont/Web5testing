"""
tests/conftest.py

Root conftest — provides proper isolation between test modules that
each create their own FastAPI app with different settings/DB/env.

The problem: test_api.py mutates os.environ and app.db.database.engine.
When test_payments.py runs afterward, it inherits a broken engine.

Solution: reset all mutable module-level singletons before each test module.
"""

import os
import pytest


@pytest.fixture(autouse=True, scope="module")
def isolate_module_state():
    """
    Runs around every test module:
    - BEFORE: reset all global singletons so this module starts clean
    - AFTER: reset again so the next module starts clean
    Both resets are needed because pytest collects all modules before running any.
    """
    _reset_all()   # ← reset BEFORE module starts (key fix)
    yield
    _reset_all()   # ← reset AFTER module finishes


def _reset_all():
    # 1. Settings cache
    try:
        from app.config import get_settings
        get_settings.cache_clear()
    except Exception:
        pass

    # 2. Rate limiter
    try:
        from app.middleware.rate_limiter import _store
        _store.clear()
    except Exception:
        pass

    # 3. ML classifier singleton (stateless between modules, but clear anyway)
    try:
        import app.ml.classifier as clf
        clf._pipeline = None
    except Exception:
        pass

    # 4. Reset DB engine so next module's DATABASE_URL env var takes effect
    try:
        import app.db.database as db_mod
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        db_url = os.environ.get("DATABASE_URL", "sqlite:///./securerag.db")
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
            pool_pre_ping=True,
        )
        db_mod.engine = engine
        db_mod.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    except Exception:
        pass

    # 5. Clear Paddle client singleton
    try:
        import app.payments.paddle as paddle_mod
        paddle_mod._client = None
    except Exception:
        pass
