"""
tests/test_payments.py

Tests for billing endpoints.
No real Tranzilla calls — TRANZILLA_SUPPLIER unset → dev mode.

Isolation: sets its own env, rebuilds the DB engine, clears settings cache.
"""

import os
import pytest

_TEST_DB = "sqlite:///./test_payments_run.db"
_TEST_KEYS = "sk-pay-test-key,sk-pay-test-key2"

os.environ["DATABASE_URL"] = _TEST_DB
os.environ["API_KEYS"] = _TEST_KEYS
os.environ["RATE_LIMIT_REQUESTS"] = "100"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
os.environ.pop("TRANZILLA_SUPPLIER", None)

HEADERS = {"X-API-Key": "sk-pay-test-key"}


def _rebuild_engine():
    """Force app.db.database to use our test DB, regardless of prior module state."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import app.db.database as db_mod

    engine = create_engine(
        _TEST_DB,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
    db_mod.engine = engine
    db_mod.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    from app.db.database import Base
    from app.payments.models import Subscription, PaymentEvent  # register models
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="module")
def client():
    # Pre-run cleanup: remove stale DB from a previous test run so the
    # first subscribe call always starts with a clean slate.
    _db_path = _TEST_DB.replace("sqlite:///./", "")
    if os.path.exists(_db_path):
        os.remove(_db_path)

    os.environ["DATABASE_URL"] = _TEST_DB
    os.environ["API_KEYS"] = _TEST_KEYS
    os.environ["RATE_LIMIT_REQUESTS"] = "100"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
    os.environ.pop("TRANZILLA_SUPPLIER", None)

    from app.config import get_settings
    get_settings.cache_clear()

    from app.middleware.rate_limiter import _store
    _store.clear()

    _rebuild_engine()

    from main import create_app
    from fastapi.testclient import TestClient
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(autouse=True, scope="module")
def cleanup():
    yield
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)


# ── Plans ─────────────────────────────────────────────────────────────────────

class TestPlans:
    def test_list_plans_public(self, client):
        r = client.get("/billing/plans")
        assert r.status_code == 200
        data = r.json()
        assert "plans" in data
        assert "starter" in data["plans"]
        assert "growth" in data["plans"]
        assert "enterprise" in data["plans"]

    def test_plan_has_required_fields(self, client):
        r = client.get("/billing/plans")
        plan = r.json()["plans"]["starter"]
        assert "price_ils" in plan
        assert "requests_per_month" in plan
        assert "rate_limit_per_min" in plan


# ── Subscribe ─────────────────────────────────────────────────────────────────

class TestSubscribe:
    def test_subscribe_dev_mode_success(self, client):
        payload = {
            "user_id": "user-test-001",
            "email": "test@example.com",
            "plan_id": "starter",
            "tranzila_token": "fake-token-dev",
        }
        r = client.post("/billing/subscribe", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["plan_id"] == "starter"
        assert data["api_key"].startswith("sk-starter-")
        assert "transaction_id" in data

    def test_duplicate_subscription_rejected(self, client):
        payload = {
            "user_id": "user-test-001",
            "email": "test@example.com",
            "plan_id": "starter",
            "tranzila_token": "fake-token-dev",
        }
        r = client.post("/billing/subscribe", json=payload)
        assert r.status_code == 409

    def test_invalid_plan_rejected(self, client):
        payload = {
            "user_id": "user-test-002",
            "email": "test@example.com",
            "plan_id": "diamond",
            "tranzila_token": "fake-token-dev",
        }
        r = client.post("/billing/subscribe", json=payload)
        assert r.status_code == 422


# ── Subscription status ───────────────────────────────────────────────────────

class TestSubscriptionStatus:
    def test_get_status_requires_auth(self, client):
        r = client.get("/billing/subscription/user-test-001")
        assert r.status_code == 401

    def test_get_status_with_auth(self, client):
        r = client.get("/billing/subscription/user-test-001", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["plan_id"] == "starter"
        assert data["status"] == "active"
        assert "requests_used" in data

    def test_nonexistent_user_404(self, client):
        r = client.get("/billing/subscription/no-such-user", headers=HEADERS)
        assert r.status_code == 404


# ── Cancel ────────────────────────────────────────────────────────────────────

class TestCancel:
    def test_cancel_requires_auth(self, client):
        r = client.post("/billing/subscription/user-test-001/cancel")
        assert r.status_code == 401

    def test_cancel_existing_subscription(self, client):
        client.post("/billing/subscribe", json={
            "user_id": "user-cancel-test",
            "email": "cancel@example.com",
            "plan_id": "growth",
            "tranzila_token": "fake",
        })
        r = client.post("/billing/subscription/user-cancel-test/cancel", headers=HEADERS)
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_cancel_nonexistent_404(self, client):
        r = client.post("/billing/subscription/ghost-user/cancel", headers=HEADERS)
        assert r.status_code == 404


# ── Webhook ───────────────────────────────────────────────────────────────────

class TestWebhook:
    def test_webhook_accepted(self, client):
        r = client.post(
            "/billing/payment/webhook",
            data={"Response": "000", "ConfNum": "TEST123", "user_data": "user-test-001"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "received"

    def test_webhook_failed_payment_logged(self, client):
        r = client.post(
            "/billing/payment/webhook",
            data={"Response": "051", "ConfNum": "", "user_data": "user-test-001"},
        )
        assert r.status_code == 200
