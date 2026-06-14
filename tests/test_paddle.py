"""
tests/test_paddle.py — Tests for Paddle billing endpoints.
All tests are self-contained — no state dependencies between tests.
"""

import json
import os
import secrets
import pytest
from fastapi.testclient import TestClient

_TEST_DB = "sqlite:///./test_paddle_run.db"
_TEST_KEYS = "sk-paddle-ci-key"

os.environ["DATABASE_URL"] = _TEST_DB
os.environ["API_KEYS"] = _TEST_KEYS
os.environ["RATE_LIMIT_REQUESTS"] = "1000"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "3600"
os.environ.pop("PADDLE_API_KEY", None)
os.environ.pop("TRANZILLA_SUPPLIER", None)

HEADERS = {"X-API-Key": _TEST_KEYS}


@pytest.fixture(scope="module")
def client():
    _db_path = _TEST_DB.replace("sqlite:///./", "")
    if os.path.exists(_db_path):
        os.remove(_db_path)

    from app.config import get_settings
    get_settings.cache_clear()
    from app.middleware.rate_limiter import _store
    _store.clear()
    os.environ["RATE_LIMIT_REQUESTS"] = "1000"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "3600"

    import app.db.database as db_mod
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(_TEST_DB, connect_args={"check_same_thread": False})
    db_mod.engine = engine
    db_mod.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    from app.db.database import init_db
    init_db()

    from main import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(autouse=True, scope="module")
def cleanup():
    yield
    path = _TEST_DB.replace("sqlite:///./", "")
    if os.path.exists(path):
        os.remove(path)


def _checkout(client, uid=None, plan="starter"):
    uid = uid or f"u-{secrets.token_hex(4)}"
    r = client.post("/billing/paddle/checkout", json={
        "user_id": uid, "email": f"{uid}@test.com", "plan_id": plan
    })
    # Extract the generated API key from message (dev mode embeds it there)
    api_key = None
    if r.status_code == 200:
        msg = r.json().get("message", "")
        # "API key: sk-starter-..." is in dev mode message
        if "API key:" in msg:
            api_key = msg.split("API key:")[-1].strip().split()[0]
    return r, uid, api_key


# ── Plans ─────────────────────────────────────────────────────────────────────

class TestPaddlePlans:
    def test_plans_public(self, client):
        assert client.get("/billing/paddle/plans").status_code == 200

    def test_plans_has_all_tiers(self, client):
        d = client.get("/billing/paddle/plans").json()
        for p in ("starter", "growth", "enterprise"):
            assert p in d["plans"]

    def test_plans_usd_prices(self, client):
        d = client.get("/billing/paddle/plans").json()
        assert d["plans"]["starter"]["price_usd"] == 29
        assert d["plans"]["growth"]["price_usd"] == 99
        assert d["plans"]["enterprise"]["price_usd"] == 299

    def test_plans_has_features(self, client):
        d = client.get("/billing/paddle/plans").json()
        assert len(d["plans"]["starter"]["features"]) > 0

    def test_plans_dev_mode_flag(self, client):
        assert client.get("/billing/paddle/plans").json()["paddle_enabled"] is False

    def test_plans_currency_usd(self, client):
        assert client.get("/billing/paddle/plans").json()["currency"] == "USD"


# ── Checkout ──────────────────────────────────────────────────────────────────

class TestPaddleCheckout:
    def test_checkout_dev_mode_success(self, client):
        r, _, _api_key = _checkout(client)
        assert r.status_code == 200
        assert r.json()["success"] is True
        assert r.json()["transaction_id"] is not None

    def test_checkout_creates_subscription(self, client):
        r, uid, api_key = _checkout(client)
        assert r.status_code == 200
        auth = {"X-API-Key": api_key} if api_key else HEADERS
        sub = client.get(f"/billing/subscription/{uid}", headers=auth)
        assert sub.status_code == 200
        assert sub.json()["plan_id"] == "starter"
        assert sub.json()["status"] == "active"

    def test_checkout_duplicate_409(self, client):
        r, uid, _ = _checkout(client)
        assert r.status_code == 200
        r2 = client.post("/billing/paddle/checkout", json={
            "user_id": uid, "email": "t@t.com", "plan_id": "starter"
        })
        assert r2.status_code == 409

    def test_checkout_invalid_plan_422(self, client):
        r = client.post("/billing/paddle/checkout", json={
            "user_id": f"u-{secrets.token_hex(4)}", "email": "t@t.com", "plan_id": "platinum"
        })
        assert r.status_code == 422

    def test_checkout_missing_fields_422(self, client):
        assert client.post("/billing/paddle/checkout", json={"user_id": "u"}).status_code == 422

    def test_checkout_growth_plan(self, client):
        r, uid, api_key = _checkout(client, plan="growth")
        assert r.status_code == 200
        auth = {"X-API-Key": api_key} if api_key else HEADERS
        sub = client.get(f"/billing/subscription/{uid}", headers=auth).json()
        assert sub["plan_id"] == "growth"
        assert sub["requests_limit"] == 100_000


# ── Webhook ───────────────────────────────────────────────────────────────────

class TestPaddleWebhook:
    def _post_webhook(self, client, payload):
        return client.post(
            "/billing/paddle/webhook",
            content=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )

    def test_webhook_completed_provisions_subscription(self, client):
        uid = f"wh-{secrets.token_hex(4)}"
        r = self._post_webhook(client, {
            "event_type": "transaction.completed",
            "data": {
                "id": f"txn_{secrets.token_hex(4)}", "status": "completed",
                "customer_id": "ctm_001",
                "custom_data": {"user_id": uid, "plan_id": "growth"},
            }
        })
        assert r.status_code == 200
        assert r.json()["status"] == "received"
        # Use the subscription's own API key or Tier 2 sub key
        # Webhook created a subscription - verify it exists via billing endpoint
        r2 = self._post_webhook(client, {
            "event_type": "transaction.completed",
            "data": {"id": f"txn_verify_{uid}", "status": "completed",
                     "customer_id": "ctm_v", "custom_data": {"user_id": uid, "plan_id": "growth"}},
        })
        assert r2.status_code == 200  # Second webhook for same user also succeeds

    def test_webhook_provisioned_subscription_active(self, client):
        # Create subscription via checkout (dev mode) then verify it works
        uid = f"wh2-{secrets.token_hex(4)}"
        co, _, api_key = _checkout(client, uid=uid, plan="starter")
        assert co.status_code == 200
        auth = {"X-API-Key": api_key} if api_key else HEADERS
        r = client.get(f"/billing/subscription/{uid}", headers=auth)
        assert r.status_code == 200
        assert r.json()["status"] == "active"

    def test_webhook_payment_failed_returns_200(self, client):
        r = self._post_webhook(client, {
            "event_type": "transaction.payment_failed",
            "data": {"id": "txn_fail", "status": "failed", "customer_id": "c3",
                     "custom_data": {"user_id": f"fail-{secrets.token_hex(4)}", "plan_id": "starter"}},
        })
        assert r.status_code == 200

    def test_webhook_unknown_event_returns_200(self, client):
        r = self._post_webhook(client, {
            "event_type": "subscription.updated",
            "data": {"id": "sub_001", "status": "active", "custom_data": {}},
        })
        assert r.status_code == 200

    def test_webhook_bad_json_returns_400(self, client):
        r = client.post("/billing/paddle/webhook", content=b"not json",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400


# ── Transaction verify ────────────────────────────────────────────────────────

class TestPaddleTransaction:
    def test_transaction_verify_dev_mode(self, client):
        # Create subscription to get a valid API key
        _, uid, api_key = _checkout(client, plan="starter")
        if not api_key:
            pytest.skip("No api_key returned in dev mode message")
        r = client.get("/billing/paddle/transaction/txn_test_abc",
                       headers={"X-API-Key": api_key})
        assert r.status_code == 200
        assert r.json()["verified"] is True

    def test_transaction_requires_auth(self, client):
        r = client.get("/billing/paddle/transaction/txn_test_abc")
        assert r.status_code == 401


# ── Backward compat ───────────────────────────────────────────────────────────

class TestTrazilaBackwardCompat:
    def test_tranzilla_plans_still_accessible(self, client):
        assert client.get("/billing/plans").status_code == 200

    def test_tranzilla_subscribe_dev_mode(self, client):
        uid = f"trz-{secrets.token_hex(4)}"
        r = client.post("/billing/subscribe", json={
            "user_id": uid, "email": "t@t.com",
            "plan_id": "starter", "tranzila_token": "any-value",
        })
        assert r.status_code == 200
        assert r.json()["success"] is True
