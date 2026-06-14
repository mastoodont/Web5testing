"""
payments/paddle.py

Paddle Billing integration for SecureRAG Guard.
Paddle is the Merchant of Record — they handle VAT, compliance, refunds globally.
Works perfectly from Israel for charging global clients (USD/EUR/GBP).

Paddle REST API v2: https://developer.paddle.com/api-reference

Environment variables required:
  PADDLE_API_KEY          — your Paddle secret API key (live_... or test_...)
  PADDLE_WEBHOOK_SECRET   — from Paddle dashboard → Notifications → webhook secret
  PADDLE_ENVIRONMENT      — "production" or "sandbox" (default: sandbox)

Setup steps:
  1. Sign up at paddle.com (works from Israel)
  2. Create products + prices in Paddle dashboard for each plan
  3. Set PADDLE_PRODUCT_STARTER, PADDLE_PRODUCT_GROWTH, PADDLE_PRODUCT_ENTERPRISE
     to the Paddle price IDs (pri_...)
  4. Set PADDLE_WEBHOOK_SECRET from dashboard
  5. Set PADDLE_SUCCESS_URL and PADDLE_CANCEL_URL
"""

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

import httpx

logger = logging.getLogger("securerag.payments.paddle")

# ── Environment ───────────────────────────────────────────────────────────────

PADDLE_API_KEY = os.getenv("PADDLE_API_KEY", "")
PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "")
PADDLE_ENVIRONMENT = os.getenv("PADDLE_ENVIRONMENT", "sandbox")
PADDLE_SUCCESS_URL = os.getenv("PADDLE_SUCCESS_URL", "https://your-app.railway.app/payment/success")
PADDLE_CANCEL_URL = os.getenv("PADDLE_CANCEL_URL", "https://your-app.railway.app/payment/cancel")

# Paddle price IDs — create these in Paddle dashboard for each plan
PADDLE_PRICE_IDS: Dict[str, str] = {
    "starter":    os.getenv("PADDLE_PRICE_STARTER", ""),
    "growth":     os.getenv("PADDLE_PRICE_GROWTH", ""),
    "enterprise": os.getenv("PADDLE_PRICE_ENTERPRISE", ""),
}

PADDLE_BASE_URL = (
    "https://api.paddle.com"
    if PADDLE_ENVIRONMENT == "production"
    else "https://sandbox-api.paddle.com"
)

# ── Plan definitions (USD prices for global market) ───────────────────────────

PLANS: Dict[str, Dict] = {
    "starter": {
        "name": "Starter",
        "price_usd": 29,           # $29/month — competitive globally
        "price_ils": 99,           # ₪99/month — for Israeli clients via Tranzilla
        "requests_per_month": 10_000,
        "rate_limit_per_min": 60,
        "description": "Up to 10K API calls/month",
        "features": [
            "10,000 scans/month",
            "60 req/min rate limit",
            "Prompt injection detection",
            "Document poisoning detection",
            "Python SDK",
            "Email support",
        ],
    },
    "growth": {
        "name": "Growth",
        "price_usd": 99,
        "price_ils": 299,
        "requests_per_month": 100_000,
        "rate_limit_per_min": 300,
        "description": "Up to 100K API calls/month",
        "features": [
            "100,000 scans/month",
            "300 req/min rate limit",
            "All Starter features",
            "LangChain + OpenAI middleware",
            "PDF/DOCX file scanning",
            "Priority support",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_usd": 299,
        "price_ils": 999,
        "requests_per_month": 1_000_000,
        "rate_limit_per_min": 1000,
        "description": "Up to 1M API calls/month + SLA",
        "features": [
            "1,000,000 scans/month",
            "1,000 req/min rate limit",
            "All Growth features",
            "99.9% SLA",
            "Custom patterns",
            "Dedicated Slack channel",
            "Custom integrations",
        ],
    },
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class CheckoutResult:
    success: bool
    checkout_url: Optional[str]       # redirect user here for payment
    transaction_id: Optional[str]     # Paddle transaction ID after payment
    customer_id: Optional[str]
    error_message: Optional[str]
    raw_response: Dict


@dataclass
class WebhookEvent:
    event_type: str                   # e.g. "transaction.completed"
    transaction_id: Optional[str]
    customer_id: Optional[str]
    user_data: Optional[str]          # custom_data we passed in checkout
    plan_id: Optional[str]
    status: str                       # "completed" / "failed" / etc.
    raw: Dict


# ── Paddle API Client ─────────────────────────────────────────────────────────

class PaddleClient:
    """
    Paddle Billing REST API v2 client.

    Paddle is Merchant of Record — they handle:
    - Global card processing (Visa, Mastercard, PayPal, Apple Pay)
    - VAT / GST calculation and remittance
    - Refunds and disputes
    - PCI compliance

    You never touch card data — Paddle's hosted checkout handles everything.
    """

    def __init__(self):
        if not PADDLE_API_KEY:
            raise RuntimeError(
                "PADDLE_API_KEY env var not set. "
                "Get your API key from paddle.com dashboard → Developer → Authentication."
            )
        self._headers = {
            "Authorization": f"Bearer {PADDLE_API_KEY}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str, params: Dict = None) -> Dict:
        try:
            r = httpx.get(
                f"{PADDLE_BASE_URL}{path}",
                headers=self._headers,
                params=params or {},
                timeout=15.0,
            )
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.error("Paddle GET %s → %s: %s", path, e.response.status_code, e.response.text)
            return {"error": {"type": "http_error", "detail": e.response.text}}
        except httpx.HTTPError as e:
            logger.error("Paddle network error: %s", e)
            return {"error": {"type": "network_error", "detail": str(e)}}

    def _post(self, path: str, body: Dict) -> Dict:
        try:
            r = httpx.post(
                f"{PADDLE_BASE_URL}{path}",
                headers=self._headers,
                json=body,
                timeout=15.0,
            )
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            logger.error("Paddle POST %s → %s: %s", path, e.response.status_code, e.response.text)
            return {"error": {"type": "http_error", "detail": e.response.text}}
        except httpx.HTTPError as e:
            logger.error("Paddle network error: %s", e)
            return {"error": {"type": "network_error", "detail": str(e)}}

    def create_checkout(
        self,
        plan_id: str,
        user_id: str,
        customer_email: str,
    ) -> CheckoutResult:
        """
        Create a Paddle checkout session.
        Returns a URL to redirect the user to for payment.
        Paddle handles the card form, VAT, currency conversion.

        After payment, Paddle POSTs a webhook to /billing/paddle/webhook.
        """
        price_id = PADDLE_PRICE_IDS.get(plan_id)
        if not price_id:
            return CheckoutResult(
                success=False,
                checkout_url=None,
                transaction_id=None,
                customer_id=None,
                error_message=f"Paddle price ID not configured for plan '{plan_id}'. "
                              f"Set PADDLE_PRICE_{plan_id.upper()} env var.",
                raw_response={},
            )

        body = {
            "items": [{"price_id": price_id, "quantity": 1}],
            "customer": {"email": customer_email},
            "custom_data": {
                "user_id": user_id,
                "plan_id": plan_id,
            },
            "settings": {
                "success_url": f"{PADDLE_SUCCESS_URL}?user_id={user_id}&plan={plan_id}",
                "display_mode": "overlay",
                "theme": "dark",
                "locale": "en",
            },
        }

        raw = self._post("/transactions", body)

        if "error" in raw:
            return CheckoutResult(
                success=False,
                checkout_url=None,
                transaction_id=None,
                customer_id=None,
                error_message=raw["error"].get("detail", "Paddle API error"),
                raw_response=raw,
            )

        data = raw.get("data", {})
        checkout_url = data.get("checkout", {}).get("url")
        transaction_id = data.get("id")
        customer_id = data.get("customer_id")

        logger.info("Paddle checkout created: txn=%s user=%s plan=%s", transaction_id, user_id, plan_id)

        return CheckoutResult(
            success=bool(checkout_url),
            checkout_url=checkout_url,
            transaction_id=transaction_id,
            customer_id=customer_id,
            error_message=None if checkout_url else "Checkout URL not returned by Paddle",
            raw_response=raw,
        )

    def get_transaction(self, transaction_id: str) -> Dict:
        """Fetch a transaction by ID — use to verify payment after webhook."""
        return self._get(f"/transactions/{transaction_id}")

    def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a Paddle subscription immediately."""
        raw = self._post(
            f"/subscriptions/{subscription_id}/cancel",
            {"effective_from": "next_billing_period"},
        )
        return "error" not in raw

    def verify_webhook(self, raw_body: bytes, signature_header: str) -> bool:
        """
        Verify a Paddle webhook signature.
        Paddle uses a timestamp + HMAC-SHA256 scheme.

        signature_header format: "ts=1234567890;h1=abcdef..."
        """
        if not PADDLE_WEBHOOK_SECRET:
            logger.warning("PADDLE_WEBHOOK_SECRET not set — skipping webhook verification")
            return True  # dev mode: accept all

        try:
            parts = dict(item.split("=", 1) for item in signature_header.split(";"))
            ts = parts.get("ts", "")
            h1 = parts.get("h1", "")

            signed_payload = f"{ts}:{raw_body.decode('utf-8')}"
            expected = hmac.new(
                PADDLE_WEBHOOK_SECRET.encode(),
                signed_payload.encode(),
                hashlib.sha256,
            ).hexdigest()

            return hmac.compare_digest(expected, h1)
        except Exception as e:
            logger.error("Webhook signature verification error: %s", e)
            return False

    def parse_webhook(self, body: Dict) -> WebhookEvent:
        """Parse a Paddle webhook payload into a structured WebhookEvent."""
        event_type = body.get("event_type", "")
        data = body.get("data", {})

        custom_data = data.get("custom_data") or {}
        if isinstance(custom_data, str):
            import json
            try:
                custom_data = json.loads(custom_data)
            except Exception:
                custom_data = {}

        return WebhookEvent(
            event_type=event_type,
            transaction_id=data.get("id"),
            customer_id=data.get("customer_id"),
            user_data=custom_data.get("user_id"),
            plan_id=custom_data.get("plan_id"),
            status=data.get("status", "unknown"),
            raw=body,
        )


# ── Module-level singleton ─────────────────────────────────────────────────────

_client: Optional[PaddleClient] = None


def get_client() -> PaddleClient:
    global _client
    if _client is None:
        _client = PaddleClient()
    return _client


def is_paddle_enabled() -> bool:
    """True when PADDLE_API_KEY is set — use Paddle. Otherwise dev/Tranzilla mode."""
    return bool(PADDLE_API_KEY)
