"""
payments/paypal.py — PayPal Subscriptions integration for USA market.

Supports:
    - PayPal subscription plans (recurring billing)
    - Checkout session creation → redirect to PayPal
    - Webhook verification + event handling
    - Subscription cancel via PayPal API

Docs: https://developer.paypal.com/docs/subscriptions/
"""

import os
import logging
import hashlib
import hmac
import base64
from typing import Optional, Dict
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("securerag.paypal")

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_ENVIRONMENT = os.getenv("PAYPAL_ENVIRONMENT", "sandbox")  # sandbox | live
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")

PAYPAL_BASE_URL = (
    "https://api-m.paypal.com"
    if PAYPAL_ENVIRONMENT == "live"
    else "https://api-m.sandbox.paypal.com"
)

SUCCESS_URL = os.getenv("PAYPAL_SUCCESS_URL", "https://your-app.railway.app/payment/success")
CANCEL_URL = os.getenv("PAYPAL_CANCEL_URL", "https://your-app.railway.app/payment/cancel")

# Plans: plan_id from PayPal dashboard → our internal plan
PAYPAL_PLAN_IDS: Dict[str, str] = {
    "starter":    os.getenv("PAYPAL_PLAN_STARTER", ""),
    "growth":     os.getenv("PAYPAL_PLAN_GROWTH", ""),
    "enterprise": os.getenv("PAYPAL_PLAN_ENTERPRISE", ""),
}

PLANS = {
    "starter": {
        "name": "Starter",
        "price_usd": 29,
        "requests_per_month": 10_000,
        "rate_limit_per_min": 60,
    },
    "growth": {
        "name": "Growth",
        "price_usd": 99,
        "requests_per_month": 100_000,
        "rate_limit_per_min": 300,
    },
    "enterprise": {
        "name": "Enterprise",
        "price_usd": 299,
        "requests_per_month": 1_000_000,
        "rate_limit_per_min": 1000,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# PayPal API client
# ─────────────────────────────────────────────────────────────────────────────

class PayPalClient:
    def __init__(self):
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0

    def _get_access_token(self) -> str:
        """Get OAuth2 access token. Auto-refreshes when expired."""
        import time
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        credentials = base64.b64encode(
            f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()
        ).decode()

        response = httpx.post(
            f"{PAYPAL_BASE_URL}/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"grant_type": "client_credentials"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        import time
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3600)
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_subscription(
        self,
        plan_id_internal: str,
        user_id: str,
        email: str,
        return_url: str = SUCCESS_URL,
        cancel_url: str = CANCEL_URL,
    ) -> dict:
        """
        Create a PayPal subscription and return the approval URL.
        Redirect the user to approval_url to complete payment.
        """
        paypal_plan_id = PAYPAL_PLAN_IDS.get(plan_id_internal)
        if not paypal_plan_id:
            raise ValueError(
                f"PAYPAL_PLAN_{plan_id_internal.upper()} not set in environment"
            )

        payload = {
            "plan_id": paypal_plan_id,
            "subscriber": {
                "email_address": email,
            },
            "application_context": {
                "brand_name": "SecureRAG Guard",
                "locale": "en-US",
                "shipping_preference": "NO_SHIPPING",
                "user_action": "SUBSCRIBE_NOW",
                "payment_method": {
                    "payer_selected": "PAYPAL",
                    "payee_preferred": "IMMEDIATE_PAYMENT_REQUIRED",
                },
                "return_url": f"{return_url}?user_id={user_id}&plan={plan_id_internal}",
                "cancel_url": cancel_url,
            },
            "custom_id": user_id,  # stored in webhook events
        }

        response = httpx.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions",
            headers=self._headers(),
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        # Extract approval URL
        approval_url = next(
            (link["href"] for link in data.get("links", []) if link["rel"] == "approve"),
            None,
        )

        return {
            "subscription_id": data["id"],
            "status": data["status"],
            "approval_url": approval_url,
        }

    def get_subscription(self, subscription_id: str) -> dict:
        """Get subscription details from PayPal."""
        response = httpx.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers=self._headers(),
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def cancel_subscription(self, subscription_id: str, reason: str = "User requested cancellation") -> bool:
        """Cancel a PayPal subscription."""
        response = httpx.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/cancel",
            headers=self._headers(),
            json={"reason": reason},
            timeout=10,
        )
        return response.status_code == 204

    def verify_webhook(self, headers: dict, body: bytes) -> bool:
        """
        Verify PayPal webhook signature.
        https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature
        """
        if not PAYPAL_WEBHOOK_ID:
            logger.warning("PAYPAL_WEBHOOK_ID not set — skipping webhook verification")
            return True

        try:
            payload = {
                "auth_algo": headers.get("paypal-auth-algo", ""),
                "cert_url": headers.get("paypal-cert-url", ""),
                "transmission_id": headers.get("paypal-transmission-id", ""),
                "transmission_sig": headers.get("paypal-transmission-sig", ""),
                "transmission_time": headers.get("paypal-transmission-time", ""),
                "webhook_id": PAYPAL_WEBHOOK_ID,
                "webhook_event": body.decode(),
            }
            response = httpx.post(
                f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature",
                headers=self._headers(),
                json=payload,
                timeout=10,
            )
            data = response.json()
            return data.get("verification_status") == "SUCCESS"
        except Exception as e:
            logger.error(f"Webhook verification failed: {e}")
            return False


# Singleton
_client: Optional[PayPalClient] = None


def get_client() -> PayPalClient:
    global _client
    if _client is None:
        if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
            raise RuntimeError(
                "PayPal not configured. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET."
            )
        _client = PayPalClient()
    return _client


def is_enabled() -> bool:
    return bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET)
