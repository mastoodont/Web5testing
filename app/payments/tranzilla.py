"""
payments/tranzilla.py

Production Tranzilla payment gateway integration.
Tranzilla is an Israeli payment processor (tranzila.com).

Supports:
  - One-time charges (credit card tokenization via TranzilaTK)
  - Subscription plan creation and management
  - Webhook signature verification
  - Refunds

Docs: https://www.tranzila.com/en/developers

Environment variables required:
  TRANZILLA_SUPPLIER     — your Tranzilla supplier name (terminal ID)
  TRANZILLA_TOKEN        — API token for server-side calls
  TRANZILLA_NOTIFY_URL   — webhook URL Tranzilla will POST to
  TRANZILLA_SUCCESS_URL  — redirect after successful hosted-page payment
  TRANZILLA_FAIL_URL     — redirect after failed hosted-page payment
"""

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlencode

import httpx

logger = logging.getLogger("securerag.payments.tranzilla")

TRANZILLA_BASE_URL = "https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi"
TRANZILLA_HOSTED_URL = "https://direct.tranzila.com/{supplier}/iframenew.php"

SUPPLIER = os.getenv("TRANZILLA_SUPPLIER", "")
TOKEN = os.getenv("TRANZILLA_TOKEN", "")
NOTIFY_URL = os.getenv("TRANZILLA_NOTIFY_URL", "")
SUCCESS_URL = os.getenv("TRANZILLA_SUCCESS_URL", "")
FAIL_URL = os.getenv("TRANZILLA_FAIL_URL", "")


# ── Plan definitions ──────────────────────────────────────────────────────────

PLANS: Dict[str, Dict] = {
    "starter": {
        "name": "Starter",
        "price_ils": 99,           # ₪ per month
        "requests_per_month": 10_000,
        "rate_limit_per_min": 60,
        "description": "Up to 10K API calls/month",
    },
    "growth": {
        "name": "Growth",
        "price_ils": 299,
        "requests_per_month": 100_000,
        "rate_limit_per_min": 300,
        "description": "Up to 100K API calls/month",
    },
    "enterprise": {
        "name": "Enterprise",
        "price_ils": 999,
        "requests_per_month": 1_000_000,
        "rate_limit_per_min": 1000,
        "description": "Up to 1M API calls/month + SLA",
    },
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ChargeResult:
    success: bool
    transaction_id: Optional[str]
    error_code: Optional[str]
    error_message: Optional[str]
    raw_response: Dict


@dataclass
class RefundResult:
    success: bool
    transaction_id: Optional[str]
    error_message: Optional[str]
    raw_response: Dict


# ── Tranzilla API client ───────────────────────────────────────────────────────

class TranzillaClient:
    """
    Server-side Tranzilla API client.

    For PCI compliance, never pass raw card numbers through your server.
    Use TranzilaTK (hosted fields) to tokenize on the client side,
    then pass the token here.
    """

    def __init__(self):
        if not SUPPLIER:
            raise RuntimeError(
                "TRANZILLA_SUPPLIER env var is not set. "
                "Get your supplier name from the Tranzilla admin panel."
            )

    def _post(self, params: Dict) -> Dict:
        """Send a form-POST to the Tranzilla gateway and parse the response."""
        params["supplier"] = SUPPLIER
        if TOKEN:
            params["TranzilaTK"] = TOKEN

        logger.debug("Tranzilla request params (masked): %s", _mask_params(params))

        try:
            response = httpx.post(
                TRANZILLA_BASE_URL,
                data=params,
                timeout=15.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Tranzilla HTTP error: %s", exc)
            return {"Response": "9999", "error": str(exc)}

        # Tranzilla returns key=value pairs in the body
        result = _parse_tranzilla_response(response.text)
        logger.info(
            "Tranzilla response: Response=%s ConfNum=%s",
            result.get("Response"),
            result.get("ConfNum", "—"),
        )
        return result

    def charge_token(
        self,
        tranzila_token: str,
        amount_ils: float,
        plan_id: str,
        customer_email: str,
        description: str = "",
    ) -> ChargeResult:
        """
        Charge a customer using a TranzilaTK token (PCI-safe).

        tranzila_token — token returned by the hosted fields JS library
        amount_ils     — amount in Israeli shekels (e.g. 99.00)
        """
        params = {
            "TranzilaTK": tranzila_token,
            "sum": f"{amount_ils:.2f}",
            "currency": "1",          # 1 = ILS, 2 = USD, 978 = EUR
            "cred_type": "1",         # 1 = regular credit
            "tranmode": "A",          # A = charge
            "email": customer_email,
            "remarks": description or f"SecureRAG Guard — {plan_id}",
            "notify_url": NOTIFY_URL,
        }

        raw = self._post(params)
        success = raw.get("Response") == "000"

        return ChargeResult(
            success=success,
            transaction_id=raw.get("ConfNum"),
            error_code=raw.get("Response") if not success else None,
            error_message=_tranzilla_error(raw.get("Response", "")) if not success else None,
            raw_response=raw,
        )

    def refund(
        self,
        original_transaction_id: str,
        amount_ils: float,
    ) -> RefundResult:
        """Refund a previous transaction."""
        params = {
            "tranmode": "C",          # C = credit (refund)
            "sum": f"{amount_ils:.2f}",
            "currency": "1",
            "index": original_transaction_id,
        }

        raw = self._post(params)
        success = raw.get("Response") == "000"

        return RefundResult(
            success=success,
            transaction_id=raw.get("ConfNum"),
            error_message=_tranzilla_error(raw.get("Response", "")) if not success else None,
            raw_response=raw,
        )

    def generate_hosted_page_url(
        self,
        plan_id: str,
        customer_email: str,
        user_id: str,
    ) -> str:
        """
        Generate a Tranzilla hosted payment page URL.
        Redirect the customer here for card entry — your server never sees raw card data.
        """
        plan = PLANS.get(plan_id)
        if not plan:
            raise ValueError(f"Unknown plan: {plan_id}")

        params = {
            "supplier": SUPPLIER,
            "sum": str(plan["price_ils"]),
            "currency": "1",
            "cred_type": "1",
            "tranmode": "A",
            "email": customer_email,
            "remarks": f"SecureRAG Guard — {plan['name']}",
            "notify_url": NOTIFY_URL,
            "success_url": SUCCESS_URL,
            "fail_url": FAIL_URL,
            "hidesum": "1",
            "lang": "il",             # "il" = Hebrew, "en" = English
            "user_data": user_id,
        }

        base = TRANZILLA_HOSTED_URL.format(supplier=SUPPLIER)
        return f"{base}?{urlencode(params)}"

    def verify_webhook(self, payload: str, received_signature: str) -> bool:
        """
        Verify a Tranzilla webhook notification using HMAC-SHA256.
        The shared secret is your TRANZILLA_TOKEN.
        """
        secret = TOKEN.encode()
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

        return hmac.compare_digest(expected, received_signature)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_tranzilla_response(body: str) -> Dict:
    """Parse Tranzilla's key=value response body into a dict."""
    result = {}
    for line in body.strip().split("\n"):
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _mask_params(params: Dict) -> Dict:
    sensitive = {"TranzilaTK", "ccno", "expdate", "mycvv"}
    return {k: ("***" if k in sensitive else v) for k, v in params.items()}


_TRANZILLA_ERRORS: Dict[str, str] = {
    "001": "Card blocked",
    "002": "Card stolen",
    "003": "Contact issuer",
    "004": "Card declined",
    "005": "Card refused",
    "006": "General error",
    "007": "Incorrect card number",
    "008": "No such issuer",
    "033": "Expired card",
    "036": "Card restricted",
    "039": "No credit account",
    "051": "Insufficient funds",
    "054": "Expired card",
    "057": "Transaction not permitted",
    "058": "Transaction not permitted to terminal",
    "061": "Exceeds withdrawal amount",
    "062": "Restricted card",
    "065": "Exceeds withdrawal frequency",
    "075": "PIN tries exceeded",
    "082": "Incorrect CVV",
    "091": "Card issuer unavailable",
    "096": "System error",
}


def _tranzilla_error(code: str) -> str:
    return _TRANZILLA_ERRORS.get(code, f"Transaction declined (code {code})")


# ── Module-level singleton ────────────────────────────────────────────────────

_client: TranzillaClient | None = None


def get_client() -> TranzillaClient:
    global _client
    if _client is None:
        _client = TranzillaClient()
    return _client
