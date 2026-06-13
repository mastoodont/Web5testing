"""
payments/paddle_routes.py

Paddle Billing endpoints:

  GET  /billing/paddle/plans              — plans with USD prices (public)
  POST /billing/paddle/checkout           — create Paddle checkout session
  POST /billing/paddle/webhook            — Paddle webhook receiver
  GET  /billing/paddle/transaction/{id}   — verify transaction status
"""

import logging
import secrets
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.payments.paddle import (
    PLANS,
    get_client,
    is_paddle_enabled,
    PaddleClient,
)
from app.payments.models import (
    create_subscription,
    get_subscription_by_user,
    cancel_subscription,
    log_payment_event,
)
from app.auth.api_key import verify_api_key

logger = logging.getLogger("securerag.payments.paddle")
paddle_router = APIRouter(prefix="/billing/paddle", tags=["billing-paddle"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class CheckoutRequest(BaseModel):
    user_id: str
    email: str
    plan_id: str

    @field_validator("plan_id")
    @classmethod
    def validate_plan(cls, v):
        if v not in PLANS:
            raise ValueError(f"Invalid plan. Choose from: {list(PLANS.keys())}")
        return v


class CheckoutResponse(BaseModel):
    success: bool
    checkout_url: Optional[str]
    transaction_id: Optional[str]
    message: str


class TransactionStatus(BaseModel):
    transaction_id: str
    status: str
    plan_id: Optional[str]
    user_id: Optional[str]
    verified: bool


# ── Routes ────────────────────────────────────────────────────────────────────

@paddle_router.get("/plans")
async def paddle_plans():
    """
    Return all plans with USD prices for global clients.
    No auth required.
    """
    return {
        "currency": "USD",
        "billing": "monthly",
        "plans": {
            plan_id: {
                "name": plan["name"],
                "price_usd": plan["price_usd"],
                "price_ils": plan["price_ils"],
                "requests_per_month": plan["requests_per_month"],
                "rate_limit_per_min": plan["rate_limit_per_min"],
                "description": plan["description"],
                "features": plan.get("features", []),
            }
            for plan_id, plan in PLANS.items()
        },
        "paddle_enabled": is_paddle_enabled(),
    }


@paddle_router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    body: CheckoutRequest,
    db: Session = Depends(get_db),
):
    """
    Create a Paddle checkout session.

    Returns a checkout_url — redirect the user there.
    Paddle handles card entry, VAT, currency conversion.
    After payment, Paddle POSTs to /billing/paddle/webhook.

    In dev mode (no PADDLE_API_KEY), returns a mock response.
    """
    # Check for existing subscription
    existing = get_subscription_by_user(db, body.user_id)
    if existing and existing.status == "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User {body.user_id} already has an active {existing.plan_id} subscription.",
        )

    plan = PLANS[body.plan_id]

    if not is_paddle_enabled():
        # Dev mode — simulate checkout without real Paddle call
        logger.warning("PADDLE_API_KEY not set — dev mode, simulating checkout")

        dev_txn_id = f"txn_dev_{secrets.token_hex(8)}"
        new_api_key = f"sk-{body.plan_id}-{secrets.token_urlsafe(32)}"

        create_subscription(
            db=db,
            user_id=body.user_id,
            api_key=new_api_key,
            plan_id=body.plan_id,
            requests_limit=plan["requests_per_month"],
            rate_limit_per_min=plan["rate_limit_per_min"],
            amount_ils=float(plan["price_ils"]),
            conf_num=dev_txn_id,
        )

        log_payment_event(
            db=db,
            user_id=body.user_id,
            event_type="checkout_dev",
            success=True,
            plan_id=body.plan_id,
            amount_ils=float(plan["price_ils"]),
            conf_num=dev_txn_id,
        )

        logger.info("DEV checkout: user=%s plan=%s key=%s", body.user_id, body.plan_id, new_api_key[:20])

        return CheckoutResponse(
            success=True,
            checkout_url=None,
            transaction_id=dev_txn_id,
            message=(
                f"[DEV MODE] Subscription created. API key: {new_api_key} "
                f"(Set PADDLE_API_KEY for real payments)"
            ),
        )

    # Real Paddle checkout
    try:
        client = get_client()
        result = client.create_checkout(
            plan_id=body.plan_id,
            user_id=body.user_id,
            customer_email=body.email,
        )
    except Exception as exc:
        logger.error("Paddle checkout error for user %s: %s", body.user_id, exc)
        raise HTTPException(status_code=502, detail="Payment gateway error. Please try again.")

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not create checkout: {result.error_message}",
        )

    log_payment_event(
        db=db,
        user_id=body.user_id,
        event_type="checkout_created",
        success=True,
        plan_id=body.plan_id,
        amount_ils=float(plan["price_ils"]),
        conf_num=result.transaction_id,
    )

    return CheckoutResponse(
        success=True,
        checkout_url=result.checkout_url,
        transaction_id=result.transaction_id,
        message=f"Redirect user to checkout_url to complete payment for {plan['name']} plan.",
    )


@paddle_router.post("/webhook")
async def paddle_webhook(
    request: Request,
    db: Session = Depends(get_db),
    paddle_signature: Optional[str] = Header(default=None, alias="Paddle-Signature"),
):
    """
    Receive Paddle webhook notifications.

    Paddle sends events here after each transaction.
    On transaction.completed — provision the subscription and generate API key.

    Configure this URL in Paddle dashboard → Notifications.
    """
    raw_body = await request.body()

    # Verify signature
    if is_paddle_enabled() and paddle_signature:
        try:
            client = get_client()
            if not client.verify_webhook(raw_body, paddle_signature):
                logger.warning("Paddle webhook signature verification FAILED")
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Webhook verification error: %s", e)
            raise HTTPException(status_code=400, detail="Webhook verification error")

    import json
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    try:
        client = get_client() if is_paddle_enabled() else _MockPaddleClient()
        event = client.parse_webhook(body)
    except Exception as e:
        logger.error("Webhook parse error: %s", e)
        raise HTTPException(status_code=400, detail="Could not parse webhook")

    logger.info(
        "Paddle webhook: event=%s txn=%s user=%s plan=%s status=%s",
        event.event_type, event.transaction_id,
        event.user_data, event.plan_id, event.status,
    )

    # Handle successful payment — provision subscription
    if event.event_type == "transaction.completed" and event.status == "completed":
        user_id = event.user_data
        plan_id = event.plan_id

        if user_id and plan_id and plan_id in PLANS:
            plan = PLANS[plan_id]
            existing = get_subscription_by_user(db, user_id)

            if not existing or existing.status != "active":
                new_api_key = f"sk-{plan_id}-{secrets.token_urlsafe(32)}"
                create_subscription(
                    db=db,
                    user_id=user_id,
                    api_key=new_api_key,
                    plan_id=plan_id,
                    requests_limit=plan["requests_per_month"],
                    rate_limit_per_min=plan["rate_limit_per_min"],
                    amount_ils=float(plan["price_ils"]),
                    conf_num=event.transaction_id,
                )
                logger.info(
                    "Subscription provisioned via webhook: user=%s plan=%s txn=%s",
                    user_id, plan_id, event.transaction_id,
                )

            log_payment_event(
                db=db,
                user_id=user_id or "unknown",
                event_type="paddle_webhook_completed",
                success=True,
                plan_id=plan_id,
                amount_ils=float(PLANS.get(plan_id, {}).get("price_ils", 0)),
                conf_num=event.transaction_id,
            )

    # Handle payment failure
    elif event.event_type in ("transaction.payment_failed", "subscription.past_due"):
        log_payment_event(
            db=db,
            user_id=event.user_data or "unknown",
            event_type=f"paddle_{event.event_type}",
            success=False,
            plan_id=event.plan_id,
            conf_num=event.transaction_id,
            error_message=f"Paddle event: {event.event_type}",
        )

    return {"status": "received", "event_type": event.event_type}


@paddle_router.get("/transaction/{transaction_id}", response_model=TransactionStatus)
async def get_transaction(
    transaction_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """
    Verify a Paddle transaction status.
    Use after the user returns from the checkout page to confirm payment.
    Requires valid API key.
    """
    if not is_paddle_enabled():
        # Dev mode
        return TransactionStatus(
            transaction_id=transaction_id,
            status="completed",
            plan_id=None,
            user_id=None,
            verified=True,
        )

    try:
        client = get_client()
        raw = client.get_transaction(transaction_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not fetch transaction: {e}")

    if "error" in raw:
        raise HTTPException(status_code=404, detail="Transaction not found")

    data = raw.get("data", {})
    custom_data = data.get("custom_data") or {}
    if isinstance(custom_data, str):
        import json
        try:
            custom_data = json.loads(custom_data)
        except Exception:
            custom_data = {}

    return TransactionStatus(
        transaction_id=transaction_id,
        status=data.get("status", "unknown"),
        plan_id=custom_data.get("plan_id"),
        user_id=custom_data.get("user_id"),
        verified=data.get("status") == "completed",
    )


# ── Internal mock for dev mode webhook parsing ────────────────────────────────

class _MockPaddleClient:
    """Used in dev mode (no PADDLE_API_KEY) for webhook parsing."""
    def parse_webhook(self, body: Dict) -> object:
        from app.payments.paddle import PaddleClient, WebhookEvent
        # Re-use PaddleClient's parser — it doesn't need API key
        # Instantiate without env check by calling the method directly
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
