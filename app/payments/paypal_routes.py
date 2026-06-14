"""
payments/paypal_routes.py — PayPal subscription endpoints for USA market.

Endpoints:
    GET  /billing/paypal/plans              — list plans with USD prices
    POST /billing/paypal/checkout           — create subscription → return approval URL
    POST /billing/paypal/webhook            — receive PayPal events
    GET  /billing/paypal/subscription/{id}  — get subscription status
    POST /billing/paypal/cancel/{user_id}   — cancel subscription
"""

import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.auth.api_key import verify_api_key
from app.payments.paypal import get_client, is_enabled, PLANS
from app.payments.models import (
    Subscription,
    create_subscription,
    get_subscription_by_user,
    cancel_subscription,
    log_payment_event,
)

logger = logging.getLogger("securerag.paypal")
paypal_router = APIRouter(prefix="/billing/paypal", tags=["billing-paypal"])


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class PayPalCheckoutRequest(BaseModel):
    user_id: str
    email: str
    plan_id: str  # starter | growth | enterprise


class PayPalCheckoutResponse(BaseModel):
    approval_url: str       # redirect user here to complete PayPal payment
    subscription_id: str    # PayPal subscription ID (save this)
    plan_id: str
    plan_name: str
    price_usd: int


class PayPalSubscriptionStatus(BaseModel):
    user_id: str
    plan_id: str
    status: str
    requests_used: int
    requests_limit: int
    rate_limit_per_min: int
    current_period_end: datetime
    price_usd: float
    paypal_subscription_id: Optional[str] = None


class CancelResponse(BaseModel):
    success: bool
    message: str


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@paypal_router.get("/plans")
async def list_plans():
    """Return all plans with USD pricing. No auth required."""
    return {"plans": PLANS, "currency": "USD", "payment_method": "PayPal"}


@paypal_router.post("/checkout", response_model=PayPalCheckoutResponse)
async def create_checkout(
    body: PayPalCheckoutRequest,
    db: Session = Depends(get_db),
):
    """
    Create a PayPal subscription checkout session.
    Returns approval_url — redirect the user there to complete payment.
    After approval, PayPal redirects to SUCCESS_URL with subscription_id.
    """
    if body.plan_id not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan. Choose from: {list(PLANS.keys())}",
        )

    # Check for existing active subscription
    existing = get_subscription_by_user(db, body.user_id)
    if existing and existing.status == "active":
        raise HTTPException(
            status_code=409,
            detail=f"User already has an active {existing.plan_id} subscription.",
        )

    if not is_enabled():
        # Dev mode — simulate checkout
        logger.warning("PayPal not configured — dev mode, simulating checkout")
        fake_sub_id = f"DEV-SUB-{secrets.token_hex(8).upper()}"
        plan = PLANS[body.plan_id]
        return PayPalCheckoutResponse(
            approval_url=f"https://sandbox.paypal.com/checkoutnow?token={fake_sub_id}",
            subscription_id=fake_sub_id,
            plan_id=body.plan_id,
            plan_name=plan["name"],
            price_usd=plan["price_usd"],
        )

    try:
        client = get_client()
        result = client.create_subscription(
            plan_id_internal=body.plan_id,
            user_id=body.user_id,
            email=body.email,
        )
    except Exception as e:
        logger.error(f"PayPal checkout failed for user {body.user_id}: {e}")
        raise HTTPException(status_code=502, detail="PayPal gateway error. Please try again.")

    plan = PLANS[body.plan_id]

    # Log the initiated payment event
    log_payment_event(
        db=db,
        user_id=body.user_id,
        event_type="paypal_checkout_initiated",
        success=True,
        plan_id=body.plan_id,
        amount_ils=float(plan["price_usd"]),  # reusing field for USD
        conf_num=result["subscription_id"],
    )

    logger.info(
        f"PayPal checkout created: user={body.user_id} plan={body.plan_id} "
        f"sub_id={result['subscription_id']}"
    )

    return PayPalCheckoutResponse(
        approval_url=result["approval_url"],
        subscription_id=result["subscription_id"],
        plan_id=body.plan_id,
        plan_name=plan["name"],
        price_usd=plan["price_usd"],
    )


@paypal_router.post("/webhook")
async def paypal_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Receive PayPal webhook events.
    Configure in PayPal dashboard → Webhooks → add this URL.

    Handles:
        BILLING.SUBSCRIPTION.ACTIVATED  → activate subscription in DB
        BILLING.SUBSCRIPTION.CANCELLED  → cancel subscription in DB
        BILLING.SUBSCRIPTION.EXPIRED    → mark past_due
        PAYMENT.SALE.COMPLETED          → log successful payment
        PAYMENT.SALE.DENIED             → log failed payment
    """
    body_bytes = await request.body()

    # Verify webhook signature
    if is_enabled():
        client = get_client()
        if not client.verify_webhook(dict(request.headers), body_bytes):
            logger.warning("PayPal webhook signature verification failed")
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    import json
    try:
        event = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_type = event.get("event_type", "")
    resource = event.get("resource", {})
    subscription_id = resource.get("id", "")
    custom_id = resource.get("custom_id", "")  # our user_id

    logger.info(f"PayPal webhook: {event_type} sub={subscription_id} user={custom_id}")

    if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
        # Subscription approved — create in our DB
        plan_id = _extract_plan_id_from_resource(resource)
        if plan_id and custom_id:
            existing = get_subscription_by_user(db, custom_id)
            if not existing:
                plan = PLANS.get(plan_id, PLANS["starter"])
                new_api_key = f"sk-{plan_id}-{secrets.token_urlsafe(32)}"
                create_subscription(
                    db=db,
                    user_id=custom_id,
                    api_key=new_api_key,
                    plan_id=plan_id,
                    requests_limit=plan["requests_per_month"],
                    rate_limit_per_min=plan["rate_limit_per_min"],
                    amount_ils=float(plan["price_usd"]),
                    conf_num=subscription_id,
                )
                logger.info(
                    f"Subscription activated: user={custom_id} plan={plan_id} "
                    f"api_key={new_api_key[:12]}…"
                )
            else:
                # Update existing subscription
                existing.status = "active"
                existing.tranzilla_conf_num = subscription_id
                db.commit()

        log_payment_event(
            db=db,
            user_id=custom_id or "unknown",
            event_type="paypal_subscription_activated",
            success=True,
            plan_id=plan_id,
            conf_num=subscription_id,
        )

    elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
        if custom_id:
            cancel_subscription(db, custom_id)
            logger.info(f"Subscription cancelled via webhook: user={custom_id}")

        log_payment_event(
            db=db,
            user_id=custom_id or "unknown",
            event_type="paypal_subscription_cancelled",
            success=True,
            conf_num=subscription_id,
        )

    elif event_type == "BILLING.SUBSCRIPTION.EXPIRED":
        sub = get_subscription_by_user(db, custom_id) if custom_id else None
        if sub:
            sub.status = "past_due"
            db.commit()

        log_payment_event(
            db=db,
            user_id=custom_id or "unknown",
            event_type="paypal_subscription_expired",
            success=False,
            conf_num=subscription_id,
        )

    elif event_type == "PAYMENT.SALE.COMPLETED":
        sale_id = resource.get("id", "")
        amount = resource.get("amount", {})
        log_payment_event(
            db=db,
            user_id=custom_id or "unknown",
            event_type="paypal_payment_completed",
            success=True,
            amount_ils=float(amount.get("total", 0)),
            conf_num=sale_id,
        )

    elif event_type == "PAYMENT.SALE.DENIED":
        log_payment_event(
            db=db,
            user_id=custom_id or "unknown",
            event_type="paypal_payment_denied",
            success=False,
            conf_num=subscription_id,
            error_message="PayPal payment denied",
        )

    return {"status": "received", "event_type": event_type}


@paypal_router.get("/subscription/{user_id}", response_model=PayPalSubscriptionStatus)
async def get_subscription_status(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """Get subscription status for a user."""
    sub = get_subscription_by_user(db, user_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    return PayPalSubscriptionStatus(
        user_id=sub.user_id,
        plan_id=sub.plan_id,
        status=sub.status,
        requests_used=sub.requests_used,
        requests_limit=sub.requests_limit,
        rate_limit_per_min=sub.rate_limit_per_min,
        current_period_end=sub.current_period_end,
        price_usd=sub.amount_ils,  # stored as USD in PayPal flow
        paypal_subscription_id=sub.tranzilla_conf_num,
    )


@paypal_router.post("/cancel/{user_id}", response_model=CancelResponse)
async def cancel_paypal_subscription(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """
    Cancel a PayPal subscription.
    1. Cancel in PayPal via API
    2. Mark cancelled in our DB
    """
    sub = get_subscription_by_user(db, user_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    # Cancel in PayPal if we have the subscription ID
    paypal_sub_id = sub.tranzilla_conf_num
    if paypal_sub_id and is_enabled() and not paypal_sub_id.startswith("DEV-"):
        try:
            client = get_client()
            client.cancel_subscription(paypal_sub_id)
        except Exception as e:
            logger.error(f"PayPal cancel API failed: {e}")
            # Still cancel in our DB

    cancel_subscription(db, user_id)
    log_payment_event(
        db=db,
        user_id=user_id,
        event_type="paypal_cancel_requested",
        success=True,
        conf_num=paypal_sub_id,
    )

    logger.info(f"Subscription cancelled: user={user_id}")
    return CancelResponse(
        success=True,
        message="Subscription cancelled. Access continues until end of billing period.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _extract_plan_id_from_resource(resource: dict) -> Optional[str]:
    """Extract our internal plan_id from PayPal subscription resource."""
    from app.payments.paypal import PAYPAL_PLAN_IDS
    paypal_plan_id = resource.get("plan_id", "")
    # Reverse lookup: PayPal plan ID → our internal plan key
    for internal_id, pp_id in PAYPAL_PLAN_IDS.items():
        if pp_id == paypal_plan_id:
            return internal_id
    return "starter"  # default fallback
