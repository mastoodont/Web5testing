"""
payments/routes.py — Subscription and payment endpoints.

Endpoints:
  GET  /plans                    — list available plans (public)
  POST /subscribe                — create subscription, charge via Tranzilla
  GET  /subscription/{user_id}   — get subscription status
  POST /subscription/{user_id}/cancel
  GET  /payment/hosted/{user_id}/{plan_id} — get hosted payment page URL
  POST /payment/webhook          — Tranzilla webhook receiver
"""

import hashlib
import logging
import secrets
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.payments.tranzilla import PLANS, get_client, TranzillaClient
from app.payments.models import (
    create_subscription,
    get_subscription_by_user,
    cancel_subscription,
    log_payment_event,
)
from app.auth.api_key import verify_api_key

logger = logging.getLogger("securerag.payments")
payment_router = APIRouter(prefix="/billing", tags=["billing"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class SubscribeRequest(BaseModel):
    user_id: str
    email: str
    plan_id: str
    tranzila_token: str          # token from Tranzilla hosted fields JS

    @field_validator("plan_id")
    @classmethod
    def validate_plan(cls, v):
        if v not in PLANS:
            raise ValueError(f"Invalid plan. Choose from: {list(PLANS.keys())}")
        return v


class SubscribeResponse(BaseModel):
    success: bool
    user_id: str
    plan_id: str
    api_key: str                 # newly generated API key for the subscriber
    requests_limit: int
    rate_limit_per_min: int
    period_end: datetime
    transaction_id: Optional[str]
    message: str


class SubscriptionStatus(BaseModel):
    user_id: str
    plan_id: str
    status: str
    requests_used: int
    requests_limit: int
    rate_limit_per_min: int
    current_period_end: datetime
    amount_ils: float


class CancelResponse(BaseModel):
    success: bool
    message: str


class HostedPageResponse(BaseModel):
    url: str
    plan_id: str
    plan_name: str
    price_ils: int


# ── Routes ────────────────────────────────────────────────────────────────────

@payment_router.get("/plans")
async def list_plans():
    """Return all available subscription plans. No auth required."""
    return {"plans": PLANS}


@payment_router.post("/subscribe", response_model=SubscribeResponse)
async def subscribe(
    body: SubscribeRequest,
    db: Session = Depends(get_db),
):
    """
    Create a subscription:
    1. Verify plan exists
    2. Charge via Tranzilla using the client-side token
    3. Generate a unique API key
    4. Persist subscription to DB
    5. Return the new API key
    """
    # Check for existing subscription
    existing = get_subscription_by_user(db, body.user_id)
    if existing and existing.status == "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User {body.user_id} already has an active {existing.plan_id} subscription.",
        )

    plan = PLANS[body.plan_id]

    # Charge via Tranzilla
    tranzilla_enabled = bool(os.getenv("TRANZILLA_SUPPLIER"))
    if tranzilla_enabled:
        try:
            client = get_client()
            result = client.charge_token(
                tranzila_token=body.tranzila_token,
                amount_ils=float(plan["price_ils"]),
                plan_id=body.plan_id,
                customer_email=body.email,
                description=f"SecureRAG Guard — {plan['name']}",
            )
        except Exception as exc:
            logger.error("Tranzilla charge failed for user %s: %s", body.user_id, exc)
            raise HTTPException(status_code=502, detail="Payment gateway error. Please try again.")

        log_payment_event(
            db=db,
            user_id=body.user_id,
            event_type="charge",
            success=result.success,
            plan_id=body.plan_id,
            amount_ils=float(plan["price_ils"]),
            conf_num=result.transaction_id,
            error_message=result.error_message,
        )

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"Payment failed: {result.error_message}",
            )

        conf_num = result.transaction_id
    else:
        # Dev mode — skip real payment
        logger.warning("TRANZILLA_SUPPLIER not set — running in dev mode, skipping charge")
        conf_num = f"DEV-{secrets.token_hex(6).upper()}"

    # Generate a secure API key for this subscriber
    new_api_key = f"sk-{body.plan_id}-{secrets.token_urlsafe(32)}"

    sub = create_subscription(
        db=db,
        user_id=body.user_id,
        api_key=new_api_key,
        plan_id=body.plan_id,
        requests_limit=plan["requests_per_month"],
        rate_limit_per_min=plan["rate_limit_per_min"],
        amount_ils=float(plan["price_ils"]),
        conf_num=conf_num,
    )

    logger.info(
        "New subscription: user=%s plan=%s conf=%s",
        body.user_id, body.plan_id, conf_num,
    )

    return SubscribeResponse(
        success=True,
        user_id=body.user_id,
        plan_id=body.plan_id,
        api_key=new_api_key,
        requests_limit=sub.requests_limit,
        rate_limit_per_min=sub.rate_limit_per_min,
        period_end=sub.current_period_end,
        transaction_id=conf_num,
        message=f"Subscribed to {plan['name']}. Your API key is in this response — save it.",
    )


@payment_router.get("/subscription/{user_id}", response_model=SubscriptionStatus)
async def get_status(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    sub = get_subscription_by_user(db, user_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return SubscriptionStatus(
        user_id=sub.user_id,
        plan_id=sub.plan_id,
        status=sub.status,
        requests_used=sub.requests_used,
        requests_limit=sub.requests_limit,
        rate_limit_per_min=sub.rate_limit_per_min,
        current_period_end=sub.current_period_end,
        amount_ils=sub.amount_ils,
    )


@payment_router.post("/subscription/{user_id}/cancel", response_model=CancelResponse)
async def cancel(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    success = cancel_subscription(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found")
    logger.info("Subscription cancelled: user=%s", user_id)
    return CancelResponse(
        success=True,
        message="Subscription cancelled. Access continues until the end of the billing period.",
    )


@payment_router.get("/payment/hosted/{user_id}/{plan_id}", response_model=HostedPageResponse)
async def hosted_page(user_id: str, plan_id: str):
    """
    Get a Tranzilla hosted payment page URL.
    Redirect the user there — card entry happens on Tranzilla's PCI-compliant page.
    """
    if plan_id not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {plan_id}")

    tranzilla_enabled = bool(os.getenv("TRANZILLA_SUPPLIER"))
    if not tranzilla_enabled:
        raise HTTPException(
            status_code=503,
            detail="Payment gateway not configured. Set TRANZILLA_SUPPLIER.",
        )

    plan = PLANS[plan_id]
    client = get_client()
    url = client.generate_hosted_page_url(
        plan_id=plan_id,
        customer_email="",    # will be collected on hosted page
        user_id=user_id,
    )
    return HostedPageResponse(
        url=url,
        plan_id=plan_id,
        plan_name=plan["name"],
        price_ils=plan["price_ils"],
    )


@payment_router.post("/payment/webhook")
async def tranzilla_webhook(
    request: Request,
    db: Session = Depends(get_db),
    x_tranzilla_signature: Optional[str] = Header(default=None),
):
    """
    Receive and verify Tranzilla payment notifications.
    Tranzilla POSTs form data to this endpoint after each transaction.
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode()

    # Verify signature in production
    if os.getenv("TRANZILLA_SUPPLIER"):
        client = get_client()
        if x_tranzilla_signature:
            if not client.verify_webhook(body_str, x_tranzilla_signature):
                logger.warning("Webhook signature verification failed")
                raise HTTPException(status_code=401, detail="Invalid webhook signature")

    form = await request.form()
    response_code = form.get("Response", "")
    conf_num = form.get("ConfNum", "")
    user_data = form.get("user_data", "")   # user_id we passed in the URL

    success = response_code == "000"

    log_payment_event(
        db=db,
        user_id=user_data or "unknown",
        event_type="webhook",
        success=success,
        conf_num=conf_num,
        error_message=None if success else f"Response code {response_code}",
    )

    logger.info(
        "Webhook received: user=%s Response=%s ConfNum=%s",
        user_data, response_code, conf_num,
    )

    return {"status": "received"}
