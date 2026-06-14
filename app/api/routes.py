"""
app/api/routes.py — API routes with continuous learning integrated.

Every scan is automatically logged to the learning DB.
Feedback endpoint allows operators to correct false positives/negatives.
Admin endpoint for manual retrain trigger and learning stats.
"""

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.api_key import verify_api_key
from app.models.schemas import (
    SecureRetrieveRequest,
    SecureRetrieveResponse,
    DemoStatusResponse,
    ThreatDetail,
    HealthResponse,
)
from app.core.security_engine import scan_query, scan_chunks
from app.core.scoring import compute_score
from app.ml.classifier import predict as ml_predict
from app.ml.continuous_learning import (
    log_scan,
    submit_feedback,
    retrain_with_new_data,
    get_learning_stats,
)
from app.db.database import (
    get_db,
    save_request,
    save_threats,
    save_score_audit,
    check_db_connection,
    get_demo_usage,
    increment_demo_usage,
    DEMO_LIMIT,
)
from app.config import get_settings

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas for new endpoints
# ─────────────────────────────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    sample_id: int
    label: int          # 1 = was attack (true positive), 0 = was benign (false positive)
    source: str = 'human'


class FeedbackResponse(BaseModel):
    success: bool
    message: str


class RetrainResponse(BaseModel):
    status: str
    version: Optional[str] = None
    ensemble_f1: Optional[float] = None
    total_samples: Optional[int] = None
    new_samples: Optional[int] = None


class LearningStatsResponse(BaseModel):
    total_logged_samples: int
    labeled_samples: int
    unlabeled_samples: int
    pending_for_retrain: int
    retrain_threshold: int
    active_model: dict
    last_retrain_job: Optional[dict]


# ─────────────────────────────────────────────────────────────────────────────
# Shared scan logic
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(payload: SecureRetrieveRequest, db: Session, api_key_hint: str | None):
    request_id = str(uuid.uuid4())
    t_start = time.perf_counter()

    query_threats = scan_query(payload.user_query)
    chunk_threats, unsafe_chunk_indices = scan_chunks(payload.retrieved_chunks)
    all_threats = query_threats + chunk_threats
    ml_result = ml_predict(payload.user_query)
    risk_score, component_scores, blocked, reasons = compute_score(
        all_threats, ml_result=ml_result
    )

    safe_chunks: List[str] = [
        chunk for i, chunk in enumerate(payload.retrieved_chunks)
        if i not in unsafe_chunk_indices
    ]
    if blocked and (query_threats or ml_result.get("malicious")):
        safe_chunks = []

    processing_time_ms = (time.perf_counter() - t_start) * 1000
    query_hash = hashlib.sha256(payload.user_query.encode()).hexdigest()

    # ── Save to main DB ───────────────────────────────────────────────────────
    save_request(
        db=db, request_id=request_id, user_id=payload.user_id,
        query_hash=query_hash, risk_score=risk_score, blocked=blocked,
        chunks_received=len(payload.retrieved_chunks), chunks_passed=len(safe_chunks),
        threats_detected=len(all_threats), processing_time_ms=processing_time_ms,
        api_key_hint=api_key_hint,
    )
    if all_threats:
        save_threats(db=db, request_id=request_id, threats=all_threats)
    component_scores["ml_result"] = ml_result
    save_score_audit(
        db=db, request_id=request_id,
        component_scores=component_scores, final_score=risk_score
    )

    # ── Log to learning DB (async-safe, non-blocking) ─────────────────────────
    try:
        sample_id = log_scan(
            text=payload.user_query,
            ml_confidence=ml_result.get('confidence', 0.0),
            regex_threat_count=len(query_threats),
            risk_score=risk_score,
            blocked=blocked,
        )
    except Exception:
        sample_id = None  # learning log failure must never break the scan

    threats = [
        ThreatDetail(
            threat_type=t["threat_type"], description=t["description"],
            severity=t["severity"], matched_pattern=t.get("matched_pattern"),
            source=t["source"],
        )
        for t in all_threats
    ]

    return dict(
        request_id=request_id,
        safe_chunks=safe_chunks,
        risk_score=risk_score,
        blocked=blocked,
        reasons=reasons,
        threats=threats,
        chunks_filtered=len(payload.retrieved_chunks) - len(safe_chunks),
        processing_time_ms=round(processing_time_ms, 2),
        timestamp=datetime.now(timezone.utc),
        sample_id=sample_id,  # returned so client can submit feedback
    )


# ─────────────────────────────────────────────────────────────────────────────
# Core scan endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/secure-retrieve", response_model=SecureRetrieveResponse)
async def secure_retrieve(
    payload: SecureRetrieveRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    result = _run_scan(payload, db, (api_key[:8] + "…") if api_key else None)
    return SecureRetrieveResponse(**result)


def _ip_hash(request: Request) -> str:
    ip = request.headers.get("x-forwarded-for", request.client.host or "unknown")
    ip = ip.split(",")[0].strip()
    return hashlib.sha256(ip.encode()).hexdigest()


@router.get("/demo/status", response_model=DemoStatusResponse)
async def demo_status(request: Request, db: Session = Depends(get_db)):
    ip_hash = _ip_hash(request)
    used = get_demo_usage(db, ip_hash)
    return DemoStatusResponse(
        scans_used=used,
        scans_limit=DEMO_LIMIT,
        scans_remaining=max(0, DEMO_LIMIT - used),
        exhausted=used >= DEMO_LIMIT,
    )


@router.post("/demo/scan", response_model=SecureRetrieveResponse)
async def demo_scan(
    payload: SecureRetrieveRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    ip_hash = _ip_hash(request)
    used = get_demo_usage(db, ip_hash)
    if used >= DEMO_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "demo_limit_exhausted",
                "message": f"Demo limit of {DEMO_LIMIT} scans reached. Subscribe to continue.",
                "scans_used": used,
                "scans_limit": DEMO_LIMIT,
            },
        )
    result = _run_scan(payload, db, "demo")
    new_count = increment_demo_usage(db, ip_hash)
    return SecureRetrieveResponse(
        **result,
        demo_scans_used=new_count,
        demo_scans_remaining=max(0, DEMO_LIMIT - new_count),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Feedback endpoint — operators correct false positives/negatives
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/feedback", response_model=FeedbackResponse)
async def submit_scan_feedback(
    payload: FeedbackRequest,
    api_key: str = Depends(verify_api_key),
):
    """
    Submit feedback for a scan result.
    Use this to correct false positives and false negatives.
    The model will automatically retrain on accumulated feedback.

    label=1: "yes, this was an attack" (confirm block or report missed attack)
    label=0: "no, this was benign" (report false positive)
    """
    if payload.label not in (0, 1):
        raise HTTPException(status_code=400, detail="label must be 0 or 1")

    success = submit_feedback(
        sample_id=payload.sample_id,
        label=payload.label,
        source=payload.source,
    )
    if not success:
        raise HTTPException(status_code=404, detail=f"Sample {payload.sample_id} not found")

    label_text = "malicious (attack confirmed)" if payload.label == 1 else "benign (false positive reported)"
    return FeedbackResponse(
        success=True,
        message=f"Feedback recorded: sample {payload.sample_id} labeled as {label_text}. "
                f"Model will retrain automatically when threshold is reached.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Admin: learning stats + manual retrain
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/admin/learning-stats", response_model=LearningStatsResponse)
async def learning_stats(api_key: str = Depends(verify_api_key)):
    """
    Monitor the continuous learning system:
    - How many samples are logged
    - How many are labeled / pending retrain
    - Current model version and F1 score
    - Last retrain job status
    """
    stats = get_learning_stats()
    return LearningStatsResponse(**stats)


@router.post("/admin/retrain", response_model=RetrainResponse)
async def manual_retrain(api_key: str = Depends(verify_api_key)):
    """
    Trigger a manual model retrain immediately.
    Merges base training data with all labeled samples from the learning DB.
    Hot-reloads the model without restarting the server.
    """
    try:
        result = retrain_with_new_data(trigger_reason='manual_api')
        return RetrainResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrain failed: {str(e)}")


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health():
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        db_connected=check_db_connection(),
        timestamp=datetime.now(timezone.utc),
    )
