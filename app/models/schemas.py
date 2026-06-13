from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime


class SecureRetrieveRequest(BaseModel):
    user_query: str = Field(..., min_length=1, max_length=10000)
    retrieved_chunks: List[str] = Field(..., min_length=1, max_length=100)
    user_id: Optional[str] = Field(default=None, max_length=255)

    @field_validator("retrieved_chunks")
    @classmethod
    def validate_chunks(cls, v: List[str]) -> List[str]:
        for chunk in v:
            if not isinstance(chunk, str):
                raise ValueError("Each chunk must be a string")
            if len(chunk) > 50000:
                raise ValueError("Each chunk must be under 50,000 characters")
        return v


class ThreatDetail(BaseModel):
    threat_type: str
    description: str
    severity: str           # "low" | "medium" | "high" | "critical"
    matched_pattern: Optional[str] = None
    source: str             # "user_query" | "chunk_{n}"


class SecureRetrieveResponse(BaseModel):
    request_id: str
    safe_chunks: List[str]
    risk_score: int = Field(..., ge=0, le=100)
    blocked: bool
    reasons: List[str]
    threats: List[ThreatDetail]
    chunks_filtered: int
    processing_time_ms: float
    timestamp: datetime
    # Only present on /demo/scan responses
    demo_scans_used: Optional[int] = None
    demo_scans_remaining: Optional[int] = None


class DemoStatusResponse(BaseModel):
    scans_used: int
    scans_limit: int
    scans_remaining: int
    exhausted: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    db_connected: bool
    timestamp: datetime


class RequestLogEntry(BaseModel):
    request_id: str
    user_id: Optional[str]
    risk_score: int
    blocked: bool
    threats_detected: int
    chunks_received: int
    chunks_passed: int
    timestamp: datetime
