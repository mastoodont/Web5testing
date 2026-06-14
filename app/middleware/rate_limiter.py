"""
middleware/rate_limiter.py — Sliding-window rate limiter keyed on API key.

Uses an in-process deque per key. For multi-process / multi-node deployments,
swap the in-memory store for Redis (e.g. via aioredis) without changing the
interface — just replace _store with a Redis-backed class.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.config import get_settings

logger = logging.getLogger("securerag.rate_limiter")

# key → deque of request timestamps (float epoch seconds)
_store: Dict[str, Deque[float]] = defaultdict(deque)

# Endpoints exempt from rate limiting
_EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}


class RateLimiterMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        settings = get_settings()
        limit = settings.rate_limit_requests
        window = settings.rate_limit_window_seconds
        header_name = settings.api_key_header

        api_key = request.headers.get(header_name, "anonymous")
        now = time.monotonic()
        cutoff = now - window

        bucket = _store[api_key]

        # Evict timestamps outside the window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            oldest = bucket[0]
            retry_after = int(window - (now - oldest)) + 1
            logger.warning(
                "Rate limit exceeded for key %s… (%d/%d in %ds window)",
                api_key[:8],
                len(bucket),
                limit,
                window,
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": f"Rate limit exceeded. Max {limit} requests per {window}s.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)

        response = await call_next(request)
        remaining = max(0, limit - len(bucket))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Window"] = str(window)
        return response
