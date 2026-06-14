"""
middleware/request_logger.py — Structured per-request logging middleware.

Logs method, path, status code, duration, API key prefix, and request ID
on every response. Uses Python's stdlib logging so output format is
controlled centrally (JSON formatter can be swapped in for prod log aggregators).
"""

import logging
import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.config import get_settings

logger = logging.getLogger("securerag.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        settings = get_settings()
        request_id = str(uuid.uuid4())
        api_key_raw = request.headers.get(settings.api_key_header, "")
        api_key_hint = (api_key_raw[:8] + "…") if api_key_raw else "none"

        # Attach request_id so downstream handlers can log it
        request.state.request_id = request_id

        t0 = time.perf_counter()
        status_code = 500  # default if call_next raises

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
        except Exception:
            logger.exception(
                "Unhandled exception | request_id=%s path=%s",
                request_id,
                request.url.path,
            )
            raise
        finally:
            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.info(
                "%s %s → %d | %.2fms | key=%s | id=%s",
                request.method,
                request.url.path,
                status_code,
                duration_ms,
                api_key_hint,
                request_id,
            )

        response.headers["X-Request-ID"] = request_id
        return response
