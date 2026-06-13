import logging
import pathlib
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.api.document_routes import document_router
from app.payments.routes import payment_router
from app.payments.paddle_routes import paddle_router
from app.integrations.routes import integration_router
from app.auth.users import user_router
from app.config import get_settings
from app.db.database import init_db
from app.middleware.rate_limiter import RateLimiterMiddleware
from app.middleware.request_logger import RequestLoggingMiddleware


def configure_logging(level: str) -> None:
    logging.basicConfig(
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = logging.getLogger("securerag")
    logger.info("SecureRAG Guard starting (env=%s) …", settings.app_env)
    from app.auth.users import User  # noqa: F401 — ensures table is created
    init_db()
    logger.info("Database ready.")
    logger.info("Loading ML classifier …")
    from app.ml.classifier import _get_bundle
    _get_bundle()
    logger.info("ML classifier ready.")
    yield
    logger.info("SecureRAG Guard shutting down.")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="SecureRAG Guard",
        description=(
            "Production-ready RAG security middleware. "
            "Hybrid regex + ML detection against prompt injection, "
            "data exfiltration, and context injection. "
            "Includes Tranzilla billing and ecosystem SDK integrations."
        ),
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimiterMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        logging.getLogger("securerag").exception(
            "Unhandled exception on %s %s", request.method, request.url
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Request has been logged."},
        )

    app.include_router(router)
    app.include_router(document_router)
    app.include_router(payment_router)
    app.include_router(paddle_router)
    app.include_router(integration_router)
    app.include_router(user_router)

    # Serve frontend
    frontend_dir = pathlib.Path(__file__).parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_frontend():
            return FileResponse(str(frontend_dir / "index.html"))

    return app


app = create_app()
