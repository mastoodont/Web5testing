"""
integrations/routes.py

Endpoints that help clients integrate SecureRAG Guard
into their own ecosystems.

GET  /integrations/sdk/python        — download Python SDK client
GET  /integrations/sdk/langchain     — download LangChain middleware
GET  /integrations/sdk/openai        — download OpenAI middleware
GET  /integrations/quickstart        — JSON quickstart guide
POST /integrations/validate-key      — check if an API key is valid (no auth required)
GET  /integrations/openapi-client    — ready-to-use OpenAPI spec snippet
"""

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, JSONResponse

from app.auth.api_key import verify_api_key
from app.integrations.sdk import (
    PYTHON_SDK_CODE,
    LANGCHAIN_MIDDLEWARE_CODE,
    OPENAI_MIDDLEWARE_CODE,
    LLAMAINDEX_MIDDLEWARE_CODE,
)

integration_router = APIRouter(prefix="/integrations", tags=["integrations"])


@integration_router.get("/sdk/python", response_class=PlainTextResponse)
async def sdk_python():
    """Download the Python SDK client — no auth required."""
    return PlainTextResponse(
        content=PYTHON_SDK_CODE,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="securerag_client.py"'},
    )


@integration_router.get("/sdk/langchain", response_class=PlainTextResponse)
async def sdk_langchain():
    """Download the LangChain drop-in retriever."""
    return PlainTextResponse(
        content=LANGCHAIN_MIDDLEWARE_CODE,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="securerag_langchain.py"'},
    )


@integration_router.get("/sdk/openai", response_class=PlainTextResponse)
async def sdk_openai():
    """Download the OpenAI pipeline middleware."""
    return PlainTextResponse(
        content=OPENAI_MIDDLEWARE_CODE,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="securerag_openai.py"'},
    )


@integration_router.get("/quickstart")
async def quickstart():
    """
    JSON guide explaining how to integrate SecureRAG Guard.
    No auth required — this is public documentation.
    """
    return {
        "title": "SecureRAG Guard — Integration Quickstart",
        "steps": [
            {
                "step": 1,
                "title": "Subscribe and get your key",
                "description": "POST /billing/subscribe with your email, user_id, plan, and Tranzilla card token. The response contains your sk-... key.",
            },
            {
                "step": 2,
                "title": "Add one call before your LLM",
                "description": "After your vector search returns chunks, POST them to /secure-retrieve with your key in X-API-Key.",
                "example_curl": (
                    'curl -X POST https://your-app.railway.app/secure-retrieve \\\n'
                    '  -H "X-API-Key: sk-your-key" \\\n'
                    '  -H "Content-Type: application/json" \\\n'
                    '  -d \'{"user_query": "...", "retrieved_chunks": ["..."]}\''
                ),
            },
            {
                "step": 3,
                "title": "Use safe_chunks from the response",
                "description": "Pass only safe_chunks to your LLM. If blocked=true, return an error to the user instead.",
                "response_fields": {
                    "safe_chunks": "Filtered list of documents safe to pass to your LLM",
                    "blocked": "True if the entire request should be rejected",
                    "risk_score": "0-100. Requests ≥40 are blocked",
                    "reasons": "Human-readable explanation of what was detected",
                    "threats": "Detailed list of each detected threat with severity and source",
                },
            },
        ],
        "sdk_downloads": {
            "python":      "/integrations/sdk/python",
            "langchain":   "/integrations/sdk/langchain",
            "openai":      "/integrations/sdk/openai",
            "llamaindex":  "/integrations/sdk/llamaindex",
        },
        "rate_limits": {
            "starter":    "60 req/min",
            "growth":     "300 req/min",
            "enterprise": "1000 req/min",
        },
    }


@integration_router.get("/sdk/llamaindex", response_class=PlainTextResponse)
async def sdk_llamaindex():
    """Download the LlamaIndex QueryEngine wrapper."""
    return PlainTextResponse(
        content=LLAMAINDEX_MIDDLEWARE_CODE,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="securerag_llamaindex.py"'},
    )


@integration_router.post("/validate-key")
async def validate_key(api_key: str = Depends(verify_api_key)):
    """
    Check whether an API key is valid.
    Returns 200 if valid, 401/403 if not (handled by the auth dependency).
    """
    return {"valid": True, "message": "API key is valid"}


@integration_router.get("/openapi-snippet")
async def openapi_snippet():
    """
    Returns the minimal OpenAPI 3.0 snippet for /secure-retrieve
    so clients can generate their own API clients automatically.
    """
    return {
        "openapi": "3.0.3",
        "info": {"title": "SecureRAG Guard", "version": "1.0.0"},
        "paths": {
            "/secure-retrieve": {
                "post": {
                    "summary": "Scan query and chunks",
                    "security": [{"ApiKeyAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["user_query", "retrieved_chunks"],
                                    "properties": {
                                        "user_query": {"type": "string", "maxLength": 10000},
                                        "retrieved_chunks": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "maxItems": 100,
                                        },
                                        "user_id": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Scan result",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "safe_chunks": {"type": "array", "items": {"type": "string"}},
                                            "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                                            "blocked": {"type": "boolean"},
                                            "reasons": {"type": "array", "items": {"type": "string"}},
                                            "threats": {"type": "array"},
                                            "chunks_filtered": {"type": "integer"},
                                            "processing_time_ms": {"type": "number"},
                                        },
                                    }
                                }
                            },
                        },
                        "401": {"description": "Missing API key"},
                        "403": {"description": "Invalid API key"},
                        "429": {"description": "Rate limit exceeded"},
                    },
                }
            }
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                }
            }
        },
    }
