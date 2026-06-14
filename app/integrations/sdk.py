"""
integrations/sdk.py

SecureRAG Guard — Client Integration Layer

Three ways to integrate:

1. REST API (any language)
   POST /secure-retrieve  with X-API-Key header

2. Python SDK (pip install securerag-guard)
   from securerag_guard import SecureRAGClient
   client = SecureRAGClient(api_key="sk-...", base_url="https://your-app.railway.app")
   result = client.scan(query, chunks)

3. LangChain middleware (drop-in)
   from securerag_guard.langchain import SecureRAGRetriever
   retriever = SecureRAGRetriever(base_retriever=your_retriever, api_key="sk-...")

This module ships the SDK code as downloadable text so clients can
copy it into their projects — no separate PyPI package needed at this stage.
"""

PYTHON_SDK_CODE = '''"""
SecureRAG Guard Python SDK
Install: pip install requests
Usage:
    from securerag_client import SecureRAGClient
    client = SecureRAGClient(api_key="sk-...", base_url="https://your-app.railway.app")
    result = client.scan("user query", ["chunk 1", "chunk 2"])
    if result["blocked"]:
        raise ValueError("Request blocked by SecureRAG Guard")
    safe_chunks = result["safe_chunks"]
"""
import requests
from typing import List, Optional, Dict


class SecureRAGClient:
    def __init__(self, api_key: str, base_url: str = "https://your-app.railway.app"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        })

    def scan(
        self,
        user_query: str,
        retrieved_chunks: List[str],
        user_id: Optional[str] = None,
    ) -> Dict:
        """
        Scan a query and its retrieved chunks.
        Returns the full SecureRetrieveResponse dict.
        Raises ValueError if blocked, requests.HTTPError on API errors.
        """
        payload = {
            "user_query": user_query,
            "retrieved_chunks": retrieved_chunks,
        }
        if user_id:
            payload["user_id"] = user_id

        resp = self.session.post(f"{self.base_url}/secure-retrieve", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def scan_safe(
        self,
        user_query: str,
        retrieved_chunks: List[str],
        user_id: Optional[str] = None,
    ) -> List[str]:
        """
        Scan and return only the safe chunks.
        Returns empty list if the request is blocked entirely.
        """
        result = self.scan(user_query, retrieved_chunks, user_id)
        return result.get("safe_chunks", [])

    def scan_files(
        self,
        user_query: str,
        file_paths: list,
        user_id: Optional[str] = None,
    ) -> Dict:
        """
        Scan a query plus local PDF/DOCX/DOC files (up to 5).
        Files are sent as multipart/form-data; text is extracted server-side.

        Args:
            user_query: The user message to scan.
            file_paths: List of local file paths (PDF, DOCX, DOC). Max 5.
        Returns:
            Full SecureRetrieveResponse dict.
        """
        import os
        if len(file_paths) > 5:
            raise ValueError("scan_files: maximum 5 files allowed")

        # Remove Content-Type so requests sets multipart boundary automatically
        headers = {k: v for k, v in self.session.headers.items()
                   if k.lower() != "content-type"}
        headers["X-API-Key"] = self.api_key

        files = []
        open_handles = []
        try:
            for path in file_paths:
                ext = os.path.splitext(path)[1].lower()
                mime = {
                    ".pdf": "application/pdf",
                    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ".doc":  "application/msword",
                }.get(ext, "application/octet-stream")
                fh = open(path, "rb")
                open_handles.append(fh)
                files.append(("files", (os.path.basename(path), fh, mime)))

            data = {"user_query": user_query}
            if user_id:
                data["user_id"] = user_id

            resp = requests.post(
                f"{self.base_url}/scan-files",
                headers=headers,
                data=data,
                files=files,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            for fh in open_handles:
                fh.close()

    def health(self) -> Dict:
        """Check if the SecureRAG Guard API is reachable."""
        resp = self.session.get(f"{self.base_url}/health", timeout=5)
        resp.raise_for_status()
        return resp.json()
'''

LANGCHAIN_MIDDLEWARE_CODE = '''
"""
SecureRAG Guard — LangChain Drop-in Retriever
Wraps any LangChain BaseRetriever and filters retrieved docs
through SecureRAG Guard before they reach the LLM.

Requires: pip install langchain-core requests
Also download securerag_client.py from /integrations/sdk/python

Usage:
    from langchain_community.vectorstores import Chroma
    from securerag_langchain import SecureRAGRetriever

    base_retriever = Chroma(...).as_retriever()
    safe_retriever = SecureRAGRetriever(
        base_retriever=base_retriever,
        api_key="sk-...",
        base_url="https://your-app.railway.app",
    )
    # Use exactly like any other retriever
    chain = RetrievalQA.from_chain_type(llm=llm, retriever=safe_retriever)
"""
from typing import List
from langchain_core.retrievers import BaseRetriever
from langchain_core.documents import Document
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.pydantic_v1 import PrivateAttr
from securerag_client import SecureRAGClient


class SecureRAGRetriever(BaseRetriever):
    """
    LangChain BaseRetriever wrapper that scans retrieved documents
    through SecureRAG Guard before they reach your LLM.
    """
    base_retriever: BaseRetriever

    # PrivateAttr keeps Pydantic from treating _client as a model field
    _client: SecureRAGClient = PrivateAttr()

    def __init__(self, base_retriever: BaseRetriever, api_key: str, base_url: str, **kwargs):
        super().__init__(base_retriever=base_retriever, **kwargs)
        # PrivateAttr must be assigned after super().__init__
        object.__setattr__(self, "_client", SecureRAGClient(api_key=api_key, base_url=base_url))

    def _get_relevant_documents(
        self,
        query: str,
        *,
        run_manager: CallbackManagerForRetrieverRun,
    ) -> List[Document]:
        # 1. Fetch raw docs — use invoke(), get_relevant_documents() is deprecated in LC >=0.2
        raw_docs: List[Document] = self.base_retriever.invoke(query)
        chunks = [doc.page_content for doc in raw_docs]

        if not chunks:
            return []

        # 2. Scan through SecureRAG Guard
        result = self._client.scan(user_query=query, retrieved_chunks=chunks)

        if result["blocked"]:
            # Raise so LangChain callbacks surface the reason; LLM gets no context
            raise ValueError(
                f"SecureRAG Guard blocked retrieval. "
                f"Score: {result['risk_score']}/100. "
                f"Reasons: {result['reasons']}"
            )

        # 3. Return only safe docs, preserving original Document metadata
        safe_set = set(result["safe_chunks"])
        return [doc for doc in raw_docs if doc.page_content in safe_set]
'''

OPENAI_MIDDLEWARE_CODE = '''"""
SecureRAG Guard — OpenAI Assistant middleware
Wraps the retrieval step of an OpenAI-based RAG pipeline.

Usage:
    from securerag_openai import secure_retrieve

    # Before passing to OpenAI:
    safe_chunks = secure_retrieve(
        user_query=user_message,
        raw_chunks=your_vector_search_results,
        api_key="sk-...",
        base_url="https://your-app.railway.app",
    )
    context = "\\n\\n".join(safe_chunks)
    # Now pass context to your OpenAI prompt
"""
from securerag_client import SecureRAGClient

_clients = {}

def secure_retrieve(
    user_query: str,
    raw_chunks: list,
    api_key: str,
    base_url: str = "https://your-app.railway.app",
    raise_on_block: bool = False,
) -> list:
    """
    Returns safe chunks. Empty list if blocked.
    Set raise_on_block=True to raise ValueError instead of returning [].
    """
    client_key = f"{api_key}:{base_url}"
    if client_key not in _clients:
        _clients[client_key] = SecureRAGClient(api_key=api_key, base_url=base_url)

    result = _clients[client_key].scan(user_query, raw_chunks)

    if result["blocked"]:
        if raise_on_block:
            raise ValueError(
                f"Query blocked by SecureRAG Guard "
                f"(score {result[\'risk_score\']}/100): {result[\'reasons\']}"
            )
        return []

    return result["safe_chunks"]
'''

LLAMAINDEX_MIDDLEWARE_CODE = '''
"""
SecureRAG Guard — LlamaIndex QueryEngine wrapper
Scans retrieved nodes through SecureRAG Guard before they reach the LLM.

Requires: pip install llama-index-core requests
Also download securerag_client.py from /integrations/sdk/python

Usage:
    from llama_index.core import VectorStoreIndex
    from securerag_llamaindex import SecureRAGQueryEngine

    base_engine = index.as_query_engine()
    safe_engine = SecureRAGQueryEngine(
        base_engine=base_engine,
        api_key="sk-...",
        base_url="https://your-app.railway.app",
    )
    response = safe_engine.query("What is in the documents?")
"""
from typing import Optional
from llama_index.core.query_engine import BaseQueryEngine
from llama_index.core.schema import QueryBundle
from llama_index.core.base.response.schema import RESPONSE_TYPE
from securerag_client import SecureRAGClient


class SecureRAGQueryEngine(BaseQueryEngine):
    """
    LlamaIndex QueryEngine wrapper that scans retrieved context
    through SecureRAG Guard before passing it to the LLM.
    """

    def __init__(
        self,
        base_engine: BaseQueryEngine,
        api_key: str,
        base_url: str,
        raise_on_block: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._base_engine = base_engine
        self._client = SecureRAGClient(api_key=api_key, base_url=base_url)
        self._raise_on_block = raise_on_block

    def _query(self, query_bundle: QueryBundle) -> RESPONSE_TYPE:
        query_str = query_bundle.query_str

        # Retrieve nodes from base engine
        retriever = self._base_engine.retriever
        nodes = retriever.retrieve(query_bundle)
        chunks = [node.get_content() for node in nodes]

        if not chunks:
            return self._base_engine.query(query_bundle)

        # Scan with SecureRAG Guard
        result = self._client.scan(
            user_query=query_str,
            retrieved_chunks=chunks,
        )

        if result["blocked"]:
            if self._raise_on_block:
                raise ValueError(
                    f"SecureRAG Guard blocked query. "
                    f"Score: {result['risk_score']}/100. "
                    f"Reasons: {result['reasons']}"
                )
            # Return safe response without context
            from llama_index.core.response.schema import Response
            return Response(
                response="This request was blocked by SecureRAG Guard due to detected security threats.",
                metadata={"securerag_blocked": True, "risk_score": result["risk_score"]},
            )

        # Filter to safe chunks only and re-query with safe context
        safe_set = set(result["safe_chunks"])
        safe_nodes = [n for n in nodes if n.get_content() in safe_set]

        if not safe_nodes:
            from llama_index.core.response.schema import Response
            return Response(
                response="All retrieved documents were filtered by SecureRAG Guard.",
                metadata={"securerag_all_filtered": True},
            )

        # Re-synthesize with safe nodes only
        from llama_index.core.response_synthesizers import get_response_synthesizer
        synthesizer = get_response_synthesizer()
        return synthesizer.synthesize(query_str, nodes=safe_nodes)

    async def _aquery(self, query_bundle: QueryBundle) -> RESPONSE_TYPE:
        # Fall back to sync for simplicity; override for async pipelines
        return self._query(query_bundle)
'''


