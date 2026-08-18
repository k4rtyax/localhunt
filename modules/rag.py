"""
lokalHunt - RAG Engine
Handles embeddings (via Ollama on Mac) and vector search (via ChromaDB local).

Flow:
  document text -> Ollama nomic-embed-text (Mac) -> vector -> ChromaDB (Windows local)
  query text    -> Ollama nomic-embed-text (Mac) -> vector -> similarity search ChromaDB
"""

import hashlib
import httpx
import chromadb
from chromadb.config import Settings
from pathlib import Path
from typing import List, Tuple
from config import (
    OLLAMA_BASE_URL, EMBEDDING_MODEL, CHROMA_DB_DIR,
    REQUEST_TIMEOUT, RAG_TOP_K
)


class RAGEngine:
    """
    Manages embeddings and vector search for the lokalHunt knowledge base.
    Embeddings are computed on Mac (via Ollama), stored locally in ChromaDB.
    """

    COLLECTION_NAME = "lokalhunt_kb"

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        embedding_model: str = EMBEDDING_MODEL,
        db_dir: str = CHROMA_DB_DIR,
    ):
        self.base_url = base_url.rstrip("/")
        self.embedding_model = embedding_model
        self.db_dir = db_dir
        # nomic-embed-text is trained with task prefixes and ranks noticeably
        # worse without them. Other models take the text as-is.
        self._uses_task_prefix = "nomic-embed" in embedding_model.lower()

        Path(db_dir).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=db_dir,
            settings=Settings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    def embed(self, text: str, task: str = "search_document") -> List[float]:
        """
        Get embedding vector from Ollama.
        task: "search_document" when indexing, "search_query" when retrieving.
        Returns a list of floats (vector).
        """
        prompt = f"{task}: {text}" if self._uses_task_prefix else text
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{self.base_url}/api/embeddings",
                json={
                    "model": self.embedding_model,
                    "prompt": prompt,
                },
            )
            resp.raise_for_status()
            return resp.json()["embedding"]

    def embed_batch(
        self, texts: List[str], task: str = "search_document"
    ) -> List[List[float]]:
        """Embed multiple texts. Returns list of vectors."""
        return [self.embed(t, task=task) for t in texts]

    def add_chunks(
        self,
        chunks: List[str],
        source: str,
        metadata: dict | None = None,
    ) -> int:
        """
        Add text chunks to the vector store.
        Returns number of chunks added.
        """
        if not chunks:
            return 0

        ids = [
            hashlib.md5(f"{source}::{i}::{chunk[:50]}".encode()).hexdigest()
            for i, chunk in enumerate(chunks)
        ]

        existing = self._collection.get(ids=ids, include=[])["ids"]
        existing_set = set(existing)

        new_ids, new_chunks, new_metas = [], [], []
        for cid, chunk in zip(ids, chunks):
            if cid not in existing_set:
                new_ids.append(cid)
                new_chunks.append(chunk)
                new_metas.append({
                    "source": source,
                    **(metadata or {}),
                })

        if not new_chunks:
            return 0

        embeddings = self.embed_batch(new_chunks)

        self._collection.add(
            ids=new_ids,
            embeddings=embeddings,
            documents=new_chunks,
            metadatas=new_metas,
        )

        return len(new_chunks)

    def delete_source(self, source: str):
        """Remove all chunks from a specific source document."""
        results = self._collection.get(
            where={"source": source},
            include=["documents"],
        )
        if results["ids"]:
            self._collection.delete(ids=results["ids"])

    def search(
        self,
        query: str,
        top_k: int = RAG_TOP_K,
        categories: tuple[str, ...] | None = None,
    ) -> List[Tuple[str, str, float]]:
        """
        Search for relevant chunks.
        categories: restrict to these Indexer categories (owasp, malware, ...).
        Returns list of (chunk_text, source, relevance_score).
        """
        query_vector = self.embed(query, task="search_query")

        results = self._collection.query(
            query_embeddings=[query_vector],
            n_results=min(top_k, max(self.count(), 1)),
            include=["documents", "metadatas", "distances"],
            where={"category": {"$in": list(categories)}} if categories else None,
        )

        output = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            # Convert cosine distance to similarity score (0-1, higher = more relevant)
            score = 1 - dist
            output.append((doc, meta.get("source", "unknown"), score))

        return output

    def format_context(
        self,
        query: str,
        top_k: int = RAG_TOP_K,
        min_score: float = 0.3,
        categories: tuple[str, ...] | None = None,
    ) -> str | None:
        """
        Search and format results as a context string for AI prompt injection.
        Returns None if no relevant results found.
        """
        results = self.search(query, top_k=top_k, categories=categories)

        relevant = [(doc, src, score) for doc, src, score in results if score >= min_score]

        if not relevant:
            return None

        lines = [
            "## Relevant Security Knowledge (from your knowledge base)\n",
            "Use the following context to enhance your analysis:\n",
        ]

        for i, (doc, src, score) in enumerate(relevant, 1):
            src_name = Path(src).name
            lines.append(f"### [{i}] Source: `{src_name}` (relevance: {score:.0%})")
            lines.append(doc)
            lines.append("")

        lines.append("---\n")
        return "\n".join(lines)

    def count(self) -> int:
        """Total chunks in the vector store."""
        return self._collection.count()

    def list_sources(self) -> List[dict]:
        """List all unique source documents in the KB."""
        if self.count() == 0:
            return []

        results = self._collection.get(include=["metadatas"])
        sources: dict[str, int] = {}
        for meta in results["metadatas"]:
            src = meta.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        return [
            {"source": src, "chunks": count}
            for src, count in sorted(sources.items())
        ]

    def check_embedding_model(self) -> Tuple[bool, str]:
        """Verify the embedding model is available on Ollama (Mac)."""
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return False, "Ollama tidak merespons."

                models = resp.json().get("models", [])
                model_names = [m["name"] for m in models]
                model_base = self.embedding_model.split(":")[0]

                if not any(model_base in name for name in model_names):
                    return False, (
                        f"Embedding model '{self.embedding_model}' tidak ada di Mac.\n"
                        f"Jalankan di Mac: ollama pull {self.embedding_model}"
                    )
                return True, "OK"
        except httpx.ConnectError:
            return False, "Tidak bisa konek ke Ollama di Mac."
        except Exception as e:
            return False, str(e)
