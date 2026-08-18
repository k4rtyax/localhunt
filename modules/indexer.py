"""
lokalHunt - Indexer
Reads documents from the knowledge/ folder, chunks them, and indexes into RAG.

Supported formats: .md, .txt
"""

import re
from pathlib import Path
from typing import Iterator, List
from config import (
    KNOWLEDGE_DIR, KNOWLEDGE_EXTENSIONS,
    CHUNK_SIZE, CHUNK_OVERLAP
)

try:
    import tiktoken
    _tokenizer = tiktoken.get_encoding("cl100k_base")
    def _count_tokens(text: str) -> int:
        return len(_tokenizer.encode(text))
except ImportError:
    # Fallback: approximate token count, roughly 4 characters per token.
    def _count_tokens(text: str) -> int:
        return len(text) // 4


class Indexer:
    """
    Reads knowledge base documents, chunks them, and indexes into RAGEngine.
    """

    def __init__(
        self,
        knowledge_dir: str = KNOWLEDGE_DIR,
        chunk_size: int = CHUNK_SIZE,
        chunk_overlap: int = CHUNK_OVERLAP,
    ):
        self.knowledge_dir = Path(knowledge_dir)
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def list_documents(self) -> List[Path]:
        """List all indexable documents in the knowledge directory."""
        if not self.knowledge_dir.exists():
            return []

        docs = []
        for ext in KNOWLEDGE_EXTENSIONS:
            docs.extend(self.knowledge_dir.rglob(f"*{ext}"))
        return sorted(docs)

    def chunk_text(self, text: str) -> List[str]:
        """
        Split text into overlapping chunks by token count.
        Uses paragraph boundaries where possible for cleaner cuts.
        """
        paragraphs = re.split(r"\n\s*\n", text.strip())
        paragraphs = [p.strip() for p in paragraphs if p.strip()]

        chunks: List[str] = []
        current_chunk = ""
        current_tokens = 0

        for para in paragraphs:
            para_tokens = _count_tokens(para)

            if para_tokens > self.chunk_size:
                sentences = re.split(r"(?<=[.!?])\s+", para)
                for sentence in sentences:
                    sent_tokens = _count_tokens(sentence)
                    if current_tokens + sent_tokens > self.chunk_size and current_chunk:
                        chunks.append(current_chunk.strip())
                        overlap_text = self._get_overlap(current_chunk)
                        current_chunk = overlap_text + " " + sentence
                        current_tokens = _count_tokens(current_chunk)
                    else:
                        current_chunk += " " + sentence
                        current_tokens += sent_tokens
            else:
                if current_tokens + para_tokens > self.chunk_size and current_chunk:
                    chunks.append(current_chunk.strip())
                    overlap_text = self._get_overlap(current_chunk)
                    current_chunk = overlap_text + "\n\n" + para
                    current_tokens = _count_tokens(current_chunk)
                else:
                    current_chunk += "\n\n" + para if current_chunk else para
                    current_tokens += para_tokens

        if current_chunk.strip():
            chunks.append(current_chunk.strip())

        return [c for c in chunks if len(c.strip()) > 50]  # skip tiny chunks

    def _get_overlap(self, text: str) -> str:
        """Get the last N tokens from text for overlap."""
        words = text.split()
        # Approximate: overlap_tokens words
        approx_words = max(1, self.chunk_overlap * 3 // 4)
        return " ".join(words[-approx_words:])

    def index_file(self, filepath: Path) -> List[str]:
        """Read and chunk a single file. Returns list of chunks."""
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            raise IOError(f"Gagal membaca {filepath}: {e}")

        if not text.strip():
            return []

        doc_title = filepath.stem.replace("_", " ").replace("-", " ").title()
        chunks = self.chunk_text(text)

        enriched = [
            f"[Source: {doc_title} | File: {filepath.name}]\n{chunk}"
            for chunk in chunks
        ]
        return enriched

    def index_all(
        self,
        rag_engine,
        force: bool = False,
    ) -> Iterator[dict]:
        """
        Index all documents in knowledge_dir into RAGEngine.
        Yields progress dicts: {file, chunks, skipped, error}
        """
        docs = self.list_documents()

        if not docs:
            return

        existing_sources = {
            item["source"] for item in rag_engine.list_sources()
        }

        for filepath in docs:
            src_key = str(filepath)

            if not force and src_key in existing_sources:
                yield {
                    "file": filepath.name,
                    "chunks": 0,
                    "skipped": True,
                    "error": None,
                }
                continue

            try:
                if force and src_key in existing_sources:
                    rag_engine.delete_source(src_key)

                chunks = self.index_file(filepath)
                if not chunks:
                    yield {"file": filepath.name, "chunks": 0, "skipped": True, "error": "kosong"}
                    continue

                added = rag_engine.add_chunks(
                    chunks=chunks,
                    source=src_key,
                    metadata={
                        "filename": filepath.name,
                        "category": self._detect_category(filepath),
                    },
                )

                yield {
                    "file": filepath.name,
                    "chunks": added,
                    "skipped": False,
                    "error": None,
                }

            except Exception as e:
                yield {
                    "file": filepath.name,
                    "chunks": 0,
                    "skipped": False,
                    "error": str(e),
                }

    def _detect_category(self, filepath: Path) -> str:
        """Auto-detect document category from filename/path."""
        name = filepath.stem.lower()
        if any(k in name for k in ["cve", "cwe", "nvd"]):
            return "cve"
        elif any(k in name for k in ["owasp", "cheat"]):
            return "owasp"
        elif any(k in name for k in ["writeup", "report", "bounty", "poc"]):
            return "writeup"
        elif any(k in name for k in ["malware", "obfusc", "skimmer"]):
            return "malware"
        elif any(k in name for k in ["pattern", "signature", "custom"]):
            return "custom"
        elif any(k in name for k in ["api", "doc", "target", "scope"]):
            return "target_doc"
        else:
            return "general"
