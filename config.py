"""
Configuration settings for lokalHunt.

Network values can be overridden with LOKALHUNT_HOST, LOKALHUNT_PORT, or
OLLAMA_BASE_URL. The default assumes an SSH tunnel to the Ollama host:
    ssh -N -L 11434:127.0.0.1:11434 user@host
"""

import os

# `set-host` rewrites DEFAULT_HOST.
DEFAULT_HOST = "127.0.0.1"
MAC_IP = os.getenv("LOKALHUNT_HOST", DEFAULT_HOST)
OLLAMA_PORT = int(os.getenv("LOKALHUNT_PORT", "11434"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL") or f"http://{MAC_IP}:{OLLAMA_PORT}"

# Model configuration
DEFAULT_MODEL = "qwen3:4b"
EMBEDDING_MODEL = "nomic-embed-text"

# Storage and path configuration
CHROMA_DB_DIR = "./db"
KNOWLEDGE_DIR = "./knowledge"
REPORTS_DIR = "reports"

# RAG retrieval parameters
RAG_TOP_K = 4
CHUNK_SIZE = 400
CHUNK_OVERLAP = 60

# Network and resource limits
REQUEST_TIMEOUT = 300
MAX_FILE_SIZE = 50_000

# Target file filters
DEFAULT_EXTENSIONS = [
    ".js", ".ts", ".jsx", ".tsx",
    ".html", ".htm",
    ".php",
    ".py", ".rb",
    ".java", ".cs", ".go",
    ".json", ".env",
    ".config", ".xml",
    ".yml", ".yaml",
]

KNOWLEDGE_EXTENSIONS = [".md", ".txt"]

# Terminal theme mapping
THEME = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
    "success": "bold green",
    "header": "bold blue",
    "model": "bold magenta",
    "rag": "bold green",
}


# Ollama allocates NUM_CTX * OLLAMA_NUM_PARALLEL of KV cache. For qwen3:4b
# that is roughly 1.2 GB per slot at 8192, on top of the 2.5 GB model.
NUM_CTX = 8192

# Tokens reserved for the model's own answer inside NUM_CTX.
RESERVE_OUTPUT_TOKENS = 2048

# Max code tokens per request. Larger files are split into overlapping
# line windows.
CHUNK_TOKENS = 2000
CHUNK_OVERLAP_LINES = 12

# Keep aligned with OLLAMA_NUM_PARALLEL and the KV cache budget above.
SWARM_CONCURRENCY = 2

# Skeptic verifiers per finding. 1 means a single skeptic decides; that is not
# a majority, it is just the one vote. Raising this only helps if the votes
# disagree, but the skeptic runs at temperature 0.0 (SKEPTIC in
# modules/agents.py), so extra votes come back near-identical and mostly add
# cost on an 8 GB host. Measure on a target with known findings before raising.
VERIFIER_VOTES = 1

# Findings below this confidence are dropped before the verify phase.
MIN_CONFIDENCE = 0.35

# Keep the model resident between agent calls.
KEEP_ALIVE = "10m"

# qwen3 emits <think> blocks. Disable server-side, strip whatever remains.
DISABLE_THINKING = True
