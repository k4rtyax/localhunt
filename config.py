"""
Configuration settings for lokalHunt.
"""

# Network configuration
MAC_IP = "192.168.1.5"
OLLAMA_PORT = 11434
OLLAMA_BASE_URL = f"http://{MAC_IP}:{OLLAMA_PORT}"

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
