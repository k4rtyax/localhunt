"""
lokalHunt modules.

Exports are resolved lazily so that importing, say, the scanner does not drag
in the RAG stack (chromadb) - the CLI stays usable when optional extras are
not installed.
"""

_LAZY = {
    "get_prompt": "modules.prompts",
    "Scanner": "modules.scanner",
    "Analyzer": "modules.analyzer",
    "Reporter": "modules.reporter",
    "RAGEngine": "modules.rag",
    "Indexer": "modules.indexer",
    "OllamaClient": "modules.llm",
    "AGENTS": "modules.agents",
    "Swarm": "modules.orchestrator",
}

__all__ = list(_LAZY)


def __getattr__(name: str):
    import importlib
    if name in _LAZY:
        return getattr(importlib.import_module(_LAZY[name]), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
