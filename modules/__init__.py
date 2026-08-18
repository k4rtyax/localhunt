"""
lokalHunt modules.

Import submodules directly (``from modules.scanner import Scanner``) so that
importing, say, the scanner does not drag in the RAG stack (chromadb) - the
CLI stays usable when optional extras are not installed.
"""
