"""
lokalHunt - Analyzer Module
Backs the interactive `chat` command. Thin layer over OllamaClient: it owns
the prompt, the client owns the transport.
"""

from typing import Generator
from config import OLLAMA_BASE_URL, DEFAULT_MODEL
from modules.llm import OllamaClient
from modules.prompts import get_prompt


class Analyzer:
    """Sends code to Ollama for security analysis."""

    def __init__(self, model: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def _client(self) -> OllamaClient:
        # One connection per call: these commands are sequential, and the
        # caller may abandon a stream at any point.
        return OllamaClient(
            model=self.model, base_url=self.base_url, max_connections=1
        )

    def check_ollama(self) -> tuple[bool, str]:
        """Check if Ollama is running and the model is available."""
        with self._client() as client:
            return client.check()

    def chat_stream(
        self,
        messages: list[dict],
    ) -> Generator[str, None, None]:
        """
        Stream interactive chat with Ollama.
        messages: list of {"role": "user"/"assistant", "content": "..."}
        """
        full_messages = [
            {"role": "system", "content": get_prompt("full")}
        ] + messages

        with self._client() as client:
            yield from client.chat_stream(full_messages, temperature=0.4)
