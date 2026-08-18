"""
localHunt - Analyzer Module
Handles communication with Ollama API to analyze file content.
Supports RAG context injection from the knowledge base.
"""

import json
import httpx
from typing import Generator
from config import OLLAMA_BASE_URL, DEFAULT_MODEL, REQUEST_TIMEOUT
from modules.prompts import get_prompt


class Analyzer:
    """Sends code to Ollama (Qwen) for security analysis."""

    def __init__(self, model: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def check_ollama(self) -> tuple[bool, str]:
        """Check if Ollama is running and model is available."""
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return False, "Ollama tidak merespons dengan benar."
                
                models = resp.json().get("models", [])
                model_names = [m["name"].split(":")[0] for m in models]
                model_base = self.model.split(":")[0]
                
                if not any(model_base in name for name in model_names):
                    available = ", ".join([m["name"] for m in models]) or "tidak ada"
                    return False, (
                        f"Model '{self.model}' tidak ditemukan di Ollama.\n"
                        f"Model tersedia: {available}\n"
                        f"Jalankan: ollama pull {self.model}"
                    )
                return True, "OK"
        except httpx.ConnectError:
            return False, (
                "Tidak bisa konek ke Ollama.\n"
                "Pastikan Ollama sudah jalan:\n"
                "  macOS/Linux: ollama serve\n"
                "  Windows: buka aplikasi Ollama"
            )
        except Exception as e:
            return False, f"Error: {e}"

    def analyze_stream(
        self,
        content: str,
        mode: str = "full",
        filename: str = "unknown",
        rag_context: str | None = None,
    ) -> Generator[str, None, None]:
        """
        Stream analysis from Ollama. Yields text chunks as they arrive.
        rag_context: optional context string from knowledge base (RAG).
        """
        system_prompt = get_prompt(mode)

        # Inject RAG context into the system prompt if available
        if rag_context:
            system_prompt = system_prompt + "\n\n" + rag_context

        user_message = (
            f"Analyze this file for security vulnerabilities.\n"
            f"Filename: {filename}\n\n"
            f"```\n{content}\n```"
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": True,
            "options": {
                "temperature": 0.2,   # Rendah agar output konsisten & faktual
                "top_p": 0.9,
                "num_ctx": 8192,
            },
        }

        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        chunk = data.get("message", {}).get("content", "")
                        if chunk:
                            yield chunk
                        if data.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue

    def chat_stream(
        self,
        messages: list[dict],
    ) -> Generator[str, None, None]:
        """
        Stream interactive chat with Ollama.
        messages: list of {"role": "user"/"assistant", "content": "..."}
        """
        system_prompt = get_prompt("full")

        full_messages = [{"role": "system", "content": system_prompt}] + messages

        payload = {
            "model": self.model,
            "messages": full_messages,
            "stream": True,
            "options": {
                "temperature": 0.4,
                "top_p": 0.9,
                "num_ctx": 8192,
            },
        }

        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        chunk = data.get("message", {}).get("content", "")
                        if chunk:
                            yield chunk
                        if data.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
