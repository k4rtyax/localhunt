"""
lokalHunt - Ollama client
Thread-safe wrapper with JSON-schema output, retries, and a pooled connection
shared by every agent in a swarm run.
"""

import json
import time
import httpx
from typing import Any, Generator

from config import (
    OLLAMA_BASE_URL, DEFAULT_MODEL, REQUEST_TIMEOUT,
    NUM_CTX, KEEP_ALIVE, DISABLE_THINKING,
)
from modules.textutil import strip_think


class LLMError(RuntimeError):
    """Raised when Ollama cannot produce a usable response."""


class OllamaClient:
    """Talks to Ollama's /api/chat."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = OLLAMA_BASE_URL,
        timeout: int = REQUEST_TIMEOUT,
        num_ctx: int = NUM_CTX,
        keep_alive: str = KEEP_ALIVE,
        max_connections: int = 8,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.num_ctx = num_ctx
        self.keep_alive = keep_alive
        self._supports_think = DISABLE_THINKING
        self._client = httpx.Client(
            timeout=timeout,
            limits=httpx.Limits(max_connections=max_connections),
        )

    def _payload(
        self,
        messages: list[dict],
        *,
        schema: dict | None,
        temperature: float,
        stream: bool,
    ) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": temperature,
                "top_p": 0.9,
                "num_ctx": self.num_ctx,
            },
        }
        if schema is not None:
            payload["format"] = schema
        if self._supports_think:
            payload["think"] = False
        return payload

    def _post(self, payload: dict) -> httpx.Response:
        resp = self._client.post(f"{self.base_url}/api/chat", json=payload)

        # Older servers and non-reasoning models reject the think flag.
        if resp.status_code >= 400 and "think" in payload:
            if "think" in resp.text.lower():
                self._supports_think = False
                payload = {k: v for k, v in payload.items() if k != "think"}
                resp = self._client.post(f"{self.base_url}/api/chat", json=payload)

        resp.raise_for_status()
        return resp

    def chat_json(
        self,
        messages: list[dict],
        schema: dict,
        *,
        temperature: float = 0.1,
        retries: int = 2,
    ) -> dict:
        """Completion constrained to a JSON Schema. Returns the parsed object."""
        payload = self._payload(
            messages, schema=schema, temperature=temperature, stream=False
        )

        last_error = ""
        for attempt in range(retries + 1):
            data = self._request_with_retry(payload, retries=1)
            content = strip_think(data.get("message", {}).get("content", ""))
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as e:
                last_error = f"{e} (response began: {content[:120]!r})"
                if attempt < retries:
                    time.sleep(0.5 * (attempt + 1))
                continue

            if not isinstance(parsed, dict):
                raise LLMError(f"Expected a JSON object, got {type(parsed).__name__}")
            return parsed

        raise LLMError(f"Model did not return valid JSON: {last_error}")

    def chat_stream(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.3,
    ) -> Generator[str, None, None]:
        """Stream a completion, yielding text chunks."""
        payload = self._payload(
            messages, schema=None, temperature=temperature, stream=True
        )

        started = False
        try:
            for chunk in self._stream(payload):
                started = True
                yield chunk
        except httpx.HTTPStatusError as e:
            # Same fallback _post() does: older servers reject the think flag.
            if started or "think" not in payload:
                raise
            if "think" not in e.response.text.lower():
                raise
            self._supports_think = False
            payload.pop("think", None)
            yield from self._stream(payload)

    def _stream(self, payload: dict) -> Generator[str, None, None]:
        with self._client.stream(
            "POST", f"{self.base_url}/api/chat", json=payload
        ) as resp:
            if resp.status_code >= 400:
                resp.read()          # so .text is available to the caller
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                chunk = data.get("message", {}).get("content", "")
                if chunk:
                    yield chunk
                if data.get("done"):
                    break

    def _request_with_retry(self, payload: dict, retries: int) -> dict:
        last: Exception | None = None
        for attempt in range(retries + 1):
            try:
                return self._post(payload).json()
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = e
            except httpx.HTTPStatusError as e:
                if e.response.status_code < 500:
                    raise LLMError(
                        f"Ollama rejected the request "
                        f"(HTTP {e.response.status_code}): {e.response.text[:200]}"
                    ) from e
                last = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"Ollama request failed after {retries + 1} attempts: {last}")

    def check(self) -> tuple[bool, str]:
        """Verify the server is up and the model is pulled."""
        try:
            resp = self._client.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False, f"Ollama responded with HTTP {resp.status_code}."

            models = resp.json().get("models", [])
            names = [m.get("name", "") for m in models]
            base = self.model.split(":")[0]
            if not any(base == n.split(":")[0] for n in names):
                available = ", ".join(names) or "none"
                return False, (
                    f"Model '{self.model}' is not present on the server.\n"
                    f"Available: {available}\n"
                    f"Run: ollama pull {self.model}"
                )
            return True, "OK"
        except httpx.ConnectError:
            return False, (
                f"Cannot reach Ollama at {self.base_url}.\n"
                "Start it with: OLLAMA_HOST=0.0.0.0 ollama serve"
            )
        except Exception as e:
            return False, str(e)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
