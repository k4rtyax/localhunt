"""
lokalHunt - Text utilities
Token counting, line numbering, and window splitting shared by the agents.
"""

import re
from typing import Iterator, Tuple

try:
    import tiktoken
    _tokenizer = tiktoken.get_encoding("cl100k_base")

    def count_tokens(text: str) -> int:
        return len(_tokenizer.encode(text, disallowed_special=()))
except Exception:
    # Fallback: source code averages ~3.5 characters per token.
    def count_tokens(text: str) -> int:
        return len(text) // 3 + 1


_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)
_UNCLOSED_THINK_RE = re.compile(r"<think>.*$", re.DOTALL | re.IGNORECASE)


def strip_think(text: str) -> str:
    """Remove qwen3-style reasoning blocks from a model response."""
    text = _THINK_RE.sub("", text)
    text = _UNCLOSED_THINK_RE.sub("", text)
    return text.strip()


def number_lines(content: str, start: int = 1) -> str:
    """
    Prefix each line with its absolute line number so the model can cite
    positions that actually exist in the file.
    """
    lines = content.splitlines()
    width = len(str(start + len(lines) - 1))
    return "\n".join(
        f"{start + i:>{width}} | {line}" for i, line in enumerate(lines)
    )


def window_by_lines(
    content: str,
    max_tokens: int,
    overlap_lines: int = 0,
) -> Iterator[Tuple[int, str]]:
    """
    Split content into overlapping windows that each fit in max_tokens.
    Yields (start_line_number, chunk_text) with 1-based line numbers, so a
    finding reported inside a chunk maps back to the real file position.
    """
    lines = content.splitlines()
    if not lines:
        return

    total = count_tokens(content)
    if total <= max_tokens:
        yield 1, content
        return

    avg = max(total / len(lines), 0.5)
    est_lines = max(int(max_tokens / avg), 20)

    idx = 0
    while idx < len(lines):
        end = min(idx + est_lines, len(lines))
        chunk = "\n".join(lines[idx:end])

        while end > idx + 1 and count_tokens(chunk) > max_tokens:
            end -= max(1, (end - idx) // 8)
            chunk = "\n".join(lines[idx:end])

        yield idx + 1, chunk

        if end >= len(lines):
            break
        idx = max(end - overlap_lines, idx + 1)


def normalize_snippet(text: str) -> str:
    """Collapse whitespace so evidence can be matched against source text."""
    return re.sub(r"\s+", " ", text or "").strip().lower()


def squash(text: str) -> str:
    """Drop whitespace entirely, for matching code the model has reflowed."""
    return re.sub(r"\s+", "", text or "").lower()


def truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "..."
