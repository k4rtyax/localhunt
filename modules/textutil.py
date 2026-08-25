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


# A cut inside a line lands mid-token or mid-literal, so consecutive slices
# share this fraction of their width. A construct straddling one cut still
# appears whole in the neighbouring slice.
_SLICE_OVERLAP = 0.15


def split_long_line(line: str, max_tokens: int) -> Iterator[str]:
    """
    Cut one oversized line into overlapping character slices that each fit in
    max_tokens. Used only where line-boundary splitting cannot reduce further.
    """
    tokens = count_tokens(line)
    if tokens <= max_tokens:
        yield line
        return

    # Measure this line's own density instead of assuming one, since packed
    # source and prose differ by several characters per token.
    per_token = max(len(line) / tokens, 1.0)
    width = max(int(max_tokens * per_token), 1)

    start = 0
    while start < len(line):
        piece = line[start:start + width]
        while len(piece) > 1 and count_tokens(piece) > max_tokens:
            piece = piece[:max(len(piece) * 7 // 8, 1)]
        yield piece
        if start + len(piece) >= len(line):
            break
        start += max(int(len(piece) * (1 - _SLICE_OVERLAP)), 1)


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

        if count_tokens(chunk) > max_tokens:
            # The window is down to a single line that still does not fit, so
            # line boundaries have nothing left to give. This is the ordinary
            # shape of minified and packed source, the input the deobfuscator
            # exists for, so cut inside the line rather than hand the model a
            # chunk the server would otherwise truncate in silence.
            for piece in split_long_line(chunk, max_tokens):
                yield idx + 1, piece
        else:
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


def evidence_span(evidence: str, source: str) -> tuple[int, int] | None:
    """
    Locate a quoted snippet inside the source it came from.

    The span is in whitespace-stripped coordinates, so a quote the model
    reflowed still lands on the code it copied. Returns None when the snippet
    is too short to place or is not in the source at all.
    """
    needle = squash(evidence)
    if len(needle) < 8:
        return None
    pos = squash(source).find(needle)
    if pos < 0:
        return None
    return pos, pos + len(needle)


def truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "..."
