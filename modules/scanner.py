"""
lokalHunt — Scanner Module
Handles file discovery and content reading.
"""

import os
from pathlib import Path
from typing import Iterator
from config import DEFAULT_EXTENSIONS, MAX_FILE_SIZE


class Scanner:
    """Discovers and reads files for analysis."""

    def __init__(
        self,
        extensions: list[str] | None = None,
        max_size: int = MAX_FILE_SIZE,
    ):
        self.extensions = [ext.lower() for ext in (extensions or DEFAULT_EXTENSIONS)]
        self.max_size = max_size

    def scan_file(self, path: str | Path) -> dict | None:
        """
        Read a single file.
        Returns dict with file info and content, or None on error.
        """
        path = Path(path)

        if not path.exists():
            return {"error": f"File tidak ditemukan: {path}"}

        if not path.is_file():
            return {"error": f"Bukan file: {path}"}

        size = path.stat().st_size

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return {"error": f"Gagal membaca file: {e}"}

        truncated = False
        if len(content.encode("utf-8")) > self.max_size:
            # Truncate to max_size bytes
            content = content.encode("utf-8")[: self.max_size].decode(
                "utf-8", errors="ignore"
            )
            truncated = True

        return {
            "path": str(path),
            "name": path.name,
            "extension": path.suffix.lower(),
            "size": size,
            "content": content,
            "truncated": truncated,
            "error": None,
        }

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> Iterator[dict]:
        """
        Scan a directory and yield file info dicts.
        Skips hidden dirs, node_modules, .git, dist, etc.
        """
        directory = Path(directory)
        SKIP_DIRS = {
            "node_modules", ".git", ".svn", "dist", "build",
            "__pycache__", ".cache", "vendor", ".idea", ".vscode",
            "coverage", ".nyc_output", "bower_components",
        }

        if recursive:
            for root, dirs, files in os.walk(directory):
                # Skip unwanted directories (modify in-place)
                dirs[:] = [
                    d for d in dirs
                    if d not in SKIP_DIRS and not d.startswith(".")
                ]

                for filename in files:
                    filepath = Path(root) / filename
                    if filepath.suffix.lower() in self.extensions:
                        result = self.scan_file(filepath)
                        if result:
                            yield result
        else:
            for filepath in directory.iterdir():
                if filepath.is_file() and filepath.suffix.lower() in self.extensions:
                    result = self.scan_file(filepath)
                    if result:
                        yield result

    def count_files(self, directory: str | Path, recursive: bool = True) -> int:
        """Count how many files will be scanned (for progress bar)."""
        return sum(1 for _ in self.scan_directory(directory, recursive))

    @staticmethod
    def is_binary(filepath: Path) -> bool:
        """Quick check if a file is likely binary."""
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception:
            return True
