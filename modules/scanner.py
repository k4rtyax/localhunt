"""
lokalHunt - Scanner Module
Handles file discovery and content reading.
"""

import os
from pathlib import Path
from typing import Iterator
from config import DEFAULT_EXTENSIONS, DEFAULT_FILENAMES, MAX_FILE_SIZE


class Scanner:
    """Discovers and reads files for analysis."""

    SKIP_DIRS = {
        "node_modules", ".git", ".svn", "dist", "build",
        "__pycache__", ".cache", "vendor", ".idea", ".vscode",
        "coverage", ".nyc_output", "bower_components",
    }

    def __init__(
        self,
        extensions: list[str] | None = None,
        max_size: int = MAX_FILE_SIZE,
    ):
        self.extensions = [ext.lower() for ext in (extensions or DEFAULT_EXTENSIONS)]
        # An explicit --ext is taken literally, so the dotfile names apply only
        # when the defaults are in use.
        self.filenames = [] if extensions else [n.lower() for n in DEFAULT_FILENAMES]
        self.max_size = max_size

    def wants(self, filepath: Path) -> bool:
        """Whether a discovered path passes the filter."""
        return (
            filepath.suffix.lower() in self.extensions
            or filepath.name.lower() in self.filenames
        )

    def scan_file(self, path: str | Path) -> dict | None:
        """
        Read a single file.
        Returns dict with file info and content, or None on error.
        """
        path = Path(path)

        if not path.exists():
            return {"path": str(path), "error": f"File tidak ditemukan: {path}"}

        if not path.is_file():
            return {"path": str(path), "error": f"Bukan file: {path}"}

        if self.is_binary(path):
            return {"path": str(path), "error": "Binary file, skipped"}

        size = path.stat().st_size

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return {"path": str(path), "error": f"Gagal membaca file: {e}"}

        truncated = False
        if len(content.encode("utf-8")) > self.max_size:
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

    def iter_paths(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> Iterator[Path]:
        """
        Yield the paths that pass the filter, without reading them.
        Skips hidden dirs, node_modules, .git, dist, etc.
        """
        directory = Path(directory)

        if recursive:
            for root, dirs, files in os.walk(directory):
                # Skip unwanted directories (modify in-place)
                dirs[:] = [
                    d for d in dirs
                    if d not in self.SKIP_DIRS and not d.startswith(".")
                ]

                for filename in files:
                    filepath = Path(root) / filename
                    if self.wants(filepath):
                        yield filepath
        else:
            for filepath in directory.iterdir():
                if filepath.is_file() and self.wants(filepath):
                    yield filepath

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> Iterator[dict]:
        """Scan a directory and yield file info dicts."""
        for filepath in self.iter_paths(directory, recursive):
            result = self.scan_file(filepath)
            if result:
                yield result

    def count_files(self, directory: str | Path, recursive: bool = True) -> int:
        """Count how many files will be scanned (for progress bar)."""
        return sum(1 for _ in self.iter_paths(directory, recursive))

    @staticmethod
    def is_binary(filepath: Path) -> bool:
        """Quick check if a file is likely binary."""
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception:
            return True
