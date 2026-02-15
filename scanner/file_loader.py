"""
File loading and filtering for GuardRail scanner.

Handles file discovery, binary detection, size limits, and .secretignore filtering.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator


@dataclass
class FileContent:
    """Holds the content and metadata of a loaded file."""

    path: Path
    lines: list[str]
    encoding: str = "utf-8"

    @property
    def content(self) -> str:
        return "".join(self.lines)

    @property
    def line_count(self) -> int:
        return len(self.lines)


@dataclass
class LoaderConfig:
    """Configuration for the file loader."""

    max_file_size: int = 5_242_880  # 5 MB
    skip_extensions: set[str] = field(default_factory=set)
    binary_detection: bool = True
    ignore_file: str = ".secretignore"


class SecretIgnore:
    """Parses and evaluates .secretignore patterns."""

    def __init__(self, root: Path) -> None:
        self._patterns: list[str] = []
        self._root = root
        ignore_path = root / ".secretignore"
        if ignore_path.is_file():
            self._load(ignore_path)

    def _load(self, path: Path) -> None:
        with open(path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    self._patterns.append(stripped)

    def is_ignored(self, path: Path) -> bool:
        """Return True if the path matches any ignore pattern."""
        try:
            relative = str(path.relative_to(self._root)).replace("\\", "/")
        except ValueError:
            relative = str(path).replace("\\", "/")

        for pattern in self._patterns:
            if fnmatch.fnmatch(relative, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            # Match directory prefix (e.g. "tests/")
            if pattern.endswith("/") and relative.startswith(pattern):
                return True
        return False


def _is_binary(path: Path, sample_size: int = 8192) -> bool:
    """Heuristic binary detection via null-byte sampling."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        return b"\x00" in chunk
    except OSError:
        return True


def load_file(path: Path, config: LoaderConfig) -> FileContent | None:
    """
    Load a single file, applying size/binary/extension guards.

    Returns None if the file should be skipped.
    """
    if not path.is_file():
        return None

    if path.suffix.lower() in config.skip_extensions:
        return None

    try:
        size = path.stat().st_size
    except OSError:
        return None

    if size > config.max_file_size:
        return None

    if config.binary_detection and _is_binary(path):
        return None

    for encoding in ("utf-8", "latin-1"):
        try:
            with open(path, encoding=encoding) as f:
                lines = f.readlines()
            return FileContent(path=path, lines=lines, encoding=encoding)
        except (UnicodeDecodeError, OSError):
            continue

    return None


def load_directory(
    root: Path,
    config: LoaderConfig,
    recursive: bool = True,
) -> Generator[FileContent, None, None]:
    """
    Yield FileContent objects for all scannable files under root.

    Respects .secretignore patterns found at the root level.
    """
    ignore = SecretIgnore(root)
    walk = os.walk(root) if recursive else [(str(root), [], os.listdir(root))]

    for dirpath, dirnames, filenames in walk:
        current_dir = Path(dirpath)

        # Prune ignored directories in-place to prevent descent
        dirnames[:] = [
            d for d in dirnames
            if not ignore.is_ignored(current_dir / d)
            and not d.startswith(".")
        ]

        for filename in filenames:
            file_path = current_dir / filename
            if ignore.is_ignored(file_path):
                continue
            result = load_file(file_path, config)
            if result is not None:
                yield result


def build_loader_config(rules_config: dict) -> LoaderConfig:
    """Construct a LoaderConfig from the parsed rules.json scan block."""
    scan_cfg = rules_config.get("scan", {})
    return LoaderConfig(
        max_file_size=scan_cfg.get("max_file_size_bytes", 5_242_880),
        skip_extensions=set(scan_cfg.get("skip_extensions", [])),
        binary_detection=scan_cfg.get("binary_detection", True),
    )
