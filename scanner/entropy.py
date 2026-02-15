"""
Shannon entropy-based secret detection for GuardRail.

Identifies high-entropy tokens that may represent secrets even when
they don't match known patterns (e.g., random keys, unknown formats).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.file_loader import FileContent
    from scanner.pattern_engine import Finding

from scanner.pattern_engine import SUPPRESS_MARKER, Finding, _redact, _truncate_line


@dataclass(frozen=True)
class EntropyConfig:
    """Configuration for entropy-based detection."""

    enabled: bool = True
    threshold: float = 4.5
    min_length: int = 20
    max_length: int = 200
    base_score: int = 50
    token_separators: str = r"[\s=:'\"`,\[\]{}()\\]"


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Returns a value in [0, log2(len(charset))].
    Higher values indicate more randomness.
    """
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_tokens(line: str, separators: str) -> list[str]:
    """Split a line into candidate tokens using the configured separators."""
    return [t for t in re.split(separators, line) if t]


def _looks_like_path_or_url(token: str) -> bool:
    """Filter out common false positives like file paths and URLs."""
    return (
        token.startswith(("http://", "https://", "ftp://", "/", "./", "../"))
        or "\\" in token
        or token.endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".txt"))
    )


def scan_entropy(
    file_content: "FileContent",
    config: EntropyConfig,
) -> list["Finding"]:
    """
    Scan file lines for high-entropy tokens.

    Skips tokens that look like paths, URLs, or short/long strings.
    Suppresses findings on lines with SUPPRESS_MARKER.
    Returns findings sorted by line number.
    """
    if not config.enabled:
        return []

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for line_num, line in enumerate(file_content.lines, start=1):
        if SUPPRESS_MARKER in line:
            continue

        tokens = _extract_tokens(line, config.token_separators)

        for token in tokens:
            if not (config.min_length <= len(token) <= config.max_length):
                continue
            if _looks_like_path_or_url(token):
                continue

            entropy = shannon_entropy(token)
            if entropy < config.threshold:
                continue

            dedup_key = (line_num, token)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                Finding(
                    rule_id="high_entropy",
                    rule_name="High Entropy String",
                    file_path=str(file_content.path),
                    line_number=line_num,
                    line_content=_truncate_line(line),
                    matched_value=_redact(token, visible_chars=6),
                    base_score=config.base_score,
                    severity="medium",
                    source="entropy",
                    entropy_value=round(entropy, 3),
                )
            )

    findings.sort(key=lambda f: f.line_number)
    return findings


def build_entropy_config(entropy_cfg: dict) -> EntropyConfig:
    """Construct EntropyConfig from the parsed rules.json entropy block."""
    return EntropyConfig(
        enabled=entropy_cfg.get("enabled", True),
        threshold=float(entropy_cfg.get("threshold", 4.5)),
        min_length=int(entropy_cfg.get("min_length", 20)),
        max_length=int(entropy_cfg.get("max_length", 200)),
        base_score=int(entropy_cfg.get("base_score", 50)),
        token_separators=entropy_cfg.get("token_separators", r"[\s=:'\"`,\[\]{}()\\]"),
    )
