"""
Regex-based pattern detection engine for GuardRail.

Loads rules from config and applies them to file content,
returning structured findings with line-level precision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.file_loader import FileContent

# Inline suppression marker — add this comment to suppress a finding on that line
SUPPRESS_MARKER = "guardrail:ignore"


@dataclass(frozen=True)
class PatternRule:
    """A single compiled detection rule."""

    id: str
    name: str
    pattern: re.Pattern[str]
    base_score: int
    severity: str
    description: str


@dataclass
class Finding:
    """A single detection finding from either pattern or entropy analysis."""

    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    line_content: str  # redacted snippet shown to user
    matched_value: str  # partial match for display (truncated/redacted)
    base_score: int
    severity: str
    source: str = "pattern"  # "pattern" | "entropy"
    entropy_value: float | None = None


def _redact(value: str, visible_chars: int = 4) -> str:
    """Partially redact a sensitive value, keeping a small visible prefix."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def _truncate_line(line: str, max_len: int = 120) -> str:
    """Truncate long lines for display."""
    line = line.rstrip("\n\r")
    if len(line) > max_len:
        return line[:max_len] + "..."
    return line


def build_rules(patterns_config: list[dict]) -> list[PatternRule]:
    """Compile regex patterns from the config list into PatternRule objects."""
    rules: list[PatternRule] = []
    for entry in patterns_config:
        try:
            compiled = re.compile(entry["regex"])
            rules.append(
                PatternRule(
                    id=entry["id"],
                    name=entry["name"],
                    pattern=compiled,
                    base_score=int(entry["base_score"]),
                    severity=entry["severity"],
                    description=entry["description"],
                )
            )
        except re.error as exc:
            # Malformed rule — skip and warn without crashing
            import warnings
            warnings.warn(f"Invalid regex in rule '{entry.get('id', '?')}': {exc}")
    return rules


def scan_file(file_content: "FileContent", rules: list[PatternRule]) -> list[Finding]:
    """
    Apply all pattern rules to the given file content.

    Returns a deduplicated list of findings ordered by line number.
    Suppresses findings on lines containing SUPPRESS_MARKER.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()  # (rule_id, line_number, match_start)

    for line_num, line in enumerate(file_content.lines, start=1):
        if SUPPRESS_MARKER in line:
            continue

        for rule in rules:
            for match in rule.pattern.finditer(line):
                # Use the first capturing group if present, else full match
                value = match.group(1) if match.lastindex else match.group(0)
                dedup_key = (rule.id, line_num, match.start(0).__str__())
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        file_path=str(file_content.path),
                        line_number=line_num,
                        line_content=_truncate_line(line),
                        matched_value=_redact(value),
                        base_score=rule.base_score,
                        severity=rule.severity,
                        source="pattern",
                    )
                )

    findings.sort(key=lambda f: f.line_number)
    return findings
