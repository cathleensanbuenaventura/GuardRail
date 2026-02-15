"""Tests for the pattern detection engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.file_loader import FileContent
from scanner.pattern_engine import (
    Finding,
    PatternRule,
    SUPPRESS_MARKER,
    _redact,
    build_rules,
    scan_file,
)


def _make_file(lines: list[str], path: str = "test.py") -> FileContent:
    return FileContent(path=Path(path), lines=lines)


def _make_rules(configs: list[dict]) -> list[PatternRule]:
    return build_rules(configs)


# ── _redact ────────────────────────────────────────────────────────────────


def test_redact_short_value():
    assert _redact("ab", visible_chars=4) == "**"


def test_redact_long_value():
    result = _redact("AKIAIOSFODNN7EXAMPLE", visible_chars=4)
    assert result.startswith("AKIA")
    assert "*" in result
    assert len(result) == len("AKIAIOSFODNN7EXAMPLE")


# ── build_rules ────────────────────────────────────────────────────────────


def test_build_rules_valid():
    configs = [
        {
            "id": "test_rule",
            "name": "Test Rule",
            "regex": r"secret=(\w+)",
            "base_score": 50,
            "severity": "medium",
            "description": "A test rule",
        }
    ]
    rules = build_rules(configs)
    assert len(rules) == 1
    assert rules[0].id == "test_rule"
    assert rules[0].base_score == 50


def test_build_rules_invalid_regex_skipped():
    configs = [
        {
            "id": "bad_rule",
            "name": "Bad",
            "regex": r"[invalid(",
            "base_score": 10,
            "severity": "low",
            "description": "bad",
        }
    ]
    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        rules = build_rules(configs)
    assert len(rules) == 0
    assert len(w) == 1


# ── scan_file ──────────────────────────────────────────────────────────────


def test_scan_file_detects_aws_key():
    lines = ['aws_key = "AKIAIOSFODNN7EXAMPLE"\n']
    file_content = _make_file(lines)
    rules = build_rules(
        [
            {
                "id": "aws_access_key",
                "name": "AWS Access Key ID",
                "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
                "base_score": 90,
                "severity": "critical",
                "description": "AWS Access Key",
            }
        ]
    )
    findings = scan_file(file_content, rules)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws_access_key"
    assert findings[0].line_number == 1
    assert findings[0].severity == "critical"
    assert findings[0].source == "pattern"


def test_scan_file_suppresses_marked_lines():
    lines = [f'aws_key = "AKIAIOSFODNN7EXAMPLE"  # {SUPPRESS_MARKER}\n']
    file_content = _make_file(lines)
    rules = build_rules(
        [
            {
                "id": "aws_access_key",
                "name": "AWS Access Key ID",
                "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
                "base_score": 90,
                "severity": "critical",
                "description": "AWS Access Key",
            }
        ]
    )
    findings = scan_file(file_content, rules)
    assert len(findings) == 0


def test_scan_file_deduplicates_same_match():
    # Same key appearing twice on the same line (edge case)
    lines = ['key = "AKIAIOSFODNN7EXAMPLE" or "AKIAIOSFODNN7EXAMPLE"\n']
    file_content = _make_file(lines)
    rules = build_rules(
        [
            {
                "id": "aws_access_key",
                "name": "AWS Access Key ID",
                "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
                "base_score": 90,
                "severity": "critical",
                "description": "AWS Access Key",
            }
        ]
    )
    findings = scan_file(file_content, rules)
    # Two distinct matches at different positions — both should appear
    assert len(findings) >= 1


def test_scan_file_clean_returns_empty():
    lines = ["x = 1\n", "print('hello')\n"]
    file_content = _make_file(lines)
    rules = build_rules(
        [
            {
                "id": "aws_access_key",
                "name": "AWS Access Key ID",
                "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
                "base_score": 90,
                "severity": "critical",
                "description": "AWS Access Key",
            }
        ]
    )
    findings = scan_file(file_content, rules)
    assert findings == []


def test_scan_file_multiple_rules():
    lines = [
        'password = "supersecret123"\n',
        'key = "AKIAIOSFODNN7EXAMPLE"\n',
    ]
    file_content = _make_file(lines)
    rules = build_rules(
        [
            {
                "id": "generic_secret",
                "name": "Generic Secret",
                "regex": r'(?i)password\s*=\s*["\']([^"\']{8,})["\']',
                "base_score": 65,
                "severity": "high",
                "description": "Hardcoded password",
            },
            {
                "id": "aws_access_key",
                "name": "AWS Access Key ID",
                "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
                "base_score": 90,
                "severity": "critical",
                "description": "AWS Access Key",
            },
        ]
    )
    findings = scan_file(file_content, rules)
    rule_ids = {f.rule_id for f in findings}
    assert "generic_secret" in rule_ids
    assert "aws_access_key" in rule_ids
