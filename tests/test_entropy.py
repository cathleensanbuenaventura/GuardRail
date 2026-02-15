"""Tests for Shannon entropy analysis."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.entropy import (
    EntropyConfig,
    _extract_tokens,
    _looks_like_path_or_url,
    scan_entropy,
    shannon_entropy,
)
from scanner.file_loader import FileContent
from scanner.pattern_engine import SUPPRESS_MARKER


def _make_file(lines: list[str], path: str = "test.py") -> FileContent:
    return FileContent(path=Path(path), lines=lines)


# ── shannon_entropy ────────────────────────────────────────────────────────


def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_uniform_string():
    # All unique characters should have max entropy
    s = "abcdefgh"
    e = shannon_entropy(s)
    assert e == pytest.approx(3.0, abs=0.01)


def test_entropy_high_random_string():
    # A random-looking 40-char string should score > 4.0
    s = "xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ1kM"
    assert shannon_entropy(s) > 4.0


def test_entropy_low_repetitive_string():
    s = "aaaaaaaaaaaaaaaaaaaaaa"
    assert shannon_entropy(s) == 0.0


# ── _looks_like_path_or_url ────────────────────────────────────────────────


def test_path_filter_https():
    assert _looks_like_path_or_url("https://example.com/secret") is True


def test_path_filter_unix_path():
    assert _looks_like_path_or_url("/usr/local/bin/python") is True


def test_path_filter_normal_token():
    assert _looks_like_path_or_url("xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ") is False


# ── _extract_tokens ────────────────────────────────────────────────────────


def test_extract_tokens_basic():
    tokens = _extract_tokens('key = "somevalue"', r"[\s=:'\"`,\[\]{}()\\]")
    assert "key" in tokens
    assert "somevalue" in tokens


# ── scan_entropy ───────────────────────────────────────────────────────────


def test_scan_entropy_finds_high_entropy():
    # A plausible-looking secret: high entropy, right length
    secret = "xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ1kM2nO"  # 36 chars
    lines = [f'token = "{secret}"\n']
    file_content = _make_file(lines)
    config = EntropyConfig(threshold=3.5, min_length=20, max_length=200)
    findings = scan_entropy(file_content, config)
    assert any(f.rule_id == "high_entropy" for f in findings)


def test_scan_entropy_skips_short_tokens():
    lines = ["key = short\n"]
    file_content = _make_file(lines)
    config = EntropyConfig(threshold=3.5, min_length=20, max_length=200)
    findings = scan_entropy(file_content, config)
    assert findings == []


def test_scan_entropy_disabled():
    secret = "xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ1kM2nO"
    lines = [f'token = "{secret}"\n']
    file_content = _make_file(lines)
    config = EntropyConfig(enabled=False)
    findings = scan_entropy(file_content, config)
    assert findings == []


def test_scan_entropy_suppressed_line():
    secret = "xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ1kM2nO"
    lines = [f'token = "{secret}"  # {SUPPRESS_MARKER}\n']
    file_content = _make_file(lines)
    config = EntropyConfig(threshold=3.5, min_length=20)
    findings = scan_entropy(file_content, config)
    assert findings == []


def test_scan_entropy_source_field():
    secret = "xK9mP2qN7vL4wR8jC0bA3dF5gH6iJ1kM2nO"
    lines = [f'token = "{secret}"\n']
    file_content = _make_file(lines)
    config = EntropyConfig(threshold=3.5, min_length=20)
    findings = scan_entropy(file_content, config)
    for f in findings:
        assert f.source == "entropy"
        assert f.entropy_value is not None
