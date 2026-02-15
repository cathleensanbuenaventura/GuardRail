"""Tests for the risk scoring engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pattern_engine import Finding
from scanner.risk_engine import (
    RiskConfig,
    ScanResult,
    _additive_capped_score,
    _deduplicate,
    _severity_from_score,
    compute_risk,
    highest_severity,
)


def _finding(rule_id: str = "test", score: int = 50, severity: str = "medium", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="Test",
        file_path="test.py",
        line_number=line,
        line_content="...",
        matched_value="****",
        base_score=score,
        severity=severity,
    )


_DEFAULT_CONFIG = RiskConfig(low=1, medium=40, high=70, critical=90, max_score=100)


# ── _severity_from_score ───────────────────────────────────────────────────


@pytest.mark.parametrize("score,expected", [
    (0, "clean"),
    (1, "low"),
    (39, "low"),
    (40, "medium"),
    (69, "medium"),
    (70, "high"),
    (89, "high"),
    (90, "critical"),
    (100, "critical"),
])
def test_severity_from_score(score, expected):
    assert _severity_from_score(score, _DEFAULT_CONFIG) == expected


# ── _additive_capped_score ─────────────────────────────────────────────────


def test_score_single_finding():
    findings = [_finding(score=50)]
    assert _additive_capped_score(findings, 100) == 50


def test_score_multiple_rules():
    findings = [_finding("rule_a", 50), _finding("rule_b", 40)]
    assert _additive_capped_score(findings, 100) == 90


def test_score_capped_at_max():
    findings = [_finding("rule_a", 90), _finding("rule_b", 90)]
    assert _additive_capped_score(findings, 100) == 100


def test_score_diminishing_returns_same_rule():
    # Second hit of same rule contributes half
    findings = [_finding("rule_a", 60, line=1), _finding("rule_a", 60, line=2)]
    score = _additive_capped_score(findings, 100)
    # First = 60, second = 30 → 90
    assert score == 90


def test_score_empty_findings():
    assert _additive_capped_score([], 100) == 0


# ── _deduplicate ───────────────────────────────────────────────────────────


def test_deduplicate_removes_exact_duplicates():
    f = _finding()
    duped = [f, _finding(line=1)]  # same rule_id, line, matched_value
    result = _deduplicate(duped)
    assert len(result) == 1


def test_deduplicate_keeps_different_lines():
    findings = [_finding(line=1), _finding(line=2)]
    result = _deduplicate(findings)
    assert len(result) == 2


# ── compute_risk ───────────────────────────────────────────────────────────


def test_compute_risk_critical():
    findings = [_finding("aws", score=95, severity="critical")]
    result = compute_risk(findings, _DEFAULT_CONFIG, "test.py")
    assert result.severity == "critical"
    assert result.total_score == 95


def test_compute_risk_clean():
    result = compute_risk([], _DEFAULT_CONFIG, "test.py")
    assert result.severity == "clean"
    assert result.total_score == 0
    assert result.is_clean is True


def test_compute_risk_file_path():
    result = compute_risk([], _DEFAULT_CONFIG, "/some/path/file.py")
    assert result.file_path == "/some/path/file.py"


# ── highest_severity ──────────────────────────────────────────────────────


def test_highest_severity_mixed():
    results = [
        ScanResult("a.py", severity="low", total_score=10),
        ScanResult("b.py", severity="critical", total_score=95),
        ScanResult("c.py", severity="medium", total_score=50),
    ]
    assert highest_severity(results) == "critical"


def test_highest_severity_all_clean():
    results = [ScanResult("a.py"), ScanResult("b.py")]
    assert highest_severity(results) == "clean"


def test_highest_severity_empty():
    assert highest_severity([]) == "clean"
