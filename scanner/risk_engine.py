"""
Risk scoring and severity classification engine for GuardRail.

Aggregates findings from pattern and entropy detectors, computes
a normalized total score, and maps it to a severity level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from scanner.pattern_engine import Finding

SeverityLevel = Literal["clean", "low", "medium", "high", "critical"]

_SEVERITY_ORDER: dict[str, int] = {
    "clean": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class RiskConfig:
    """Configuration for risk threshold mapping."""

    low: int = 1
    medium: int = 40
    high: int = 70
    critical: int = 90
    max_score: int = 100


@dataclass
class ScanResult:
    """Aggregated result for a single scanned file."""

    file_path: str
    findings: list[Finding] = field(default_factory=list)
    total_score: int = 0
    severity: SeverityLevel = "clean"

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def is_clean(self) -> bool:
        return self.severity == "clean"

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 0)


def _severity_from_score(score: int, config: RiskConfig) -> SeverityLevel:
    """Map a numeric score to a severity label."""
    if score >= config.critical:
        return "critical"
    if score >= config.high:
        return "high"
    if score >= config.medium:
        return "medium"
    if score >= config.low:
        return "low"
    return "clean"


def _additive_capped_score(findings: list[Finding], max_score: int) -> int:
    """
    Compute score via additive aggregation with diminishing returns.

    Each subsequent finding of the same rule contributes half the previous
    finding's contribution, preventing score inflation from repeated matches.
    Capped at max_score.
    """
    rule_contributions: dict[str, float] = {}
    total: float = 0.0

    for finding in findings:
        rule_id = finding.rule_id
        previous = rule_contributions.get(rule_id, 0.0)
        # Diminishing multiplier: first hit = 1.0, second = 0.5, third = 0.25, ...
        multiplier = 0.5 ** (1 if previous > 0 else 0)
        contribution = finding.base_score * multiplier
        rule_contributions[rule_id] = previous + contribution
        total += contribution

    return min(round(total), max_score)


def compute_risk(
    findings: list[Finding],
    config: RiskConfig,
    file_path: str,
) -> ScanResult:
    """
    Compute the risk score and severity for a list of findings.

    Deduplicates findings by (rule_id, line_number) before scoring.
    """
    deduped = _deduplicate(findings)
    score = _additive_capped_score(deduped, config.max_score)
    severity = _severity_from_score(score, config)

    return ScanResult(
        file_path=file_path,
        findings=deduped,
        total_score=score,
        severity=severity,
    )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings by (rule_id, line_number, matched_value)."""
    seen: set[tuple[str, int, str]] = set()
    result: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.line_number, f.matched_value)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def highest_severity(results: list[ScanResult]) -> SeverityLevel:
    """Return the highest severity level across a set of scan results."""
    if not results:
        return "clean"
    return max(results, key=lambda r: r.severity_rank).severity


def build_risk_config(risk_cfg: dict) -> RiskConfig:
    """Construct RiskConfig from the parsed rules.json risk block."""
    thresholds = risk_cfg.get("thresholds", {})
    return RiskConfig(
        low=thresholds.get("low", 1),
        medium=thresholds.get("medium", 40),
        high=thresholds.get("high", 70),
        critical=thresholds.get("critical", 90),
        max_score=risk_cfg.get("max_score", 100),
    )
