"""
High-level scan orchestrator for GuardRail.

Coordinates file loading, pattern detection, entropy analysis,
and risk computation into a single scan pipeline.
"""

from __future__ import annotations

from pathlib import Path

from scanner.config_loader import AppConfig
from scanner.entropy import scan_entropy
from scanner.file_loader import load_directory, load_file
from scanner.pattern_engine import scan_file
from scanner.risk_engine import ScanResult, compute_risk


def scan_single_file(path: Path, config: AppConfig) -> ScanResult:
    """Scan a single file and return its risk result."""
    file_content = load_file(path, config.loader)

    if file_content is None:
        # File was skipped (binary, too large, etc.)
        return ScanResult(file_path=str(path))

    pattern_findings = scan_file(file_content, config.rules)
    entropy_findings = scan_entropy(file_content, config.entropy)
    all_findings = pattern_findings + entropy_findings

    return compute_risk(all_findings, config.risk, str(path))


def scan_files(paths: list[Path], config: AppConfig) -> list[ScanResult]:
    """Scan a list of file paths and return results for each."""
    return [scan_single_file(p, config) for p in paths]


def scan_directory(root: Path, config: AppConfig, recursive: bool = True) -> list[ScanResult]:
    """Recursively scan all eligible files under a directory."""
    results: list[ScanResult] = []
    for file_content in load_directory(root, config.loader, recursive=recursive):
        pattern_findings = scan_file(file_content, config.rules)
        entropy_findings = scan_entropy(file_content, config.entropy)
        all_findings = pattern_findings + entropy_findings
        result = compute_risk(all_findings, config.risk, str(file_content.path))
        results.append(result)
    return results
