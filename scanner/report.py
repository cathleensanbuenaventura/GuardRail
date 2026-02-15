"""
Report generation for GuardRail scan results.

Handles console output (rich-formatted) and JSON report writing.
Audit log entries are appended to a persistent log file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from scanner.risk_engine import ScanResult, SeverityLevel, highest_severity

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "clean": "green",
}

_SEVERITY_LABELS: dict[str, str] = {
    "critical": "[!!]",
    "high": "[!] ",
    "medium": "[~] ",
    "low": "[-] ",
    "clean": "[+] ",
}

# Force ASCII-safe output; avoids encoding errors on Windows cp1252 terminals
_console = Console(highlight=False)


def _severity_text(severity: str) -> Text:
    color = _SEVERITY_COLORS.get(severity, "white")
    label = _SEVERITY_LABELS.get(severity, "")
    return Text(f"{label} {severity.upper()}", style=color)


def print_file_result(result: ScanResult) -> None:
    """Print a rich-formatted summary for a single file scan result."""
    if result.is_clean:
        _console.print(f"  [green][+][/green] [dim]{result.file_path}[/dim] - clean")
        return

    _console.print()
    _console.print(
        f"  [bold]{result.file_path}[/bold]  "
        f"score=[bold]{result.total_score}[/bold]  "
        f"severity=",
        end="",
    )
    _console.print(_severity_text(result.severity))

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
    )
    table.add_column("Line", style="dim", width=6, justify="right")
    table.add_column("Rule", min_width=22)
    table.add_column("Match", min_width=16)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Sev", width=10)
    table.add_column("Src", width=8, style="dim")

    for finding in result.findings:
        sev_color = _SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            str(finding.line_number),
            finding.rule_name,
            finding.matched_value,
            str(finding.base_score),
            Text(finding.severity.upper(), style=sev_color),
            finding.source,
        )

    _console.print(table)


def print_summary(results: list[ScanResult], elapsed: float | None = None) -> None:
    """Print a final scan summary across all scanned files."""
    total_files = len(results)
    clean_files = sum(1 for r in results if r.is_clean)
    flagged_files = total_files - clean_files
    total_findings = sum(r.finding_count for r in results)
    overall = highest_severity(results)

    _console.print()
    _console.print("[bold]--- Scan Summary ---[/bold]")
    _console.print(f"  Files scanned : [bold]{total_files}[/bold]")
    _console.print(f"  Clean files   : [green]{clean_files}[/green]")
    _console.print(f"  Flagged files : [{'red' if flagged_files else 'green'}]{flagged_files}[/]")
    _console.print(f"  Total findings: [bold]{total_findings}[/bold]")
    _console.print(f"  Overall risk  : ", end="")
    _console.print(_severity_text(overall))
    if elapsed is not None:
        _console.print(f"  Elapsed       : [dim]{elapsed:.2f}s[/dim]")
    _console.print()


def build_json_report(results: list[ScanResult]) -> dict:
    """Construct a serializable JSON report structure."""
    return {
        "guardrail_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_severity": highest_severity(results),
        "total_findings": sum(r.finding_count for r in results),
        "files": [
            {
                "file": r.file_path,
                "total_score": r.total_score,
                "severity": r.severity,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "rule_name": f.rule_name,
                        "line": f.line_number,
                        "matched_value": f.matched_value,
                        "base_score": f.base_score,
                        "severity": f.severity,
                        "source": f.source,
                        **({"entropy": f.entropy_value} if f.entropy_value is not None else {}),
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ],
    }


def write_json_report(results: list[ScanResult], output_path: Path) -> None:
    """Write the JSON report to a file."""
    report = build_json_report(results)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def append_audit_log(results: list[ScanResult], log_path: Path) -> None:
    """Append a timestamped audit entry to the audit log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_severity": highest_severity(results),
        "files_scanned": len(results),
        "total_findings": sum(r.finding_count for r in results),
        "files": [
            {"file": r.file_path, "score": r.total_score, "severity": r.severity}
            for r in results
            if not r.is_clean
        ],
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
