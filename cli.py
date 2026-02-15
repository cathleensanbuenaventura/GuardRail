"""
GuardRail CLI — secret detection and pre-commit scanner.

Commands:
  scan              Scan a single file
  scan-directory    Recursively scan a directory
  install-hook      Install the pre-commit hook into a Git repo
"""

from __future__ import annotations

import shutil
import stat
import sys
import time
from pathlib import Path

import click
from rich.console import Console

from scanner.config_loader import load_config
from scanner.report import (
    append_audit_log,
    print_file_result,
    print_summary,
    write_json_report,
)
from scanner.risk_engine import _SEVERITY_ORDER, highest_severity
from scanner.scanner import scan_directory, scan_single_file

_console = Console()

_HOOK_TEMPLATE = """\
#!/usr/bin/env python3
# GuardRail pre-commit hook — auto-generated, do not edit manually
import subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from git_hooks.pre_commit import main
main()
"""


def _resolve_config(config_path: str | None):
    """Load AppConfig, exiting with a user-friendly message on failure."""
    try:
        return load_config(Path(config_path) if config_path else None)
    except FileNotFoundError as exc:
        _console.print(f"[bold red]Config error:[/bold red] {exc}")
        sys.exit(2)


def _exit_for_severity(results, block_threshold: str) -> None:
    """Exit with code 1 if overall severity meets the block threshold."""
    overall = highest_severity(results)
    if _SEVERITY_ORDER.get(overall, 0) >= _SEVERITY_ORDER.get(block_threshold, 3):
        sys.exit(1)


@click.group()
@click.version_option("1.0.0", prog_name="guardrail")
def cli() -> None:
    """GuardRail — local secret detection and pre-commit scanner."""


@cli.command("scan")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--config", "-c", default=None, help="Path to custom rules.json")
@click.option("--json-out", "-j", default=None, type=click.Path(path_type=Path), help="Write JSON report to file")
@click.option("--audit-log", "-a", default=None, type=click.Path(path_type=Path), help="Append to audit log file")
@click.option("--block", "-b", default="high", show_default=True,
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Severity level that triggers a non-zero exit code")
def cmd_scan(file: Path, config: str | None, json_out: Path | None, audit_log: Path | None, block: str) -> None:
    """Scan a single FILE for secrets and sensitive information."""
    cfg = _resolve_config(config)

    start = time.monotonic()
    result = scan_single_file(file, cfg)
    elapsed = time.monotonic() - start

    print_file_result(result)
    print_summary([result], elapsed=elapsed)

    if json_out:
        write_json_report([result], json_out)
        _console.print(f"[dim]JSON report written to {json_out}[/dim]")

    if audit_log:
        append_audit_log([result], audit_log)

    _exit_for_severity([result], block)


@cli.command("scan-directory")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--config", "-c", default=None, help="Path to custom rules.json")
@click.option("--json-out", "-j", default=None, type=click.Path(path_type=Path), help="Write JSON report to file")
@click.option("--audit-log", "-a", default=None, type=click.Path(path_type=Path), help="Append to audit log file")
@click.option("--block", "-b", default="high", show_default=True,
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Severity level that triggers a non-zero exit code")
@click.option("--no-recursive", is_flag=True, default=False, help="Disable recursive directory scan")
def cmd_scan_directory(
    directory: Path,
    config: str | None,
    json_out: Path | None,
    audit_log: Path | None,
    block: str,
    no_recursive: bool,
) -> None:
    """Recursively scan a DIRECTORY for secrets and sensitive information."""
    cfg = _resolve_config(config)

    _console.print(f"[bold]Scanning[/bold] [dim]{directory}[/dim] …")
    start = time.monotonic()
    results = scan_directory(directory, cfg, recursive=not no_recursive)
    elapsed = time.monotonic() - start

    if not results:
        _console.print("[green]No scannable files found.[/green]")
        return

    for result in results:
        print_file_result(result)

    print_summary(results, elapsed=elapsed)

    if json_out:
        write_json_report(results, json_out)
        _console.print(f"[dim]JSON report written to {json_out}[/dim]")

    if audit_log:
        append_audit_log(results, audit_log)

    _exit_for_severity(results, block)


@cli.command("install-hook")
@click.argument("repo", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def cmd_install_hook(repo: Path) -> None:
    """Install the GuardRail pre-commit hook into a Git REPO (default: current directory)."""
    hooks_dir = Path(repo) / ".git" / "hooks"
    if not hooks_dir.is_dir():
        _console.print(
            f"[bold red]Error:[/bold red] {repo} does not appear to be a Git repository "
            f"(missing .git/hooks/)."
        )
        sys.exit(2)

    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        backup = hook_path.with_suffix(".bak")
        shutil.copy2(hook_path, backup)
        _console.print(f"[yellow]Existing hook backed up to {backup}[/yellow]")

    hook_path.write_text(_HOOK_TEMPLATE, encoding="utf-8")
    # Make executable
    current = stat.S_IMODE(hook_path.stat().st_mode)
    hook_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    _console.print(f"[green]✓[/green] GuardRail pre-commit hook installed at [bold]{hook_path}[/bold]")
