"""
GuardRail Git pre-commit hook.

Retrieves staged files, scans them, and blocks the commit if the
overall severity meets or exceeds the configured block threshold.

Install via: python main.py install-hook
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Allow running directly from the repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scanner.config_loader import load_config  # noqa: E402
from scanner.scanner import scan_files  # noqa: E402
from scanner.report import print_file_result, print_summary  # noqa: E402
from scanner.risk_engine import highest_severity, _SEVERITY_ORDER  # noqa: E402

_BLOCK_THRESHOLD = "high"  # configurable via config if needed


def _get_staged_files() -> list[Path]:
    """Return a list of staged file paths using git diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[guardrail] Failed to list staged files: {exc}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[guardrail] git not found in PATH.", file=sys.stderr)
        sys.exit(1)

    return [
        Path(line.strip())
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def main() -> None:
    """Entry point for the pre-commit hook."""
    staged = _get_staged_files()
    if not staged:
        sys.exit(0)

    # Filter to files that actually exist (deleted files may appear in diff)
    existing = [p for p in staged if p.is_file()]
    if not existing:
        sys.exit(0)

    print("[guardrail] Scanning staged files for secrets…")

    config = load_config()
    results = scan_files(existing, config)

    for result in results:
        print_file_result(result)

    print_summary(results)

    overall = highest_severity(results)
    block_rank = _SEVERITY_ORDER.get(_BLOCK_THRESHOLD, 3)
    result_rank = _SEVERITY_ORDER.get(overall, 0)

    if result_rank >= block_rank:
        print(
            f"[guardrail] COMMIT BLOCKED — severity '{overall}' meets block "
            f"threshold '{_BLOCK_THRESHOLD}'.\n"
            f"[guardrail] Review findings above, remediate secrets, "
            f"then re-stage your files.\n"
            f"[guardrail] To suppress a line: append  # guardrail:ignore",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
