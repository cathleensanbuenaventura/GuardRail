"""
Configuration loader for GuardRail.

Locates and parses rules.json, constructs all sub-configs,
and provides a single AppConfig object consumed by all modules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scanner.entropy import EntropyConfig, build_entropy_config
from scanner.file_loader import LoaderConfig, build_loader_config
from scanner.pattern_engine import PatternRule, build_rules
from scanner.risk_engine import RiskConfig, build_risk_config

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.json"


@dataclass
class AppConfig:
    """Top-level configuration object aggregating all sub-configs."""

    rules: list[PatternRule]
    entropy: EntropyConfig
    loader: LoaderConfig
    risk: RiskConfig
    block_threshold: str = "high"
    audit_log: Path | None = None
    json_report: Path | None = None


def load_config(config_path: Path | None = None) -> AppConfig:
    """
    Load and parse the rules.json configuration file.

    Falls back to the bundled default if no path is provided.
    """
    path = config_path or _DEFAULT_CONFIG_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Config not found: {path}")

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    return AppConfig(
        rules=build_rules(raw.get("patterns", [])),
        entropy=build_entropy_config(raw.get("entropy", {})),
        loader=build_loader_config(raw),
        risk=build_risk_config(raw.get("risk", {})),
    )
