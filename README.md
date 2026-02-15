# GuardRail

A lightweight, local secret detection and pre-commit scanner for Python projects. GuardRail identifies sensitive information (API keys, database credentials, tokens, etc.) in your code before they're committed to version control.

## Features

- **Pattern-based Detection**: Detects common secret formats (AWS keys, GitHub tokens, Stripe keys, database URLs, etc.)
- **Entropy Analysis**: Identifies high-entropy strings that may be encoded secrets
- **Risk Scoring**: Assigns severity levels (low, medium, high, critical) to findings
- **Pre-commit Hook**: Automatically blocks commits containing secrets above a configurable threshold
- **Flexible Scanning**: Scan individual files or entire directories recursively
- **JSON Reports**: Export findings in structured JSON format for integration with CI/CD pipelines
- **Audit Logging**: Track scan history in audit logs for compliance

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd GuardRail
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install the pre-commit hook:
```bash
python main.py install-hook
```

## How to Use:

### Scan a File
```bash
python main.py scan <file_path>
```

### Scan a Directory
```bash
python main.py scan-directory <directory_path>
```

### Scan a Directory with JSON Report
```bash
python main.py scan-directory . --json-out report.json
```

#### Options:
- `--config, -c`: Path to custom `rules.json` configuration
- `--json-out, -j`: Export findings as JSON file report
- `--audit-log, -a`: Append scan results to audit log
- `--block, -b`: Severity threshold to trigger non-zero exit (default: `high`)
  - Levels: `low`, `medium`, `high`, `critical`
- `--no-recursive`: Scan only the specified directory without recursing

### Install Pre-commit Hook
```bash
python main.py install-hook [repo_path]
```
The hook will automatically scan staged files before each commit and block if secrets are detected.

## Configuration

GuardRail uses a `rules.json` configuration file with pattern definitions and risk settings. Customize detection rules by modifying:

```
config/rules.json
```

## Requirements

- Python 3.8+
- click >= 8.1
- rich >= 13.0
