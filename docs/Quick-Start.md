# 🚀 Quick Start Guide

Get up and running with **Secret Leak Guard** in less than 3 minutes.

---

## 📥 Installation

Install using Python 3.8+:

```bash
# Via PyPI
pip install secret-leak-guard

# Or install in developer editable mode
git clone https://github.com/slopggobblercobbler81/secret-leak-guard.git
cd secret-leak-guard
pip install -e .
```

---

## ⚡ CLI Examples

### 1. Scan Local Git Diff (Pre-Commit Workflow)

Scan only staged changes that are about to be committed:
```bash
secret-leak-guard diff --staged
```

If secrets are detected, the command returns exit code `1` and prints findings:
```text
🚨 Found 1 potential secret:
  File: config/production.py (line 42)
  Rule: AWS Access Key ID [CRITICAL]
  Match: AKIAIOSFODNN7EXAMPLE
```

### 2. Scan Entire Codebase

Scan an existing repository or specific subdirectory:
```bash
# Scan full current working directory
secret-leak-guard scan .

# Filter by minimum severity threshold
secret-leak-guard scan . --severity HIGH

# Scan specific directory
secret-leak-guard scan src/services/
```

### 3. Automatic Pre-Commit Hook

Install a git pre-commit hook into `.git/hooks/pre-commit`:
```bash
secret-leak-guard hook install
```
Now every `git commit` automatically validates staged changes and blocks commits containing credentials!

To remove the hook:
```bash
secret-leak-guard hook uninstall
```

---

## 🤖 CI/CD Integration

### GitHub Actions Workflow

Add `.github/workflows/secret-scan.yml` to your repository:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Secret Leak Guard
        run: pip install secret-leak-guard

      - name: Scan Codebase & Generate SARIF
        run: |
          secret-leak-guard scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```
