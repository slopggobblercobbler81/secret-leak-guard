# 🛡️ Secret Leak Guard

[![CI](https://github.com/slopggobblercobbler81/secret-leak-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/secret-leak-guard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![SARIF: 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-green.svg)](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
[![Zero Dependency](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)

> **High-performance CLI regex & Shannon entropy scanner for accidental tokens, credentials, and API keys in git diffs, commits, and codebases.**

---

## ⚡ Overview

Accidentally committing credentials to public repositories is one of the most common causes of infrastructure breaches. **Secret Leak Guard** detects leaked API keys, tokens, private certificates, and passwords before they leave developer machines or get merged into `main`.

Unlike heavy secret scanning daemons, **Secret Leak Guard** is:
- **Lightning-fast & Zero Third-Party Runtime Dependencies**: Pure Python standard library implementation.
- **Git-Diff Aware**: Scans only newly added (`+`) lines in staged commits, PR diffs, or git history—avoiding noisy legacy warnings.
- **Shannon Entropy Powered**: Uses algorithmic character-diversity and entropy analysis ($H(X) = -\sum p_i \log_2 p_i$) to weed out false positives and catch unformatted high-entropy secrets.
- **GitHub Actions & SARIF Native**: Emits SARIF 2.1.0 for seamless GitHub Code Scanning tab integration, as well as PR-ready Markdown tables.
- **One-Command Pre-Commit Hook**: Install a blocking git pre-commit hook with a single command.

---

## 🚀 Installation

### Using pip
```bash
pip install secret-leak-guard
```

### From source
```bash
git clone https://github.com/slopggobblercobbler81/secret-leak-guard.git
cd secret-leak-guard
pip install .
```

---

## 💻 CLI Usage

```text
secret-leak-guard [-h] [-v] {scan,diff,hook,rules} ...
```

### 1. Scan Git Diffs (Working Tree or Staged Changes)
Scan only changed or staged files before committing:
```bash
# Scan unstaged working directory git diff
secret-leak-guard diff

# Scan git staged changes (great for pre-commit checks)
secret-leak-guard diff --staged

# Scan changes introduced by a specific commit
secret-leak-guard diff --commit HEAD~1
```

### 2. Scan Files and Directories
Scan an entire project directory or single file:
```bash
# Scan entire project
secret-leak-guard scan .

# Scan specific file
secret-leak-guard scan src/config.py

# Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
secret-leak-guard scan . --severity HIGH
```

### 3. Multiple Output Formats
```bash
# Clean terminal report with ANSI color highlights (default)
secret-leak-guard scan .

# Output formatted JSON for custom CI/CD pipelines
secret-leak-guard scan . --format json --output report.json

# Output SARIF 2.1.0 for GitHub Code Scanning
secret-leak-guard scan . --format sarif --output secret-report.sarif

# Output Markdown table for Pull Request comments
secret-leak-guard scan . --format markdown --output pr-summary.md
```

### 4. Install Git Pre-Commit Hook
Prevent secret leaks automatically on every `git commit`:
```bash
secret-leak-guard hook install
```
To remove the hook at any time:
```bash
secret-leak-guard hook uninstall
```

### 5. Inspect Built-in Rules
```bash
secret-leak-guard rules
```

---

## 🔒 Built-in Detection Rules

| Rule ID | Severity | Target Provider / Pattern | Description |
| :--- | :--- | :--- | :--- |
| `SLG001` | **CRITICAL** | AWS Access Key ID | Detects standard AWS 20-character AKIA identifiers |
| `SLG002` | **CRITICAL** | AWS Secret Access Key | Detects 40-character base64 AWS secrets in config assignments |
| `SLG003` | **CRITICAL** | GitHub PAT | Classic tokens (`ghp_`), fine-grained (`github_pat_`), and OAuth (`gho_`) |
| `SLG004` | **HIGH** | GitLab PAT | GitLab Personal Access Tokens (`glpat-`) |
| `SLG005` | **HIGH** | Slack Token | Slack Bot, User, and App tokens (`xoxb-`, `xoxp-`, etc.) |
| `SLG006` | **HIGH** | Slack Incoming Webhook | Webhook URLs (`hooks.slack.com/services/...`) |
| `SLG007` | **CRITICAL** | Stripe API Key | Stripe live and test secret keys (`sk_live_`, `rk_live_`, etc.) |
| `SLG008` | **CRITICAL** | OpenAI API Key | Project keys (`sk-proj-`) and standard API tokens |
| `SLG009` | **CRITICAL** | Anthropic API Key | Claude API tokens (`sk-ant-`) |
| `SLG010` | **HIGH** | Google / Firebase API Key | Google Cloud and Firebase API Keys (`AIza...`) |
| `SLG011` | **HIGH** | Hugging Face Token | User access tokens (`hf_...`) |
| `SLG012` | **HIGH** | SendGrid API Key | SendGrid Mail API tokens (`SG...`) |
| `SLG013` | **CRITICAL** | Private Cryptographic Keys | RSA, DSA, EC, OPENSSH, and PGP unencrypted private keys |
| `SLG014` | **MEDIUM** | JSON Web Token (JWT) | 3-part signed JWT authentication tokens |
| `SLG015` | **HIGH** | Database URI Password | Plaintext credentials embedded in Postgres, MySQL, MongoDB URLs |
| `SLG016` | **HIGH** | Generic High-Entropy Secret | Assignments with high Shannon entropy ($H \ge 3.7$) |

---

## ⚙️ Configuration & Suppressions

### Inline Suppression
If a test or mock file contains a benign key, suppress the warning directly in code:

```python
# Same-line suppression
DEMO_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret

# Preceding line suppression
# nosecret
MOCK_TOKEN = "ghp_111122223333444455556666777788889999"
```

Supported suppression directives:
- `pragma: allowlist secret` / `pragma: whitelist secret`
- `nosecret`
- `secret-leak-guard: ignore`
- `slg: ignore`

### Configuration File (`.secretleakguard.json`)
Place a `.secretleakguard.json` file in the root of your project:

```json
{
  "ignore_rules": ["SLG014"],
  "ignore_paths": [
    "tests/fixtures/*",
    "docs/examples/**"
  ]
}
```

---

## 🤖 GitHub Actions Workflow

Use Secret Leak Guard in your CI/CD pipeline with GitHub Code Scanning:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Secret Leak Guard
        uses: slopggobblercobbler81/secret-leak-guard@v1
        with:
          scan-mode: "diff"
          severity: "HIGH"
          format: "sarif"
          output-file: "results.sarif"
          fail-on-findings: "true"

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🧪 Testing

Run the full unit test suite:
```bash
pytest -v
```

All 41+ tests run locally with 100% pass rate.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
