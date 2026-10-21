"""
Unit tests for package registry and service token detection patterns (PyPI, npm, Discord).
"""

import pytest
from secret_leak_guard.rules import get_default_rules
from secret_leak_guard.scanner import SecretScanner


def test_pypi_token_detection():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG017"]

    pypi_prefix = "pypi-" + "AgEIcHlwaS5vcmc"
    pypi_payload = "1234567890abcdefghijklmnopqrstuvwxyz01234567890abcdef_"
    mock_pypi = pypi_prefix + pypi_payload

    sample = f"POETRY_PYPI_TOKEN_PYPI='{mock_pypi}'"
    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(0) == mock_pypi

    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(sample, file_path="deploy.sh")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG017"


def test_npm_token_detection():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG018"]

    mock_npm = "npm_" + "1234567890abcdef1234567890abcdef1234"
    sample = f"NPM_TOKEN={mock_npm}"

    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(0) == mock_npm

    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(sample, file_path=".npmrc")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG018"


def test_discord_token_detection():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG019"]

    part1 = "MTA1OTI0ODU5MDY1NjEyMDk2MA"
    part2 = "Gz9fK4"
    part3 = "abcdefghijklmnopqrstuvwxyz123456789012"
    mock_discord = f"{part1}.{part2}.{part3}"
    sample = f"DISCORD_BOT_TOKEN = \"{mock_discord}\""

    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(0) == mock_discord

    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(sample, file_path="bot.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG019"
