"""
Unit tests for output formatters.
"""

import json
from secret_leak_guard.formatters import (
    format_cli_table,
    format_json,
    format_markdown,
    format_sarif,
)
from secret_leak_guard.scanner import Finding

MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def sample_findings():
    return [
        Finding(
            rule_id="SLG001",
            rule_name="AWS Access Key ID",
            severity="CRITICAL",
            file_path="src/config.py",
            line_number=12,
            matched_text=MOCK_AWS,
            redacted_text="AKIA************MPLE",
            entropy=3.9,
            snippet=f"AWS_ACCESS_KEY_ID = '{MOCK_AWS}'",
        )
    ]


def test_format_cli_table():
    output = format_cli_table(sample_findings(), use_color=False)
    assert "SECRET LEAK GUARD: 1 Potential Secret(s) Found" in output
    assert "SLG001 (AWS Access Key ID)" in output
    assert "src/config.py:12" in output

    empty_output = format_cli_table([], use_color=False)
    assert "No secrets detected" in empty_output


def test_format_json():
    json_str = format_json(sample_findings())
    data = json.loads(json_str)
    assert data["tool"] == "secret-leak-guard"
    assert data["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "SLG001"


def test_format_markdown():
    md = format_markdown(sample_findings())
    assert "### ⚠️ Secret Leak Guard: Secrets Detected" in md
    assert "| 🔴 CRITICAL | **SLG001** - AWS Access Key ID |" in md

    empty_md = format_markdown([])
    assert "No secrets detected" in empty_md


def test_format_sarif():
    sarif_str = format_sarif(sample_findings())
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    runs = data["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "secret-leak-guard"
    assert len(runs[0]["results"]) == 1
    assert runs[0]["results"][0]["ruleId"] == "SLG001"
