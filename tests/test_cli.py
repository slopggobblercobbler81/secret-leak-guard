"""
Unit tests for CLI commands and options.
"""

from pathlib import Path
import tempfile
import pytest
from secret_leak_guard.cli import main

MOCK_GHP = "ghp_" + "111122223333444455556666777788889999"
MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "secret-leak-guard 1.0.0" in captured.out


def test_cli_rules(capsys):
    ret = main(["rules"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "SLG001" in captured.out
    assert "AWS Access Key ID" in captured.out


def test_cli_scan_clean(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "main.py"
        test_file.write_text("print('All clean!')", encoding="utf-8")
        ret = main(["scan", str(test_file), "--no-color"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No secrets detected" in captured.out


def test_cli_scan_leak_fails(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "vuln.py"
        test_file.write_text(f"GITHUB_TOKEN='{MOCK_GHP}'", encoding="utf-8")
        ret = main(["scan", str(test_file), "--no-color", "--fail-on-findings"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Potential Secret(s) Found" in captured.out
        assert "SLG003" in captured.out


def test_cli_scan_leak_no_fail(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "vuln.py"
        test_file.write_text(f"GITHUB_TOKEN='{MOCK_GHP}'", encoding="utf-8")
        ret = main(["scan", str(test_file), "--no-color", "--no-fail"])
        assert ret == 0


def test_cli_scan_json_output(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "vuln.py"
        test_file.write_text(f"AWS_ID='{MOCK_AWS}'", encoding="utf-8")
        ret = main(["scan", str(test_file), "--format", "json", "--no-fail"])
        assert ret == 0
        captured = capsys.readouterr()
        assert '"tool": "secret-leak-guard"' in captured.out


def test_cli_scan_output_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "vuln.py"
        test_file.write_text(f"AWS_ID='{MOCK_AWS}'", encoding="utf-8")
        out_file = Path(tmpdir) / "report.json"
        ret = main(["scan", str(test_file), "--format", "json", "--output", str(out_file), "--no-fail"])
        assert ret == 0
        assert out_file.exists()
        assert '"SLG001"' in out_file.read_text(encoding="utf-8")
