"""
Additional integration tests for CLI commands.
"""

from pathlib import Path
import os
import tempfile
import pytest
from secret_leak_guard.cli import main

MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_no_args(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_hook_lifecycle(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / ".git").mkdir()

        orig_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            ret_install = main(["hook", "install"])
            assert ret_install == 0
            assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()

            ret_uninstall = main(["hook", "uninstall"])
            assert ret_uninstall == 0
            assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()
        finally:
            os.chdir(orig_cwd)


def test_cli_scan_nonexistent_path(capsys):
    ret = main(["scan", "nonexistent_directory_or_file_12345"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_cli_config_file_filtering(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cfg_file = tmp_path / ".secretleakguard.json"
        cfg_file.write_text('{"ignore_rules": ["SLG001"]}', encoding="utf-8")

        test_file = tmp_path / "creds.py"
        test_file.write_text(f"AWS_KEY = '{MOCK_AWS}'", encoding="utf-8")

        ret = main(["scan", str(test_file), "--config", str(cfg_file), "--no-color"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No secrets detected" in captured.out
