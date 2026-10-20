"""
Unit tests for pre-commit hook installer and uninstaller.
"""

from pathlib import Path
import tempfile
from secret_leak_guard.hooks import install_git_hook, uninstall_git_hook


def test_install_and_uninstall_hook():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        git_dir = repo_path / ".git"
        git_dir.mkdir()

        # Install hook
        success = install_git_hook(repo_path)
        assert success is True
        hook_file = git_dir / "hooks" / "pre-commit"
        assert hook_file.exists()
        content = hook_file.read_text(encoding="utf-8")
        assert "secret-leak-guard" in content

        # Uninstall hook
        uninstalled = uninstall_git_hook(repo_path)
        assert uninstalled is True
        assert not hook_file.exists()


def test_install_fails_non_git():
    with tempfile.TemporaryDirectory() as tmpdir:
        non_git_path = Path(tmpdir)
        import pytest
        with pytest.raises(RuntimeError):
            install_git_hook(non_git_path)
