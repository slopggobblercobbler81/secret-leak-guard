"""
Unit tests for SecretScanner.
"""

from pathlib import Path
import tempfile
from secret_leak_guard.scanner import SecretScanner, redact_secret

MOCK_GHP1 = "ghp_" + "111122223333444455556666777788889999"
MOCK_GHP2 = "ghp_" + "222233334444555566667777888899990000"
MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
MOCK_STRIPE = "sk_live_" + "1234567890abcdef1234567890abcdef"


def test_redact_secret():
    assert redact_secret("") == ""
    assert redact_secret("12345") == "*****"
    masked = redact_secret("ghp_" + "123456789012345678901234567890123456")
    assert masked.startswith("ghp_")
    assert masked.endswith("456")
    assert "*" in masked


def test_scan_text_findings():
    scanner = SecretScanner()
    code = f"""
    import os
    API_KEY = "{MOCK_GHP1}"
    AWS_ID = "{MOCK_AWS}"
    """
    findings = scanner.scan_text(code, file_path="config.py")
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "SLG003" in rule_ids  # GitHub
    assert "SLG001" in rule_ids  # AWS


def test_inline_suppression():
    scanner = SecretScanner()
    code = f"""
    # pragma: allowlist secret
    API_KEY = "{MOCK_GHP1}"
    TOKEN = "{MOCK_AWS}"  # nosecret
    LEAK = "{MOCK_GHP2}"
    """
    findings = scanner.scan_text(code, file_path="sample.py")
    assert len(findings) == 1
    assert findings[0].line_number == 5


def test_scan_file_and_directory():
    scanner = SecretScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("print('hello world')", encoding="utf-8")

        dirty_file = tmp_path / "secret.env"
        dirty_file.write_text(f"STRIPE_KEY='{MOCK_STRIPE}'", encoding="utf-8")

        ignored_dir = tmp_path / "node_modules"
        ignored_dir.mkdir()
        (ignored_dir / "dep.js").write_text(f"API='{MOCK_AWS}'", encoding="utf-8")

        findings = scanner.scan_directory(tmp_path)
        assert len(findings) == 1
        assert "secret.env" in findings[0].file_path


def test_severity_filtering():
    critical_scanner = SecretScanner(min_severity="CRITICAL")
    # JWT is MEDIUM severity
    jwt_sample = "jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
    findings = critical_scanner.scan_text(jwt_sample)
    assert len(findings) == 0

    medium_scanner = SecretScanner(min_severity="MEDIUM")
    findings_med = medium_scanner.scan_text(jwt_sample)
    assert len(findings_med) >= 1
