"""
Unit tests for git diff parser and scanner.
"""

from secret_leak_guard.git_diff import parse_git_diff, scan_git_diff
from secret_leak_guard.scanner import SecretScanner

MOCK_GHP = "ghp_" + "111122223333444455556666777788889999"
MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"

SAMPLE_DIFF = f"""diff --git a/app.py b/app.py
index e69de29..4901f40 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 def main():
-    pass
+    # Added line
+    token = "{MOCK_GHP}"
+    return True
"""


def test_parse_git_diff_added_lines():
    added = parse_git_diff(SAMPLE_DIFF)
    assert len(added) == 3
    # Check first added line
    file_path, line_no, content = added[0]
    assert file_path == "app.py"
    assert line_no == 2
    assert "token =" in added[1][2]


def test_scan_git_diff_detects_secret():
    scanner = SecretScanner()
    findings = scan_git_diff(scanner, SAMPLE_DIFF)
    assert len(findings) == 1
    f = findings[0]
    assert f.file_path == "app.py"
    assert f.line_number == 3
    assert f.rule_id == "SLG003"


def test_scan_git_diff_ignores_deleted_secrets():
    diff_with_deleted_secret = f"""diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,1 @@
-{f"AWS_KEY = '{MOCK_AWS}'"}
+AWS_KEY = os.getenv("AWS_KEY")
"""
    scanner = SecretScanner()
    findings = scan_git_diff(scanner, diff_with_deleted_secret)
    assert len(findings) == 0
