"""
Git diff scanner and parser.
Detects secrets specifically in added lines in staged commits, branches, or PR diffs.
"""

from pathlib import Path
import re
import subprocess
from typing import List, Optional, Tuple, Union

from secret_leak_guard.scanner import Finding, SecretScanner


def parse_git_diff(diff_text: str) -> List[Tuple[str, int, str]]:
    """
    Parses unified git diff output and returns a list of tuples:
    (file_path, new_line_number, line_content)
    Only considers added lines ('+'), ignoring deleted lines and diff headers.
    """
    added_lines: List[Tuple[str, int, str]] = []
    current_file: Optional[str] = None
    current_line_num: int = 0

    hunk_regex = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for raw_line in diff_text.splitlines():
        # Diff header for target file
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue
        elif raw_line.startswith("+++ /dev/null"):
            current_file = None
            continue
        elif raw_line.startswith("--- "):
            continue

        # Chunk header
        hunk_match = hunk_regex.match(raw_line)
        if hunk_match:
            current_line_num = int(hunk_match.group(1))
            continue

        if current_file is None:
            continue

        # Added line
        if raw_line.startswith("+"):
            content = raw_line[1:]
            added_lines.append((current_file, current_line_num, content))
            current_line_num += 1
        elif raw_line.startswith("-"):
            # Deleted line in old file, ignore for new line count
            pass
        elif raw_line.startswith(" "):
            # Unchanged context line
            current_line_num += 1

    return added_lines


def get_git_diff(
    cached: bool = False,
    commit: Optional[str] = None,
    repo_dir: Union[str, Path] = ".",
) -> str:
    """
    Executes git diff in the specified directory and returns stdout.
    Raises RuntimeError if git fails or directory is not a git repo.
    """
    cmd = ["git", "diff", "--unified=1"]
    if cached:
        cmd.append("--cached")
    if commit:
        cmd.append(commit)

    try:
        res = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Git diff failed with code {res.returncode}: {res.stderr.strip()}")
        return res.stdout
    except FileNotFoundError:
        raise RuntimeError("git executable not found in PATH.")


def scan_git_diff(scanner: SecretScanner, diff_text: str) -> List[Finding]:
    """
    Extracts added lines from a git diff and scans each line with the scanner.
    """
    added_lines = parse_git_diff(diff_text)
    findings: List[Finding] = []

    for file_path, line_num, content in added_lines:
        if scanner._should_ignore_file(file_path):
            continue
        line_findings = scanner.scan_line(content, line_num, file_path=file_path)
        findings.extend(line_findings)

    return findings
