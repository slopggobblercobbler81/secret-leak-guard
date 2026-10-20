"""
Core secret scanning engine.
"""

from dataclasses import dataclass, asdict
import fnmatch
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from secret_leak_guard.entropy import calculate_entropy, is_high_entropy
from secret_leak_guard.rules import SecretRule, get_default_rules

# Directories to ignore by default
DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
}

# File extensions to ignore by default (binaries, lockfiles, images)
DEFAULT_IGNORED_EXTS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".pyo",
    ".lock",
    ".bin",
    ".parquet",
    ".db",
    ".sqlite",
    ".sqlite3",
}

# Comment suppression annotations
INLINE_SUPPRESSION_TAGS = [
    "pragma: allowlist secret",
    "pragma: whitelist secret",
    "nosecret",
    "secret-leak-guard: ignore",
    "slg: ignore",
    "slg: allow",
]


def redact_secret(secret: str) -> str:
    """Mask the secret for safe terminal output and reporting."""
    if not secret:
        return ""
    if len(secret) <= 6:
        return "*" * len(secret)
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(3, len(secret) // 4)
    masked_len = len(secret) - prefix_len - suffix_len
    return secret[:prefix_len] + ("*" * masked_len) + secret[-suffix_len:]


@dataclass
class Finding:
    """A detected secret finding."""
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    matched_text: str
    redacted_text: str
    entropy: float
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


class SecretScanner:
    """Configurable secret scanner that evaluates rules and entropy."""

    def __init__(
        self,
        rules: Optional[List[SecretRule]] = None,
        min_severity: str = "LOW",
        config_path: Optional[Union[str, Path]] = None,
    ):
        self.rules = rules if rules is not None else get_default_rules()
        self.min_severity = min_severity.upper()
        self.ignored_rules: Set[str] = set()
        self.ignored_paths: List[str] = []
        self.ignored_patterns: List[str] = []

        if config_path and Path(config_path).exists():
            self._load_config(Path(config_path))
        elif Path(".secretleakguard.json").exists():
            self._load_config(Path(".secretleakguard.json"))

    def _load_config(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.ignored_rules.update(data.get("ignore_rules", []))
            self.ignored_paths.extend(data.get("ignore_paths", []))
            self.ignored_patterns.extend(data.get("ignore_patterns", []))
        except Exception:
            pass

    def _should_ignore_file(self, path: Union[str, Path]) -> bool:
        p = Path(path)
        # Check extensions
        if p.suffix.lower() in DEFAULT_IGNORED_EXTS:
            return True
        # Check path parts against ignored dirs
        for part in p.parts:
            if part in DEFAULT_IGNORED_DIRS:
                return True
        # Check user config ignored paths
        path_str = str(p).replace("\\", "/")
        for pattern in self.ignored_paths:
            if fnmatch.fnmatch(path_str, pattern):
                return True
        return False

    def _is_suppressed(self, line: str) -> bool:
        line_lower = line.lower()
        return any(tag in line_lower for tag in INLINE_SUPPRESSION_TAGS)

    def _meets_severity(self, rule_severity: str) -> bool:
        hierarchy = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        rule_level = hierarchy.get(rule_severity.upper(), 1)
        min_level = hierarchy.get(self.min_severity, 1)
        return rule_level >= min_level

    def scan_line(self, line: str, line_number: int, file_path: str = "<stdin>") -> List[Finding]:
        """Scan a single line of code/text for secrets."""
        if self._is_suppressed(line):
            return []

        findings: List[Finding] = []

        for rule in self.rules:
            if rule.id in self.ignored_rules:
                continue
            if not self._meets_severity(rule.severity):
                continue

            for match in rule.pattern.finditer(line):
                try:
                    matched_secret = match.group(rule.group_index)
                except IndexError:
                    matched_secret = match.group(0)

                # Entropy verification if rule requires it
                entropy = calculate_entropy(matched_secret)
                if rule.min_entropy > 0:
                    if not is_high_entropy(matched_secret, threshold=rule.min_entropy):
                        continue

                # Template / Placeholder filtering
                if matched_secret.startswith(("${", "%", "<", "$(")) or matched_secret.endswith(("}", "%", ">", ")")):
                    continue

                # Prepare snippet
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_number,
                        matched_text=matched_secret,
                        redacted_text=redact_secret(matched_secret),
                        entropy=entropy,
                        snippet=snippet,
                    )
                )

        return findings

    def scan_text(self, text: str, file_path: str = "<stdin>") -> List[Finding]:
        """Scan multi-line text content for secrets."""
        findings: List[Finding] = []
        lines = text.splitlines()
        suppress_next = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_suppressed(line):
                # If this line is a dedicated comment-only line, suppress the following line
                if stripped.startswith(("#", "//", "/*", "*", ";")):
                    suppress_next = True
                continue

            if suppress_next:
                suppress_next = False
                continue

            findings.extend(self.scan_line(line, idx, file_path=file_path))
        return findings

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """Scan an individual file."""
        path = Path(file_path)
        if not path.is_file():
            return []
        if self._should_ignore_file(path):
            return []

        # Avoid reading excessively large files (> 10MB)
        try:
            if path.stat().st_size > 10 * 1024 * 1024:
                return []
        except OSError:
            return []

        # Try reading file as text
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        return self.scan_text(content, file_path=str(path).replace("\\", "/"))

    def scan_directory(self, root: Union[str, Path], recursive: bool = True) -> List[Finding]:
        """Scan all files inside a directory."""
        findings: List[Finding] = []
        root_path = Path(root)

        if not root_path.exists():
            return []

        if root_path.is_file():
            return self.scan_file(root_path)

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Prune ignored directories in-place to avoid descending
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORED_DIRS]

            for fname in filenames:
                file_full = Path(dirpath) / fname
                if not self._should_ignore_file(file_full):
                    findings.extend(self.scan_file(file_full))

        return findings
