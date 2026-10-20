"""
Command line interface for secret-leak-guard.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from secret_leak_guard import __version__
from secret_leak_guard.formatters import (
    format_cli_table,
    format_json,
    format_markdown,
    format_sarif,
)
from secret_leak_guard.git_diff import get_git_diff, scan_git_diff
from secret_leak_guard.hooks import install_git_hook, uninstall_git_hook
from secret_leak_guard.rules import get_default_rules
from secret_leak_guard.scanner import Finding, SecretScanner


def _output_result(
    findings: List[Finding],
    fmt: str,
    output_file: Optional[str] = None,
    use_color: bool = True,
) -> None:
    fmt = fmt.lower()
    if fmt == "json":
        text = format_json(findings)
    elif fmt == "sarif":
        text = format_sarif(findings)
    elif fmt == "markdown" or fmt == "md":
        text = format_markdown(findings)
    else:
        text = format_cli_table(findings, use_color=use_color)

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_text(text, encoding="utf-8")
        print(f"Results written to {output_file}")
    else:
        print(text)


def handle_scan(args: argparse.Namespace) -> int:
    scanner = SecretScanner(min_severity=args.severity, config_path=args.config)
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"Error: Path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    if target_path.is_file():
        findings = scanner.scan_file(target_path)
    else:
        findings = scanner.scan_directory(target_path)

    _output_result(
        findings=findings,
        fmt=args.format,
        output_file=args.output,
        use_color=not args.no_color,
    )

    if findings and args.fail_on_findings:
        return 1
    return 0


def handle_diff(args: argparse.Namespace) -> int:
    scanner = SecretScanner(min_severity=args.severity, config_path=args.config)

    try:
        diff_text = get_git_diff(
            cached=args.staged or args.cached,
            commit=args.commit,
            repo_dir=Path.cwd(),
        )
    except RuntimeError as e:
        print(f"Git error: {e}", file=sys.stderr)
        return 2

    findings = scan_git_diff(scanner, diff_text)

    _output_result(
        findings=findings,
        fmt=args.format,
        output_file=args.output,
        use_color=not args.no_color,
    )

    if findings and args.fail_on_findings:
        return 1
    return 0


def handle_hook(args: argparse.Namespace) -> int:
    action = args.hook_action
    try:
        if action == "install":
            install_git_hook(Path.cwd())
            print("✔ Pre-commit hook installed successfully in .git/hooks/pre-commit.")
            return 0
        elif action == "uninstall":
            if uninstall_git_hook(Path.cwd()):
                print("✔ Pre-commit hook uninstalled.")
            else:
                print("No active secret-leak-guard hook found.")
            return 0
        else:
            print("Specify 'install' or 'uninstall'.", file=sys.stderr)
            return 2
    except RuntimeError as e:
        print(f"Hook error: {e}", file=sys.stderr)
        return 2


def handle_rules(args: argparse.Namespace) -> int:
    rules = get_default_rules()
    print(f"Secret Leak Guard - Active Detection Rules ({len(rules)} total):\n")
    print(f"{'ID':<8} {'Severity':<10} {'Name':<32} {'Description'}")
    print("-" * 80)
    for r in rules:
        print(f"{r.id:<8} {r.severity:<10} {r.name:<32} {r.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-leak-guard",
        description="🛡️ High-performance CLI regex & entropy scanner for accidental tokens/secrets.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files or directories for secrets.")
    scan_parser.add_argument(
        "path", nargs="?", default=".", help="Path to file or directory (default: current directory)"
    )
    scan_parser.add_argument(
        "-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text", help="Output format"
    )
    scan_parser.add_argument("-o", "--output", help="Write output to file path")
    scan_parser.add_argument(
        "-s", "--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW", help="Minimum severity"
    )
    scan_parser.add_argument("-c", "--config", help="Path to configuration file")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_parser.add_argument(
        "--fail-on-findings",
        dest="fail_on_findings",
        action="store_true",
        default=True,
        help="Exit with code 1 when secrets are detected (default: true)",
    )
    scan_parser.add_argument(
        "--no-fail",
        dest="fail_on_findings",
        action="store_false",
        help="Do not exit with failure even if secrets are found",
    )

    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Scan git diff for secrets.")
    diff_parser.add_argument(
        "--staged", "--cached", dest="staged", action="store_true", help="Scan staged changes"
    )
    diff_parser.add_argument("--commit", help="Scan specific git commit hash/ref")
    diff_parser.add_argument(
        "-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text", help="Output format"
    )
    diff_parser.add_argument("-o", "--output", help="Write output to file path")
    diff_parser.add_argument(
        "-s", "--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW", help="Minimum severity"
    )
    diff_parser.add_argument("-c", "--config", help="Path to configuration file")
    diff_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    diff_parser.add_argument(
        "--fail-on-findings",
        dest="fail_on_findings",
        action="store_true",
        default=True,
        help="Exit with code 1 when secrets are detected (default: true)",
    )
    diff_parser.add_argument(
        "--no-fail",
        dest="fail_on_findings",
        action="store_false",
        help="Do not exit with failure even if secrets are found",
    )

    # Hook command
    hook_parser = subparsers.add_parser("hook", help="Manage git pre-commit hook")
    hook_parser.add_argument("hook_action", choices=["install", "uninstall"], help="Action to execute")

    # Rules command
    subparsers.add_parser("rules", help="List all built-in secret detection rules")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "diff":
        return handle_diff(args)
    elif args.command == "hook":
        return handle_hook(args)
    elif args.command == "rules":
        return handle_rules(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
