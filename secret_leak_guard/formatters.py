"""
Output formatters: Terminal/CLI table, JSON, SARIF 2.1.0, and Markdown.
"""

import json
from typing import List
from secret_leak_guard.scanner import Finding

# ANSI escape codes for terminal styling
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def _colorize(text: str, color_code: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{color_code}{text}{RESET}"


def format_cli_table(findings: List[Finding], use_color: bool = True) -> str:
    """Format findings as a clear terminal report."""
    if not findings:
        clean_msg = "[OK] No secrets detected. Repository is clean!"
        return _colorize(clean_msg, GREEN, use_color)

    lines = []
    header = f"{BOLD}[!] SECRET LEAK GUARD: {len(findings)} Potential Secret(s) Found{RESET}" if use_color else f"[!] SECRET LEAK GUARD: {len(findings)} Potential Secret(s) Found"
    lines.append(header)
    lines.append("=" * 80)

    for idx, f in enumerate(findings, start=1):
        sev_color = RED if f.severity in ("CRITICAL", "HIGH") else (YELLOW if f.severity == "MEDIUM" else CYAN)
        badge = f"[{f.severity}]"
        colored_badge = _colorize(badge, BOLD + sev_color, use_color)
        rule_info = f"{f.rule_id} ({f.rule_name})"
        location = f"{f.file_path}:{f.line_number}"

        lines.append(f"{idx}. {colored_badge} {BOLD}{rule_info}{RESET if use_color else ''}")
        lines.append(f"   Location: {location}")
        lines.append(f"   Secret:   {_colorize(f.redacted_text, sev_color, use_color)} (Entropy: {f.entropy:.2f})")
        lines.append(f"   Snippet:  {f.snippet}")
        lines.append("-" * 80)

    # Summary by severity
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    summary_parts = []
    if crit_count:
        summary_parts.append(_colorize(f"{crit_count} CRITICAL", RED, use_color))
    if high_count:
        summary_parts.append(_colorize(f"{high_count} HIGH", RED, use_color))
    if med_count:
        summary_parts.append(_colorize(f"{med_count} MEDIUM", YELLOW, use_color))
    if low_count:
        summary_parts.append(_colorize(f"{low_count} LOW", CYAN, use_color))

    lines.append(f"Summary: {', '.join(summary_parts)}")
    return "\n".join(lines)


def format_json(findings: List[Finding]) -> str:
    """Format findings as JSON string."""
    payload = {
        "tool": "secret-leak-guard",
        "version": "1.0.0",
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding]) -> str:
    """Format findings as a GitHub Flavored Markdown table."""
    if not findings:
        return "### ✅ Secret Leak Guard: No secrets detected\n\nAll scanned files are clean."

    md_lines = [
        "### ⚠️ Secret Leak Guard: Secrets Detected\n",
        f"Found **{len(findings)}** potential secret(s) in codebase / diff:\n",
        "| Severity | Rule | Location | Redacted Value | Snippet |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for f in findings:
        sev_icon = "🔴" if f.severity in ("CRITICAL", "HIGH") else ("🟡" if f.severity == "MEDIUM" else "🔵")
        loc_str = f"`{f.file_path}:{f.line_number}`"
        rule_str = f"**{f.rule_id}** - {f.rule_name}"
        redacted = f"`{f.redacted_text}`"
        clean_snippet = f.snippet.replace('|', '\\|')
        snip = f"`{clean_snippet}`"
        md_lines.append(f"| {sev_icon} {f.severity} | {rule_str} | {loc_str} | {redacted} | {snip} |")

    return "\n".join(md_lines)


def format_sarif(findings: List[Finding]) -> str:
    """
    Format findings into SARIF 2.1.0 standard JSON for GitHub Code Scanning integration.
    """
    rules_dict = {}
    sarif_results = []

    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    for f in findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name.replace(" ", ""),
                "shortDescription": {"text": f.rule_name},
                "defaultConfiguration": {"level": level_map.get(f.severity, "warning")},
            }

        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "message": {
                    "text": f"Potential leak of {f.rule_name} (masked: {f.redacted_text}, entropy: {f.entropy:.2f})."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, f.line_number),
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-leak-guard",
                        "informationUri": "https://github.com/slopggobblercobbler81/secret-leak-guard",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
