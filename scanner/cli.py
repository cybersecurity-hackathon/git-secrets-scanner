"""CLI entry point for GitSentinel — the secrets detection scanner.

Provides three subcommands:

    python -m scanner.cli scan  <repo>   — Scan a repository for secrets
    python -m scanner.cli validate <repo> — Validate detected credentials
    python -m scanner.cli rotate <repo>  — Trigger credential rotation

This module handles argument parsing, orchestrates the pipeline stages
(Collector → Detector → output), and formats results for the terminal.

Note
----
Scoring, validation, and rotation logic is handled by teammate modules
(``scorer.py``, ``validator.py``, ``rotator.py``).  This CLI integrates
them when available, but can run in **scan-only mode** without them.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

# Cross-platform colour support
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    # Graceful fallback if colorama is not installed
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()  # type: ignore[assignment]
    Style = _NoColor()  # type: ignore[assignment]

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None  # type: ignore[assignment]

from .collector import Collector
from .detector import Detector
from .models import Finding, Severity, ScanSource, ValidationStatus


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = r"""
{bold}{cyan}
  ╔══════════════════════════════════════════════════════════════════╗
  ║                                                                ║
  ║   🔐  G i t S e n t i n e l                                   ║
  ║                                                                ║
  ║   Automated Secrets Detection & Credential Rotation            ║
  ║   MITRE ATT&CK T1552.001 — Credentials In Files               ║
  ║                                                                ║
  ╚══════════════════════════════════════════════════════════════════╝
{reset}""".format(
    bold=Style.BRIGHT if hasattr(Style, "BRIGHT") else "",
    cyan=Fore.CYAN if hasattr(Fore, "CYAN") else "",
    reset=Style.RESET_ALL if hasattr(Style, "RESET_ALL") else "",
)

SEVERITY_COLORS = {
    Severity.CRITICAL: Fore.RED,
    Severity.HIGH: Fore.YELLOW,
    Severity.MEDIUM: Fore.CYAN,
    Severity.LOW: Fore.GREEN,
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴 CRIT",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MED ",
    Severity.LOW: "🟢 LOW ",
}

STATUS_ICONS = {
    ValidationStatus.LIVE: "LIVE",
    ValidationStatus.POSSIBLY_LIVE: "POSS",
    ValidationStatus.REVOKED: "REVK",
    ValidationStatus.INVALID: "INVL",
    ValidationStatus.UNKNOWN: "UNKN",
    ValidationStatus.TEST: "TEST",
}


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with scan / validate / rotate subcommands."""
    parser = argparse.ArgumentParser(
        prog="gitsentinel",
        description="🔐 GitSentinel — Automated Secrets Detection & Rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scanner.cli scan ./vulnerable_repo\n"
            "  python -m scanner.cli scan ./vulnerable_repo --format json\n"
            "  python -m scanner.cli scan ./vulnerable_repo --no-history\n"
            "  python -m scanner.cli scan ./vulnerable_repo --min-severity HIGH\n"
        ),
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Git repository for leaked secrets.",
    )
    scan_parser.add_argument(
        "repo_path",
        help="Path to the Git repository to scan.",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "summary", "html", "metrics", "graph"],
        default="table",
        help="Output format (default: table).",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write output to a file instead of stdout.",
    )
    scan_parser.add_argument(
        "--no-history",
        action="store_true",
        help="Skip commit history scanning (current tree only).",
    )
    scan_parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable Shannon entropy analysis.",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Only show findings at or above this severity.",
    )
    scan_parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="Maximum number of commits to scan in history.",
    )

    # --- validate ---
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate detected credentials for liveness.",
    )
    validate_parser.add_argument("repo_path", help="Path to the Git repository.")

    # --- rotate ---
    rotate_parser = subparsers.add_parser(
        "rotate",
        help="Trigger automated credential rotation.",
    )
    rotate_parser.add_argument("repo_path", help="Path to the Git repository.")
    rotate_parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-rotate all CRITICAL findings without prompting.",
    )
    rotate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be rotated without actually doing it.",
    )

    return parser


# ---------------------------------------------------------------------------
# Scan Command Implementation
# ---------------------------------------------------------------------------

def run_scan(args: argparse.Namespace) -> List[Finding]:
    """Execute the scan pipeline: Collector → Detector → Output.

    Returns the list of findings (useful for chaining with validate/rotate).
    """
    print(BANNER)

    # --- Stage 1: Collect ---
    print(f"  {Fore.CYAN}📂 Repository:{Style.RESET_ALL} {args.repo_path}")

    start_time = time.time()

    try:
        collector = Collector(
            repo_path=args.repo_path,
            scan_history=not args.no_history,
            max_commits=args.max_commits,
        )
    except ValueError as exc:
        print(f"\n  {Fore.RED}✗ Error:{Style.RESET_ALL} {exc}")
        sys.exit(1)

    print(f"  {Fore.CYAN}🔍 Scanning...{Style.RESET_ALL}", end="", flush=True)

    # --- Stage 2: Detect ---
    detector = Detector(enable_entropy=not args.no_entropy)
    all_findings: List[Finding] = []

    target_count = 0
    for target in collector.collect():
        target_count += 1
        findings = detector.scan(target)
        all_findings.extend(findings)

    elapsed = time.time() - start_time

    try:
        from .config import ScanConfig
        from .validator import validate_findings
        from .scorer import score_findings
        from .models import Severity
        print(f"\r  {Fore.CYAN}🔎 Validating & Scoring...{Style.RESET_ALL}                    ", end="", flush=True)
        config = ScanConfig()
        all_findings = validate_findings(all_findings, config)
        all_findings = score_findings(all_findings)
        for f in all_findings:
            if getattr(f, 'severity_label', None):
                f.severity = Severity(f.severity_label)
    except ImportError:
        pass

    # Apply minimum severity filter
    min_sev = Severity(args.min_severity)
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    min_index = severity_order.index(min_sev)
    filtered = [f for f in all_findings if severity_order.index(f.severity) <= min_index]

    # Sort: CRITICAL first, then by severity score descending
    filtered.sort(key=lambda f: (severity_order.index(f.severity), -f.entropy_score))

    print(f"\r  {Fore.GREEN}✓ Scan complete!{Style.RESET_ALL}                    ")

    # --- Statistics ---
    print()
    print(f"  {Style.BRIGHT}Commits scanned:{Style.RESET_ALL} {collector.stats['commits_scanned']}"
          f" | {Style.BRIGHT}Branches:{Style.RESET_ALL} {collector.stats['branches_scanned']}"
          f" | {Style.BRIGHT}Files:{Style.RESET_ALL} {collector.stats['files_scanned']}")
    print(f"  {Style.BRIGHT}Scan duration:{Style.RESET_ALL} {elapsed:.1f}s")
    print(f"  {Style.BRIGHT}Targets processed:{Style.RESET_ALL} {detector.stats['targets_scanned']}"
          f" | {Style.BRIGHT}Lines scanned:{Style.RESET_ALL} {detector.stats['lines_scanned']}")
    print(f"  {Style.BRIGHT}Pattern matches:{Style.RESET_ALL} {detector.stats['pattern_matches']}"
          f" | {Style.BRIGHT}Entropy matches:{Style.RESET_ALL} {detector.stats['entropy_matches']}"
          f" | {Style.BRIGHT}Duplicates suppressed:{Style.RESET_ALL} {detector.stats['duplicates_suppressed']}")
    print()

    # --- Stage 3: Output ---
    if args.format == "json":
        output = _format_json(filtered)
    elif args.format == "summary":
        output = _format_summary(filtered)
    elif args.format == "html":
        output = _format_html(filtered, collector.stats, detector.stats, elapsed, args.repo_path)
    elif args.format == "metrics":
        output = _format_metrics(collector.stats, detector.stats, elapsed)
    elif args.format == "graph":
        output = _format_graph(filtered)
    else:
        output = _format_table(filtered)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"  {Fore.GREEN}📄 Report written to:{Style.RESET_ALL} {args.output}")
    else:
        print(output)

    # --- Recommendations ---
    _print_recommendations(filtered)

    return filtered


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def _format_table(findings: List[Finding]) -> str:
    """Format findings as a coloured CLI table."""
    if not findings:
        return f"\n  {Fore.GREEN}✅ No secrets detected — repository is clean!{Style.RESET_ALL}\n"

    if tabulate is None:
        # Fallback if tabulate is not installed
        return _format_table_manual(findings)

    headers = ["Severity", "Secret Type", "File", "Line", "Source", "Status", "Entropy"]
    rows = []

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "")
        sev_icon = SEVERITY_ICONS.get(f.severity, str(f.severity))
        status = STATUS_ICONS.get(f.validation_status, "UNKN")

        # Truncate file path for display
        file_display = f.file_path
        if len(file_display) > 30:
            file_display = "…" + file_display[-29:]

        source_str = "TREE" if f.source == ScanSource.WORKING_TREE else (
            "HIST" if f.source == ScanSource.HISTORY else "STGD"
        )

        rows.append([
            f"{sev_color}{sev_icon}{Style.RESET_ALL}",
            f.rule_name[:24],
            file_display,
            str(f.line_number),
            source_str,
            status,
            f"{f.entropy_score:.1f}",
        ])

    table = tabulate(rows, headers=headers, tablefmt="simple_grid")

    # Add box decoration
    title_line = f"  {Style.BRIGHT}🔐 GitSentinel Scan Report{Style.RESET_ALL}"
    separator = "  " + "─" * 78
    return f"\n{title_line}\n{separator}\n{table}\n{separator}\n"


def _format_table_manual(findings: List[Finding]) -> str:
    """Simple table format without the tabulate dependency."""
    if not findings:
        return f"\n  {Fore.GREEN}✅ No secrets detected — repository is clean!{Style.RESET_ALL}\n"

    lines = [
        f"\n  {Style.BRIGHT}🔐 GitSentinel Scan Report{Style.RESET_ALL}",
        "  " + "─" * 78,
        f"  {'Severity':<10} {'Secret Type':<25} {'File':<28} {'Ln':<4} {'Src':<5} {'Status':<6}",
        "  " + "─" * 78,
    ]

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "")
        sev_icon = SEVERITY_ICONS.get(f.severity, str(f.severity))
        status = STATUS_ICONS.get(f.validation_status, "UNKN")
        file_display = f.file_path[-27:] if len(f.file_path) > 28 else f.file_path
        source_str = "TREE" if f.source == ScanSource.WORKING_TREE else (
            "HIST" if f.source == ScanSource.HISTORY else "STGD"
        )

        lines.append(
            f"  {sev_color}{sev_icon}{Style.RESET_ALL}"
            f"   {f.rule_name[:24]:<25}"
            f" {file_display:<28}"
            f" {f.line_number:<4}"
            f" {source_str:<5}"
            f" {status:<6}"
        )

    lines.append("  " + "─" * 78)
    return "\n".join(lines) + "\n"


def _format_json(findings: List[Finding]) -> str:
    """Format findings as a JSON report for CI/CD integration."""
    report = {
        "tool": "GitSentinel",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "summary": {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "secret_type": f.secret_type.value,
                "severity": f.severity.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "line_content": f.line_content,
                "redacted_match": f.redacted_match,
                "commit_sha": f.commit_sha,
                "commit_date": f.commit_date.isoformat() if f.commit_date else None,
                "author": f.author,
                "branch": f.branch,
                "source": f.source.value,
                "detection_method": f.detection_method.value,
                "entropy_score": round(f.entropy_score, 2),
                "validation_status": f.validation_status.value,
                "severity_score": round(f.severity_score, 2),
            }
            for f in findings
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def _format_summary(findings: List[Finding]) -> str:
    """Format a brief summary of findings by severity."""
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
    }
    for f in findings:
        counts[f.severity] += 1

    lines = [
        f"\n  {Style.BRIGHT}📊 Scan Summary{Style.RESET_ALL}",
        "  " + "─" * 40,
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        color = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]
        lines.append(f"  {color}{icon}{Style.RESET_ALL}  {counts[sev]} finding(s)")

    lines.append("  " + "─" * 40)
    lines.append(f"  {Style.BRIGHT}Total: {len(findings)} finding(s){Style.RESET_ALL}")
    return "\n".join(lines) + "\n"


def _format_html(findings: List[Finding], col_stats: dict, det_stats: dict, elapsed: float, repo_path: str) -> str:
    """Generate HTML report using the reporter module."""
    try:
        from .reporter import HTML_TEMPLATE
    except ImportError:
        return "Error: reporter module not found for HTML template."
        
    from datetime import datetime
    
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)
    
    rows_html = ""
    for f in findings:
        sev_class = f.severity.value.lower()
        stat_class = f.validation_status.value.lower().replace("_", "-")
        badge_map = {
            "live": "badge-live", "possibly-live": "badge-live", "revoked": "badge-revoked",
            "unknown": "badge-unknown", "test": "badge-test", "historical": "badge-unknown"
        }
        badge = badge_map.get(stat_class, "badge-unknown")
        
        rows_html += f'''
            <tr>
                <td><span class="badge badge-{sev_class}">{f.severity.value}</span></td>
                <td>{f.rule_name}</td>
                <td><code>{f.file_path}</code></td>
                <td>{f.line_number}</td>
                <td><span class="badge {badge}">{f.validation_status.value}</span></td>
                <td>{f.final_score:.1f}/10</td>
                <td><code>{f.commit_sha[:8] if f.commit_sha else 'tree'}</code></td>
            </tr>'''

    html = HTML_TEMPLATE
    html = html.replace("{{repo_path}}", repo_path)
    html = html.replace("{{scan_date}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{duration}}", f"{elapsed:.1f}")
    html = html.replace("{{critical_count}}", str(critical_count))
    html = html.replace("{{high_count}}", str(high_count))
    html = html.replace("{{medium_count}}", str(medium_count))
    html = html.replace("{{low_count}}", str(low_count))
    html = html.replace("{{total_findings}}", str(len(findings)))
    html = html.replace("{{findings_rows}}", rows_html)
    return html


def _format_metrics(col_stats: dict, det_stats: dict, elapsed: float) -> str:
    """Format performance metrics for the scan."""
    lines_sec = det_stats.get('lines_scanned', 0) / max(elapsed, 0.001)
    lines = [
        f"\n  {Style.BRIGHT}⏱️  Performance Metrics{Style.RESET_ALL}",
        "  " + "─" * 45,
        f"  Total Scan Time:       {elapsed:.3f}s",
        f"  Commits Processed:     {col_stats.get('commits_scanned', 0)}",
        f"  Files Analyzed:        {col_stats.get('files_scanned', 0)}",
        f"  Lines Scanned:         {det_stats.get('lines_scanned', 0)}",
        f"  Scan Speed:            {lines_sec:.1f} lines/sec",
        f"  Pattern Matches:       {det_stats.get('pattern_matches', 0)}",
        f"  Entropy Checks:        {det_stats.get('entropy_matches', 0)}",
        f"  Duplicates Suppressed: {det_stats.get('duplicates_suppressed', 0)}",
        "  " + "─" * 45,
    ]
    return "\n".join(lines) + "\n"


def _format_graph(findings: List[Finding]) -> str:
    """Format an ASCII bar chart of findings."""
    from collections import Counter
    counts = Counter(f.severity for f in findings)
    type_counts = Counter(f.secret_type for f in findings)
    
    max_count = max(counts.values()) if counts else 1
    max_t_count = max(type_counts.values()) if type_counts else 1
    
    lines = [
        f"\n  {Style.BRIGHT}📈 Findings Graph{Style.RESET_ALL}",
        "  " + "─" * 60,
        f"  {Style.BRIGHT}By Severity:{Style.RESET_ALL}"
    ]
    
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        cnt = counts[sev]
        bar_len = int((cnt / max_count) * 30) if max_count > 0 else 0
        bar = "█" * bar_len
        color = SEVERITY_COLORS.get(sev, "")
        lines.append(f"  {color}{sev.value:<8}{Style.RESET_ALL} | {color}{bar:<30}{Style.RESET_ALL} {cnt}")
        
    lines.extend([
        "",
        f"  {Style.BRIGHT}By Secret Type (Top 5):{Style.RESET_ALL}"
    ])
    
    for stype, cnt in type_counts.most_common(5):
        bar_len = int((cnt / max_t_count) * 30) if max_t_count > 0 else 0
        bar = "█" * bar_len
        lines.append(f"  {stype.value[:20]:<20} | {Fore.CYAN}{bar:<30}{Style.RESET_ALL} {cnt}")
        
    lines.append("  " + "─" * 60)
    return "\n".join(lines) + "\n"


def _print_recommendations(findings: List[Finding]) -> None:
    """Print actionable recommendations based on findings."""
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

    if crit_count > 0:
        print(f"  {Fore.RED}⚠  {crit_count} CRITICAL finding(s) require IMMEDIATE rotation{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Run: python -m scanner.cli rotate <repo> --auto{Style.RESET_ALL}")
    if high_count > 0:
        print(f"  {Fore.YELLOW}⚠  {high_count} HIGH finding(s) should be rotated within 24 hours{Style.RESET_ALL}")
    if crit_count == 0 and high_count == 0 and findings:
        print(f"  {Fore.GREEN}ℹ  No critical/high findings — review MEDIUM/LOW at next security cycle{Style.RESET_ALL}")

    print()


# ---------------------------------------------------------------------------
# Validate & Rotate stubs (delegate to teammate modules)
# ---------------------------------------------------------------------------

def run_validate(args: argparse.Namespace) -> None:
    """Validate detected credentials for liveness.

    Delegates to ``scanner.validator`` if available.
    """
    print(BANNER)
    print(f"  {Fore.CYAN}📂 Repository:{Style.RESET_ALL} {args.repo_path}")

    # First, run a scan to get findings
    # Temporarily set format args for internal use
    args.format = "summary"
    args.output = None
    args.no_history = False
    args.no_entropy = False
    args.min_severity = "LOW"
    args.max_commits = None

    findings = run_scan(args)

    try:
        from .validator import validate_findings
        from .config import ScanConfig
        config = ScanConfig()
        validated = validate_findings(findings, config)
        print(f"\n  {Fore.GREEN}✓ Validation complete — {len(validated)} credential(s) checked{Style.RESET_ALL}")
    except ImportError:
        print(f"\n  {Fore.YELLOW}⚠  Validator module not yet implemented.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}   Credential liveness checks will be available when{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}   scanner/validator.py is implemented by your teammate.{Style.RESET_ALL}")
    except Exception as exc:
        print(f"\n  {Fore.RED}✗ Validation error: {exc}{Style.RESET_ALL}")


def run_rotate(args: argparse.Namespace) -> None:
    """Trigger automated credential rotation.

    Delegates to ``scanner.rotator`` if available.
    """
    print(BANNER)
    print(f"  {Fore.CYAN}📂 Repository:{Style.RESET_ALL} {args.repo_path}")

    if args.dry_run:
        print(f"  {Fore.YELLOW}🏃 DRY RUN MODE — no credentials will be rotated{Style.RESET_ALL}")

    # First, run a scan to get findings
    args.format = "summary"
    args.output = None
    args.no_history = False
    args.no_entropy = False
    args.min_severity = "LOW"
    args.max_commits = None

    findings = run_scan(args)

    # Filter for rotation-eligible findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]

    if not critical_findings:
        print(f"\n  {Fore.GREEN}✅ No CRITICAL findings to rotate.{Style.RESET_ALL}")
        return

    print(f"\n  {Fore.RED}🔄 {len(critical_findings)} CRITICAL finding(s) eligible for rotation:{Style.RESET_ALL}")
    for f in critical_findings:
        print(f"     • {f.rule_name} in {f.file_path}")

    try:
        from .rotator import rotate_findings
        from .config import ScanConfig
        config = ScanConfig()
        config.enable_rotation = True
        config.rotation_dry_run = args.dry_run
        
        results = rotate_findings(
            critical_findings,
            config=config,
        )
        print(f"\n  {Fore.GREEN}✓ Rotation complete — {len(results)} credential(s) processed{Style.RESET_ALL}")
    except ImportError:
        print(f"\n  {Fore.YELLOW}⚠  Rotator module not yet implemented.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}   Credential rotation will be available when{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}   scanner/rotator.py is implemented by your teammate.{Style.RESET_ALL}")
    except Exception as exc:
        print(f"\n  {Fore.RED}✗ Rotation error: {exc}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    """CLI main entry point — parse args and dispatch to the correct handler."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "scan":
        run_scan(args)
    elif args.command == "validate":
        run_validate(args)
    elif args.command == "rotate":
        run_rotate(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
