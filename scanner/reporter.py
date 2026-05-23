"""
Report generation for GitSentinel.

Supports three output formats:
  - CLI Table  — Colored terminal output with severity indicators
  - JSON       — Machine-readable for CI/CD pipeline integration
  - HTML       — Styled dashboard for stakeholder reporting

All formats use the shared ScanReport data model.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from scanner.models import Finding, RotationRecord, ScanReport


# ============================================================
# CLI Table Report
# ============================================================


def print_cli_report(report: ScanReport, colorize: bool = True) -> None:
    """
    Print a colored CLI table report to stdout.

    Uses tabulate for table formatting and colorama for colors.
    """
    try:
        from tabulate import tabulate
    except ImportError:
        # Fallback if tabulate not installed
        _print_simple_report(report)
        return

    if colorize:
        try:
            from colorama import init, Fore, Style
            init(autoreset=True)
        except ImportError:
            colorize = False

    # Header
    print()
    print("╔" + "═" * 74 + "╗")
    print("║" + "🔐 GitSentinel Scan Report".center(74) + "║")
    print("╠" + "═" * 74 + "╣")
    print()

    # Summary
    print(f"  Repository:     {report.repo_path}")
    print(
        f"  Commits scanned: {report.total_commits_scanned} | "
        f"Branches: {report.total_branches_scanned} | "
        f"Files: {report.total_files_scanned}"
    )
    print(f"  Scan duration:  {report.duration_seconds:.1f}s")
    print(f"  Total findings: {len(report.findings)}")
    print()

    if not report.findings:
        print("  ✅ No secrets detected — repository is clean!")
        print()
        print("╚" + "═" * 74 + "╝")
        return

    # Build table rows
    rows = []
    for f in report.findings:
        # Severity indicator
        severity_map = {
            "CRITICAL": "🔴 CRIT",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MED",
            "LOW": "🟢 LOW",
        }
        severity = severity_map.get(f.severity_label, f.severity_label)

        # Validation status
        status_map = {
            "LIVE": "LIVE",
            "POSSIBLY_LIVE": "POSS",
            "REVOKED": "REVKD",
            "UNKNOWN": "UNKN",
            "TEST": "TEST",
            "HISTORICAL": "HIST",
        }
        status = status_map.get(f.validation_status.value, f.validation_status.value)

        # Truncate file path if too long
        file_display = f.file_path
        if len(file_display) > 22:
            file_display = "..." + file_display[-19:]

        rows.append([
            severity,
            f.rule_name[:24],
            file_display,
            status,
            f"{f.final_score:.1f}/10",
        ])

    headers = ["Severity", "Secret Type", "File", "Status", "Score"]
    print(tabulate(rows, headers=headers, tablefmt="simple_grid"))
    print()

    # Summary counts
    crit = report.critical_count
    high = report.high_count
    med = report.medium_count
    low = report.low_count

    if crit > 0:
        print(f"  ⚠️  {crit} CRITICAL finding(s) require immediate rotation")
    if high > 0:
        print(f"  ⚠️  {high} HIGH finding(s) should be rotated within 24 hours")
    if med > 0:
        print(f"  ℹ️  {med} MEDIUM finding(s) — review at next security cycle")
    if low > 0:
        print(f"  ℹ️  {low} LOW finding(s) — informational")

    if crit > 0:
        print()
        print(f"  ℹ️  Run: python -m scanner.cli rotate {report.repo_path} --auto")

    # Rotation records
    if report.rotation_records:
        print()
        print("  🔄 Rotation Results:")
        for r in report.rotation_records:
            status_icon = {
                "SUCCESS": "✅",
                "FAILED": "❌",
                "DRY_RUN": "🔍",
                "SKIPPED": "⏭️",
            }.get(r.rotation_status.value, "❓")
            print(f"    {status_icon} {r.finding.secret_type.value}: {r.detail}")

    print()
    print("╚" + "═" * 74 + "╝")
    print()


def _print_simple_report(report: ScanReport) -> None:
    """Fallback plain-text report when tabulate is not available."""
    print(f"\n=== GitSentinel Scan Report ===")
    print(f"Repository: {report.repo_path}")
    print(f"Findings: {len(report.findings)}")
    print()

    for f in report.findings:
        print(
            f"  [{f.severity_label}] {f.rule_name} | "
            f"{f.file_path}:{f.line_number} | "
            f"Score: {f.final_score:.1f}/10 | "
            f"Status: {f.validation_status.value}"
        )

    print()


# ============================================================
# JSON Report
# ============================================================


def generate_json_report(report: ScanReport, output_file: str = "") -> str:
    """
    Generate a JSON report from scan results.

    Args:
        report: The completed ScanReport.
        output_file: Path to write JSON file. If empty, returns as string.

    Returns:
        JSON string of the report.
    """
    report_dict = report.to_dict()
    json_str = json.dumps(report_dict, indent=2, ensure_ascii=False)

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"  📄 JSON report written to: {output_path}")

    return json_str


# ============================================================
# HTML Report
# ============================================================


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitSentinel Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            text-align: center;
            font-size: 2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            text-align: center;
            color: #94a3b8;
            margin-bottom: 2rem;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .summary-card {
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #334155;
        }
        .summary-card .number {
            font-size: 2.5rem;
            font-weight: 700;
        }
        .summary-card .label { color: #94a3b8; font-size: 0.875rem; }
        .critical .number { color: #ef4444; }
        .high .number { color: #f97316; }
        .medium .number { color: #eab308; }
        .low .number { color: #22c55e; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border-radius: 12px;
            overflow: hidden;
        }
        th {
            background: #334155;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        td {
            padding: 0.875rem 1rem;
            border-bottom: 1px solid #334155;
            font-size: 0.9rem;
        }
        tr:hover td { background: #334155; }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-critical { background: #7f1d1d; color: #fca5a5; }
        .badge-high { background: #7c2d12; color: #fdba74; }
        .badge-medium { background: #713f12; color: #fde047; }
        .badge-low { background: #14532d; color: #86efac; }
        .badge-live { background: #7f1d1d; color: #fca5a5; }
        .badge-unknown { background: #374151; color: #9ca3af; }
        .badge-test { background: #1e3a5f; color: #93c5fd; }
        .badge-revoked { background: #14532d; color: #86efac; }
        .footer {
            text-align: center;
            margin-top: 2rem;
            color: #475569;
            font-size: 0.875rem;
        }
        code {
            background: #334155;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 GitSentinel Scan Report</h1>
        <p class="subtitle">
            Repository: <code>{{repo_path}}</code> |
            Scanned: {{scan_date}} |
            Duration: {{duration}}s
        </p>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="number">{{critical_count}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{{high_count}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{{medium_count}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{{low_count}}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #60a5fa;">{{total_findings}}</div>
                <div class="label">Total Findings</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Secret Type</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Status</th>
                    <th>Score</th>
                    <th>Commit</th>
                </tr>
            </thead>
            <tbody>
                {{findings_rows}}
            </tbody>
        </table>

        <div class="footer">
            Generated by GitSentinel | MITRE ATT&CK T1552.001 | {{scan_date}}
        </div>
    </div>
</body>
</html>"""


def generate_html_report(report: ScanReport, output_file: str = "report.html") -> str:
    """
    Generate a styled HTML report from scan results.

    Args:
        report: The completed ScanReport.
        output_file: Path to write HTML file.

    Returns:
        HTML string.
    """
    # Build table rows
    rows_html = ""
    for f in report.findings:
        severity_class = f.severity_label.lower() if f.severity_label else "low"
        status_class = f.validation_status.value.lower().replace("_", "-")

        # Map status to badge class
        badge_status_map = {
            "live": "badge-live",
            "possibly-live": "badge-live",
            "revoked": "badge-revoked",
            "unknown": "badge-unknown",
            "test": "badge-test",
            "historical": "badge-unknown",
        }
        status_badge = badge_status_map.get(status_class, "badge-unknown")

        rows_html += f"""
                <tr>
                    <td><span class="badge badge-{severity_class}">{f.severity_label}</span></td>
                    <td>{f.rule_name}</td>
                    <td><code>{f.file_path}</code></td>
                    <td>{f.line_number}</td>
                    <td><span class="badge {status_badge}">{f.validation_status.value}</span></td>
                    <td>{f.final_score:.1f}/10</td>
                    <td><code>{f.commit_sha[:8] if f.commit_sha else 'tree'}</code></td>
                </tr>"""

    # Fill template
    html = HTML_TEMPLATE
    html = html.replace("{{repo_path}}", report.repo_path)
    html = html.replace("{{scan_date}}", report.scan_start.strftime("%Y-%m-%d %H:%M:%S"))
    html = html.replace("{{duration}}", f"{report.duration_seconds:.1f}")
    html = html.replace("{{critical_count}}", str(report.critical_count))
    html = html.replace("{{high_count}}", str(report.high_count))
    html = html.replace("{{medium_count}}", str(report.medium_count))
    html = html.replace("{{low_count}}", str(report.low_count))
    html = html.replace("{{total_findings}}", str(len(report.findings)))
    html = html.replace("{{findings_rows}}", rows_html)

    # Write to file
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f_out:
        f_out.write(html)
    print(f"  📄 HTML report written to: {output_path}")

    return html


# ============================================================
# Dispatcher
# ============================================================


def generate_report(
    report: ScanReport,
    output_format: str = "table",
    output_file: str = "",
    colorize: bool = True,
) -> Optional[str]:
    """
    Generate a report in the specified format.

    Args:
        report: The completed ScanReport.
        output_format: "table", "json", or "html".
        output_file: File path for json/html output.
        colorize: Whether to use ANSI colors for CLI.

    Returns:
        Report string for json/html formats, None for table (printed directly).
    """
    if output_format == "table":
        print_cli_report(report, colorize=colorize)
        return None
    elif output_format == "json":
        return generate_json_report(report, output_file=output_file)
    elif output_format == "html":
        return generate_html_report(
            report,
            output_file=output_file or "report.html",
        )
    else:
        print(f"  ⚠️  Unknown format '{output_format}', defaulting to table")
        print_cli_report(report, colorize=colorize)
        return None
