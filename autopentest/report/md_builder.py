"""Markdown report builder — formatted for HackerOne/Bugcrowd submission."""

from datetime import datetime, timezone
from typing import Any


class MarkdownReportBuilder:
    """Generate Markdown-formatted reports for bug bounty platforms."""

    def build(self, scan_data: dict[str, Any], findings: list[dict[str, Any]],
              output_path: str, platform: str = "hackerone") -> str:
        """Build a full markdown report for all findings."""
        lines: list[str] = []

        lines.append(f"# Security Assessment Report — {scan_data.get('target', 'Unknown')}")
        lines.append(f"\n**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        lines.append(f"**Profile:** {scan_data.get('profile', 'standard')}")
        lines.append(f"**Scan ID:** {scan_data.get('id', 'N/A')}")

        # Severity summary
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        lines.append("\n## Executive Summary\n")
        lines.append(f"Total findings: **{len(findings)}**\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            lines.append(f"| {sev.upper()} | {count} |")

        # Findings
        lines.append("\n---\n")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "info").upper()
            lines.append(f"## [{sev}] {f.get('title', 'Untitled')}\n")
            if f.get("cvss_score"):
                lines.append(f"**CVSS:** {f['cvss_score']}")
            if f.get("url"):
                lines.append(f"**URL:** `{f['url']}`")
            if f.get("host"):
                lines.append(f"**Host:** `{f['host']}`")
            lines.append(f"**Tool:** {f.get('tool_name', 'N/A')}\n")

            if f.get("description"):
                lines.append(f"### Description\n\n{f['description']}\n")

            if f.get("evidence"):
                lines.append("### Evidence\n")
                lines.append(f"```\n{f['evidence'][:1000]}\n```\n")

            lines.append("---\n")

        content = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        return output_path

    def build_single_finding(self, finding: dict[str, Any],
                              report_sections: dict[str, str],
                              platform: str = "hackerone") -> str:
        """Generate a single-finding report for H1/Bugcrowd submission."""
        lines: list[str] = []

        title = report_sections.get("title", finding.get("title", "Untitled"))
        lines.append(f"## {title}\n")

        sev = finding.get("severity", "info").upper()
        lines.append(f"**Severity:** {sev}")

        cvss = report_sections.get("cvss", "")
        if cvss:
            lines.append(f"**CVSS:** {cvss}")

        lines.append(f"\n### Description\n\n{report_sections.get('description', 'N/A')}\n")
        lines.append(f"### Steps to Reproduce\n\n{report_sections.get('repro_steps', 'N/A')}\n")
        lines.append(f"### Impact\n\n{report_sections.get('impact', 'N/A')}\n")

        if finding.get("evidence"):
            lines.append("### Supporting Material / Evidence\n")
            lines.append(f"```\n{finding['evidence'][:2000]}\n```\n")

        lines.append(f"### Remediation\n\n{report_sections.get('remediation', 'N/A')}\n")

        return "\n".join(lines)
