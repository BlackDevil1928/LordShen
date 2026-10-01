"""SQLMap wrapper — SQL injection detection (safe mode)."""

import re
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class SqlmapWrapper:
    """Wrapper for sqlmap SQL injection detection tool."""

    name: str = "sqlmap"
    binary: str = "sqlmap"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run sqlmap in safe mode against a URL with parameters.

        Args:
            target: URL with parameters (e.g., https://example.com/search?q=test).
        """
        output_dir = get_temp_output_path("sqlmap", "dir")
        output_dir = output_dir.with_suffix("")  # Remove extension

        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--level=3",
            "--risk=2",
            "--forms",
            f"--output-dir={output_dir}",
            "--threads=4",
        ]

        result = await run_tool(cmd, timeout=600)

        findings = self.parse_output(result.stdout, target=target)

        # Clean up output directory
        if output_dir.exists():
            import shutil
            try:
                shutil.rmtree(output_dir)
            except OSError:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse sqlmap stdout for injection findings."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        # Patterns that indicate confirmed injection
        injection_patterns = [
            (r"Parameter: (.+?) \((.+?)\)", "parameter"),
            (r"Type: (.+?)(?:\n|\r)", "type"),
            (r"Payload: (.+?)(?:\n|\r)", "payload"),
        ]

        # Check for confirmed injections
        if "sqlmap identified the following injection point" in raw:
            # Extract injection details
            param_matches = re.findall(
                r"Parameter: (.+?) \((.+?)\)", raw
            )
            type_matches = re.findall(r"Type: (.+?)(?:\n|\r)", raw)
            payload_matches = re.findall(r"Payload: (.+?)(?:\n|\r)", raw)

            for param_name, param_type in param_matches:
                evidence_parts = [
                    f"Parameter: {param_name} ({param_type})",
                ]
                if type_matches:
                    evidence_parts.append(f"Injection types: {', '.join(type_matches[:3])}")
                if payload_matches:
                    evidence_parts.append(f"Payload: {payload_matches[0][:200]}")

                findings.append(ToolFinding(
                    title=f"SQL Injection in {param_name} ({param_type})",
                    severity="critical",
                    url=target,
                    cvss_score=9.8,
                    tool_name=self.name,
                    evidence="\n".join(evidence_parts),
                    description=f"SQL injection vulnerability confirmed in the {param_name} parameter",
                    extra={
                        "type": "sqli",
                        "parameter": param_name,
                        "param_type": param_type,
                        "injection_types": type_matches[:5],
                    },
                ))

        # Check for DB type detection
        db_match = re.search(r"back-end DBMS: (.+?)(?:\n|\r)", raw)
        if db_match:
            db_type = db_match.group(1).strip()
            findings.append(ToolFinding(
                title=f"Database detected: {db_type}",
                severity="info",
                url=target,
                tool_name=self.name,
                evidence=f"Back-end DBMS: {db_type}",
                extra={"type": "db_detection", "dbms": db_type},
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("sqlmap")
