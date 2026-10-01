"""SSRFmap wrapper — SSRF detection and exploitation."""

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class SsrfmapWrapper:
    """Wrapper for SSRFmap SSRF detection tool."""

    name: str = "ssrfmap"
    binary: str = "ssrfmap"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run SSRFmap against a request with a potentially vulnerable parameter.

        Args:
            target: Target URL (not directly used — needs request file).
            request_file: Path to saved HTTP request file.
            param: Parameter name to test.
        """
        request_file = kwargs.get("request_file", "")
        param = kwargs.get("param", "url")
        module = kwargs.get("module", "readfiles")

        if not request_file:
            return []

        cmd = f"python3 -m ssrfmap -r {request_file} -p {param} -m {module}"
        result = await run_tool(cmd, timeout=120, shell=True)
        return self.parse_output(result.stdout, target=target, param=param)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse SSRFmap stdout."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")
        param = kwargs.get("param", "url")

        # Look for successful SSRF indicators
        if any(indicator in raw.lower() for indicator in [
            "root:x:", "/etc/passwd", "ami-id", "instance-id",
            "meta-data", "169.254.169.254", "successful",
        ]):
            severity = "critical"
            evidence = raw[:500]

            if "169.254.169.254" in raw or "meta-data" in raw:
                title = f"SSRF: Cloud metadata access via {param}"
                evidence = "Cloud metadata endpoint accessible via SSRF"
            elif "root:x:" in raw or "/etc/passwd" in raw:
                title = f"SSRF: Local file read via {param}"
            else:
                title = f"SSRF confirmed in {param} parameter"

            findings.append(ToolFinding(
                title=title,
                severity=severity,
                url=target,
                cvss_score=9.1,
                tool_name=self.name,
                evidence=evidence,
                extra={"type": "ssrf", "parameter": param},
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("ssrfmap")
