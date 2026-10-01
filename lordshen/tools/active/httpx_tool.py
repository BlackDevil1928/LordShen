"""httpx wrapper — HTTP probing with tech detection and CDN identification."""

import json
import tempfile
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class HttpxWrapper:
    """Wrapper for projectdiscovery/httpx HTTP probe tool."""

    name: str = "httpx"
    binary: str = "httpx"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Probe subdomains/URLs to find live hosts with tech detection.

        Args:
            target: Single URL or domain.
            subs_file: Path to file containing subdomains (one per line).
        """
        output_path = get_temp_output_path("httpx", "json")
        subs_file = kwargs.get("subs_file", "")

        if subs_file and Path(subs_file).exists():
            cmd = [
                "httpx",
                "-l", subs_file,
                "-title", "-tech-detect", "-status-code",
                "-cdn", "-json",
                "-o", str(output_path),
                "-silent",
            ]
        else:
            cmd = [
                "httpx",
                "-u", target,
                "-title", "-tech-detect", "-status-code",
                "-cdn", "-json",
                "-o", str(output_path),
                "-silent",
            ]

        result = await run_tool(cmd, timeout=600)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw)
            try:
                output_path.unlink()
            except OSError:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse httpx JSON lines output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                host = data.get("host", "")
                status = data.get("status_code", 0)
                title = data.get("title", "")
                tech = data.get("tech", [])
                cdn = data.get("cdn", False)
                cdn_name = data.get("cdn_name", "")

                display_title = f"Live: {url} [{status}]"
                if title:
                    display_title += f" - {title[:50]}"

                findings.append(ToolFinding(
                    title=display_title,
                    severity="info",
                    host=host,
                    url=url,
                    tool_name=self.name,
                    evidence=f"Status: {status}, Title: {title}",
                    extra={
                        "type": "live_host",
                        "status_code": status,
                        "title": title,
                        "technologies": tech,
                        "cdn": cdn,
                        "cdn_name": cdn_name,
                        "content_length": data.get("content_length", 0),
                        "webserver": data.get("webserver", ""),
                    },
                ))
            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("httpx")
