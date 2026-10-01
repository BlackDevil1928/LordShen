"""GAU (GetAllUrls) wrapper — historical URL collection."""

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class GauWrapper:
    """Wrapper for GetAllUrls — historical URLs from Wayback, AlienVault, URLScan."""

    name: str = "gau"
    binary: str = "gau"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run gau to collect historical URLs for a domain."""
        output_path = get_temp_output_path("gau", "txt")

        cmd = [
            "gau", target,
            "--subs",
            "--threads", "10",
            "--o", str(output_path),
        ]

        result = await run_tool(cmd, timeout=600)

        raw = ""
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            try:
                output_path.unlink()
            except OSError:
                pass
        elif result.stdout.strip():
            raw = result.stdout

        return self.parse_output(raw, target=target)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse gau text output — one URL per line."""
        findings: list[ToolFinding] = []
        seen: set[str] = set()

        for line in raw.strip().splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

            has_params = "?" in url and "=" in url

            findings.append(ToolFinding(
                title=f"Historical URL: {url[:80]}{'...' if len(url) > 80 else ''}",
                severity="info",
                url=url,
                tool_name=self.name,
                evidence=url,
                extra={
                    "type": "url",
                    "has_params": has_params,
                    "source": "gau",
                },
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        """Check if gau is installed."""
        return check_binary("gau")
