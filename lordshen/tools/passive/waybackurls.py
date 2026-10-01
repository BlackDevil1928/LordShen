"""Waybackurls wrapper — historical URL retrieval from Wayback Machine."""

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class WaybackurlsWrapper:
    """Wrapper for tomnomnom/waybackurls."""

    name: str = "waybackurls"
    binary: str = "waybackurls"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run waybackurls to retrieve historical URLs."""
        cmd = ["waybackurls", target]
        result = await run_tool(cmd, timeout=300)
        return self.parse_output(result.stdout, target=target)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse waybackurls text output."""
        findings: list[ToolFinding] = []
        seen: set[str] = set()

        for line in raw.strip().splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

            findings.append(ToolFinding(
                title=f"Wayback URL: {url[:80]}{'...' if len(url) > 80 else ''}",
                severity="info",
                url=url,
                tool_name=self.name,
                evidence=url,
                extra={"type": "url", "source": "wayback"},
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("waybackurls")
