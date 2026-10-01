"""crt.sh wrapper — certificate transparency log subdomain discovery."""

import json

import httpx

from lordshen.tools import ToolFinding


class CrtshWrapper:
    """Wrapper for crt.sh certificate transparency API."""

    name: str = "crtsh"
    binary: str = ""  # No binary — pure API

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Query crt.sh for subdomains via certificate transparency logs.

        Args:
            target: Domain to search certificates for.

        Returns:
            List of ToolFinding objects with discovered subdomains.
        """
        url = f"https://crt.sh/?q=%.{target}&output=json"

        try:
            async with httpx.AsyncClient(
                timeout=60.0, follow_redirects=True, verify=False
            ) as client:
                response = await client.get(url)
                response.raise_for_status()
                raw = response.text
                return self.parse_output(raw, target=target)
        except httpx.TimeoutException:
            return [ToolFinding(
                title="crt.sh timeout",
                severity="info",
                host=target,
                tool_name=self.name,
                evidence="Request to crt.sh timed out after 60s",
            )]
        except httpx.HTTPStatusError as e:
            return [ToolFinding(
                title=f"crt.sh HTTP error: {e.response.status_code}",
                severity="info",
                host=target,
                tool_name=self.name,
                evidence=str(e),
            )]
        except Exception as e:
            return []

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse crt.sh JSON response."""
        findings: list[ToolFinding] = []
        seen: set[str] = set()
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        for entry in data:
            name_value = entry.get("name_value", "")
            # name_value can contain multiple domains separated by newlines
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Remove wildcard prefix
                if name.startswith("*."):
                    name = name[2:]
                if name and name not in seen and "." in name:
                    seen.add(name)
                    findings.append(ToolFinding(
                        title=f"Subdomain (CT): {name}",
                        severity="info",
                        host=name,
                        tool_name=self.name,
                        evidence=f"Found in certificate transparency log (crt.sh)",
                        extra={
                            "type": "subdomain",
                            "source": "crt.sh",
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        },
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        """crt.sh is an API — always available if network is up."""
        return True
