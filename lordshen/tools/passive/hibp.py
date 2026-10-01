"""HaveIBeenPwned wrapper — breach data checking via API."""

import httpx

from lordshen.tools import ToolFinding
from lordshen.core.config import get_config_value


class HIBPWrapper:
    """Wrapper for HaveIBeenPwned API to check breached accounts."""

    name: str = "hibp"
    binary: str = ""  # Pure API

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Check if an email appears in known data breaches.

        Args:
            target: Email address to check.
            **kwargs: Additional options.

        Returns:
            List of ToolFinding for any breach matches.
        """
        emails = kwargs.get("emails", [target])
        findings: list[ToolFinding] = []

        api_key = get_config_value("hibp-api-key")
        if not api_key:
            return [ToolFinding(
                title="HIBP API key not configured",
                severity="info",
                tool_name=self.name,
                evidence="Set key with: lordshen config --set hibp-api-key YOUR_KEY",
            )]

        headers = {
            "hibp-api-key": api_key,
            "user-agent": "lordshen-security-audit",
        }

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            for email in emails:
                try:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                    response = await client.get(url)

                    if response.status_code == 200:
                        breaches = response.json()
                        findings.extend(self.parse_output(
                            breaches, email=email
                        ))
                    elif response.status_code == 404:
                        # Not found in breaches — good
                        pass
                    elif response.status_code == 429:
                        findings.append(ToolFinding(
                            title="HIBP rate limited",
                            severity="info",
                            tool_name=self.name,
                            evidence="Rate limit hit, try again later",
                        ))
                        break
                except Exception as e:
                    continue

        return findings

    def parse_output(self, breaches: list, **kwargs) -> list[ToolFinding]:
        """Parse HIBP breach data."""
        findings: list[ToolFinding] = []
        email = kwargs.get("email", "")

        for breach in breaches:
            if isinstance(breach, dict):
                name = breach.get("Name", "Unknown")
                date = breach.get("BreachDate", "Unknown")
                data_classes = breach.get("DataClasses", [])

                findings.append(ToolFinding(
                    title=f"Breach: {email} in {name} ({date})",
                    severity="medium",
                    tool_name=self.name,
                    evidence=f"Email {email} found in {name} breach ({date}). "
                             f"Exposed data: {', '.join(data_classes)}",
                    extra={
                        "type": "breach",
                        "email": email,
                        "breach_name": name,
                        "breach_date": date,
                        "data_classes": data_classes,
                        "is_verified": breach.get("IsVerified", False),
                    },
                ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return True  # Pure API, always available
