"""SMTP user enumeration wrapper."""

import re

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class SmtpUserEnumWrapper:
    """Wrapper for smtp-user-enum SMTP user enumeration tool."""

    name: str = "smtp_user_enum"
    binary: str = "smtp-user-enum"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run SMTP user enumeration."""
        users_file = kwargs.get("users_file", "")
        method = kwargs.get("method", "VRFY")

        if not users_file:
            return []

        cmd = f"smtp-user-enum -M {method} -U {users_file} -t {target}"
        result = await run_tool(cmd, timeout=300, shell=True)
        return self.parse_output(result.stdout, target=target)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse smtp-user-enum stdout."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        # Pattern: user exists
        for line in raw.strip().splitlines():
            if "exists" in line.lower():
                user_match = re.search(r"(\S+@?\S*)\s+exists", line, re.IGNORECASE)
                if user_match:
                    user = user_match.group(1)
                    findings.append(ToolFinding(
                        title=f"SMTP user exists: {user}",
                        severity="medium",
                        host=target,
                        tool_name=self.name,
                        evidence=line.strip(),
                        extra={"type": "smtp_user", "user": user},
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("smtp-user-enum")
