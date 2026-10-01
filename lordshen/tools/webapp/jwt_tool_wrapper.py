"""JWT Tool wrapper — JWT token attack testing."""

import re

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class JwtToolWrapper:
    """Wrapper for jwt_tool JWT security tester."""

    name: str = "jwt_tool"
    binary: str = "jwt_tool"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run jwt_tool against a JWT token.

        Args:
            target: Target URL.
            token: JWT token to test.
        """
        token = kwargs.get("token", "")
        if not token:
            return []

        cmd = f"python3 -m jwt_tool {token} -t {target} -M at"
        result = await run_tool(cmd, timeout=120, shell=True)
        return self.parse_output(result.stdout, target=target)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse jwt_tool stdout."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        # Check for algorithm confusion
        if "alg:none" in raw.lower() or "algorithm none" in raw.lower():
            findings.append(ToolFinding(
                title="JWT Algorithm None accepted",
                severity="critical",
                url=target,
                cvss_score=9.8,
                tool_name=self.name,
                evidence="Server accepts JWT tokens with alg:none",
                extra={"type": "jwt_vuln", "attack": "alg_none"},
            ))

        # Check for key confusion RS256 to HS256
        if "rs256" in raw.lower() and "hs256" in raw.lower():
            if "accepted" in raw.lower() or "valid" in raw.lower():
                findings.append(ToolFinding(
                    title="JWT RS256/HS256 Key Confusion",
                    severity="critical",
                    url=target,
                    cvss_score=9.1,
                    tool_name=self.name,
                    evidence="Server vulnerable to RS256→HS256 key confusion attack",
                    extra={"type": "jwt_vuln", "attack": "key_confusion"},
                ))

        # Check for weak signing secret
        weak_secret_match = re.search(r"(?:secret|key).*?found.*?[\"'](.+?)[\"']", raw, re.IGNORECASE)
        if weak_secret_match:
            findings.append(ToolFinding(
                title="JWT Weak Signing Secret",
                severity="high",
                url=target,
                cvss_score=7.5,
                tool_name=self.name,
                evidence=f"Weak JWT secret discovered: {weak_secret_match.group(1)[:20]}...",
                extra={"type": "jwt_vuln", "attack": "weak_secret"},
            ))

        # Check for expired token acceptance
        if "expired" in raw.lower() and "accepted" in raw.lower():
            findings.append(ToolFinding(
                title="JWT Expired Token Accepted",
                severity="medium",
                url=target,
                tool_name=self.name,
                evidence="Server accepts expired JWT tokens",
                extra={"type": "jwt_vuln", "attack": "expired_accepted"},
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("jwt_tool")
