"""Interactsh wrapper — out-of-band interaction detection."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class InteractshWrapper:
    """Wrapper for projectdiscovery/interactsh-client OOB callback detector."""

    name: str = "interactsh"
    binary: str = "interactsh-client"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Start interactsh client and listen for OOB callbacks.

        Args:
            target: Not directly used.
            timeout: How long to listen (default: 60s).
        """
        timeout = kwargs.get("timeout", 60)
        cmd = f"interactsh-client -server interactsh.com -json -n 1 -poll-interval 5"
        result = await run_tool(cmd, timeout=timeout, shell=True)
        return self.parse_output(result.stdout)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse interactsh JSON output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                protocol = data.get("protocol", "unknown")
                remote_addr = data.get("remote-address", "")
                unique_id = data.get("unique-id", "")
                raw_request = data.get("raw-request", "")

                severity = "medium"
                if protocol.lower() == "http":
                    severity = "high"
                elif protocol.lower() == "dns":
                    severity = "medium"

                findings.append(ToolFinding(
                    title=f"OOB callback: {protocol} from {remote_addr}",
                    severity=severity,
                    tool_name=self.name,
                    evidence=f"Protocol: {protocol}, From: {remote_addr}, ID: {unique_id}",
                    extra={
                        "type": "oob_callback",
                        "protocol": protocol,
                        "remote_address": remote_addr,
                        "unique_id": unique_id,
                    },
                ))
            except json.JSONDecodeError:
                # Extract the interactsh domain from non-JSON output
                if ".interact.sh" in line or ".oast." in line:
                    findings.append(ToolFinding(
                        title=f"Interactsh domain: {line.strip()[:80]}",
                        severity="info",
                        tool_name=self.name,
                        evidence=line.strip(),
                        extra={"type": "interactsh_domain"},
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("interactsh-client")
