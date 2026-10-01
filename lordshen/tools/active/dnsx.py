"""dnsx wrapper — DNS resolution and record enumeration."""

import json
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class DnsxWrapper:
    """Wrapper for projectdiscovery/dnsx DNS toolkit."""

    name: str = "dnsx"
    binary: str = "dnsx"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Resolve DNS records for subdomains.

        Args:
            target: Domain (used if no subs_file provided).
            subs_file: Path to file containing subdomains.
        """
        output_path = get_temp_output_path("dnsx", "json")
        subs_file = kwargs.get("subs_file", "")

        if subs_file and Path(subs_file).exists():
            cmd = f"cat {subs_file} | dnsx -a -aaaa -cname -mx -txt -resp -json -o {output_path}"
        else:
            cmd = f"echo {target} | dnsx -a -aaaa -cname -mx -txt -resp -json -o {output_path}"

        result = await run_tool(cmd, timeout=300, shell=True)

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
        """Parse dnsx JSON lines output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                a_records = data.get("a", [])
                aaaa_records = data.get("aaaa", [])
                cname_records = data.get("cname", [])
                mx_records = data.get("mx", [])
                txt_records = data.get("txt", [])

                evidence_parts = []
                if a_records:
                    evidence_parts.append(f"A: {', '.join(a_records)}")
                if cname_records:
                    evidence_parts.append(f"CNAME: {', '.join(cname_records)}")
                if mx_records:
                    evidence_parts.append(f"MX: {', '.join(mx_records)}")

                findings.append(ToolFinding(
                    title=f"DNS: {host}",
                    severity="info",
                    host=host,
                    tool_name=self.name,
                    evidence="; ".join(evidence_parts),
                    extra={
                        "type": "dns",
                        "a": a_records,
                        "aaaa": aaaa_records,
                        "cname": cname_records,
                        "mx": mx_records,
                        "txt": txt_records,
                    },
                ))

                # Check for potential subdomain takeover via dangling CNAME
                for cname in cname_records:
                    if any(svc in cname.lower() for svc in [
                        "github.io", "herokuapp.com", "netlify",
                        "s3.amazonaws.com", "azurewebsites.net",
                        "cloudfront.net", "shopify",
                    ]):
                        findings.append(ToolFinding(
                            title=f"Potential takeover: {host} → {cname}",
                            severity="high",
                            host=host,
                            tool_name=self.name,
                            evidence=f"CNAME {host} points to {cname} which may be unclaimed",
                            extra={"type": "potential_takeover", "cname": cname},
                        ))

            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("dnsx")
