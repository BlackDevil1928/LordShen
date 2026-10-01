"""Trufflehog wrapper — secret scanning in repos and files."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary


class TrufflehogWrapper:
    """Wrapper for trufflesecurity/trufflehog secret scanner."""

    name: str = "trufflehog"
    binary: str = "trufflehog"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run trufflehog against a git repo or filesystem path."""
        scan_type = kwargs.get("scan_type", "git")

        if scan_type == "git":
            cmd = f"trufflehog git {target} --json --no-update"
        else:
            cmd = f"trufflehog filesystem {target} --json"

        result = await run_tool(cmd, timeout=600, shell=True)
        return self.parse_output(result.stdout)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse trufflehog JSON lines output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                detector = data.get("DetectorName", data.get("SourceMetadata", {}).get("DetectorName", "unknown"))
                raw_secret = data.get("Raw", "")
                source_meta = data.get("SourceMetadata", {})
                file_path = ""
                if isinstance(source_meta, dict):
                    data_meta = source_meta.get("Data", {})
                    if isinstance(data_meta, dict):
                        file_path = (
                            data_meta.get("Filesystem", {}).get("file", "") or
                            data_meta.get("Git", {}).get("file", "")
                        )

                verified = data.get("Verified", False)
                severity = "critical" if verified else "high"

                # Redact the actual secret in the finding
                redacted = raw_secret[:6] + "..." + raw_secret[-4:] if len(raw_secret) > 10 else "***"

                findings.append(ToolFinding(
                    title=f"Secret ({detector}): {redacted}",
                    severity=severity,
                    tool_name=self.name,
                    evidence=f"Detector: {detector}, File: {file_path}, Verified: {verified}",
                    extra={
                        "type": "secret",
                        "detector": detector,
                        "verified": verified,
                        "file": file_path,
                    },
                ))
            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("trufflehog")
