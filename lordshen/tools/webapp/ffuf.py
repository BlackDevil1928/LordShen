"""ffuf wrapper — fast web fuzzer for directory/endpoint discovery."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path

SENSITIVE_PATHS = {
    "admin", "administrator", "login", "dashboard", "config", "backup",
    "debug", "test", "staging", "internal", "api", "graphql", "console",
    "phpmyadmin", "wp-admin", "manager", "panel", ".git", ".env",
    "swagger", "docs", "actuator", "metrics", "health",
}


class FfufWrapper:
    """Wrapper for ffuf fast web fuzzer."""

    name: str = "ffuf"
    binary: str = "ffuf"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run ffuf directory brute force."""
        output_path = get_temp_output_path("ffuf", "json")
        wordlist = kwargs.get(
            "wordlist",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        )
        threads = kwargs.get("threads", 50)
        match_codes = kwargs.get("match_codes", "200,301,302,403")

        # Ensure target has trailing slash
        fuzz_url = target.rstrip("/") + "/FUZZ"

        cmd = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-mc", match_codes,
            "-t", str(threads),
            "-o", str(output_path),
            "-of", "json",
            "-s",
        ]

        result = await run_tool(cmd, timeout=600)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw, target=target)
            try:
                output_path.unlink()
            except OSError:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse ffuf JSON output."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])
        for entry in results:
            if not isinstance(entry, dict):
                continue

            input_val = entry.get("input", {})
            fuzz_word = input_val.get("FUZZ", "") if isinstance(input_val, dict) else ""
            status = entry.get("status", 0)
            length = entry.get("length", 0)
            words = entry.get("words", 0)
            url = entry.get("url", f"{target}/{fuzz_word}")

            # Determine severity based on path sensitivity
            severity = "info"
            fuzz_lower = fuzz_word.lower()
            if any(sp in fuzz_lower for sp in SENSITIVE_PATHS):
                severity = "medium"
            if any(sp in fuzz_lower for sp in [".git", ".env", "backup", "config"]):
                severity = "high"

            findings.append(ToolFinding(
                title=f"Directory: /{fuzz_word} [{status}]",
                severity=severity,
                url=url,
                host=target,
                tool_name=self.name,
                evidence=f"Status: {status}, Size: {length}, Words: {words}",
                extra={
                    "type": "directory",
                    "path": fuzz_word,
                    "status_code": status,
                    "content_length": length,
                    "word_count": words,
                },
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("ffuf")
