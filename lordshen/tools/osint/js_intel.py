"""JS Intelligence — extract secrets and endpoints from JavaScript files."""

import re
from typing import Any

from lordshen.tools import ToolFinding


# Regex patterns for secret detection in JS files
JS_PATTERNS: dict[str, tuple[str, str]] = {
    "aws_access_key": (r"AKIA[0-9A-Z]{16}", "critical"),
    "aws_secret_key": (r"(?i)aws_secret_access_key[\s]*[=:][\s]*['\"]?([A-Za-z0-9/+=]{40})", "critical"),
    "google_api_key": (r"AIza[0-9A-Za-z\-_]{35}", "high"),
    "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "critical"),
    "jwt_token": (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "high"),
    "slack_token": (r"xox[baprs]-[0-9a-zA-Z-]{10,250}", "high"),
    "private_key": (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "critical"),
    "s3_bucket": (r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com", "medium"),
    "s3_bucket_url": (r"s3://[a-zA-Z0-9.\-_/]+", "medium"),
    "heroku_api_key": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "low"),
    "firebase_url": (r"[a-z0-9.-]+\.firebaseio\.com", "medium"),
    "internal_ip": (r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "low"),
}

API_ENDPOINT_PATTERN = re.compile(
    r"""(?:['"`])(/(?:api|v[0-9]|graphql|rest|auth|oauth|admin|internal)[a-zA-Z0-9/_\-.{}]*?)(?:['"`])""",
    re.IGNORECASE,
)


class JsIntelWrapper:
    """Extract secrets and API endpoints from JavaScript files using Playwright."""

    name: str = "js_intel"
    binary: str = ""

    async def run(self, target: str, **kwargs: Any) -> list[ToolFinding]:
        """Navigate to target and intercept JavaScript files for analysis."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return [ToolFinding(
                title="Playwright not installed",
                severity="info",
                tool_name=self.name,
                evidence="pip install playwright && playwright install chromium",
            )]

        js_contents: list[tuple[str, str]] = []  # (url, content)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                # Intercept JS responses
                async def handle_response(response: Any) -> None:
                    try:
                        url = response.url
                        content_type = response.headers.get("content-type", "")
                        if (url.endswith(".js") or "javascript" in content_type) and response.ok:
                            body = await response.text()
                            if len(body) < 5_000_000:  # Skip files > 5MB
                                js_contents.append((url, body))
                    except Exception:
                        pass

                page.on("response", handle_response)

                url = target if target.startswith("http") else f"https://{target}"
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await browser.close()

        except Exception as e:
            return [ToolFinding(
                title=f"JS Intel error: {str(e)[:60]}",
                severity="info",
                tool_name=self.name,
                evidence=str(e),
            )]

        # Analyze all collected JS files
        findings: list[ToolFinding] = []
        for js_url, js_body in js_contents:
            findings.extend(self._analyze_js(js_url, js_body))

        return findings

    def _analyze_js(self, js_url: str, content: str) -> list[ToolFinding]:
        """Analyze a single JS file for secrets and endpoints."""
        findings: list[ToolFinding] = []

        # Check for secrets
        for pattern_name, (pattern, severity) in JS_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches[:3]:  # Limit per pattern
                if isinstance(match, tuple):
                    match = match[0]
                redacted = match[:8] + "..." if len(match) > 8 else match
                findings.append(ToolFinding(
                    title=f"JS Secret ({pattern_name}): {redacted}",
                    severity=severity,
                    url=js_url,
                    tool_name=self.name,
                    evidence=f"Pattern: {pattern_name}, File: {js_url}",
                    extra={"type": "js_secret", "pattern": pattern_name, "js_file": js_url},
                ))

        # Extract API endpoints
        endpoints = set(API_ENDPOINT_PATTERN.findall(content))
        for endpoint in list(endpoints)[:20]:
            findings.append(ToolFinding(
                title=f"JS API endpoint: {endpoint}",
                severity="info",
                url=js_url,
                tool_name=self.name,
                evidence=f"Endpoint: {endpoint}, Source: {js_url}",
                extra={"type": "api_endpoint", "endpoint": endpoint, "js_file": js_url},
            ))

        return findings

    def parse_output(self, raw: str, **kwargs: Any) -> list[ToolFinding]:
        """Not used — analysis is inline."""
        return []

    @staticmethod
    def is_installed() -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False
