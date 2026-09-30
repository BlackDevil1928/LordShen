"""Rule-based false positive pattern matching."""

import json
import re
from pathlib import Path
from typing import Any


FP_RULES_PATH = Path(__file__).parent.parent / "data" / "fp_rules.json"


class FPRuleEngine:
    """Rule-based false positive detection using pattern matching."""

    def __init__(self) -> None:
        self.rules: list[dict[str, Any]] = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        """Load FP rules from data/fp_rules.json."""
        if FP_RULES_PATH.exists():
            try:
                return json.loads(FP_RULES_PATH.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return self._default_rules()

    def _default_rules(self) -> list[dict[str, Any]]:
        """Fallback FP rules."""
        return [
            {"id": "fp_waf_block", "tool": "any", "pattern": "403|Access Denied|Forbidden",
             "condition": "evidence_contains", "reason": "WAF blocked request, not a real finding"},
            {"id": "fp_generic_info", "tool": "nuclei", "pattern": ".*-info$",
             "condition": "template_matches", "reason": "Generic info template, low value"},
            {"id": "fp_404_page", "tool": "any", "pattern": "404|Not Found",
             "condition": "evidence_contains", "reason": "Custom 404 page matched as finding"},
            {"id": "fp_cdn_header", "tool": "any", "pattern": "cloudflare|akamai|fastly",
             "condition": "evidence_contains", "reason": "CDN header mistaken for vulnerability"},
        ]

    def check(self, finding: dict[str, Any]) -> tuple[bool, str]:
        """Check a finding against all FP rules.

        Returns:
            Tuple of (is_false_positive, reason).
        """
        tool_name = finding.get("tool_name", "").lower()
        title = finding.get("title", "")
        evidence = finding.get("evidence", "")
        severity = finding.get("severity", "")

        for rule in self.rules:
            rule_tool = rule.get("tool", "any").lower()
            if rule_tool != "any" and rule_tool != tool_name:
                continue

            pattern = rule.get("pattern", "")
            condition = rule.get("condition", "")
            reason = rule.get("reason", "Matched FP rule")

            try:
                if condition == "evidence_contains":
                    if re.search(pattern, evidence, re.IGNORECASE):
                        return True, reason
                elif condition == "title_matches":
                    if re.search(pattern, title, re.IGNORECASE):
                        return True, reason
                elif condition == "template_matches":
                    template_id = finding.get("extra", {}).get("template_id", "")
                    if re.search(pattern, template_id, re.IGNORECASE):
                        return True, reason
            except re.error:
                continue

        return False, ""
