"""ReAct AI agent loop — autonomous tool selection via Groq AI."""

import json
from typing import Any

from rich.panel import Panel

from lordshen.core.console import console, print_info, print_warning, print_error
from lordshen.llm.router import LLMRouter
from lordshen.llm.prompts import AGENT_DECISION
from lordshen.scope.models import ProgramScope
from lordshen.tools import ToolFinding
from lordshen.pipeline.orchestrator import TOOL_MAP


class AgentLoop:
    """Autonomous ReAct agent: Observe → Think (Groq) → Act → repeat."""

    def __init__(self, target: str, scope: ProgramScope, max_turns: int = 20) -> None:
        self.router = LLMRouter()
        self.target = target
        self.scope = scope
        self.max_turns = max_turns
        self.findings: list[ToolFinding] = []
        self.tools_run: list[str] = []
        self.turn = 0

    async def run(self) -> list[ToolFinding]:
        """Execute the agent loop up to max_turns."""
        console.print(Panel(
            f"[bold cyan]AI Agent Mode[/bold cyan]\n"
            f"Target: {self.target}\n"
            f"Max turns: {self.max_turns}\n"
            f"Scope: {self.scope.program_name}",
            title="Agent Loop Started",
            border_style="blue",
        ))

        for self.turn in range(1, self.max_turns + 1):
            action = await self._get_next_action()
            if not action:
                print_warning("Agent could not decide next action. Stopping.")
                break

            if action.get("done", False):
                print_info("Agent decided all testing is complete.")
                break

            # Display agent reasoning
            self._display_turn(action)

            # Execute the chosen tool
            new_findings = await self._execute_action(action)
            self.findings.extend(new_findings)

        console.print(Panel(
            f"[bold green]Agent completed {self.turn} turns[/bold green]\n"
            f"Total findings: {len(self.findings)}",
            title="Agent Loop Finished",
            border_style="green",
        ))

        return self.findings

    async def _get_next_action(self) -> dict[str, Any] | None:
        """Ask Groq AI what to do next."""
        findings_summary = self._format_findings_summary()

        prompt = AGENT_DECISION.format(
            program_name=self.scope.program_name,
            platform=self.scope.platform,
            in_scope=", ".join(self.scope.in_scope_domains[:10]),
            oos_domains=", ".join(self.scope.oos_domains[:10]),
            oos_vulns=", ".join(self.scope.oos_vuln_classes[:10]),
            priority_vulns=", ".join(self.scope.priority_vulns[:10]),
        )

        user_msg = (
            f"Target: {self.target}\n"
            f"Turn: {self.turn}/{self.max_turns}\n"
            f"Tools already run: {', '.join(self.tools_run) or 'none'}\n"
            f"Findings so far:\n{findings_summary}\n\n"
            f"Available tools: {', '.join(TOOL_MAP.keys())}\n"
            f"What should I do next?"
        )

        try:
            response = await self.router.complete(
                system=prompt,
                user=user_msg,
                task="agent_decision",
                json_mode=True,
            )
            return json.loads(response) if response else None
        except (json.JSONDecodeError, Exception) as e:
            print_error(f"Agent decision error: {e}")
            return None

    async def _execute_action(self, action: dict[str, Any]) -> list[ToolFinding]:
        """Execute the tool chosen by the agent."""
        tool_name = action.get("tool_name", "")
        arguments = action.get("arguments", {})

        if tool_name not in TOOL_MAP:
            print_warning(f"Agent chose unknown tool: {tool_name}")
            return []

        self.tools_run.append(tool_name)

        module_path, cls_name = TOOL_MAP[tool_name]
        try:
            import importlib
            module = importlib.import_module(module_path)
            cls = getattr(module, cls_name)
            wrapper = cls()

            if hasattr(wrapper, "is_installed") and not wrapper.is_installed():
                print_warning(f"{tool_name} is not installed. Skipping.")
                return []

            target = arguments.pop("target", self.target)
            result = await wrapper.run(target, **arguments)
            print_info(f"  ✓ {tool_name} returned {len(result)} findings")
            return result

        except Exception as e:
            print_error(f"  ✗ {tool_name} execution failed: {e}")
            return []

    def _display_turn(self, action: dict[str, Any]) -> None:
        """Display the agent's reasoning as a Rich panel."""
        reasoning = action.get("reasoning", "No reasoning provided")
        tool = action.get("tool_name", "unknown")
        confidence = action.get("confidence", 0)
        expected = action.get("expected_finding_type", "unknown")

        usage = self.router.groq.get_daily_usage()
        tokens = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)

        panel_text = (
            f"[bold blue]Reasoning:[/bold blue] {reasoning}\n"
            f"[bold magenta]Action:[/bold magenta]    {tool}\n"
            f"[bold]Confidence:[/bold]  {confidence:.0%}\n"
            f"[bold]Expected:[/bold]    {expected}\n"
            f"[dim]Groq tokens used: {tokens:,} / 500,000[/dim]"
        )

        console.print(Panel(
            panel_text,
            title=f"Agent Turn {self.turn}/{self.max_turns}",
            border_style="blue",
        ))

    def _format_findings_summary(self) -> str:
        """Create text summary of findings for LLM context."""
        if not self.findings:
            return "No findings yet."

        severity_counts: dict[str, int] = {}
        lines: list[str] = []

        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        lines.append(f"Total: {len(self.findings)} findings")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"  {sev.upper()}: {count}")

        # Add top findings (non-info)
        notable = [f for f in self.findings if f.severity != "info"][:10]
        if notable:
            lines.append("\nNotable findings:")
            for f in notable:
                lines.append(f"  [{f.severity}] {f.title[:80]}")

        return "\n".join(lines)
