"""Scan orchestrator — runs all stages in order with parallel tool execution."""

import asyncio
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from lordshen.core.console import console, print_banner, print_info, print_error, print_success, print_warning, get_severity_style, create_findings_table
from lordshen.core.database import get_session, store_finding, store_scan, log_audit, init_db
from lordshen.core.exceptions import ScopeError, ToolError
from lordshen.scope.models import ProgramScope
from lordshen.scope.guard import check_scope_or_abort
from lordshen.tools import ToolFinding
from lordshen.pipeline.stages import Stage, get_stages_for_profile

# Tool class name → (module_path, class_name)
TOOL_MAP: dict[str, tuple[str, str]] = {
    "SubfinderWrapper": ("lordshen.tools.passive.subfinder", "SubfinderWrapper"),
    "AmassWrapper": ("lordshen.tools.passive.amass", "AmassWrapper"),
    "CrtshWrapper": ("lordshen.tools.passive.crtsh", "CrtshWrapper"),
    "GauWrapper": ("lordshen.tools.passive.gau", "GauWrapper"),
    "WaybackurlsWrapper": ("lordshen.tools.passive.waybackurls", "WaybackurlsWrapper"),
    "TheHarvesterWrapper": ("lordshen.tools.passive.theharvester", "TheHarvesterWrapper"),
    "ParamSpiderWrapper": ("lordshen.tools.passive.paramspider", "ParamSpiderWrapper"),
    "HttpxWrapper": ("lordshen.tools.active.httpx_tool", "HttpxWrapper"),
    "DnsxWrapper": ("lordshen.tools.active.dnsx", "DnsxWrapper"),
    "MasscanWrapper": ("lordshen.tools.active.masscan", "MasscanWrapper"),
    "NmapWrapper": ("lordshen.tools.active.nmap_tool", "NmapWrapper"),
    "WhatWebWrapper": ("lordshen.tools.active.whatweb", "WhatWebWrapper"),
    "Wafw00fWrapper": ("lordshen.tools.active.wafw00f_tool", "Wafw00fWrapper"),
    "NucleiWrapper": ("lordshen.tools.vuln.nuclei", "NucleiWrapper"),
    "TestsslWrapper": ("lordshen.tools.vuln.testssl", "TestsslWrapper"),
    "NiktoWrapper": ("lordshen.tools.vuln.nikto", "NiktoWrapper"),
    "SubjackWrapper": ("lordshen.tools.vuln.subjack", "SubjackWrapper"),
    "SshAuditWrapper": ("lordshen.tools.vuln.ssh_audit", "SshAuditWrapper"),
    "FfufWrapper": ("lordshen.tools.webapp.ffuf", "FfufWrapper"),
    "FeroxbusterWrapper": ("lordshen.tools.webapp.feroxbuster", "FeroxbusterWrapper"),
    "DalfoxWrapper": ("lordshen.tools.webapp.dalfox", "DalfoxWrapper"),
    "ArjunWrapper": ("lordshen.tools.webapp.arjun", "ArjunWrapper"),
    "WapitiWrapper": ("lordshen.tools.webapp.wapiti", "WapitiWrapper"),
    "CorsScannerWrapper": ("lordshen.tools.webapp.cors_scanner", "CorsScannerWrapper"),
    "NetexecWrapper": ("lordshen.tools.network.netexec", "NetexecWrapper"),
    "HydraWrapper": ("lordshen.tools.network.hydra", "HydraWrapper"),
    "S3CheckWrapper": ("lordshen.tools.cloud.s3_check", "S3CheckWrapper"),
    "TrivyWrapper": ("lordshen.tools.cloud.trivy", "TrivyWrapper"),
}


class ScanOrchestrator:
    """Runs the full scan pipeline: stages → tools → findings → DB."""

    def __init__(
        self,
        target: str,
        scope: ProgramScope,
        profile: str = "standard",
        no_active: bool = False,
        scan_id: str | None = None,
    ) -> None:
        self.target = target
        self.scope = scope
        self.profile = profile
        self.no_active = no_active
        self.scan_id = scan_id or uuid.uuid4().hex[:12]
        self.all_findings: list[ToolFinding] = []
        self.stage_data: dict[str, Any] = {}  # Data passed between stages

    async def run(self) -> str:
        """Execute the full scan pipeline. Returns scan_id."""
        init_db()

        # Validate scope
        check_scope_or_abort(self.target, self.scope)

        # Print banner
        print_banner(self.target, self.profile, self.scope.program_name, "Connected")

        # Record scan start
        with get_session() as session:
            store_scan(session, {
                "id": self.scan_id,
                "target": self.target,
                "profile": self.profile,
                "scope_name": self.scope.program_name,
                "status": "running",
                "started_at": datetime.now(timezone.utc),
            })
            log_audit(session, "scan_start", self.target, self.scope.program_name,
                      f"Profile: {self.profile}")

        stages = get_stages_for_profile(self.profile)

        # Filter out active stages if --no-active
        if self.no_active:
            stages = [s for s in stages if s.name == "passive_recon"]

        for idx, stage in enumerate(stages, 1):
            console.print(f"\n[bold cyan]━━━ [{idx}/{len(stages)}] {stage.display_name} ━━━[/bold cyan]")

            try:
                stage_findings = await self._run_stage(stage)
                self.all_findings.extend(stage_findings)

                # Print stage results panel
                self._print_stage_results(stage, stage_findings)

            except Exception as e:
                print_error(f"Stage {stage.display_name} failed: {e}")

        # Store all findings to DB
        with get_session() as session:
            for finding in self.all_findings:
                store_finding(session, {
                    "scan_id": self.scan_id,
                    **finding.to_dict(),
                })

            # Update scan status
            store_scan(session, {
                "id": self.scan_id,
                "target": self.target,
                "profile": self.profile,
                "scope_name": self.scope.program_name,
                "status": "completed",
                "finished_at": datetime.now(timezone.utc),
                "findings_count": len(self.all_findings),
            })

        # Print final summary
        self._print_final_summary()

        return self.scan_id

    async def _run_stage(self, stage: Stage) -> list[ToolFinding]:
        """Run all tools in a stage."""
        findings: list[ToolFinding] = []
        tasks = []

        for tool_name in stage.tools:
            wrapper = self._get_tool_instance(tool_name)
            if wrapper is None:
                continue
            if hasattr(wrapper, "is_installed") and not wrapper.is_installed():
                print_warning(f"  ⊘ {tool_name} not installed — skipping")
                continue

            kwargs = self._prepare_stage_input(stage.name)
            tasks.append((tool_name, wrapper, kwargs))

        if stage.parallel and len(tasks) > 1:
            # Run in parallel
            coros = [
                self._run_tool_safe(name, wrapper, **kwargs)
                for name, wrapper, kwargs in tasks
            ]
            results = await asyncio.gather(*coros, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
        else:
            # Run serially
            for name, wrapper, kwargs in tasks:
                result = await self._run_tool_safe(name, wrapper, **kwargs)
                findings.extend(result)

        # Collect data for next stages
        self._collect_stage_data(stage.name, findings)

        return findings

    async def _run_tool_safe(self, name: str, wrapper: Any, **kwargs: Any) -> list[ToolFinding]:
        """Run a single tool with error handling and 5-min hard timeout."""
        try:
            print_info(f"  ▶ Running {name}...")
            result = await asyncio.wait_for(
                wrapper.run(self.target, **kwargs), timeout=300
            )
            print_success(f"  ✓ {name} — {len(result)} findings")
            return result
        except asyncio.TimeoutError:
            print_warning(f"  ⏱ {name} timed out after 5 min — skipping")
            return []
        except Exception as e:
            print_error(f"  ✗ {name} failed: {str(e)[:100]}")
            return []

    def _get_tool_instance(self, class_name: str) -> Any:
        """Dynamically import and instantiate a tool wrapper."""
        if class_name not in TOOL_MAP:
            return None
        module_path, cls_name = TOOL_MAP[class_name]
        try:
            import importlib
            module = importlib.import_module(module_path)
            cls = getattr(module, cls_name)
            return cls()
        except (ImportError, AttributeError) as e:
            print_warning(f"  Could not load {class_name}: {e}")
            return None

    def _prepare_stage_input(self, stage_name: str) -> dict[str, Any]:
        """Prepare kwargs for a stage based on previous stage output."""
        kwargs: dict[str, Any] = {}

        # Write subdomains to temp file for tools that need a file input
        subs = self.stage_data.get("subdomains", [])
        if subs:
            subs_file = Path(tempfile.gettempdir()) / f"lordshen_subs_{self.scan_id}.txt"
            subs_file.write_text("\n".join(subs))
            kwargs["subs_file"] = str(subs_file)

        live_hosts = self.stage_data.get("live_hosts", [])
        if live_hosts:
            targets_file = Path(tempfile.gettempdir()) / f"lordshen_targets_{self.scan_id}.txt"
            targets_file.write_text("\n".join(live_hosts))
            kwargs["targets_file"] = str(targets_file)

        ports = self.stage_data.get("open_ports", "")
        if ports:
            kwargs["ports"] = ports

        return kwargs

    def _collect_stage_data(self, stage_name: str, findings: list[ToolFinding]) -> None:
        """Extract data from findings for use by subsequent stages."""
        if stage_name == "passive_recon":
            subs = set(self.stage_data.get("subdomains", []))
            for f in findings:
                if f.extra.get("type") == "subdomain" and f.host:
                    subs.add(f.host)
            self.stage_data["subdomains"] = list(subs)

        elif stage_name == "active_recon":
            live = set()
            ports = set()
            for f in findings:
                if f.extra.get("type") == "live_host" and f.url:
                    live.add(f.url)
                if f.extra.get("type") == "open_port":
                    ports.add(str(f.extra.get("port", "")))
            self.stage_data["live_hosts"] = list(live)
            if ports:
                self.stage_data["open_ports"] = ",".join(ports)

    def _print_stage_results(self, stage: Stage, findings: list[ToolFinding]) -> None:
        """Print a Rich panel summarizing stage results."""
        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        lines = [f"[bold]Total findings: {len(findings)}[/bold]"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = get_severity_style(sev)
                lines.append(f"  [{style}]{sev.upper()}: {count}[/{style}]")

        panel = Panel("\n".join(lines), title=f"{stage.display_name} Results", border_style="cyan")
        console.print(panel)

    def _print_final_summary(self) -> None:
        """Print the final findings summary table."""
        console.print("\n[bold cyan]━━━ SCAN COMPLETE ━━━[/bold cyan]")
        console.print(f"Scan ID: [bold]{self.scan_id}[/bold]")
        console.print(f"Total findings: [bold]{len(self.all_findings)}[/bold]\n")

        # Only show non-info findings in the summary table
        notable = [f for f in self.all_findings if f.severity != "info"]

        if notable:
            table = create_findings_table()
            for f in sorted(notable, key=lambda x: ["critical", "high", "medium", "low"].index(x.severity) if x.severity in ["critical", "high", "medium", "low"] else 99):
                style = get_severity_style(f.severity)
                table.add_row(
                    f"[{style}]{f.severity.upper()}[/{style}]",
                    str(f.cvss_score) if f.cvss_score else "-",
                    f.title[:60],
                    f.host[:30] if f.host else "-",
                )
            console.print(table)
        else:
            print_info("No significant vulnerabilities found.")

        console.print(f"\n[dim]View details: lordshen history --scan-id {self.scan_id} --findings[/dim]")
        console.print(f"[dim]Export report: lordshen export --scan-id {self.scan_id} --format pdf[/dim]")
