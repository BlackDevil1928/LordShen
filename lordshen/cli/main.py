"""LordShen AI — main CLI entry point with all command groups."""

import asyncio
import click
from rich.panel import Panel

from lordshen import __version__
from lordshen.core.console import console


@click.group()
@click.version_option(__version__, prog_name="lordshen")
def cli() -> None:
    """LordShen AI — Professional CLI penetration testing tool.

    AI-powered pentesting with 35+ integrated tools, Groq LLM analysis,
    scope-aware scanning, and professional report generation.
    """
    pass


# ─────────────────────── scan ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name (from saved scopes)")
@click.option("--profile", "-p", type=click.Choice(["quick", "standard", "deep"]),
              default="standard", help="Scan profile")
@click.option("--no-active", is_flag=True, help="Only run passive recon (no active probing)")
@click.option("--scan-id", default=None, help="Custom scan ID")
def scan(target: str, scope: str, profile: str, no_active: bool, scan_id: str) -> None:
    """Run a full penetration test against TARGET.

    Examples:
        lordshen scan example.com --scope my_program
        lordshen scan example.com --scope h1_program --profile deep
        lordshen scan example.com --scope bugcrowd_pgm --no-active
    """
    from lordshen.scope.store import load_scope
    from lordshen.pipeline.orchestrator import ScanOrchestrator
    from lordshen.core.database import init_db

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red] "
                      f"Create one with: lordshen scope --create {scope}")
        raise SystemExit(1)

    init_db()
    orchestrator = ScanOrchestrator(
        target=target, scope=program_scope, profile=profile,
        no_active=no_active, scan_id=scan_id,
    )
    try:
        asyncio.run(orchestrator.run())
    except Exception as e:
        err_name = type(e).__name__
        if "ScopeError" in err_name:
            console.print(f"\n[bold yellow]💡 Fix:[/bold yellow] Add the target to your scope:")
            console.print(f"  lordshen scope create {scope} -d '*.{target}' -d '{target}'")
            console.print(f"  [dim]Or re-create with: lordshen scope create {scope} -d '*.{target}'[/dim]")
        else:
            console.print(f"[bold red]Scan error:[/bold red] {e}")
        raise SystemExit(1)


# ─────────────────────── agent ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
@click.option("--max-turns", "-t", default=20, help="Max AI decision turns")
def agent(target: str, scope: str, max_turns: int) -> None:
    """Run autonomous AI agent mode on TARGET.

    The AI decides what tools to run and in what order.

    Examples:
        lordshen agent example.com --scope my_program
        lordshen agent example.com --scope h1 --max-turns 50
    """
    from lordshen.scope.store import load_scope
    from lordshen.pipeline.agent_loop import AgentLoop

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    loop = AgentLoop(target=target, scope=program_scope, max_turns=max_turns)
    asyncio.run(loop.run())


# ─────────────────────── scope ───────────────────────

@cli.group()
def scope() -> None:
    """Manage program scopes."""
    pass


@scope.command("create")
@click.argument("name")
@click.option("--domains", "-d", multiple=True, help="In-scope domains (repeat for multiple)")
@click.option("--oos", multiple=True, help="Out-of-scope domains")
@click.option("--ips", multiple=True, help="In-scope IP/CIDR ranges")
@click.option("--platform", type=click.Choice(["hackerone", "bugcrowd", "intigriti", "custom"]),
              default="custom")
@click.option("--program-url", default="", help="Program page URL")
@click.option("--from-file", type=click.Path(exists=True), default=None,
              help="Import scope from JSON file")
def scope_create(name: str, domains: tuple, oos: tuple, ips: tuple,
                 platform: str, program_url: str, from_file: str) -> None:
    """Create a new program scope.

    Examples:
        lordshen scope create h1_program -d '*.example.com' -d api.example.com
        lordshen scope create my_pgm --from-file scope.json
    """
    from lordshen.scope.models import ProgramScope
    from lordshen.scope.store import save_scope, load_scope_from_file
    from pathlib import Path

    if from_file:
        program_scope = load_scope_from_file(Path(from_file))
        program_scope.program_name = name
    else:
        program_scope = ProgramScope(
            program_name=name,
            platform=platform,
            program_url=program_url,
            in_scope_domains=list(domains),
            in_scope_ips=list(ips),
            oos_domains=list(oos),
        )

    path = save_scope(program_scope, name)
    console.print(f"[bold green]✓ Scope '{name}' saved to {path}[/bold green]")
    console.print(program_scope.summary())


@scope.command("list")
def scope_list() -> None:
    """List all saved scopes."""
    from lordshen.scope.store import list_scopes
    from rich.table import Table

    scopes = list_scopes()
    if not scopes:
        console.print("[dim]No scopes saved. Create one with: lordshen scope create[/dim]")
        return

    table = Table(title="Saved Scopes")
    table.add_column("Name", style="cyan bold")
    table.add_column("Platform")
    table.add_column("Domains")
    table.add_column("IPs")
    table.add_column("Created")

    for s in scopes:
        table.add_row(
            s["name"], s.get("platform", ""), str(s.get("domains_count", 0)),
            str(s.get("ips_count", 0)), s.get("created", "")[:10],
        )
    console.print(table)


@scope.command("show")
@click.argument("name")
def scope_show(name: str) -> None:
    """Show details of a saved scope."""
    from lordshen.scope.store import load_scope
    import json

    try:
        s = load_scope(name)
        console.print_json(json.dumps(s.to_dict(), indent=2))
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{name}' not found.[/bold red]")


@scope.command("delete")
@click.argument("name")
def scope_delete(name: str) -> None:
    """Delete a saved scope."""
    from lordshen.scope.store import delete_scope

    if delete_scope(name):
        console.print(f"[bold green]✓ Scope '{name}' deleted.[/bold green]")
    else:
        console.print(f"[bold red]Scope '{name}' not found.[/bold red]")


@scope.command("parse")
@click.argument("url")
@click.option("--name", "-n", required=True, help="Save scope with this name")
def scope_parse(url: str, name: str) -> None:
    """Parse a HackerOne/Bugcrowd program page into a scope using AI.

    Examples:
        lordshen scope parse https://hackerone.com/company --name h1_company
    """
    from lordshen.llm.router import LLMRouter
    from lordshen.llm.prompts import SCOPE_PARSER
    from lordshen.scope.models import ProgramScope
    from lordshen.scope.store import save_scope
    import json
    import httpx

    console.print(f"[cyan]Fetching program page: {url}...[/cyan]")

    async def _parse() -> None:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url)
            page_text = resp.text[:8000]

        router = LLMRouter()
        result = await router.complete(
            system=SCOPE_PARSER, user=page_text,
            task="recon_analysis", json_mode=True,
        )

        try:
            data = json.loads(result)
            s = ProgramScope(**data)
            path = save_scope(s, name)
            console.print(f"[bold green]✓ Scope '{name}' parsed and saved to {path}[/bold green]")
            console.print(s.summary())
        except Exception as e:
            console.print(f"[bold red]Failed to parse scope: {e}[/bold red]")
            console.print(result[:500])

    asyncio.run(_parse())


# ─────────────────────── recon ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
@click.option("--tool", "-t", multiple=True,
              help="Specific tools (subfinder, amass, crtsh, gau, theharvester)")
def recon(target: str, scope: str, tool: tuple) -> None:
    """Run passive recon only.

    Examples:
        lordshen recon example.com --scope my_pgm
        lordshen recon example.com --scope my_pgm -t subfinder -t crtsh
    """
    from lordshen.scope.store import load_scope
    from lordshen.pipeline.orchestrator import ScanOrchestrator

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    orchestrator = ScanOrchestrator(
        target=target, scope=program_scope, profile="quick", no_active=True,
    )
    asyncio.run(orchestrator.run())


# ─────────────────────── vuln ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
@click.option("--nuclei-severity", default="critical,high,medium",
              help="Nuclei severity filter")
def vuln(target: str, scope: str, nuclei_severity: str) -> None:
    """Run vulnerability scanning on TARGET.

    Examples:
        lordshen vuln https://example.com --scope my_pgm
        lordshen vuln https://example.com --scope my_pgm --nuclei-severity critical,high
    """
    from lordshen.scope.store import load_scope
    from lordshen.scope.guard import check_scope_or_abort
    from lordshen.tools.vuln.nuclei import NucleiWrapper
    from lordshen.tools.vuln.nikto import NiktoWrapper
    from lordshen.tools.vuln.testssl import TestsslWrapper
    from lordshen.core.console import print_info, get_severity_style

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    check_scope_or_abort(target, program_scope)

    async def _run() -> None:
        all_findings = []
        for WrapperCls in [NucleiWrapper, NiktoWrapper, TestsslWrapper]:
            wrapper = WrapperCls()
            if not wrapper.is_installed():
                print_info(f"  ⊘ {wrapper.name} not installed — skipping")
                continue
            print_info(f"  ▶ Running {wrapper.name}...")
            kwargs = {}
            if wrapper.name == "nuclei":
                kwargs["severity"] = nuclei_severity
            findings = await wrapper.run(target, **kwargs)
            all_findings.extend(findings)
            console.print(f"  [green]✓ {wrapper.name}: {len(findings)} findings[/green]")

        console.print(f"\n[bold]Total: {len(all_findings)} findings[/bold]")
        for f in all_findings:
            if f.severity != "info":
                style = get_severity_style(f.severity)
                console.print(f"  [{style}][{f.severity.upper()}][/{style}] {f.title[:80]}")

    asyncio.run(_run())


# ─────────────────────── webapp ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
def webapp(target: str, scope: str) -> None:
    """Run web application tests on TARGET.

    Runs: ffuf, feroxbuster, dalfox, sqlmap, wapiti, arjun, cors_scanner.
    """
    from lordshen.scope.store import load_scope
    from lordshen.scope.guard import check_scope_or_abort
    from lordshen.core.console import print_info, get_severity_style

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    check_scope_or_abort(target, program_scope)

    from lordshen.tools.webapp.ffuf import FfufWrapper
    from lordshen.tools.webapp.dalfox import DalfoxWrapper
    from lordshen.tools.webapp.sqlmap import SqlmapWrapper
    from lordshen.tools.webapp.arjun import ArjunWrapper
    from lordshen.tools.webapp.cors_scanner import CorsScannerWrapper

    async def _run() -> None:
        all_findings = []
        for WrapperCls in [FfufWrapper, DalfoxWrapper, ArjunWrapper, CorsScannerWrapper]:
            wrapper = WrapperCls()
            if not wrapper.is_installed():
                print_info(f"  ⊘ {wrapper.name} not installed — skipping")
                continue
            print_info(f"  ▶ Running {wrapper.name}...")
            findings = await wrapper.run(target)
            all_findings.extend(findings)
            console.print(f"  [green]✓ {wrapper.name}: {len(findings)} findings[/green]")

        console.print(f"\n[bold]Total: {len(all_findings)} findings[/bold]")
        for f in all_findings:
            if f.severity != "info":
                style = get_severity_style(f.severity)
                console.print(f"  [{style}][{f.severity.upper()}][/{style}] {f.title[:80]}")

    asyncio.run(_run())


# ─────────────────────── network ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
def network(target: str, scope: str) -> None:
    """Run network tests on TARGET (nmap, masscan, netexec)."""
    from lordshen.scope.store import load_scope
    from lordshen.scope.guard import check_scope_or_abort
    from lordshen.core.console import print_info, get_severity_style
    from lordshen.tools.active.nmap_tool import NmapWrapper
    from lordshen.tools.active.masscan import MasscanWrapper

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    check_scope_or_abort(target, program_scope)

    async def _run() -> None:
        all_findings = []
        for WrapperCls in [NmapWrapper, MasscanWrapper]:
            wrapper = WrapperCls()
            if not wrapper.is_installed():
                print_info(f"  ⊘ {wrapper.name} not installed — skipping")
                continue
            print_info(f"  ▶ Running {wrapper.name}...")
            findings = await wrapper.run(target)
            all_findings.extend(findings)
            console.print(f"  [green]✓ {wrapper.name}: {len(findings)} findings[/green]")

        console.print(f"\n[bold]Total: {len(all_findings)} findings[/bold]")

    asyncio.run(_run())


# ─────────────────────── dorking ───────────────────────

@cli.command()
@click.argument("target")
@click.option("--scope", "-s", required=True, help="Scope name")
@click.option("--category", "-c", default="all", help="Dork category")
@click.option("--limit", "-l", default=10, help="Max results per dork")
def dorking(target: str, scope: str, category: str, limit: int) -> None:
    """Run Google dorking against TARGET.

    Categories: credentials, admin_panels, sensitive_files, config_files,
    error_messages, api_endpoints, cloud_storage, all
    """
    from lordshen.scope.store import load_scope
    from lordshen.scope.guard import check_scope_or_abort
    from lordshen.tools.osint.dorking import DorkingEngine

    try:
        program_scope = load_scope(scope)
    except FileNotFoundError:
        console.print(f"[bold red]Scope '{scope}' not found.[/bold red]")
        raise SystemExit(1)

    check_scope_or_abort(target, program_scope)

    async def _run() -> None:
        engine = DorkingEngine()
        console.print(f"[cyan]Running dorks ({category})...[/cyan]")
        findings = await engine.run(target, category=category, limit=limit)
        console.print(f"\n[bold]Found {len(findings)} results[/bold]")
        for f in findings:
            console.print(f"  [{f.severity.upper()}] {f.title}")

    asyncio.run(_run())


# ─────────────────────── export ───────────────────────

@cli.command()
@click.option("--scan-id", required=True, help="Scan ID to export")
@click.option("--format", "-f", "fmt", type=click.Choice(["pdf", "md", "sarif", "json"]),
              default="md", help="Report format")
@click.option("--output", "-o", default=None, help="Output file path")
def export(scan_id: str, fmt: str, output: str) -> None:
    """Export scan results as a report.

    Examples:
        lordshen export --scan-id abc123 --format pdf
        lordshen export --scan-id abc123 --format sarif -o results.sarif
    """
    from lordshen.core.database import get_session, get_scan, get_findings
    from lordshen.core.config import CONFIG_DIR
    from pathlib import Path
    import json

    with get_session() as session:
        scan_obj = get_scan(session, scan_id)
        if not scan_obj:
            console.print(f"[bold red]Scan '{scan_id}' not found.[/bold red]")
            raise SystemExit(1)

        findings_objs = get_findings(session, scan_id)
        scan_data = {
            "id": scan_obj.id,
            "target": scan_obj.target,
            "profile": scan_obj.profile,
            "scope_name": scan_obj.scope_name,
        }
        findings_data = []
        for f in findings_objs:
            findings_data.append({
                "title": f.title, "severity": f.severity,
                "cvss_score": f.cvss_score, "host": f.host,
                "url": f.url, "tool_name": f.tool_name,
                "evidence": f.evidence, "description": f.description,
            })

    reports_dir = CONFIG_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not output:
        output = str(reports_dir / f"report_{scan_id}.{fmt}")

    if fmt == "pdf":
        from lordshen.report.pdf_builder import PDFReportBuilder
        PDFReportBuilder().build(scan_data, findings_data, output)
    elif fmt == "md":
        from lordshen.report.md_builder import MarkdownReportBuilder
        MarkdownReportBuilder().build(scan_data, findings_data, output)
    elif fmt == "sarif":
        from lordshen.report.sarif_builder import SarifBuilder
        SarifBuilder().build(scan_data, findings_data, output)
    elif fmt == "json":
        Path(output).write_text(json.dumps({"scan": scan_data, "findings": findings_data}, indent=2))

    console.print(f"[bold green]✓ Report saved to {output}[/bold green]")


# ─────────────────────── report ───────────────────────

@cli.command()
@click.option("--scan-id", required=True, help="Scan ID")
@click.option("--finding-index", "-i", default=0, type=int,
              help="Finding index to generate report for (0-based)")
@click.option("--scope", "-s", default=None, help="Scope name for context")
def report(scan_id: str, finding_index: int, scope: str) -> None:
    """Generate an AI-written bug bounty report for a specific finding.

    Examples:
        lordshen report --scan-id abc123 --finding-index 0
    """
    from lordshen.core.database import get_session, get_findings
    from lordshen.report.groq_writer import GroqReportWriter
    from lordshen.report.md_builder import MarkdownReportBuilder
    from lordshen.scope.store import load_scope
    from lordshen.scope.models import ProgramScope

    with get_session() as session:
        findings = get_findings(session, scan_id)
        if not findings or finding_index >= len(findings):
            console.print("[bold red]Finding not found.[/bold red]")
            raise SystemExit(1)

        f = findings[finding_index]
        finding_data = {
            "title": f.title, "severity": f.severity,
            "cvss_score": f.cvss_score, "host": f.host,
            "url": f.url, "tool_name": f.tool_name,
            "evidence": f.evidence, "description": f.description,
            "extra": {},
        }

    program_scope = ProgramScope()
    if scope:
        try:
            program_scope = load_scope(scope)
        except FileNotFoundError:
            pass

    async def _gen() -> None:
        writer = GroqReportWriter()
        console.print("[cyan]Generating AI report...[/cyan]")
        sections = await writer.generate_full_report(finding_data, program_scope)
        md = MarkdownReportBuilder().build_single_finding(finding_data, sections)
        console.print(Panel(md, title="Generated Report", border_style="green"))

    asyncio.run(_gen())


# ─────────────────────── config ───────────────────────

@cli.command()
@click.option("--set", "set_val", nargs=2, type=str, default=None,
              help="Set a config value: --set key value")
@click.option("--get", "get_val", type=str, default=None,
              help="Get a config value")
@click.option("--groq-key", default=None, help="Set Groq API key")
@click.option("--show", is_flag=True, help="Show all config")
def config(set_val: tuple, get_val: str, groq_key: str, show: bool) -> None:
    """Manage LordShen configuration.

    Examples:
        lordshen config --groq-key gsk_abc123
        lordshen config --set ollama-host http://localhost:11434
        lordshen config --show
    """
    from lordshen.core.config import (
        get_config_value, set_config_value, load_config,
        get_groq_api_key, set_groq_api_key,
    )
    import json

    if groq_key:
        set_groq_api_key(groq_key)
        console.print("[bold green]✓ Groq API key saved securely[/bold green]")
        return

    if set_val:
        key, value = set_val
        set_config_value(key, value)
        console.print(f"[bold green]✓ {key} = {value}[/bold green]")
        return

    if get_val:
        val = get_config_value(get_val)
        console.print(f"{get_val} = {val}")
        return

    if show:
        cfg = load_config()
        groq = get_groq_api_key()
        cfg["groq-key"] = f"{'*' * 8}...{groq[-4:]}" if groq and len(groq) > 4 else "(not set)"
        console.print_json(json.dumps(cfg, indent=2))
        return

    console.print("[dim]Use --help to see options.[/dim]")


# ─────────────────────── history ───────────────────────

@cli.command()
@click.option("--scan-id", default=None, help="Show specific scan")
@click.option("--findings", is_flag=True, help="Show findings for a scan")
@click.option("--severity", default=None, help="Filter by severity")
@click.option("--limit", "-l", default=20, help="Max results")
def history(scan_id: str, findings: bool, severity: str, limit: int) -> None:
    """View scan history and findings.

    Examples:
        lordshen history
        lordshen history --scan-id abc123 --findings
        lordshen history --scan-id abc123 --findings --severity critical
    """
    from lordshen.core.database import get_session, get_scan, get_findings, init_db
    from lordshen.core.console import get_severity_style
    from rich.table import Table

    init_db()

    with get_session() as session:
        if scan_id and findings:
            findings_list = get_findings(session, scan_id, severity)
            if not findings_list:
                console.print("[dim]No findings found.[/dim]")
                return

            table = Table(title=f"Findings for scan {scan_id}")
            table.add_column("#", width=4)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", width=6)
            table.add_column("Title", width=50)
            table.add_column("Host", width=25)
            table.add_column("Tool", width=12)

            for idx, f in enumerate(findings_list[:limit]):
                style = get_severity_style(f.severity)
                table.add_row(
                    str(idx), f"[{style}]{f.severity.upper()}[/{style}]",
                    str(f.cvss_score or "-"), f.title[:50],
                    (f.host or "-")[:25], f.tool_name[:12],
                )
            console.print(table)

        elif scan_id:
            s = get_scan(session, scan_id)
            if s:
                console.print(Panel(
                    f"Target: {s.target}\nProfile: {s.profile}\n"
                    f"Scope: {s.scope_name}\nStatus: {s.status}\n"
                    f"Findings: {s.findings_count}\n"
                    f"Started: {s.started_at}\nFinished: {s.finished_at}",
                    title=f"Scan {s.id}",
                ))
            else:
                console.print(f"[bold red]Scan '{scan_id}' not found.[/bold red]")

        else:
            # List all scans
            from sqlalchemy import select
            from lordshen.core.database import Scan

            stmt = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
            scans = session.execute(stmt).scalars().all()

            if not scans:
                console.print("[dim]No scans yet. Run: lordshen scan[/dim]")
                return

            table = Table(title="Scan History")
            table.add_column("ID", style="cyan")
            table.add_column("Target")
            table.add_column("Profile")
            table.add_column("Status")
            table.add_column("Findings")
            table.add_column("Date")

            for s in scans:
                table.add_row(
                    s.id[:12], s.target, s.profile, s.status,
                    str(s.findings_count or 0), str(s.started_at)[:10],
                )
            console.print(table)


# ─────────────────────── tools ───────────────────────

@cli.command()
@click.option("--check", is_flag=True, help="Check which tools are installed")
@click.option("--install", is_flag=True, help="Install missing tools")
def tools(check: bool, install: bool) -> None:
    """Check and install security tools.

    Examples:
        lordshen tools --check
        lordshen tools --install
    """
    from lordshen.tools.installer import TOOL_REGISTRY, is_tool_installed
    from rich.table import Table

    if check or not install:
        table = Table(title="Tool Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Category")
        table.add_column("Status")
        table.add_column("Install Method")

        installed = 0
        for name, info in sorted(TOOL_REGISTRY.items()):
            if is_tool_installed(name):
                status = "[green]✓ Installed[/green]"
                installed += 1
            else:
                status = "[red]✗ Missing[/red]"
            table.add_row(name, info.get("category", ""), status,
                          info.get("install", ""))

        console.print(table)
        console.print(f"\n{installed}/{len(TOOL_REGISTRY)} tools installed")

    if install:
        console.print("[cyan]Run install.sh to install all tools:[/cyan]")
        console.print("  sudo bash install.sh")


# ─────────────────────── status ───────────────────────

@cli.command()
def status() -> None:
    """Show system status — tools, AI, database."""
    from lordshen.llm.router import LLMRouter
    from lordshen.core.config import get_groq_api_key

    async def _status() -> None:
        router = LLMRouter()
        ai_status = await router.get_status()

        console.print(Panel.fit(
            f"[bold cyan]LordShen AI v{__version__}[/bold cyan]\n\n"
            f"[bold]Groq API:[/bold]    {'✓ Key set' if ai_status['groq_key_set'] else '✗ No key'}\n"
            f"[bold]Ollama:[/bold]      {'✓ Running' if ai_status['ollama_available'] else '✗ Not running'}\n"
            f"[bold]Ollama host:[/bold] {ai_status['ollama_host']}\n"
            f"[bold]Tokens today:[/bold] "
            f"{ai_status['groq_usage_today'].get('prompt_tokens', 0):,} prompt + "
            f"{ai_status['groq_usage_today'].get('completion_tokens', 0):,} completion\n"
            f"[bold]API calls:[/bold]   {ai_status['groq_usage_today'].get('calls', 0)}",
            title="System Status", border_style="blue",
        ))

    asyncio.run(_status())


if __name__ == "__main__":
    cli()
