"""Typer CLI — command-line interface for Driln.

Usage::

    driln scan example.com --type full
    driln tools list
    driln tools check
    driln report <scan_id> --format markdown
    driln intel summary <scan_id>
    driln intel recommendations <scan_id>
    driln intel tech <scan_id>
    driln serve --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

from driln import __version__

app = typer.Typer(
    name="driln",
    help="🔱 Driln — Intelligent automated pentesting engine",
    no_args_is_help=True,
)

console = Console()

# ── UI helpers ───────────────────────────────────────────────────

_BRAND = "[bold magenta]🔱 Driln[/bold magenta]"
_SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
    "informational": "dim",
    "clean": "bold green",
}


def _risk_bar(score: float, width: int = 20) -> Text:
    """Render a colored progress bar for risk score 0-100."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 80:
        color = "bold red"
    elif score >= 60:
        color = "red"
    elif score >= 40:
        color = "yellow"
    elif score >= 20:
        color = "green"
    else:
        color = "bold green"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    bar.append(f" {score:.0f}/100", style=color)
    return bar


def _sev_badge(sev: str) -> str:
    """Return a colored severity badge."""
    color = _SEV_COLORS.get(sev.lower(), "white")
    return f"[{color}] {sev.upper()} [/{color}]"


def _header(title: str, subtitle: str = "") -> Panel:
    """Render a branded header panel."""
    content = f"{_BRAND}  [bold]{title}[/bold]"
    if subtitle:
        content += f"\n[dim]{subtitle}[/dim]"
    return Panel(content, box=box.HEAVY, style="magenta", expand=False)


# ── Sub-commands ─────────────────────────────────────────────────

tools_app = typer.Typer(help="🛠  Manage pentesting tools")
app.add_typer(tools_app, name="tools")


# ── Serve ────────────────────────────────────────────────────────


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
):
    """Start the Driln API server."""
    import uvicorn

    console.print(_header("API Server", f"{host}:{port}"))
    console.print(f"  [dim]Swagger UI →[/dim] [cyan]http://{host}:{port}/docs[/cyan]")
    console.print(f"  [dim]Health     →[/dim] [cyan]http://{host}:{port}/health[/cyan]\n")
    uvicorn.run(
        "driln.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ── Scan ─────────────────────────────────────────────────────────


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host or domain"),
    scan_type: str = typer.Option("full", "--type", "-t", help="Scan type: recon, vuln, full"),
    tools: Optional[str] = typer.Option(None, "--tools", help="Comma-separated tool list override"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis"),
):
    """Run a penetration test scan against a target."""
    asyncio.run(_run_scan(target, scan_type, tools, no_ai))


async def _run_scan(target: str, scan_type: str, tools: str | None, no_ai: bool):
    from driln.core.logging import setup_logging
    from driln.db.engine import close_db, init_db
    from driln.engine.scanner import ScanEngine
    from driln.reports.generator import ReportGenerator
    from driln.tools.registry import init_registry

    setup_logging()
    await init_db()
    init_registry()

    tool_list = [t.strip() for t in tools.split(",")] if tools else None

    # Header
    console.print()
    console.print(_header("Scan", target))

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="dim")
    info_table.add_column(style="cyan")
    info_table.add_row("Target", target)
    info_table.add_row("Type", scan_type)
    if tool_list:
        info_table.add_row("Tools", ", ".join(tool_list))
    info_table.add_row("AI", "[red]Disabled[/red]" if no_ai else "[green]Enabled[/green]")
    console.print(info_table)
    console.print()

    engine = ScanEngine()
    scan_id = await engine.create_scan(
        target=target,
        scan_type=scan_type,
        tools=tool_list,
    )
    console.print(f"  [dim]Scan ID:[/dim] [yellow]{scan_id}[/yellow]\n")

    # Run scan with progress
    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running scan pipeline...", total=None)
        await engine.run_scan(scan_id)
        progress.update(task, description="[green]Scan complete[/green]")

    # Generate report
    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        generator = ReportGenerator()
        result = await generator.generate(
            scan_id=scan_id,
            format="markdown",
            include_ai_summary=not no_ai,
        )
        progress.update(task, description="[green]Report ready[/green]")

    # Summary panel
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column()
    summary.add_row("Status", "[bold green]✓ Complete[/bold green]")
    summary.add_row("Report", f"[cyan]{result['filepath']}[/cyan]")
    summary.add_row("Scan ID", f"[yellow]{scan_id}[/yellow]")

    console.print(Panel(
        summary,
        title="[bold green]Scan Finished[/bold green]",
        border_style="green",
        box=box.ROUNDED,
        expand=False,
    ))
    console.print()
    console.print(f"  [dim]Next steps:[/dim]")
    console.print(f"    driln intel summary {scan_id}")
    console.print(f"    driln intel recommendations {scan_id}")
    console.print(f"    driln report {scan_id} --format html\n")

    await close_db()


# ── Tools ────────────────────────────────────────────────────────


@tools_app.command("list")
def tools_list():
    """List all registered tools and their status."""
    asyncio.run(_tools_list())


async def _tools_list():
    from driln.core.logging import setup_logging
    from driln.tools.registry import init_registry

    setup_logging()
    registry = init_registry()
    results = await registry.check_all()

    console.print()
    console.print(_header("Tools"))

    table = Table(box=box.ROUNDED, show_lines=False, padding=(0, 1))
    table.add_column("Tool", style="bold cyan", min_width=12)
    table.add_column("Binary", style="dim")
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Path", style="dim", max_width=50)

    installed_count = 0
    for info in results.values():
        if info["installed"]:
            status = "[bold green]● Installed[/bold green]"
            installed_count += 1
        else:
            status = "[bold red]○ Missing[/bold red]"
        table.add_row(
            info["name"],
            info["binary"],
            status,
            info.get("path") or "—",
        )

    console.print(table)
    total = len(results)
    color = "green" if installed_count == total else "yellow" if installed_count > 0 else "red"
    console.print(f"\n  [{color}]{installed_count}/{total} tools ready[/{color}]\n")


@tools_app.command("check")
def tools_check():
    """Check all tool installations and show details."""
    asyncio.run(_tools_check())


async def _tools_check():
    from driln.core.logging import setup_logging
    from driln.tools.registry import init_registry

    setup_logging()
    registry = init_registry()
    results = await registry.check_all()

    console.print()
    all_ok = True
    for info in results.values():
        if info["installed"]:
            console.print(f"  [bold green]✓[/bold green] [cyan]{info['name']}[/cyan] — {info['path']}")
        else:
            console.print(f"  [bold red]✗[/bold red] [cyan]{info['name']}[/cyan] — not found in PATH")
            all_ok = False

    if all_ok:
        console.print(f"\n  [bold green]All tools installed![/bold green]\n")
    else:
        console.print(f"\n  [yellow]Some tools missing. Install with:[/yellow]")
        console.print(f"    [dim]brew install nmap subfinder[/dim]")
        console.print(f"    [dim]go install github.com/projectdiscovery/httpx/cmd/httpx@latest[/dim]")
        console.print(f"    [dim]go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]\n")


# ── Report ───────────────────────────────────────────────────────


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format: markdown, html"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI summary"),
):
    """Generate a report for a completed scan."""
    asyncio.run(_generate_report(scan_id, format, no_ai))


async def _generate_report(scan_id: str, format: str, no_ai: bool):
    from driln.core.logging import setup_logging
    from driln.db.engine import close_db, init_db
    from driln.reports.generator import ReportGenerator

    setup_logging()
    await init_db()

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        generator = ReportGenerator()
        result = await generator.generate(
            scan_id=scan_id,
            format=format,
            include_ai_summary=not no_ai,
        )
        progress.update(task, description="[green]Done[/green]")

    console.print()
    console.print(Panel(
        f"[dim]Format:[/dim] [cyan]{format}[/cyan]\n"
        f"[dim]File:  [/dim] [cyan]{result['filepath']}[/cyan]",
        title="[bold green]Report Generated[/bold green]",
        border_style="green",
        box=box.ROUNDED,
        expand=False,
    ))
    console.print()

    await close_db()


# ── Intelligence commands ─────────────────────────────────────────

intel_app = typer.Typer(help="🧠 Scan intelligence and recommendations")
app.add_typer(intel_app, name="intel")


@intel_app.command("summary")
def intel_summary(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
):
    """Show the full intelligence report for a scan."""
    async def _run() -> None:
        from driln.core.logging import setup_logging
        from driln.db.engine import init_db
        from driln.db.repos import FindingRepository, ScanRepository
        from driln.db.engine import _get_session_factory
        from driln.intelligence.context import ScanContext
        from driln.intelligence.service import IntelligenceService

        setup_logging()
        await init_db()

        factory = _get_session_factory()
        async with factory() as session:
            scan_repo = ScanRepository(session)
            finding_repo = FindingRepository(session)

            scan = await scan_repo.get(scan_id)
            if scan is None:
                console.print(f"\n  [bold red]✗[/bold red] Scan [yellow]{scan_id}[/yellow] not found\n")
                raise typer.Exit(1)

            # Build context
            context = ScanContext(
                scan_id=scan_id,
                target=scan.target,
                scan_type=scan.scan_type,
            )
            findings = await finding_repo.list_by_scan(scan_id)
            for f in findings:
                context.findings.append({
                    "id": f.id,
                    "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                    "title": f.title,
                    "description": f.description or "",
                    "host": f.host or "",
                    "port": f.port,
                    "service": f.service or "",
                })

            service = IntelligenceService()
            intel = await service.analyze(context)

            # Header
            console.print()
            console.print(_header("Intelligence Report", scan.target))

            # Risk score panel
            risk = intel.risk_summary
            risk_bar = _risk_bar(risk.score)
            risk_label = _sev_badge(risk.label)

            risk_table = Table(show_header=False, box=None, padding=(0, 2))
            risk_table.add_column(style="dim", width=16)
            risk_table.add_column()
            risk_table.add_row("Risk Score", risk_bar)
            risk_table.add_row("Rating", risk_label)
            risk_table.add_row("Severity", f"[dim]{risk.base_severity:.2f}[/dim]")
            risk_table.add_row("Exploitability", f"[dim]{risk.exploitability:.2f}[/dim]")
            risk_table.add_row("Exposure", f"[dim]{risk.exposure:.2f}[/dim]")
            risk_table.add_row("Context", f"[dim]{risk.context_boost:.2f}[/dim]")

            console.print(Panel(
                risk_table,
                title="[bold]Risk Assessment[/bold]",
                border_style=_SEV_COLORS.get(risk.label, "white").replace("bold ", ""),
                box=box.ROUNDED,
                expand=False,
            ))

            # Findings summary
            if context.findings:
                sev_counts: dict[str, int] = {}
                for f_item in context.findings:
                    s = f_item.get("severity", "info")
                    sev_counts[s] = sev_counts.get(s, 0) + 1

                findings_line = "  ".join(
                    f"{_sev_badge(s)} {c}" for s, c in
                    sorted(sev_counts.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]) if x[0] in ["critical", "high", "medium", "low", "info"] else 99)
                )
                console.print(f"\n  [bold]Findings ({len(context.findings)}):[/bold]  {findings_line}")

            # Tech profile
            if intel.tech_profile.technologies:
                tech_table = Table(box=box.SIMPLE, show_lines=False, padding=(0, 1))
                tech_table.add_column("Technology", style="bold cyan")
                tech_table.add_column("Version", style="dim")
                tech_table.add_column("Category")
                tech_table.add_column("Sources", style="dim")
                for t in intel.tech_profile.technologies:
                    tech_table.add_row(
                        t.name,
                        t.version or "—",
                        t.category,
                        ", ".join(t.sources),
                    )
                console.print(Panel(
                    tech_table,
                    title=f"[bold]Technologies ({len(intel.tech_profile.technologies)})[/bold]",
                    border_style="cyan",
                    box=box.ROUNDED,
                ))

            # Correlations
            if intel.correlation_groups:
                console.print(f"\n  [bold]Correlation Groups ({len(intel.correlation_groups)}):[/bold]")
                for g in intel.correlation_groups:
                    rel_color = {"same_service": "cyan", "attack_chain": "red", "tech_overlap": "yellow"}.get(g.relationship, "white")
                    console.print(f"    [{rel_color}]●[/{rel_color}] [{rel_color}]{g.relationship}[/{rel_color}]  {g.summary}  [dim]({len(g.finding_ids)} findings)[/dim]")

            # Recommendations
            if intel.recommendations:
                rec_table = Table(box=box.ROUNDED, show_lines=True, padding=(0, 1))
                rec_table.add_column("#", style="dim", width=3)
                rec_table.add_column("Pri", width=10)
                rec_table.add_column("Action", min_width=30)
                rec_table.add_column("Tool", width=12, style="cyan")

                for idx, r in enumerate(intel.recommendations, 1):
                    pri_color = _SEV_COLORS.get(r.priority, "white")
                    rec_table.add_row(
                        str(idx),
                        f"[{pri_color}]{r.priority.upper()}[/{pri_color}]",
                        f"{r.title}\n[dim]{r.rationale}[/dim]",
                        r.tool_name or "—",
                    )
                console.print(Panel(
                    rec_table,
                    title=f"[bold]Recommendations ({len(intel.recommendations)})[/bold]",
                    border_style="yellow",
                    box=box.ROUNDED,
                ))

            # Footer stats
            console.print(f"\n  [dim]Deduplicated: {intel.deduplicated_count}  |  Enriched: {intel.enriched_count}  |  Scan: {scan_id[:8]}…[/dim]\n")

    asyncio.run(_run())


@intel_app.command("recommendations")
def intel_recommendations(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
):
    """List recommendations for a scan."""
    async def _run() -> None:
        from driln.core.logging import setup_logging
        from driln.db.engine import init_db, _get_session_factory
        from driln.db.repos import RecommendationRepository

        setup_logging()
        await init_db()

        factory = _get_session_factory()
        async with factory() as session:
            repo = RecommendationRepository(session)
            recs = await repo.list_by_scan(scan_id)

            if not recs:
                console.print(f"\n  [dim]No recommendations found for scan {scan_id[:8]}…[/dim]\n")
                return

            console.print()
            console.print(_header("Recommendations", f"Scan {scan_id[:8]}…"))

            table = Table(box=box.ROUNDED, show_lines=True, padding=(0, 1))
            table.add_column("#", style="dim", width=3)
            table.add_column("Priority", width=10)
            table.add_column("Action", min_width=35)
            table.add_column("Tool", width=14, style="cyan")
            table.add_column("Source", width=10, style="dim")
            table.add_column("Status", width=12)

            for idx, r in enumerate(recs, 1):
                pri_color = _SEV_COLORS.get(r.priority, "white")
                status = (
                    "[bold green]✓ Accepted[/bold green]" if r.accepted is True
                    else "[bold red]✗ Dismissed[/bold red]" if r.accepted is False
                    else "[dim]⏳ Pending[/dim]"
                )
                table.add_row(
                    str(idx),
                    f"[{pri_color}]{r.priority.upper()}[/{pri_color}]",
                    f"{r.title}\n[dim]{r.rationale}[/dim]",
                    r.tool_name or "—",
                    r.source,
                    status,
                )

            console.print(table)
            console.print()

    asyncio.run(_run())


@intel_app.command("tech")
def intel_tech(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
):
    """Show the detected technology profile for a scan."""
    async def _run() -> None:
        from driln.core.logging import setup_logging
        from driln.db.engine import init_db, _get_session_factory
        from driln.db.repos import FindingRepository, ScanRepository
        from driln.intelligence.context import ScanContext
        from driln.intelligence.tech import TechAggregator

        setup_logging()
        await init_db()

        factory = _get_session_factory()
        async with factory() as session:
            scan_repo = ScanRepository(session)
            finding_repo = FindingRepository(session)

            scan = await scan_repo.get(scan_id)
            if scan is None:
                console.print(f"\n  [bold red]✗[/bold red] Scan [yellow]{scan_id}[/yellow] not found\n")
                raise typer.Exit(1)

            context = ScanContext(
                scan_id=scan_id,
                target=scan.target,
                scan_type=scan.scan_type,
            )
            findings = await finding_repo.list_by_scan(scan_id)
            for f in findings:
                context.findings.append({
                    "id": f.id,
                    "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                    "title": f.title,
                    "host": f.host or "",
                    "service": f.service or "",
                })

            aggregator = TechAggregator()
            profile = aggregator.aggregate(context)

            console.print()
            console.print(_header("Technology Profile", scan.target))

            if not profile.technologies:
                console.print("  [dim]No technologies detected.[/dim]\n")
                return

            table = Table(box=box.ROUNDED, show_lines=False, padding=(0, 1))
            table.add_column("Technology", style="bold cyan", min_width=20)
            table.add_column("Version", width=12)
            table.add_column("Category", width=12)
            table.add_column("Confidence", width=12)
            table.add_column("Sources", style="dim", min_width=15)

            for t in profile.technologies:
                conf = t.confidence
                conf_color = "green" if conf >= 0.8 else "yellow" if conf >= 0.5 else "red"
                table.add_row(
                    t.name,
                    t.version or "—",
                    t.category,
                    f"[{conf_color}]{conf:.0%}[/{conf_color}]",
                    ", ".join(t.sources),
                )

            console.print(table)

            # Summary badges
            badges = []
            if profile.servers:
                badges.append(f"[bold]Servers:[/bold] {', '.join(profile.servers)}")
            if profile.frameworks:
                badges.append(f"[bold]Frameworks:[/bold] {', '.join(profile.frameworks)}")
            if profile.languages:
                badges.append(f"[bold]Languages:[/bold] {', '.join(profile.languages)}")
            if profile.os_hints:
                badges.append(f"[bold]OS:[/bold] {', '.join(profile.os_hints)}")
            if badges:
                console.print(Panel(
                    "\n".join(badges),
                    title="[bold]Stack Summary[/bold]",
                    border_style="cyan",
                    box=box.ROUNDED,
                    expand=False,
                ))
            console.print()

    asyncio.run(_run())


# ── Version ──────────────────────────────────────────────────────


@app.command()
def version():
    """Show the Driln version."""
    console.print(Panel(
        f"[bold magenta]🔱 Driln[/bold magenta] v{__version__}\n"
        f"[dim]Intelligent automated pentesting engine[/dim]",
        box=box.ROUNDED,
        expand=False,
    ))


# ── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    app()
