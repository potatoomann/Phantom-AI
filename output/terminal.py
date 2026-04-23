from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
    "none": "dim",
}


def banner():
    console.print(
        Panel.fit(
            "[bold red]PhantomAI[/bold red] [dim]- AI-powered pentesting framework[/dim]",
            border_style="red",
        )
    )


def phase_start(phase: str, detail: str = ""):
    console.print(f"\n[bold cyan]>[/bold cyan] [bold]{phase}[/bold] [dim]{detail}[/dim]")


def phase_done(phase: str, count: int = 0):
    console.print(f"[bold green]+[/bold green] {phase} complete - [bold]{count}[/bold] items found")


def finding(ai_result: dict):
    severity = ai_result.get("severity", "info").lower()
    color = SEVERITY_COLORS.get(severity, "white")
    vuln = ai_result.get("vuln_type", "Unknown")
    url = ai_result.get("affected_url", "")
    reasoning = ai_result.get("reasoning", "")

    console.print(f"  [{color}][{severity.upper()}][/{color}] [bold]{vuln}[/bold] [dim]{url}[/dim]")
    if reasoning:
        console.print(f"  [dim]  {reasoning[:120]}[/dim]")


def ai_thinking(message: str = "AI reasoning..."):
    return console.status(f"[bold purple]{message}[/bold purple]", spinner="dots")


def next_step_decision(decision: dict):
    next_mod = decision.get("next_module", "unknown")
    reasoning = decision.get("reasoning", "")
    console.print(f"\n[bold purple]AI decision:[/bold purple] next -> [bold cyan]{next_mod}[/bold cyan]")
    console.print(f"[dim]  {reasoning[:160]}[/dim]")


def summary_table(findings: list):
    if not findings:
        console.print("\n[dim]No confirmed findings in this session.[/dim]")
        return

    table = Table(
        title="Session Findings",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=False,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=20)
    table.add_column("URL", width=45)
    table.add_column("Confidence", width=10)

    severity_order = ["critical", "high", "medium", "low", "info"]
    sorted_findings = sorted(
        findings,
        key=lambda item: severity_order.index(item.get("severity", "info"))
        if item.get("severity", "info") in severity_order
        else 99,
    )

    for finding in sorted_findings:
        severity = finding.get("severity", "info")
        color = SEVERITY_COLORS.get(severity, "white")
        confidence = finding.get("confidence", finding.get("ai_result", {}).get("confidence", 0.0))
        table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            finding.get("vuln_type", "Unknown"),
            (finding.get("affected_url") or "")[:45],
            f"{confidence:.0%}",
        )

    console.print()
    console.print(table)


def error(msg: str):
    console.print(f"[bold red]ERROR:[/bold red] {msg}")


def info(msg: str):
    console.print(f"[dim]{msg}[/dim]")
