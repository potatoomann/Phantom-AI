#!/usr/bin/env python3
import asyncio
import sys
from typing import Optional

import typer

from ai.brain import GeminiBrain, HeuristicBrain, PhantomBrain
from config import load_settings
from orchestrator import Orchestrator
from output import terminal as term
from output.logger import SessionLogger
from output.report import generate_html_report
from utils import normalize_target

app = typer.Typer(
    name="phantomai",
    help="PhantomAI - AI-powered CLI pentesting framework",
    add_completion=False,
)


def get_brain(api_key: Optional[str], config_path: Optional[str]):
    settings = load_settings(config_path)
    key = api_key or settings.anthropic_api_key

    # 1️⃣  Try Anthropic (paid)
    if key:
        try:
            return settings, PhantomBrain(
                api_key=key,
                model=settings.ai.model,
                max_tokens=settings.ai.max_tokens,
            )
        except RuntimeError as exc:
            term.info(f"{exc} Trying Gemini...")

    # 2️⃣  Try Gemini (free)
    gemini_key = settings.gemini_api_key
    if gemini_key:
        try:
            brain = GeminiBrain(api_key=gemini_key)
            term.info("Using Gemini 2.0 Flash (Fast & Free) for AI analysis.")
            return settings, brain
        except RuntimeError as exc:
            term.info(f"{exc} Falling back to heuristic mode.")

    # 3️⃣  Fallback: local heuristic
    term.info("No AI key found; running in local heuristic mode.")
    return settings, HeuristicBrain()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or domain (e.g. https://example.com)"),
    mode: str = typer.Option("full", "--mode", "-m", help="Scan mode: recon | full | ai"),
    scope: str = typer.Option("", "--scope", "-s", help="Scope restriction (e.g. *.example.com)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Anthropic API key"),
    proxy: Optional[str] = typer.Option(None, "--proxy", "-p", help="Proxy URL (e.g. http://127.0.0.1:8080)"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Config file path"),
):
    """Run a full scan against a target."""
    term.banner()
    try:
        target = normalize_target(target)
    except ValueError as exc:
        term.error(str(exc))
        raise typer.Exit(1)

    settings, brain = get_brain(api_key, config_path)
    if proxy:
        settings.proxy.enabled = True
        settings.proxy.url = proxy

    if settings.proxy.enabled and settings.proxy.url:
        term.info(f"Proxy set: {settings.proxy.url}")

    if mode not in {"recon", "full", "ai"}:
        term.error("Mode must be one of: recon, full, ai")
        raise typer.Exit(1)

    logger = SessionLogger(target=target, mode=mode)
    orchestrator = Orchestrator(
        target=target,
        mode=mode,
        brain=brain,
        logger=logger,
        scope=scope or target,
        settings=settings,
    )

    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        term.info("\nScan interrupted by user.")
        logger.finish_session()


@app.command()
def ai(
    target: str = typer.Argument(..., help="Target URL for context"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Anthropic API key"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="File containing raw tool output"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Config file path"),
):
    """
    Pipe raw output from any tool (nmap, etc.) into PhantomAI for instant triage.
    """
    term.banner()
    target = normalize_target(target)
    _, brain = get_brain(api_key, config_path)

    if file:
        from pathlib import Path

        raw = Path(file).read_text(encoding="utf-8", errors="ignore")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        term.error("Provide input via stdin or --file. Example: cat output.txt | phantomai ai https://target.com")
        raise typer.Exit(1)

    term.info(f"Triaging {len(raw)} characters of input...")

    with term.ai_thinking("AI analyzing output..."):
        result = brain.triage(target=target, module="manual", scan_output=raw)

    if result.get("error"):
        term.error(result["error"])
        raise typer.Exit(1)

    term.finding(result)

    if result.get("report_paragraph"):
        term.console.print(f"\n[bold]Report paragraph:[/bold]\n{result['report_paragraph']}")

    if result.get("next_payloads"):
        term.console.print("\n[bold]Suggested payloads:[/bold]")
        for payload in result["next_payloads"]:
            term.console.print(f"  [cyan]{payload}[/cyan]")


@app.command()
def report(
    target: str = typer.Argument(..., help="Target URL"),
    session_id: Optional[int] = typer.Option(None, "--session", "-s", help="Session ID to report on (default: latest)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output HTML file path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Anthropic API key"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Config file path"),
):
    """Generate an HTML report from a saved session."""
    term.banner()
    target = normalize_target(target)
    settings, brain = get_brain(api_key, config_path)

    if session_id:
        findings = SessionLogger.load_session_findings(session_id)
    else:
        sessions = SessionLogger.list_sessions()
        matching = [session for session in sessions if target in session["target"]]
        if not matching:
            term.error(f"No sessions found for target: {target}")
            raise typer.Exit(1)
        findings = SessionLogger.load_session_findings(matching[0]["id"])

    if not findings:
        term.info("No confirmed findings found in this session.")
        raise typer.Exit(0)

    term.info(f"Generating report for {len(findings)} findings...")

    with term.ai_thinking("AI writing report..."):
        ai_report = brain.generate_report(target=target, findings=findings)

    if ai_report.get("error"):
        term.error(ai_report["error"])
        raise typer.Exit(1)

    path = generate_html_report(
        target=target,
        ai_report=ai_report,
        output_path=output,
        report_dir=settings.output.report_dir,
    )
    term.console.print(f"\n[bold green]Report saved:[/bold green] {path}")


@app.command()
def sessions():
    """List recent scan sessions."""
    rows = SessionLogger.list_sessions()
    if not rows:
        term.info("No sessions found.")
        return

    from rich import box as rbox
    from rich.table import Table

    table = Table(box=rbox.ROUNDED, border_style="dim")
    table.add_column("ID", width=6)
    table.add_column("Target", width=40)
    table.add_column("Mode", width=10)
    table.add_column("Status", width=10)

    for row in rows:
        table.add_row(str(row["id"]), row["target"], row["mode"], row["status"])

    term.console.print(table)



if __name__ == "__main__":
    app()
