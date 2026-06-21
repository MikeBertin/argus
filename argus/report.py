"""Reporters — render an AnalysisResult as a rich CLI table or JSON."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from argus.engine import AnalysisResult
from argus.models import Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _evidence_str(evidence: dict) -> str:
    return "  ".join(f"{k}={v}" for k, v in evidence.items() if v is not None)


def render_cli(result: AnalysisResult, source: str, console: Console | None = None) -> None:
    console = console or Console()

    summary = (
        f"[bold]ARGUS[/bold]  {source}  ·  "
        f"{result.packet_count} packets  ·  {result.flow_count} flows  ·  "
        f"{result.rules_run} rules"
    )
    console.print(summary)

    if not result.findings:
        console.print("[green]No findings — capture looks clean.[/green]")
        return

    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Src → Dst", no_wrap=True)
    table.add_column("ATT&CK", no_wrap=True)
    table.add_column("Finding")

    for f in result.findings:
        sev_style = _SEV_STYLE.get(f.severity, "")
        endpoints = "—"
        if f.src or f.dst:
            endpoints = f"{f.src or '?'} → {f.dst or '?'}"
        evidence = _evidence_str(f.evidence)
        detail = f.title + (f"\n[dim]{evidence}[/dim]" if evidence else "")
        table.add_row(
            f"[{sev_style}] {f.severity.name} [/]",
            f.rule_id,
            f"{f.confidence:.2f}",
            endpoints,
            ", ".join(f.mitre),
            detail,
        )

    console.print(table)
    crit = sum(1 for f in result.findings if f.severity >= Severity.HIGH)
    console.print(
        f"[bold]{len(result.findings)} finding(s)[/bold] "
        f"({crit} high/critical)."
    )


def render_json(result: AnalysisResult, source: str) -> str:
    return json.dumps(
        {
            "source": source,
            "packets": result.packet_count,
            "flows": result.flow_count,
            "rules_run": result.rules_run,
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
    )
