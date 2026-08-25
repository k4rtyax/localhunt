"""
lokalHunt - Reporter Module
Handles terminal output and saving markdown reports.
"""

import re
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box
from config import REPORTS_DIR, THEME

console = Console()

# Diagnostics go to stderr so they never land in front of a result document on
# stdout, which is what swarm --stdout-json puts there for a machine to read.
err_console = Console(stderr=True)

# Severity rows, in the order both summary panels render them.
SEVERITY_ROWS = [
    ("Critical", THEME["critical"]),
    ("High", THEME["high"]),
    ("Medium", THEME["medium"]),
    ("Low", THEME["low"]),
    ("Info", THEME["info"]),
]


class Reporter:
    """Handles terminal display and report persistence."""

    def __init__(self):
        Path(REPORTS_DIR).mkdir(exist_ok=True)

    def print_banner(self, model: str, server: str):
        console.print(
            Panel(
                f"[bold]lokalHunt[/bold]\n"
                f"[dim]----------------------------------------[/dim]\n"
                f"Model   : [{THEME['model']}]{model}[/{THEME['model']}]\n"
                f"Server  : [{THEME['header']}]{server}[/{THEME['header']}]\n"
                f"Reports : ./{REPORTS_DIR}/",
                border_style="cyan",
                padding=(0, 2),
            )
        )

    def print_connection_ok(self, server: str, model: str):
        console.print(
            f"Connected to [bold]{server}[/bold] (model: [{THEME['model']}]{model}[/{THEME['model']}])"
        )

    def print_connection_error(self, message: str):
        err_console.print(
            Panel(
                f"Connection failed:\n\n{message}",
                border_style="red",
                title="Error",
            )
        )

    def print_skipped(self, filename: str, reason: str):
        err_console.print(f"  [dim]Skipped {filename} ({reason})[/dim]")

    def print_error(self, message: str):
        err_console.print(f"\n[{THEME['critical']}]Error:[/{THEME['critical']}] {message}")

    def print_warning(self, message: str):
        err_console.print(f"[{THEME['medium']}]Warning:[/{THEME['medium']}] {message}")

    def print_swarm_plan(self, stats: dict, agents: list[str]):
        console.print()
        console.print(
            Panel(
                f"Files        : [bold]{stats.get('files', 0)}[/bold]\n"
                f"Agent calls  : [bold]{stats.get('agent_calls', 0)}[/bold] "
                f"across {stats.get('windows', 0)} window(s)\n"
                f"Code size    : {stats.get('code_tokens', 0):,} tokens "
                f"(budget {stats.get('context_budget', 0):,}/call)\n"
                f"Agents       : [{THEME['model']}]{', '.join(agents)}[/{THEME['model']}]",
                title="Swarm Plan",
                border_style="blue",
                padding=(0, 2),
            )
        )

    def print_swarm_result(self, result, report_path: str, json_path: str | None = None):
        """Render the narrowing funnel, the findings table and the summary."""
        stats = result.stats
        counts = result.counts()

        funnel = (
            f"{stats.get('raw_findings', 0)} raw"
            f" -> {stats.get('unique_findings', 0)} unique"
            f" -> [bold]{stats.get('confirmed', 0)} confirmed[/bold]"
        )
        if stats.get("refuted"):
            funnel += f"  [dim]({stats['refuted']} refuted by skeptic)[/dim]"

        console.print()
        console.print(Rule("[bold]Swarm Results[/bold]", style="cyan"))
        console.print(funnel)

        if result.findings:
            table = Table(
                box=box.ROUNDED, border_style="cyan",
                header_style="bold cyan", show_lines=False,
            )
            table.add_column("Sev", width=8)
            table.add_column("Finding", style="bold white", overflow="fold")
            table.add_column("Location", style="dim", overflow="fold")
            table.add_column("Agent", style="dim")
            table.add_column("Conf", justify="right", width=5)

            for f in result.findings:
                color = THEME.get(f.severity, "white")
                flag = " [yellow]?[/yellow]" if f.unverified_evidence else ""
                table.add_row(
                    f"[{color}]{f.severity.upper()}[/{color}]",
                    f.title + flag,
                    f"{Path(f.file).name}:{f.line}",
                    f.agent.split(",")[0],
                    f"{f.confidence:.2f}",
                )
            console.print()
            console.print(table)
        else:
            console.print("\n[dim]No findings survived verification.[/dim]")

        sev_line = "  ".join(
            f"[{THEME.get(sev, 'white')}]{sev.title()}: {counts[sev]}[/{THEME.get(sev, 'white')}]"
            for sev in ("critical", "high", "medium", "low", "info")
            if counts.get(sev)
        )
        if sev_line:
            console.print(f"\n{sev_line}")

        if result.summary:
            body = (result.summary.get("summary") or "").strip()
            priorities = result.summary.get("top_priorities") or []
            text = body
            if priorities:
                text += "\n\n[dim]Priorities:[/dim]"
                for i, item in enumerate(priorities[:5], 1):
                    text += f"\n  {i}. {item}"
            if text.strip():
                console.print()
                console.print(
                    Panel(text, title="Triage Summary",
                          border_style="cyan", padding=(0, 2))
                )

        if result.errors:
            console.print(
                f"\n[{THEME['medium']}]Agent errors "
                f"({len(result.errors)}):[/{THEME['medium']}]"
            )
            for err in result.errors[:5]:
                console.print(f"  [dim]- {err}[/dim]")

        console.print(f"\nReport: [cyan underline]{report_path}[/cyan underline]")
        if json_path:
            console.print(f"JSON  : [cyan underline]{json_path}[/cyan underline]")

    def save_swarm_report(self, result, output_path: str | None = None) -> str:
        """Write the swarm run to markdown."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_path:
            filepath = Path(output_path)
            if not filepath.suffix:
                filepath = filepath.with_suffix(".md")
        else:
            filepath = Path(REPORTS_DIR) / f"swarm_{timestamp}.md"

        counts = result.counts()
        tally = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "none"
        lines = [
            "# lokalHunt Swarm Report",
            "",
            f"- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- Files: {', '.join(result.files)}",
            f"- Agents: {', '.join(result.agents_run)}",
            f"- Findings: {tally}",
            "",
        ]

        if result.summary:
            lines += ["## Summary", "", result.summary.get("summary", ""), ""]
            for item in result.summary.get("top_priorities") or []:
                lines.append(f"1. {item}")
            lines.append("")

        lines += ["---", "", "## Findings", ""]
        if not result.findings:
            lines += ["No findings survived verification.", ""]

        for i, f in enumerate(result.findings, 1):
            lines += [
                f"### {i}. [{f.severity.upper()}] {f.title}",
                "",
                f"- Location: `{f.file}:{f.line}`",
                f"- Category: {f.category}" + (f" ({f.cwe})" if f.cwe else ""),
                f"- Reported by: {f.agent}",
                f"- Confidence: {f.confidence:.2f} | Verdict: {f.verdict}",
            ]
            if f.unverified_evidence:
                lines.append(
                    "- WARNING: quoted evidence was not found in the source file"
                )
            lines += ["", "```", f.evidence, "```", ""]
            if f.impact:
                lines += [f"**Impact.** {f.impact}", ""]
            if f.remediation:
                lines += [f"**Fix.** {f.remediation}", ""]
            if f.verdict_reason:
                lines += [f"*Verifier: {f.verdict_reason}*", ""]

        if result.refuted:
            lines += ["---", "", "## Refuted by verification", ""]
            for f in result.refuted:
                reason = f.verdict_reason or "no reason given"
                lines.append(
                    f"- [{f.severity}] {f.title} "
                    f"(`{Path(f.file).name}:{f.line}`) - {reason}"
                )
            lines.append("")

        if result.errors:
            lines += ["---", "", "## Agent errors", ""]
            lines += [f"- {e}" for e in result.errors]
            lines.append("")

        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text("\n".join(lines), encoding="utf-8")
        return str(filepath)

    def save_swarm_json(self, result, output_path: str | None = None) -> str:
        """Write the machine-readable result, for CI or a Claude skill."""
        import json
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = (
            Path(output_path) if output_path
            else Path(REPORTS_DIR) / f"swarm_{timestamp}.json"
        )
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(filepath)
