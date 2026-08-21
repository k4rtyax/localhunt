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
        console.print(
            Panel(
                f"Connection failed:\n\n{message}",
                border_style="red",
                title="Error",
            )
        )

    def print_file_header(self, filename: str, size: int, mode: str, truncated: bool = False):
        size_str = f"{size / 1024:.1f}KB" if size > 1024 else f"{size}B"
        trunc_note = " (truncated)" if truncated else ""
        console.print()
        console.print(
            f"Analyzing [bold]{filename}[/bold] [dim]({size_str}, mode: {mode}){trunc_note}[/dim]",
            end=""
        )

    def stream_start(self):
        """Close the open file-header line and start the streamed output block."""
        console.print()
        console.print(Rule("[bold]Analysis[/bold]", style="cyan"))

    # Matches the finding header BASE_SYSTEM asks for in modules/prompts.py.
    # Anchoring the tally to this line is what stops prose that merely mentions
    # a severity from being counted as a finding.
    FINDING_HEADER = re.compile(
        r"^\s{0,3}#{1,6}\s*\[\s*(critical|high|medium|low|info)\s*\]\s*(.+?)\s*$",
        re.IGNORECASE,
    )

    # The model is asked to say this instead of emitting headers on a clean
    # file, which separates "nothing found" from "format not followed".
    NO_FINDINGS = re.compile(
        r"\bno\s+(?:security\s+)?(?:findings|issues|vulnerabilities)\b",
        re.IGNORECASE,
    )

    def parse_summary(self, text: str) -> dict:
        """
        Extract finding counts and titles from an analysis.

        Returns counts as None when the model ignored the header format, so the
        caller can omit the tally rather than print a number taken from prose.
        """
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        findings = []

        for line in text.splitlines():
            match = self.FINDING_HEADER.match(line)
            if not match:
                continue
            counts[match.group(1).capitalize()] += 1
            title = re.sub(r"\*\*(.*?)\*\*", r"\1", match.group(2)).strip()
            if title and title not in findings:
                findings.append(title)

        if not any(counts.values()):
            if self.NO_FINDINGS.search(text):
                return {"counts": counts, "findings": []}
            return {"counts": None, "findings": []}

        return {"counts": counts, "findings": findings}

    def print_analysis_summary(self, filename: str, report_path: str, summary: dict):
        """Print summary block for a single file analysis."""
        counts = summary.get("counts")

        if counts is None:
            sev_line = "[dim]Findings could not be counted, see the report[/dim]"
        else:
            sev_parts = [
                f"[{color}]{sev}: {counts[sev]}[/{color}]"
                for sev, color in SEVERITY_ROWS
                if counts[sev] > 0
            ]
            sev_line = "  ".join(sev_parts) if sev_parts else "[dim]No findings identified[/dim]"

        findings_lines = ""
        for f in summary.get("findings", [])[:4]:
            findings_lines += f"\n  - {f}"

        body = (
            f"[bold]{filename}[/bold]\n"
            f"[dim]{'-' * 40}[/dim]\n"
            f"{sev_line}"
        )
        if findings_lines:
            body += f"\n\n[dim]Key observations:[/dim]{findings_lines}"

        body += f"\n\n[dim]Report:[/dim] [cyan underline]{report_path}[/cyan underline]"

        if counts is None:
            border = "cyan"
        elif counts["Critical"]:
            border = "red"
        elif counts["High"]:
            border = "dark_orange"
        elif counts["Medium"]:
            border = "yellow"
        else:
            border = "cyan"

        console.print()
        console.print(Panel(body, border_style=border, padding=(0, 2)))

    def print_dir_summary_panel(self, total_files: int, report_path: str, all_summaries: list[dict]):
        """Print directory aggregate results."""
        totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        uncounted = 0
        for s in all_summaries:
            counts = s.get("counts")
            if counts is None:
                uncounted += 1
                continue
            for sev in totals:
                totals[sev] += counts.get(sev, 0)

        table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev, color in SEVERITY_ROWS:
            cnt = totals[sev]
            table.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{cnt}[/{color}]")

        console.print()
        console.print(Rule("[bold]Scan Results[/bold]", style="cyan"))
        console.print(f"Files analyzed: [bold]{total_files}[/bold]")
        console.print(table)
        if uncounted:
            console.print(
                f"[{THEME['medium']}]{uncounted} of {total_files} file(s) did not "
                f"follow the finding format and are not in this tally."
                f"[/{THEME['medium']}]"
            )
        console.print(f"\nReport: [cyan underline]{report_path}[/cyan underline]")

    def print_dir_summary(self, directory: str, total: int, mode: str):
        console.print()
        console.print(
            Panel(
                f"Directory : [cyan]{directory}[/cyan]\n"
                f"Files     : [bold]{total}[/bold]\n"
                f"Mode      : [{THEME['model']}]{mode}[/{THEME['model']}]",
                border_style="blue",
                padding=(0, 2),
            )
        )

    def print_skipped(self, filename: str, reason: str):
        console.print(f"  [dim]Skipped {filename} ({reason})[/dim]")

    def print_error(self, message: str):
        console.print(f"\n[{THEME['critical']}]Error:[/{THEME['critical']}] {message}")

    def print_warning(self, message: str):
        console.print(f"[{THEME['medium']}]Warning:[/{THEME['medium']}] {message}")

    def save_single_report(
        self,
        filename: str,
        mode: str,
        content: str,
        rag_used: bool = False,
        output_path: str | None = None,
    ) -> str:
        """Persist single analysis result to markdown file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = Path(filename).stem.replace(" ", "_")

        if output_path:
            filepath = Path(output_path)
            if not filepath.suffix:
                filepath = filepath.with_suffix(".md")
        else:
            filepath = Path(REPORTS_DIR) / f"{safe_name}_{mode}_{timestamp}.md"

        rag_label = " (RAG enabled)" if rag_used else ""

        lines = [
            f"# Analysis Report: {filename}",
            f"",
            f"- File: `{filename}`",
            f"- Mode: `{mode}`{rag_label}",
            f"- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
            content,
        ]

        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text("\n".join(lines), encoding="utf-8")
        return str(filepath)

    def save_dir_report(
        self,
        results: list[dict],
        output_path: str | None = None,
    ) -> str:
        """Persist directory analysis results to a consolidated markdown file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_path:
            filepath = Path(output_path)
            if not filepath.suffix:
                filepath = filepath.with_suffix(".md")
        else:
            filepath = Path(REPORTS_DIR) / f"scan_report_{timestamp}.md"

        lines = [
            f"# Consolidated Scan Report",
            f"",
            f"- Files Analyzed: {len(results)}",
            f"- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"---",
            f"",
        ]

        for i, r in enumerate(results, 1):
            rag_label = " (RAG)" if r.get("rag_used") else ""
            lines += [
                f"## {i}. {r['filename']}",
                f"",
                f"Mode: `{r['mode']}`{rag_label}",
                f"",
                r["content"],
                f"",
                f"---",
                f"",
            ]

        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text("\n".join(lines), encoding="utf-8")
        return str(filepath)

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
