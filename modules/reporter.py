"""
lokalHunt — Reporter Module
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


class Reporter:
    """Handles terminal display and report persistence."""

    def __init__(self):
        self.results: list[dict] = []
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

    def parse_summary(self, text: str) -> dict:
        """Parse analysis text to extract finding counts and summary points."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for line in text.splitlines():
            upper = line.upper()
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if re.search(rf"\b{sev.upper()}\b", upper) and len(line) < 200:
                    counts[sev] += 1

        findings = []
        for line in text.splitlines():
            stripped = line.strip()
            if (
                stripped
                and 20 < len(stripped) < 150
                and stripped[0] in ("-", "*", ">")
                and not stripped.lower().startswith(("- [", "- no ", "- none"))
            ):
                clean = re.sub(r"^\s*[-*>]+\s*", "", stripped)
                clean = re.sub(r"\*\*(.*?)\*\*", r"\1", clean)
                if clean and clean not in findings:
                    findings.append(clean)
            if len(findings) >= 5:
                break

        return {**counts, "findings": findings}

    def print_analysis_summary(self, filename: str, report_path: str, summary: dict):
        """Print summary block for a single file analysis."""
        sev_parts = []
        severity_map = [
            ("Critical", THEME["critical"]),
            ("High", THEME["high"]),
            ("Medium", THEME["medium"]),
            ("Low", THEME["low"]),
        ]
        for sev, color in severity_map:
            count = summary.get(sev, 0)
            if count > 0:
                sev_parts.append(f"[{color}]{sev}: {count}[/{color}]")

        sev_line = "  ".join(sev_parts) if sev_parts else "[dim]No critical findings identified[/dim]"

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

        border = "red" if summary.get("Critical", 0) > 0 else \
                 "dark_orange" if summary.get("High", 0) > 0 else \
                 "yellow" if summary.get("Medium", 0) > 0 else "cyan"

        console.print()
        console.print(Panel(body, border_style=border, padding=(0, 2)))

    def print_dir_summary_panel(self, total_files: int, report_path: str, all_summaries: list[dict]):
        """Print directory aggregate results."""
        totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for s in all_summaries:
            for sev in totals:
                totals[sev] += s.get(sev, 0)

        table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_map = [
            ("Critical", THEME["critical"]),
            ("High", THEME["high"]),
            ("Medium", THEME["medium"]),
            ("Low", THEME["low"]),
        ]
        for sev, color in severity_map:
            cnt = totals[sev]
            table.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{cnt}[/{color}]")

        console.print()
        console.print(Rule("[bold]Scan Results[/bold]", style="cyan"))
        console.print(f"Files analyzed: [bold]{total_files}[/bold]")
        console.print(table)
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

    def print_info(self, message: str):
        console.print(f"[{THEME['info']}]{message}[/{THEME['info']}]")

    def print_success(self, message: str):
        console.print(f"[{THEME['success']}]{message}[/{THEME['success']}]")

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
