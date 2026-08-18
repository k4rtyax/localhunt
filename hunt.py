#!/usr/bin/env python3
"""
lokalHunt - Command Line Interface
Code security analysis assistant backed by local Ollama models.
"""

import sys
import shutil
import click
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import (
    OLLAMA_BASE_URL, DEFAULT_MODEL, OLLAMA_PORT,
    EMBEDDING_MODEL, KNOWLEDGE_DIR, RAG_TOP_K, CHROMA_DB_DIR,
    THEME,
)
from modules.analyzer import Analyzer
from modules.scanner import Scanner
from modules.reporter import Reporter
from modules.prompts import AVAILABLE_MODES

# Redirected stdout defaults to cp1252 on Windows, which cannot encode the
# spinner glyphs rich emits.
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

console = Console()


def update_host_in_config(new_ip: str):
    """Update DEFAULT_HOST in config.py (LOKALHUNT_HOST still overrides it)."""
    import re
    config_path = Path(__file__).parent / "config.py"
    content = config_path.read_text(encoding="utf-8")
    new_content, n = re.subn(
        r'DEFAULT_HOST\s*=\s*"[^"]*"', f'DEFAULT_HOST = "{new_ip}"', content
    )
    if not n:
        raise ValueError("DEFAULT_HOST not found in config.py")
    config_path.write_text(new_content, encoding="utf-8")


class RAGUnavailable(RuntimeError):
    """chromadb is an optional extra: RAG commands need it, the rest do not."""


def get_rag_engine(base_url: str, model: str):
    try:
        from modules.rag import RAGEngine
    except ImportError as e:
        raise RAGUnavailable(
            "Knowledge-base support needs chromadb, which is not installed "
            "(" + str(e) + ")." + chr(10) + "Install it with: pip install chromadb"
        ) from None
    return RAGEngine(base_url=base_url, embedding_model=model)


def get_indexer():
    from modules.indexer import Indexer
    return Indexer()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """lokalHunt - Local code security analysis utility."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("check")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--model", default=DEFAULT_MODEL, help="Model name")
def cmd_check(host, model):
    """Check Ollama connectivity and model availability."""
    reporter = Reporter()
    url = host or OLLAMA_BASE_URL
    reporter.print_banner(model, url)

    analyzer = Analyzer(model=model, base_url=url)
    console.print(f"\n[dim]Checking connection to {url}...[/dim]")
    ok, msg = analyzer.check_ollama()

    if ok:
        reporter.print_connection_ok(url, model)
    else:
        reporter.print_connection_error(msg)
        console.print(
            "\n[dim]Ensure Ollama is running on the host:[/dim]\n"
            "[yellow]  OLLAMA_HOST=0.0.0.0 ollama serve[/yellow]\n"
            "[dim]Set host IP via:[/dim]\n"
            "  python hunt.py set-host <IP>"
        )
        sys.exit(1)

    console.print(f"\n[dim]Checking embedding model ({EMBEDDING_MODEL})...[/dim]")
    try:
        rag = get_rag_engine(url, EMBEDDING_MODEL)
    except RAGUnavailable as e:
        console.print("[yellow]Knowledge base unavailable:[/yellow] " + str(e))
        console.print("[dim]Scanning still works; only RAG is affected.[/dim]")
        return
    ok_emb, msg_emb = rag.check_embedding_model()

    if ok_emb:
        console.print(f"Embedding model [{THEME['model']}]{EMBEDDING_MODEL}[/{THEME['model']}] available.")
    else:
        console.print(f"[yellow]Embedding warning:[/yellow] {msg_emb}")

    kb_count = rag.count()
    console.print(f"\nKnowledge base: [bold]{kb_count}[/bold] chunks indexed")


@cli.command("set-host")
@click.argument("ip_address")
def cmd_set_host(ip_address):
    """Configure host IP address in config.py."""
    try:
        update_host_in_config(ip_address)
        console.print(
            f"Host set to: [bold cyan]{ip_address}:{OLLAMA_PORT}[/bold cyan]\n"
            f"[dim]Updated config.py[/dim]"
        )
    except Exception as e:
        console.print(f"[red]Failed to update config: {e}[/red]")


@cli.command("index")
@click.option("--dir", "kb_dir", default=KNOWLEDGE_DIR, help="Knowledge base directory")
@click.option("--force", is_flag=True, help="Force re-indexing of all documents")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--embed-model", default=EMBEDDING_MODEL, help="Embedding model name")
def cmd_index(kb_dir, force, host, embed_model):
    """Index knowledge base documents into the vector store."""
    url = host or OLLAMA_BASE_URL
    reporter = Reporter()

    console.print(
        Panel(
            f"Indexing Knowledge Base\n"
            f"[dim]----------------------------------------[/dim]\n"
            f"Source   : [cyan]{kb_dir}[/cyan]\n"
            f"Model    : [{THEME['model']}]{embed_model}[/{THEME['model']}]\n"
            f"Database : [dim]{CHROMA_DB_DIR}[/dim]\n"
            f"Force    : {'Yes' if force else 'No'}",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    kb_path = Path(kb_dir)
    if not kb_path.exists():
        kb_path.mkdir(parents=True, exist_ok=True)
        console.print(f"Created directory {kb_path.resolve()}. Add .md or .txt files and rerun indexing.")
        return

    try:
        rag = get_rag_engine(url, embed_model)
    except RAGUnavailable as e:
        reporter.print_error(str(e))
        sys.exit(1)
    ok, msg = rag.check_embedding_model()
    if not ok:
        reporter.print_connection_error(f"Embedding model unavailable:\n{msg}")
        sys.exit(1)

    indexer = get_indexer()
    docs = indexer.list_documents()

    if not docs:
        console.print(f"No documents found in {kb_dir}. Supported formats: .md, .txt")
        return

    console.print(f"\n[dim]Found {len(docs)} documents. Starting indexing...[/dim]\n")

    total_chunks = 0
    skipped = 0
    errors = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Indexing...", total=len(docs))

        for result in indexer.index_all(rag, force=force):
            if result["error"]:
                console.print(f"  [red]Failed[/red] {result['file']}: {result['error']}")
                errors += 1
            elif result["skipped"]:
                console.print(f"  [dim]Skipped {result['file']} (already indexed)[/dim]")
                skipped += 1
            else:
                console.print(f"  Indexed {result['file']} ({result['chunks']} chunks)")
                total_chunks += result["chunks"]

            progress.advance(task)

    console.print()
    console.print(
        Panel(
            f"Indexing Complete\n\n"
            f"New chunks    : [bold]{total_chunks}[/bold]\n"
            f"Skipped       : {skipped}\n"
            f"Errors        : {errors}\n"
            f"Total entries : [bold]{rag.count()}[/bold]",
            border_style="green",
            padding=(0, 2),
        )
    )


@cli.command("knowledge")
@click.option("--list", "do_list", is_flag=True, help="List indexed documents")
@click.option("--add", "add_file", default=None, help="Add document to knowledge base")
@click.option("--search", "query", default=None, help="Query knowledge base")
@click.option("--clear", is_flag=True, help="Clear knowledge base store")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--top-k", default=RAG_TOP_K, help="Result limit")
def cmd_knowledge(do_list, add_file, query, clear, host, top_k):
    """Manage and query knowledge base documents."""
    url = host or OLLAMA_BASE_URL
    reporter = Reporter()
    try:
        rag = get_rag_engine(url, EMBEDDING_MODEL)
    except RAGUnavailable as e:
        reporter.print_error(str(e))
        sys.exit(1)

    if do_list:
        sources = rag.list_sources()
        total = rag.count()

        if not sources:
            console.print("Knowledge base is empty. Run 'python hunt.py index' to populate.")
            return

        table = Table(
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            title=f"Knowledge Base ({total} chunks)",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Document", style="bold white")
        table.add_column("Chunks", justify="right", style="green")

        for i, s in enumerate(sources, 1):
            path = Path(s["source"])
            table.add_row(str(i), path.name, str(s["chunks"]))

        console.print(table)
        return

    if add_file:
        src = Path(add_file)
        if not src.exists():
            reporter.print_error(f"File not found: {add_file}")
            sys.exit(1)

        kb_path = Path(KNOWLEDGE_DIR)
        kb_path.mkdir(exist_ok=True)
        dest = kb_path / src.name

        shutil.copy2(src, dest)
        console.print(f"Copied to: [cyan]{dest}[/cyan]\nRun 'python hunt.py index' to index.")
        return

    if query:
        console.print(f"\n[dim]Searching: \"{query}\"...[/dim]\n")
        ok, msg = rag.check_embedding_model()
        if not ok:
            reporter.print_connection_error(msg)
            sys.exit(1)

        results = rag.search(query, top_k=top_k)
        if not results:
            console.print("No relevant entries found.")
            return

        for i, (doc, src, score) in enumerate(results, 1):
            src_name = Path(src).name
            console.print(
                Panel(
                    doc,
                    title=f"[{i}] {src_name} (similarity: {score:.0%})",
                    border_style="dim",
                    padding=(0, 1),
                )
            )
        return

    if clear:
        count = rag.count()
        if count == 0:
            console.print("Knowledge base is already empty.")
            return

        confirm = Prompt.ask(f"Remove {count} chunks from knowledge store? (type 'yes')")
        if confirm.lower() == "yes":
            import shutil as _shutil
            _shutil.rmtree(CHROMA_DB_DIR, ignore_errors=True)
            console.print("Knowledge base cleared.")
        else:
            console.print("Operation cancelled.")
        return

    console.print(
        "Usage:\n"
        "  python hunt.py knowledge --list\n"
        "  python hunt.py knowledge --add doc.md\n"
        "  python hunt.py knowledge --search \"pattern\"\n"
        "  python hunt.py knowledge --clear"
    )


@cli.command("scan")
@click.option("--file", "-f", "filepath", default=None, help="Target file path")
@click.option("--dir", "-d", "directory", default=None, help="Target directory path")
@click.option(
    "--mode", "-m",
    default="full",
    type=click.Choice(AVAILABLE_MODES, case_sensitive=False),
    show_default=True,
    help="Analysis mode"
)
@click.option("--rag", "use_rag", is_flag=True, help="Enable knowledge base retrieval")
@click.option("--top-k", default=RAG_TOP_K, show_default=True, help="Knowledge chunk limit")
@click.option("--ext", multiple=True, help="Filter file extensions")
@click.option("--output", "-o", default=None, help="Custom output report path")
@click.option("--stream", is_flag=True, help="Stream full response directly to terminal")
@click.option("--no-recursive", is_flag=True, help="Disable recursive directory traversal")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--model", default=DEFAULT_MODEL, show_default=True, help="Model name")
def cmd_scan(filepath, directory, mode, use_rag, top_k, ext, output, stream,
             no_recursive, host, model):
    """Analyze file or directory for security vulnerabilities."""
    if not filepath and not directory:
        console.print("[red]Specify --file or --dir[/red]")
        sys.exit(1)

    url = host or OLLAMA_BASE_URL
    reporter = Reporter()
    reporter.print_banner(model, url)

    analyzer = Analyzer(model=model, base_url=url)
    ok, msg = analyzer.check_ollama()
    if not ok:
        reporter.print_connection_error(msg)
        sys.exit(1)
    reporter.print_connection_ok(url, model)

    rag_engine = None
    if use_rag:
        try:
            rag_engine = get_rag_engine(url, EMBEDDING_MODEL)
        except RAGUnavailable as e:
            console.print("[yellow]" + str(e) + "[/yellow]")
            console.print("[dim]Running without RAG.[/dim]")
        else:
            kb_count = rag_engine.count()
            if kb_count == 0:
                console.print("[yellow]Warning: RAG requested but knowledge base is empty.[/yellow]")
            else:
                console.print(f"RAG active ({kb_count} chunks, top-k: {top_k})")

    extensions = list(ext) if ext else None
    scanner = Scanner(extensions=extensions)


    if filepath:
        file_info = scanner.scan_file(filepath)
        if not file_info or file_info.get("error"):
            reporter.print_error(file_info.get("error", "Failed to read file"))
            sys.exit(1)

        rag_context = None
        if rag_engine and rag_engine.count() > 0:
            with console.status("[dim]Retrieving knowledge base context...[/dim]"):
                query = f"{mode} analysis {file_info['name']}: {file_info['content'][:500]}"
                rag_context = rag_engine.format_context(query, top_k=top_k)

        reporter.print_file_header(
            file_info["name"], file_info["size"], mode,
            file_info.get("truncated", False)
        )

        full_response = []
        try:
            if stream:
                reporter.stream_start()
                for chunk in analyzer.analyze_stream(
                    file_info["content"],
                    mode=mode,
                    filename=file_info["name"],
                    rag_context=rag_context,
                ):
                    console.print(chunk, end="", markup=False)
                    full_response.append(chunk)
                console.print()
            else:
                with console.status(f" [cyan]Analyzing {file_info['name']}...[/cyan]"):
                    for chunk in analyzer.analyze_stream(
                        file_info["content"],
                        mode=mode,
                        filename=file_info["name"],
                        rag_context=rag_context,
                    ):
                        full_response.append(chunk)
        except KeyboardInterrupt:
            console.print("\n[yellow]Execution interrupted by user.[/yellow]")
            sys.exit(0)
        except Exception as e:
            reporter.print_error(f"Analysis failed: {e}")
            sys.exit(1)

        full_text = "".join(full_response)
        saved_path = reporter.save_single_report(
            filename=file_info["name"],
            mode=mode,
            content=full_text,
            rag_used=(rag_context is not None),
            output_path=output,
        )

        summary = reporter.parse_summary(full_text)
        reporter.print_analysis_summary(file_info["name"], saved_path, summary)


    elif directory:
        dir_path = Path(directory)
        if not dir_path.exists():
            reporter.print_error(f"Directory not found: {directory}")
            sys.exit(1)

        recursive = not no_recursive
        with console.status("[dim]Counting files...[/dim]"):
            total = scanner.count_files(dir_path, recursive)

        if total == 0:
            reporter.print_warning(f"No matching files found in {directory}")
            return

        reporter.print_dir_summary(directory, total, mode)

        all_results = []
        all_summaries = []
        scanned = 0
        errors = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=total)

            for file_info in scanner.scan_directory(dir_path, recursive):
                if file_info.get("error"):
                    reporter.print_skipped(file_info.get("path", "?"), file_info["error"])
                    errors += 1
                    progress.advance(task)
                    continue

                progress.update(task, description=f"[cyan]Analyzing: {file_info['name'][:40]}")

                rag_context = None
                if rag_engine and rag_engine.count() > 0:
                    query = f"{mode} {file_info['name']}: {file_info['content'][:300]}"
                    rag_context = rag_engine.format_context(query, top_k=top_k)

                full_response = []
                try:
                    for chunk in analyzer.analyze_stream(
                        file_info["content"],
                        mode=mode,
                        filename=file_info["name"],
                        rag_context=rag_context,
                    ):
                        full_response.append(chunk)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Execution interrupted by user.[/yellow]")
                    break
                except Exception as e:
                    reporter.print_error(f"{file_info['name']}: {e}")
                    errors += 1
                    progress.advance(task)
                    continue

                full_text = "".join(full_response)
                file_report_path = reporter.save_single_report(
                    filename=file_info["name"],
                    mode=mode,
                    content=full_text,
                    rag_used=(rag_context is not None),
                )

                summary = reporter.parse_summary(full_text)
                all_summaries.append(summary)

                all_results.append({
                    "filename": file_info["name"],
                    "mode": mode,
                    "content": full_text,
                    "rag_used": (rag_context is not None),
                    "report_path": file_report_path,
                })
                scanned += 1
                progress.advance(task)

        combined_report_path = reporter.save_dir_report(all_results, output_path=output)
        reporter.print_dir_summary_panel(scanned, combined_report_path, all_summaries)


@cli.command("chat")
@click.option("--rag", "use_rag", is_flag=True, help="Enable knowledge base retrieval")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--model", default=DEFAULT_MODEL, show_default=True, help="Model name")
def cmd_chat(use_rag, host, model):
    """Start interactive analysis session."""
    url = host or OLLAMA_BASE_URL
    reporter = Reporter()
    reporter.print_banner(model, url)

    analyzer = Analyzer(model=model, base_url=url)
    ok, msg = analyzer.check_ollama()
    if not ok:
        reporter.print_connection_error(msg)
        sys.exit(1)
    reporter.print_connection_ok(url, model)

    rag_engine = None
    if use_rag:
        try:
            rag_engine = get_rag_engine(url, EMBEDDING_MODEL)
        except RAGUnavailable as e:
            console.print("[yellow]" + str(e) + "[/yellow]")
            console.print("[dim]Running without RAG.[/dim]")
        else:
            kb_count = rag_engine.count()
            if kb_count > 0:
                console.print(f"RAG active ({kb_count} chunks)")
            else:
                console.print("[yellow]Knowledge base is empty.[/yellow]")

    console.print(
        Panel(
            "Interactive Session\n\n"
            "Commands:\n"
            "  exit / quit : Exit session\n"
            "  clear       : Reset message history",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    history = []
    while True:
        try:
            console.print()
            user_input = Prompt.ask("[bold cyan]Query[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            console.print("\nExiting session.")
            break

        cmd = user_input.lower().strip()
        if cmd in ("exit", "quit", "q"):
            break
        if cmd == "clear":
            history.clear()
            console.print("[dim]History cleared.[/dim]")
            continue
        if not user_input.strip():
            continue

        rag_injection = ""
        if rag_engine and rag_engine.count() > 0:
            ctx = rag_engine.format_context(user_input, top_k=3)
            if ctx:
                rag_injection = ctx

        final_input = (rag_injection + "\n\n" + user_input) if rag_injection else user_input
        history.append({"role": "user", "content": final_input})

        console.print()
        console.print(f"[bold {THEME['model']}]Response[/bold {THEME['model']}]", end=" ")

        full_response = []
        try:
            for chunk in analyzer.chat_stream(history):
                console.print(chunk, end="", markup=False)
                full_response.append(chunk)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
        except Exception as e:
            reporter.print_error(f"Error: {e}")
            history.pop()
            continue

        console.print()
        full_text = "".join(full_response)
        history.append({"role": "assistant", "content": full_text})


@cli.command("agents")
def cmd_agents():
    """List the specialist agents the swarm can spawn."""
    from modules.agents import FINDERS, SKEPTIC, SYNTHESIZER

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        title="Swarm Agents",
    )
    table.add_column("Agent", style="bold white")
    table.add_column("Role", style="dim", width=9)
    table.add_column("Specialty", overflow="fold")
    table.add_column("File types", style="dim", overflow="fold")

    for agent in FINDERS:
        exts = ", ".join(agent.extensions[:5]) if agent.extensions else "any"
        if agent.extensions and len(agent.extensions) > 5:
            exts += f" (+{len(agent.extensions) - 5})"
        note = " [dim](needs a signal)[/dim]" if agent.needs_signal else ""
        table.add_row(agent.name, "finder", agent.description + note, exts)

    table.add_row(SKEPTIC.name, "verifier", SKEPTIC.description, "-")
    table.add_row(SYNTHESIZER.name, "synth", SYNTHESIZER.description, "-")

    console.print(table)
    console.print(
        "\n[dim]Agents are auto-selected per file from extension and a regex\n"
        "pre-scan. Force a set with: [/dim]python hunt.py swarm -f x.js "
        "-a secrets-hunter -a xss-hunter"
    )


@cli.command("swarm")
@click.option("--file", "-f", "filepath", default=None, help="Target file path")
@click.option("--dir", "-d", "directory", default=None, help="Target directory path")
@click.option("--agent", "-a", "only_agents", multiple=True,
              help="Force a specific agent (repeatable)")
@click.option("--all-agents", is_flag=True, help="Run every agent on every file")
@click.option("--no-verify", is_flag=True, help="Skip the adversarial verify phase")
@click.option("--no-summary", is_flag=True, help="Skip the triage summary")
@click.option("--votes", default=None, type=int, help="Skeptic votes per finding")
@click.option("--concurrency", "-c", default=None, type=int,
              help="Parallel agent calls")
@click.option("--rag", "use_rag", is_flag=True, help="Enable knowledge base retrieval")
@click.option("--top-k", default=3, show_default=True, help="Knowledge chunk limit")
@click.option("--ext", multiple=True, help="Filter file extensions")
@click.option("--no-recursive", is_flag=True, help="Disable recursive traversal")
@click.option("--output", "-o", default=None, help="Markdown report path")
@click.option("--json", "json_path", default=None,
              help="Write machine-readable JSON to this path")
@click.option("--stdout-json", is_flag=True,
              help="Print the JSON result to stdout and nothing else")
@click.option("--fail-on", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Exit non-zero when a finding at or above this severity is confirmed")
@click.option("--host", default=None, help="Ollama host URL")
@click.option("--model", default=DEFAULT_MODEL, show_default=True, help="Model name")
def cmd_swarm(filepath, directory, only_agents, all_agents, no_verify, no_summary,
              votes, concurrency, use_rag, top_k, ext, no_recursive, output,
              json_path, stdout_json, fail_on, host, model):
    """Run a fleet of specialist agents against a target, then verify findings."""
    import json as _json
    from config import SWARM_CONCURRENCY, VERIFIER_VOTES
    from modules.llm import OllamaClient
    from modules.orchestrator import Swarm
    from modules.schema import SEVERITY_RANK

    if not filepath and not directory:
        console.print("[red]Specify --file or --dir[/red]")
        sys.exit(1)

    quiet = stdout_json
    url = host or OLLAMA_BASE_URL
    reporter = Reporter()
    if not quiet:
        reporter.print_banner(model, url)

    client = OllamaClient(model=model, base_url=url)
    ok, msg = client.check()
    if not ok:
        reporter.print_connection_error(msg)
        sys.exit(1)
    if not quiet:
        reporter.print_connection_ok(url, model)


    scanner = Scanner(extensions=list(ext) if ext else None)
    files: list[dict] = []

    if filepath:
        info = scanner.scan_file(filepath)
        if not info or info.get("error"):
            reporter.print_error(info.get("error", "Failed to read file"))
            sys.exit(1)
        files.append(info)
    else:
        dir_path = Path(directory)
        if not dir_path.exists():
            reporter.print_error(f"Directory not found: {directory}")
            sys.exit(1)
        for info in scanner.scan_directory(dir_path, not no_recursive):
            if info.get("error"):
                reporter.print_skipped(info.get("path", "?"), info["error"])
                continue
            files.append(info)

    if not files:
        reporter.print_warning("No matching files found.")
        sys.exit(0)


    rag_engine = None
    if use_rag:
        try:
            rag_engine = get_rag_engine(url, EMBEDDING_MODEL)
        except RAGUnavailable as e:
            console.print("[yellow]" + str(e) + "[/yellow]")
            console.print("[dim]Running without RAG.[/dim]")
        else:
            if rag_engine.count() == 0:
                console.print("[yellow]Knowledge base is empty; running without RAG.[/yellow]")
                rag_engine = None

    swarm = Swarm(
        client,
        rag=rag_engine,
        rag_top_k=top_k,
        concurrency=concurrency or SWARM_CONCURRENCY,
        verifier_votes=VERIFIER_VOTES if votes is None else votes,
    )

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        disable=quiet,
    )
    hunt_task = progress.add_task("[cyan]Hunting", total=None)
    verify_task = progress.add_task("[cyan]Verifying", total=None, visible=False)

    def on_event(ev):
        if ev.phase == "plan" and ev.status == "skip":
            if not quiet:
                reporter.print_skipped(ev.file, ev.detail)
        elif ev.phase == "hunt" and ev.status in ("done", "error"):
            label = f"[cyan]{ev.agent}[/cyan] {ev.file}"
            progress.update(hunt_task, description=label, advance=1)
        elif ev.phase == "sift" and ev.status == "done":
            progress.update(hunt_task, description=f"[cyan]Sifted[/cyan] {ev.detail}")
            progress.update(verify_task, total=ev.count, completed=0)
        elif ev.phase == "verify" and ev.status == "start":
            progress.update(verify_task, visible=True,
                            description=f"[cyan]skeptic[/cyan] {ev.detail}")
        elif ev.phase == "verify" and ev.status == "done":
            progress.advance(verify_task)
        elif ev.phase == "synth" and ev.status == "start":
            progress.update(verify_task, description="[cyan]triage-lead[/cyan] summarising")

    # Attach before plan() runs: plan is what reports files no agent covers.
    swarm.on_event = on_event

    try:
        tasks = swarm.plan(
            files, only_agents=list(only_agents) or None, run_all=all_agents
        )
    except KeyError as e:
        reporter.print_error(str(e).strip('"'))
        sys.exit(1)

    if not tasks:
        reporter.print_warning("No agent matched these files.")
        sys.exit(0)
    progress.update(hunt_task, total=len(tasks))

    if not quiet:
        reporter.print_swarm_plan(
            swarm.stats_for(files, tasks),
            sorted({t["agent"].name for t in tasks}),
        )

    try:
        with progress:
            result = swarm.run(
                files,
                only_agents=list(only_agents) or None,
                run_all=all_agents,
                verify=not no_verify,
                synthesize=not no_summary,
                tasks=tasks,
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Swarm interrupted by user.[/yellow]")
        sys.exit(130)
    finally:
        client.close()


    if stdout_json:
        click.echo(_json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        report_path = reporter.save_swarm_report(result, output_path=output)
        saved_json = reporter.save_swarm_json(result, output_path=json_path)
        reporter.print_swarm_result(result, report_path, saved_json)

    if fail_on:
        threshold = SEVERITY_RANK[fail_on]
        if any(f.rank <= threshold for f in result.findings):
            sys.exit(2)


if __name__ == "__main__":
    cli()
