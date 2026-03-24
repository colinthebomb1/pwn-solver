"""CLI entry point for pwn-solver."""

from __future__ import annotations

import os
import sys

import click
from dotenv import load_dotenv
from rich.console import Console

console = Console()


@click.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--remote", "-r", default=None, help="Remote target as host:port")
@click.option("--model", "-m", default="claude-sonnet-4-20250514", help="Anthropic model to use")
@click.option("--max-iterations", "-n", default=30, help="Max agent iterations")
def main(binary: str, remote: str | None, model: str, max_iterations: int) -> None:
    """pwn-solver — Agentic binary exploitation powered by LLMs and MCP tools."""
    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] ANTHROPIC_API_KEY not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)

    from agent.core import PwnAgent

    agent = PwnAgent(model=model, max_iterations=max_iterations, api_key=api_key)
    result = agent.solve(binary_path=binary, remote=remote)

    console.print()
    if result.success:
        console.print("[bold green]✓ Solve complete[/bold green]")
        if result.exploit_script:
            console.print("\n[bold]Final exploit script:[/bold]")
            from rich.syntax import Syntax

            console.print(Syntax(result.exploit_script, "python", theme="monokai"))
    else:
        console.print("[bold red]✗ Solve failed[/bold red]")

    console.print(f"\n[dim]Iterations: {result.iterations} | Tool calls: {len(result.tool_calls)}[/dim]")


if __name__ == "__main__":
    main()
