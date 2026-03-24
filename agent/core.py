"""ReAct agent loop — drives the exploit development process via Anthropic tool_use."""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from agent.planner import plan_from_checksec
from agent.prompts import SYSTEM_PROMPT

console = Console()

# ---------------------------------------------------------------------------
# MCP client adapter — calls the exploit-tools MCP server in-process
# ---------------------------------------------------------------------------

# We load the MCP server's tools directly to avoid needing a separate process
# during development. In production, these would be MCP client calls over stdio.

_tools_module = None


def _get_tools_module():
    global _tools_module
    if _tools_module is None:
        server_dir = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "exploit-tools")
        sys.path.insert(0, os.path.abspath(server_dir))
        import server as tools_mod

        _tools_module = tools_mod
    return _tools_module


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "checksec": {
        "description": "Run checksec on a binary to identify security mitigations (RELRO, Canary, NX, PIE). Call this FIRST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
            },
            "required": ["binary_path"],
        },
    },
    "elf_symbols": {
        "description": "List symbols from an ELF binary: functions, PLT, GOT, and sections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "symbol_type": {
                    "type": "string",
                    "enum": ["all", "functions", "plt", "got"],
                    "description": "Type of symbols to list. Defaults to 'all'.",
                },
            },
            "required": ["binary_path"],
        },
    },
    "rop_gadgets": {
        "description": "Search for ROP gadgets in a binary using ropper.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "search": {
                    "type": "string",
                    "description": "Filter string (e.g. 'pop rdi', 'ret'). If omitted, returns common gadgets.",
                },
                "max_results": {"type": "integer", "description": "Max gadgets to return. Default 50."},
            },
            "required": ["binary_path"],
        },
    },
    "cyclic_pattern": {
        "description": "Generate or query a De Bruijn cyclic pattern for finding buffer overflow offsets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["generate", "find"],
                    "description": "'generate' to create a pattern, 'find' to locate offset of a crash value.",
                },
                "length": {"type": "integer", "description": "Pattern length in bytes (for generate). Default 200."},
                "value": {"type": "string", "description": "Hex value to find (for find action), e.g. '0x61616168'."},
            },
            "required": ["action"],
        },
    },
    "strings_search": {
        "description": "Extract printable strings from a binary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the ELF binary"},
                "min_length": {"type": "integer", "description": "Minimum string length. Default 4."},
            },
            "required": ["binary_path"],
        },
    },
    "run_exploit": {
        "description": "Execute a pwntools exploit script. Write a complete Python script using pwntools, and this tool will run it and return stdout/stderr/exit_code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "The pwntools exploit script as a Python string."},
                "binary_path": {"type": "string", "description": "Path to target binary (optional, set as BINARY env var)."},
                "timeout": {"type": "integer", "description": "Execution timeout in seconds. Default 15."},
            },
            "required": ["script"],
        },
    },
}


def _call_tool(name: str, arguments: dict) -> Any:
    """Dispatch a tool call to the in-process MCP server functions."""
    mod = _get_tools_module()
    func = getattr(mod, name, None)
    if func is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return func(**arguments)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

@dataclass
class AgentResult:
    success: bool
    summary: str
    iterations: int
    exploit_script: str | None = None
    tool_calls: list[dict] = field(default_factory=list)


class PwnAgent:
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int = 30,
        api_key: str | None = None,
    ):
        self.model = model
        self.max_iterations = max_iterations
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def solve(self, binary_path: str, remote: str | None = None) -> AgentResult:
        """Run the full ReAct loop to analyze and exploit a binary."""
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            return AgentResult(success=False, summary=f"Binary not found: {binary_path}", iterations=0)

        console.print(Panel(f"[bold]Target:[/bold] {binary_path}", title="pwn-solver", border_style="blue"))

        # Build tool definitions for Anthropic API
        tools = [
            {"name": name, "description": spec["description"], "input_schema": spec["input_schema"]}
            for name, spec in TOOL_REGISTRY.items()
        ]

        system = SYSTEM_PROMPT
        if remote:
            host, port = remote.split(":")
            system += f"\n\nRemote target: {host}:{port}"

        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"Analyze and exploit the binary at `{binary_path}`. "
                    f"Start with checksec, then systematically work through recon and exploitation."
                ),
            }
        ]

        all_tool_calls: list[dict] = []

        for iteration in range(1, self.max_iterations + 1):
            console.print(f"\n[dim]─── Iteration {iteration}/{self.max_iterations} ───[/dim]")

            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                tools=tools,
                messages=messages,
            )

            # Process response content blocks
            assistant_content = response.content
            tool_use_blocks = []

            for block in assistant_content:
                if block.type == "text":
                    console.print(Panel(block.text, title="Agent", border_style="green"))
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            # If no tool calls, agent is done reasoning
            if response.stop_reason == "end_turn" and not tool_use_blocks:
                summary = ""
                for block in assistant_content:
                    if block.type == "text":
                        summary += block.text
                return AgentResult(
                    success=True,
                    summary=summary,
                    iterations=iteration,
                    tool_calls=all_tool_calls,
                )

            # Execute tool calls
            if tool_use_blocks:
                messages.append({"role": "assistant", "content": assistant_content})
                tool_results = []

                for tool_block in tool_use_blocks:
                    tool_name = tool_block.name
                    tool_input = tool_block.input

                    # Display tool call
                    self._display_tool_call(tool_name, tool_input)

                    # Execute
                    start = time.time()
                    result = _call_tool(tool_name, tool_input)
                    elapsed = time.time() - start

                    # Record
                    call_record = {
                        "iteration": iteration,
                        "tool": tool_name,
                        "input": tool_input,
                        "output": result,
                        "elapsed_seconds": round(elapsed, 2),
                    }
                    all_tool_calls.append(call_record)

                    # Display result
                    self._display_tool_result(tool_name, result, elapsed)

                    # Check if this is a successful exploit
                    if tool_name == "run_exploit" and isinstance(result, dict) and result.get("success"):
                        script = tool_input.get("script", "")
                        console.print("[bold green]Exploit succeeded![/bold green]")
                        return AgentResult(
                            success=True,
                            summary="Exploit executed successfully.",
                            iterations=iteration,
                            exploit_script=script,
                            tool_calls=all_tool_calls,
                        )

                    result_str = json.dumps(result, indent=2, default=str)
                    if len(result_str) > 8000:
                        result_str = result_str[:8000] + "\n... [truncated]"

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": result_str,
                    })

                messages.append({"role": "user", "content": tool_results})

            # If stop_reason is end_turn with tool calls already processed, continue loop
            if response.stop_reason == "end_turn" and tool_use_blocks:
                continue

        return AgentResult(
            success=False,
            summary="Max iterations reached without solving the challenge.",
            iterations=self.max_iterations,
            tool_calls=all_tool_calls,
        )

    def _display_tool_call(self, name: str, inputs: dict) -> None:
        table = Table(title=f"Tool Call: {name}", border_style="cyan", show_header=False)
        table.add_column("Param", style="bold")
        table.add_column("Value")
        for k, v in inputs.items():
            val_str = str(v)
            if len(val_str) > 200:
                val_str = val_str[:200] + "..."
            table.add_row(k, val_str)
        console.print(table)

    def _display_tool_result(self, name: str, result: Any, elapsed: float) -> None:
        result_str = json.dumps(result, indent=2, default=str) if not isinstance(result, str) else result
        if len(result_str) > 2000:
            result_str = result_str[:2000] + "\n... [truncated]"
        console.print(
            Panel(result_str, title=f"Result: {name} ({elapsed:.1f}s)", border_style="yellow")
        )
