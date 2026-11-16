from cerebrum.config.config_manager import config
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED

from cerebrum.config.config_manager import config
from cerebrum.manager.tool import ToolManager

import sys

def list_local_tools():
    console = Console()
    
    with console.status("[bold green]Scanning for local tools..."):
        tool_manager = ToolManager(config.get_kernel_url())
        tools = tool_manager.list_local_tools()
    
    if not tools:
        console.print(Panel("[bold yellow]No local tools found", title="Local Tool List"))
        return
    
    # Create a table with row separators and rounded borders
    table = Table(
        title="Available Local Tools",
        box=ROUNDED,
        show_header=True,
        header_style="bold white on blue",
        show_lines=True,  # This adds horizontal lines between rows
    )
    
    # Add columns to the table with adjusted widths
    # table.add_column("Name", style="cyan bold", no_wrap=True)
    table.add_column("Path", style="green", width=40, overflow="fold")
    table.add_column("How to Call", style="magenta", no_wrap=True)
    
    # Add rows to the table
    for tool in tools:
        # name = tool.get("name", "Unknown")
        path = tool.get("path", "Unknown path")
        id_to_call = tool.get("name", "Unknown")
        
        table.add_row(path, id_to_call)
    
    # Print the table
    console.print("\n")  # Add some space before the table
    console.print(table)
    
    # Print summary and usage instructions
    summary = Text()
    summary.append(f"\nTotal local tools available: ", style="bold")
    summary.append(f"{len(tools)}", style="bold green")
    console.print(summary)
    
    usage = Panel(
        "[bold]How to use local tools in your code:[/bold]\n\n"
        "from cerebrum.tool import AutoTool\n\n"
        "# Load a local tool\n"
        "tool = AutoTool.from_preloaded(\"tool_name\", local=True)",
        title="Usage Example",
        border_style="green"
    )
    console.print(usage)
    console.print("\n")  # Add some space after the summary

def main(): 
    list_local_tools()

if __name__ == "__main__":
    sys.exit(main())