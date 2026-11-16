from cerebrum.manager.agent import AgentManager
from cerebrum.config.config_manager import config
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED

import sys

def list_agenthub_agents():
    console = Console()
    
    with console.status("[bold green]Fetching agents from AgentHub..."):
        agent_manager = AgentManager(config.get_agent_hub_url())
        agents = agent_manager.list_agenthub_agents()
    
    if not agents:
        console.print(Panel("[bold yellow]No agents found in AgentHub", title="Agent List"))
        return
    
    # Create a table with row separators and rounded borders
    table = Table(
        title="Available Agents in AgentHub",
        box=ROUNDED,
        show_header=True,
        header_style="bold white on blue",
        show_lines=True,  # This adds horizontal lines between rows
    )
    
    # Add columns to the table with adjusted widths
    table.add_column("Name", style="cyan bold", no_wrap=True)
    table.add_column("Description", style="green", width=40, overflow="fold")
    table.add_column("Author", style="blue", no_wrap=True)
    table.add_column("Latest Version", style="magenta", no_wrap=True)
    
    # Add rows to the table
    for agent in agents:
        name = agent.get("name", "Unknown")
        description = agent.get("description", "No description available")
        author = agent.get("author", "Unknown")
        version = agent.get("version", "N/A")
        
        table.add_row(name, description, author, version)
    
    # Print the table
    console.print("\n")  # Add some space before the table
    console.print(table)
    
    # Print summary
    summary = Text()
    summary.append(f"\nTotal agents available: ", style="bold")
    summary.append(f"{len(agents)}", style="bold green")
    console.print(summary)
    console.print("\n")  # Add some space after the summary

def main():
    list_agenthub_agents()

if __name__ == "__main__":
    sys.exit(main())