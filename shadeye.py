#!/usr/bin/env python3
"""
👁️ ShadEye - Real-time TrafficShaper log viewer
"""

import time
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.live import Live

LOG_FILE = Path("logs/trafficshaper_log.jsonl")
console = Console()

def tail(file, lines=20):
    """Vrati poslednjih N linija loga"""
    with file.open("r", encoding="utf-8") as f:
        return f.readlines()[-lines:]

def parse_log_line(line):
    try:
        entry = json.loads(line)
        return {
            "time": entry.get("timestamp", "")[-8:],
            "method": entry.get("method", "-"),
            "url": entry.get("url", "-")[:50],
            "status": entry.get("status_code", "-"),
            "agent": entry.get("agent", "-"),
        }
    except Exception:
        return None

def build_table(entries):
    table = Table(title="🕶️ ShadEye: Traffic Monitor", style="bold cyan")
    table.add_column("Time", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("URL", style="white", overflow="fold")
    table.add_column("Status", style="bold")
    table.add_column("Agent", style="magenta")

    for e in entries:
        status_color = "green" if str(e["status"]).startswith("2") else "red"
        table.add_row(e["time"], e["method"], e["url"], f"[{status_color}]{e['status']}[/{status_color}]", e["agent"])
    
    return table

def main():
    console.print("👁️ [bold cyan]ShadEye pokrenut... Gledam saobraćaj[/]")
    if not LOG_FILE.exists():
        console.print(f"[red]❌ Log fajl ne postoji:[/] {LOG_FILE}")
        return

    last_size = 0
    with Live(console=console, refresh_per_second=2) as live:
        while True:
            try:
                lines = tail(LOG_FILE, 20)
                entries = [parse_log_line(l) for l in lines if parse_log_line(l)]
                table = build_table(entries)
                live.update(table)
                time.sleep(1)
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    main()
