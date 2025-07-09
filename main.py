import asyncio
import json
import socket
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from rich.table import Table
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import (
    Button, Footer, Static, Input, DataTable, ProgressBar
)
from textual.reactive import reactive

class Config:
    DEFAULT_PORTS = "21,22,25,80,443,3306,8080,8443"
    CONNECTION_TIMEOUT = 1.5
    CONCURRENCY = 250
    CVE_DB_PATH = Path("cve_db.json")

VULN_DB: Dict[str, Any] = {}

def load_vuln_db() -> str:
    global VULN_DB
    if Config.CVE_DB_PATH.exists():
        try:
            with open(Config.CVE_DB_PATH, "r", encoding="utf-8") as f:
                VULN_DB = json.load(f)
            return f"[green]OK[/] | CVE Database: [bold]{len(VULN_DB)}[/] entries"
        except json.JSONDecodeError:
            VULN_DB = {}
            return "[red]FAIL[/] | CVE Database: Invalid JSON format"
        except Exception as e:
            VULN_DB = {}
            return f"[red]FAIL[/] | CVE Database: Error loading ({e})"
    else:
        VULN_DB = {}
        return "[yellow]WARN[/] | CVE Database: cve_db.json not found"

class DashboardHeader(Static):
    stats = reactive("Idle")

    def render(self) -> Table:
        header_table = Table.grid(expand=True, padding=(0, 1))
        header_table.add_column(justify="left", ratio=1)
        header_table.add_column(justify="center", ratio=2)
        header_table.add_column(justify="right", ratio=1)
        header_table.add_row(
            "[link=https://github.com/DeCryptMan][bold #00FFFF]Cerberus v5.1 - Sentinel Nexus[/] [bold #00FF00]@DeCryptMan[/][/link]",
            f"[white]{self.stats}[/]",
            datetime.now().ctime(),
        )
        return header_table

async def resolve_host(hostname: str) -> tuple[str | None, str | None]:
    try:
        socket.inet_aton(hostname)
        return hostname, None
    except socket.error:
        try:
            info = await asyncio.get_event_loop().getaddrinfo(hostname, None)
            return info[0][4][0], None
        except socket.gaierror as e:
            return None, f"DNS resolution failed: {e}"
        except Exception as e:
            return None, f"Unexpected resolution error: {e}"

async def probe_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        with closing(writer):
            banner = ""
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            return {"port": port, "status": "open", "banner": banner or "N/A"}
    except Exception:
        return None

class CerberusApp(App):
    font_family = "monospace"

    CSS = """
    Screen {
        layout: vertical;
        background: #0D1117;
        color: #00FF00;
    }
    #header {
        height: 3;
        background: #003300;
        padding-top: 1;
        border-bottom: solid #00FF00;
        text-align: center;
    }
    #app-body {
        layout: horizontal;
        height: 1fr;
    }
    #sidebar {
        width: 30%;
        min-width: 40;
        height: 100%;
        padding: 1 2;
        border-right: solid #00AA00;
        background: #1A222C;
    }
    #main-panel {
        width: 1fr;
        height: 100%;
        padding: 1 2;
        background: #121820;
    }
    .input-group {
        margin-top: 2;
    }
    Input {
        background: #001A00;
        color: #00FFFF;
        border: round #00AA00;
    }
    Button {
        background: #006600;
        color: #00FF00;
        border: round #00FF00;
        text-style: bold;
    }
    Button:hover {
        background: #00AA00;
    }
    #results-table {
        margin-top: 1;
        height: 1fr;
        border: round #00FF00;
        background: #001A00;
    }
    DataTable {
        background: #001A00;
        color: #00FF00;
    }
    DataTable > .data-table--header {
        background: #004400;
        color: #00FFFF;
        text-style: bold;
    }
    DataTable > .data-table--cursor {
        background: #008800;
    }
    #progress-bar {
        margin-top: 1;
        height: 1;
        background: #001A00;
        color: #00FF00;
    }
    .title {
        text-style: bold italic;
        background: #002200;
        color: #00FFFF;
        padding: 0 1;
        width: 100%;
        border-bottom: dashed #00AA00;
    }
    Footer {
        background: #003300;
        border-top: solid #00FF00;
    }
    Static {
        color: #00FF00;
    }
    .text--link {
        color: #00FFFF;
        text-style: underline;
    }
    """
    BINDINGS = [("q", "quit", "Quit"), ("ctrl+s", "save_report", "Save Report")]

    def __init__(self):
        super().__init__()
        self.scan_results = []

    def compose(self) -> ComposeResult:
        yield DashboardHeader(id="header")
        with Horizontal(id="app-body"):
            with Vertical(id="sidebar"):
                yield Static("Scan Configuration", classes="title")
                with Container(classes="input-group"):
                    yield Static("Targets (IP, domain, comma-separated):")
                    yield Input(placeholder="e.g., scanme.nmap.org", id="targets-input")
                with Container(classes="input-group"):
                    yield Static("Ports (e.g., 21-25,80,443):")
                    yield Input(value=Config.DEFAULT_PORTS, id="ports-input")
                yield Button("Start Scan", variant="success", id="start-scan", classes="input-group")
            with Vertical(id="main-panel"):
                yield Static("Scan Results", classes="title")
                yield ProgressBar(total=100, show_eta=True, id="progress-bar")
                yield DataTable(id="results-table")
        yield Footer()

    def on_mount(self) -> None:
        header = self.query_one(DashboardHeader)
        header.stats = load_vuln_db()
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("Host", "Port", "Service", "Banner", "Findings")
        self.query_one("#progress-bar").visible = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start-scan":
            targets = self.query_one("#targets-input").value
            ports_str = self.query_one("#ports-input").value
            if targets and ports_str:
                self.run_worker(self.scanner_worker(targets, ports_str), exclusive=True)
            else:
                self.notify("Please enter targets and ports.", title="Input Required", severity="warning")

    async def scanner_worker(self, targets_str: str, ports_str: str):
        header = self.query_one(DashboardHeader)
        table = self.query_one(DataTable)
        progress_bar = self.query_one("#progress-bar")
        
        self.query_one("#start-scan").disabled = True
        table.clear()
        self.scan_results = []
        progress_bar.visible = True
        
        ports = self._parse_ports(ports_str)
        if not ports:
            self.notify("Invalid port format. Please use e.g., '21-25,80,443'.", title="Error", severity="error")
            self.query_one("#start-scan").disabled = False
            return
            
        targets = [t.strip() for t in targets_str.split(",") if t.strip()]
        if not targets:
            self.notify("No valid targets entered.", title="Error", severity="error")
            self.query_one("#start-scan").disabled = False
            return

        total_probes = len(targets) * len(ports)
        
        progress_bar.total = total_probes
        progress_bar.progress = 0
        
        completed_probes = 0
        vulnerabilities_found = 0

        for target_host in targets:
            ip, error = await resolve_host(target_host)
            if error:
                table.add_row(f"[red]{target_host}[/red]", "N/A", "N/A", f"Resolution failed: {error}", "[red]Error[/red]")
                completed_probes += len(ports)
                progress_bar.progress = completed_probes
                self._update_header_stats(completed_probes, total_probes, vulnerabilities_found)
                continue

            semaphore = asyncio.Semaphore(Config.CONCURRENCY)
            scan_tasks = []

            async def scan_task(port):
                nonlocal completed_probes, vulnerabilities_found
                async with semaphore:
                    result = await probe_port(ip, port, Config.CONNECTION_TIMEOUT)
                    if result:
                        findings, is_vuln = self._analyze_findings(result)
                        if is_vuln:
                            vulnerabilities_found += 1
                        
                        row_data = (ip, str(port), "Unknown", result["banner"], findings)
                        self.scan_results.append({
                            "host": ip, "port": port, "banner": result["banner"], "findings": findings
                        })
                        table.add_row(*row_data)
                    
                    completed_probes += 1
                    progress_bar.progress = completed_probes
                    self._update_header_stats(completed_probes, total_probes, vulnerabilities_found)

            for port in ports:
                scan_tasks.append(asyncio.create_task(scan_task(port)))
            
            await asyncio.gather(*scan_tasks)

        header.stats = f"[green]Scan Complete[/] | Found [bold red]{vulnerabilities_found}[/] vulnerabilities."
        self.query_one("#start-scan").disabled = False

    def _update_header_stats(self, completed: int, total: int, found: int):
        self.query_one(DashboardHeader).stats = f"Scanning: {completed}/{total} | Found: [bold red]{found}[/]"

    def _analyze_findings(self, result: dict) -> tuple[str, bool]:
        banner = result["banner"]
        for service_key, vuln_info in VULN_DB.items():
            if service_key.lower() in banner.lower():
                return f"[bold red]VULN:[/] {vuln_info.get('cve', 'N/A')} ({vuln_info.get('severity', 'N/A')})", True
        return "[dim]Clean[/dim]", False

    def _parse_ports(self, ports_str: str) -> list[int]:
        ports = set()
        try:
            for part in ports_str.split(','):
                part = part.strip()
                if not part:
                    continue
                if '-' in part:
                    start_str, end_str = part.split('-')
                    start, end = int(start_str), int(end_str)
                    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                        raise ValueError("Port range out of bounds (1-65535) or invalid order.")
                    ports.update(range(start, end + 1))
                else:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        raise ValueError("Port out of bounds (1-65535).")
                    ports.add(port)
            return sorted(list(ports))
        except ValueError as e:
            self.notify(f"Invalid port format: {e}. Please use e.g., '21-25,80,443'.", title="Port Parsing Error", severity="error")
            return []
        except Exception as e:
            self.notify(f"An unexpected error occurred while parsing ports: {e}", title="Port Parsing Error", severity="error")
            return []

    def action_save_report(self) -> None:
        if not self.scan_results:
            self.notify("No data to save. Run a scan first.", title="Save Report", severity="warning")
            return
        
        filename = f"cerberus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.scan_results, f, indent=4, ensure_ascii=False)
            self.notify(f"Report saved to {filename}", title="Save Report", severity="information")
        except Exception as e:
            self.notify(f"Failed to save report: {e}", title="Save Report", severity="error")

if __name__ == "__main__":
    app = CerberusApp()
    app.run()
