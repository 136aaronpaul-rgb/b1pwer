"""
b1pwer.ui.app - Main Textual TUI application
"""
import time
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import (
    Header, Footer, Button, Label, Input,
    Select, DataTable, ProgressBar, RichLog, Tab, TabbedContent
)
from textual import work
from ..modules.scanner import B1pwerScanner, HostResult
from ..modules.reporter import Reporter
from .. import __version__, __author__, __org__, __website__


class B1pwerApp(App):
    CSS = """
    #header-bar {
        height: 3;
        background: $primary;
        color: $text;
        content-align: center middle;
    }
    #target-input { width: 1fr; margin: 1 0; }
    #profile-select { width: 1fr; margin: 1 0; }
    #scan-button { width: 1fr; height: 3; margin: 1 0; }
    #progress-container { height: 3; margin: 1 0; display: none; }
    #results-log { height: 1fr; margin: 1 0; }
    """
    TITLE = "b1pwer"
    SUB_TITLE = f"v{__version__} | {__org__}"
    BINDINGS = [("q", "quit", "Quit"), ("s", "start_scan", "Scan")]

    def __init__(self):
        super().__init__()
        self.scanner = B1pwerScanner()
        self.reporter = Reporter()
        self.last_result = None
        self._scan_done = False

    def compose(self):
        yield Header()
        yield Label("⚡ B1PWER v1.0 — Aaron Paulos Division", id="header-bar")
        with TabbedContent(id="main-tabs"):
            with Tab("🔍 Scan"):
                yield Input(placeholder="Enter target (IP or domain)...", id="target-input")
                yield Select([
                    ("Quick (top 19 ports, ~10s)", "quick"),
                    ("Standard (1-1024 + versions, ~60s)", "standard"),
                    ("Full (all 65535 + scripts, ~5min)", "full"),
                    ("Aggressive (all + OS detection, ~10min)", "aggressive"),
                    ("Vulnerability (full + vuln scripts, ~15min)", "vuln"),
                    ("Discovery (ping scan only)", "discovery"),
                ], value="quick", id="profile-select")
                yield Button("⚡ START SCAN", variant="success", id="scan-button")
                with Container(id="progress-container"):
                    yield ProgressBar(id="scan-progress", total=100)
                yield RichLog(id="results-log", wrap=True, markup=True)
            with Tab("📊 Results"):
                yield DataTable(id="results-table")
            with Tab("📄 Reports"):
                yield RichLog(id="reports-log", wrap=True, markup=True)
            with Tab("ℹ️ About"):
                with Vertical():
                    yield Label("")
                    yield Label("    ⚡ B1PWER v1.0")
                    yield Label("")
                    yield Label(f"    Built by: {__author__}")
                    yield Label(f"    Organization: {__org__}")
                    yield Label(f"    Website: {__website__}")
                    yield Label("")
                    yield Label("    Features:")
                    yield Label("    • Full 65535 port scanning (TCP)")
                    yield Label("    • Service version detection")
                    yield Label("    • OS fingerprinting")
                    yield Label("    • DNS enumeration (A, AAAA, MX, NS, TXT, SOA)")
                    yield Label("    • Web service analysis + security headers")
                    yield Label("    • Vulnerability detection (NSE scripts)")
                    yield Label("    • IP geolocation + ASN lookup")
                    yield Label("    • Network-wide scanning (CIDR)")
                    yield Label("    • Multi-format reports (HTML, JSON)")
                    yield Label("    • Interactive TUI")
                    yield Label("")
                    yield Label("    ⚠️  For authorized security testing only.")
        yield Footer()

    @work(thread=True)
    def _run_scan(self, target, profile):
        log = self.query_one("#results-log", RichLog)
        progress = self.query_one("#scan-progress", ProgressBar)
        progress_container = self.query_one("#progress-container", Container)
        try:
            self.call_from_thread(progress_container.styles.display, "block")
            self.call_from_thread(log.print, f"[bold cyan]⚡ Starting {profile} scan on {target}...[/bold cyan]")
            result = self.scanner.scan(target, profile)
            self._scan_done = True
            self.call_from_thread(self._display_results, result)
        except Exception as e:
            self.call_from_thread(log.print, f"[bold red]✗ Error: {e}[/bold red]")
            self.call_from_thread(progress_container.styles.display, "none")

    def _display_results(self, result):
        log = self.query_one("#results-log", RichLog)
        progress_container = self.query_one("#progress-container", Container)
        progress_container.styles.display = "none"
        log.print(f"""
[bold green]✓ SCAN COMPLETE[/bold green]
Target: [bold]{result.target}[/bold] → {result.ip}
Hostname: {result.hostname or 'N/A'}
OS: {result.os_guess or 'N/A'}
Location: {result.geo}
Org: {result.org} (ASN: {result.asn})
Duration: {result.scan_duration:.1f}s
Open Ports: [bold]{len(result.ports)}[/bold]
Vulnerabilities: [bold red]{len(result.vulnerabilities)}[/bold red]
""")
        if result.ports:
            log.print("[bold cyan]🔌 Open Ports:[/bold cyan]")
            for p in result.ports:
                ver = f" ({p.version})" if p.version else ""
                log.print(f"  [yellow]{p.port}/{p.protocol}[/yellow] → {p.service}{ver}")
        if result.web_info.get("title"):
            log.print(f"\n[bold cyan]🌐 Web:[/bold cyan] {result.web_info['title']}")
            log.print(f"  Server: {result.web_info.get('server', 'N/A')}")
        if result.vulnerabilities:
            log.print("\n[bold red]⚠️  Vulnerabilities:[/bold red]")
            for v in result.vulnerabilities:
                color = "red" if v["severity"] in ["CRITICAL", "HIGH"] else "yellow"
                log.print(f"  [{color}]{v['severity']}[/] {v['script']} (port {v['port']})")
        paths = self.reporter.save_all(result)
        log.print(f"\n[green]📄 Reports saved:[/green]")
        for fmt, path in paths.items():
            log.print(f"  {fmt}: {path}")
        table = self.query_one("#results-table", DataTable)
        table.clear()
        table.add_columns("Port", "Proto", "State", "Service", "Version")
        for p in result.ports:
            table.add_row(str(p.port), p.protocol, p.state, p.service, p.version)
        reports_log = self.query_one("#reports-log", RichLog)
        for fmt, path in paths.items():
            reports_log.print(f"[green]✓ {fmt}:[/green] {path}")

    def on_button_pressed(self, event):
        if event.button.id == "scan-button":
            target = self.query_one("#target-input", Input).value.strip()
            if not target:
                log = self.query_one("#results-log", RichLog)
                log.print("[red]✗ Enter a target first.[/red]")
                return
            profile = self.query_one("#profile-select", Select).value
            self._scan_done = False
            self.scanner.progress = 0
            self._run_scan(target, profile)

    def action_start_scan(self):
        self.query_one("#scan-button", Button).press()
