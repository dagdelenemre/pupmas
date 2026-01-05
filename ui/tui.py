"""
Terminal User Interface for PUPMAS
Interactive dashboard using Textual framework
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, DataTable, TabbedContent, TabPane, Input, Label, Tree
from textual.binding import Binding
from rich.text import Text

from core.mitre_handler import MITREHandler
from core.cve_handler import CVEHandler
from core.attack_schemas import AttackSchemaEngine
from core.timeline_manager import TimelineManager
from core.siem_handler import SIEMHandler
from utils.db_manager import DatabaseManager


class DashboardWidget(Static):
    """Dashboard overview widget"""
    
    def __init__(self, db_manager: DatabaseManager):
        super().__init__()
        self.db = db_manager
    
    def on_mount(self) -> None:
        """Update dashboard when mounted"""
        self.update_dashboard()
    
    def update_dashboard(self) -> None:
        """Update dashboard statistics"""
        stats = self.db.get_statistics()
        
        content = f"""
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
[bold white]                    PUPMAS DASHBOARD                          [/bold white]
[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]

[yellow]Operations:[/yellow]
  • Total Operations:    {stats['total_operations']:>10}
  • Active Operations:   {stats['active_operations']:>10}

[yellow]Scanning:[/yellow]
  • Total Scans:         {stats['total_scans']:>10}

[yellow]Vulnerabilities:[/yellow]
  • Total Found:         {stats['total_vulnerabilities']:>10}
  • Open:                {stats['open_vulnerabilities']:>10}
  • Critical:            [red]{stats['critical_vulnerabilities']:>10}[/red]

[yellow]Artifacts:[/yellow]
  • Total Collected:     {stats['total_artifacts']:>10}

[green]System Status:[/green]     [bold green]● OPERATIONAL[/bold green]

[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]
"""
        self.update(content)


class MITREExplorerWidget(Static):
    """MITRE ATT&CK Explorer widget"""
    
    def __init__(self, mitre_handler: MITREHandler):
        super().__init__()
        self.mitre = mitre_handler
    
    def compose(self) -> ComposeResult:
        """Compose the MITRE explorer"""
        yield Label("MITRE ATT&CK Framework Explorer", classes="title")
        
        # Create tree of tactics and techniques
        tree: Tree[dict] = Tree("MITRE ATT&CK")
        tree.root.expand()
        
        # Add tactics
        for tactic_id, tactic in self.mitre.tactics.items():
            tactic_node = tree.root.add(f"[cyan]{tactic.name}[/cyan]", expand=False)
            
            # Add techniques for this tactic
            techniques = self.mitre.get_techniques_by_tactic(tactic.short_name)
            for tech in techniques[:10]:  # Limit to 10 per tactic
                tactic_node.add_leaf(f"[green]{tech.id}[/green] - {tech.name}")
        
        yield tree


class CVEBrowserWidget(Container):
    """CVE Browser widget"""
    
    def __init__(self, cve_handler: CVEHandler):
        super().__init__()
        self.cve = cve_handler
    
    def compose(self) -> ComposeResult:
        """Compose CVE browser"""
        yield Label("CVE Vulnerability Browser", classes="title")
        yield Input(placeholder="Search CVEs...", id="cve-search")
        yield DataTable(id="cve-table")
    
    def on_mount(self) -> None:
        """Setup CVE table when mounted"""
        table = self.query_one("#cve-table", DataTable)
        table.add_columns("CVE ID", "Severity", "Score", "Description")
        
        # Load recent CVEs
        recent = self.cve.get_recent_cves(days=30)
        for cve in recent[:20]:
            table.add_row(
                cve.cve_id,
                cve.severity,
                f"{cve.score:.1f}",
                cve.description[:60] + "..."
            )


class TimelineViewerWidget(Container):
    """Timeline Viewer widget"""
    
    def __init__(self, timeline_manager: TimelineManager):
        super().__init__()
        self.timeline_mgr = timeline_manager
    
    def compose(self) -> ComposeResult:
        """Compose timeline viewer"""
        yield Label("Operation Timelines", classes="title")
        
        # Timeline selector
        yield Label("Select Timeline Type:")
        with Horizontal():
            yield Button("Attack", id="timeline-attack", variant="primary")
            yield Button("Pentest", id="timeline-pentest", variant="primary")
            yield Button("Recon", id="timeline-recon", variant="primary")
            yield Button("Exfiltration", id="timeline-exfil", variant="primary")
        
        # Timeline display
        yield ScrollableContainer(
            Static(id="timeline-content"),
            id="timeline-scroll"
        )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle timeline button press"""
        timeline_type = event.button.id.replace("timeline-", "")
        # Map short names to full enum values
        type_mapping = {
            "attack": "attack",
            "pentest": "pentest",
            "recon": "reconnaissance",
            "exfil": "exfiltration"
        }
        timeline_type = type_mapping.get(timeline_type, timeline_type)
        self.load_timeline(timeline_type)
    
    def load_timeline(self, timeline_type: str) -> None:
        """Load and display timeline"""
        timelines = self.timeline_mgr.get_timelines_by_type(timeline_type)
        
        content_widget = self.query_one("#timeline-content", Static)
        
        if not timelines:
            content_widget.update(f"[yellow]No {timeline_type} timelines found[/yellow]")
            return
        
        # Display first timeline
        timeline = timelines[0]
        content = self.timeline_mgr.visualize_timeline(timeline.timeline_id)
        content_widget.update(content)


class SIEMLogViewerWidget(Container):
    """SIEM Log Viewer widget"""
    
    def __init__(self, siem_handler: SIEMHandler):
        super().__init__()
        self.siem = siem_handler
    
    def compose(self) -> ComposeResult:
        """Compose SIEM viewer"""
        yield Label("SIEM Log Analysis", classes="title")
        
        with Horizontal():
            yield Button("Generate Sample Logs", id="gen-logs", variant="success")
            yield Button("Correlate Events", id="correlate", variant="warning")
        
        yield DataTable(id="log-table")
        yield Static(id="log-analysis")
    
    def on_mount(self) -> None:
        """Setup log table"""
        table = self.query_one("#log-table", DataTable)
        table.add_columns("Timestamp", "Source", "Severity", "Event Type", "Message")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "gen-logs":
            self.generate_sample_logs()
        elif event.button.id == "correlate":
            self.correlate_events()
    
    def generate_sample_logs(self) -> None:
        """Generate and display sample logs"""
        logs = self.siem.generate_logs("normal", count=20)
        
        table = self.query_one("#log-table", DataTable)
        table.clear()
        
        for log in logs:
            table.add_row(
                log.timestamp.strftime('%H:%M:%S'),
                log.source,
                log.severity.name,
                log.event_type,
                log.message[:40] + "..."
            )
        
        # Show analysis
        analysis = self.siem.analyze_logs(logs)
        analysis_widget = self.query_one("#log-analysis", Static)
        analysis_widget.update(
            f"[bold]Analysis:[/bold]\n"
            f"Total Logs: {analysis['total_logs']}\n"
            f"Critical Events: {analysis['critical_events']}"
        )
    
    def correlate_events(self) -> None:
        """Correlate events and show alerts"""
        alerts = self.siem.correlate_events()
        
        analysis_widget = self.query_one("#log-analysis", Static)
        if alerts:
            content = f"[bold red]Alerts Generated: {len(alerts)}[/bold red]\n\n"
            for alert in alerts:
                content += f"[yellow]• {alert.title}[/yellow] ({alert.severity})\n"
            analysis_widget.update(content)
        else:
            analysis_widget.update("[green]No alerts generated[/green]")


class TUI(App):
    """
    PUPMAS Terminal User Interface
    Interactive dashboard for all operations
    """
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    .title {
        background: $accent;
        color: $text;
        padding: 1;
        text-align: center;
        text-style: bold;
    }
    
    Button {
        margin: 1;
    }
    
    DataTable {
        height: 20;
        margin: 1;
    }
    
    Tree {
        height: 30;
        margin: 1;
    }
    
    #timeline-scroll {
        height: 30;
        border: solid $accent;
        margin: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "dashboard", "Dashboard"),
        Binding("m", "mitre", "MITRE"),
        Binding("c", "cve", "CVE"),
        Binding("t", "timeline", "Timeline"),
        Binding("s", "siem", "SIEM"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def __init__(self, db_manager: DatabaseManager):
        super().__init__()
        self.db = db_manager
        
        # Initialize handlers
        self.mitre_handler = MITREHandler()
        self.cve_handler = CVEHandler()
        self.attack_schema = AttackSchemaEngine()
        self.timeline_manager = TimelineManager()
        self.siem_handler = SIEMHandler()
    
    def compose(self) -> ComposeResult:
        """Compose the UI"""
        yield Header(show_clock=True)
        
        with TabbedContent():
            with TabPane("Dashboard", id="tab-dashboard"):
                yield DashboardWidget(self.db)
            
            with TabPane("MITRE ATT&CK", id="tab-mitre"):
                yield MITREExplorerWidget(self.mitre_handler)
            
            with TabPane("CVE Browser", id="tab-cve"):
                yield CVEBrowserWidget(self.cve_handler)
            
            with TabPane("Timeline", id="tab-timeline"):
                yield TimelineViewerWidget(self.timeline_manager)
            
            with TabPane("SIEM Logs", id="tab-siem"):
                yield SIEMLogViewerWidget(self.siem_handler)
            
            with TabPane("About", id="tab-about"):
                yield Static("""
[bold cyan]╔═══════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]                    [bold white]PUPMAS v1.0.0[/bold white]                   [bold cyan]║[/bold cyan]
[bold cyan]╚═══════════════════════════════════════════════════════╝[/bold cyan]

[yellow]Puppeteer Master[/yellow] - Advanced Cybersecurity Operations Framework

[bold]Features:[/bold]
  • MITRE ATT&CK Integration
  • CVE Database Management
  • Attack Schema Engine
  • Timeline Tracking
  • SIEM Log Analysis
  • Comprehensive Reporting

[bold]Keyboard Shortcuts:[/bold]
  [cyan]Q[/cyan] - Quit
  [cyan]D[/cyan] - Dashboard
  [cyan]M[/cyan] - MITRE ATT&CK
  [cyan]C[/cyan] - CVE Browser
  [cyan]T[/cyan] - Timeline
  [cyan]S[/cyan] - SIEM Logs
  [cyan]R[/cyan] - Refresh

[red]⚠ Use responsibly on authorized systems only ⚠[/red]

[bold]Author:[/bold] PUPMAS Security Research Team
[bold]License:[/bold] MIT
[bold]GitHub:[/bold] github.com/yourusername/pupmas
                """, classes="about-content")
        
        yield Footer()
    
    def action_dashboard(self) -> None:
        """Switch to dashboard tab"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-dashboard"
    
    def action_mitre(self) -> None:
        """Switch to MITRE tab"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-mitre"
    
    def action_cve(self) -> None:
        """Switch to CVE tab"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-cve"
    
    def action_timeline(self) -> None:
        """Switch to timeline tab"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-timeline"
    
    def action_siem(self) -> None:
        """Switch to SIEM tab"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-siem"
    
    def action_refresh(self) -> None:
        """Refresh current view"""
        # Refresh dashboard
        try:
            dashboard = self.query_one(DashboardWidget)
            dashboard.update_dashboard()
        except:
            pass
    
    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()


if __name__ == "__main__":
    # For testing TUI independently
    from utils.db_manager import DatabaseManager
    db = DatabaseManager()
    app = TUI(db)
    app.run()
