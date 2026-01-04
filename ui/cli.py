"""
Command-Line Interface for PUPMAS
Handles all CLI commands and operations
"""

from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from core.mitre_handler import MITREHandler
from core.cve_handler import CVEHandler
from core.attack_schemas import AttackSchemaEngine
from core.timeline_manager import TimelineManager
from core.siem_handler import SIEMHandler
from utils.db_manager import DatabaseManager
from utils.helpers import print_success, print_error, print_info, print_warning


class CLI:
    """Command-line interface handler"""
    
    def __init__(self, db_manager: DatabaseManager, args):
        """Initialize CLI with database manager and arguments"""
        self.db = db_manager
        self.args = args
        self.console = Console()
        
        # Initialize handlers
        self.mitre = MITREHandler()
        self.cve = CVEHandler()
        self.attack_schema = AttackSchemaEngine()
        self.timeline = TimelineManager()
        self.siem = SIEMHandler()
    
    def run(self):
        """Execute CLI command based on arguments"""
        try:
            # MITRE operations
            if self.args.mitre:
                self.handle_mitre_query()
            elif self.args.tactics:
                self.handle_list_tactics()
            elif self.args.techniques:
                self.handle_list_techniques()
            elif self.args.map_attack:
                self.handle_map_attack()
            
            # CVE operations
            elif self.args.cve:
                self.handle_cve_query()
            elif self.args.cve_search:
                self.handle_cve_search()
            elif self.args.cve_update:
                self.handle_cve_update()
            elif self.args.cve_recent:
                self.handle_cve_recent()
            
            # Schema operations
            elif self.args.schema:
                self.handle_schema_query()
            elif self.args.validate:
                self.handle_validate_schema()
            elif self.args.generate_rules:
                self.handle_generate_rules()
            
            # Timeline operations
            elif self.args.timeline:
                self.handle_timeline_view()
            elif self.args.add_event:
                self.handle_add_event()
            elif self.args.export_timeline:
                self.handle_export_timeline()
            
            # Reconnaissance operations
            elif self.args.recon:
                self.handle_recon()
            
            # Exfiltration testing
            elif self.args.exfil_test:
                self.handle_exfil_test()
            
            # SIEM operations
            elif self.args.siem_parse:
                self.handle_siem_parse()
            elif self.args.generate_logs:
                self.handle_generate_logs()
            
            # Reporting
            elif self.args.report:
                self.handle_generate_report()
            
            else:
                self.console.print("[yellow]No command specified. Use --help for usage.[/yellow]")
        
        except Exception as e:
            print_error(f"Error: {e}")
            if self.args.verbose > 1:
                import traceback
                traceback.print_exc()
    
    def handle_mitre_query(self):
        """Handle MITRE technique query"""
        technique = self.mitre.get_technique(self.args.mitre)
        
        if not technique:
            print_error(f"Technique {self.args.mitre} not found")
            return
        
        # Display technique information
        table = Table(title=f"MITRE ATT&CK Technique: {technique.id}", show_header=False)
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        table.add_row("ID", technique.id)
        table.add_row("Name", technique.name)
        table.add_row("Description", technique.description)
        table.add_row("Tactics", ", ".join(technique.tactics))
        table.add_row("Platforms", ", ".join(technique.platforms))
        table.add_row("Data Sources", ", ".join(technique.data_sources))
        table.add_row("Detection", technique.detection)
        table.add_row("URL", technique.url)
        
        self.console.print(table)
        
        # Display mitigations
        if technique.mitigations:
            self.console.print("\n[bold]Mitigations:[/bold]")
            for mit in technique.mitigations:
                self.console.print(f"  • [{mit['id']}] {mit['name']}: {mit['description']}")
        
        # Display subtechniques
        if technique.subtechniques:
            self.console.print(f"\n[bold]Subtechniques:[/bold] {', '.join(technique.subtechniques)}")
    
    def handle_list_tactics(self):
        """List all MITRE tactics"""
        table = Table(title="MITRE ATT&CK Tactics")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="white")
        
        for tactic in self.mitre.tactics.values():
            table.add_row(tactic.id, tactic.name, tactic.description)
        
        self.console.print(table)
    
    def handle_list_techniques(self):
        """List techniques for a tactic"""
        techniques = self.mitre.get_techniques_by_tactic(self.args.techniques)
        
        if not techniques:
            print_error(f"No techniques found for tactic: {self.args.techniques}")
            return
        
        table = Table(title=f"Techniques for {self.args.techniques}")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Platforms", style="yellow")
        
        for tech in techniques:
            table.add_row(tech.id, tech.name, ", ".join(tech.platforms[:3]))
        
        self.console.print(table)
        print_info(f"Total techniques: {len(techniques)}")
    
    def handle_map_attack(self):
        """Map attack logs to MITRE framework"""
        log_file = Path(self.args.map_attack)
        if not log_file.exists():
            print_error(f"Log file not found: {log_file}")
            return
        
        # Read log file
        with open(log_file, 'r', encoding='utf-8') as f:
            log_entries = [line.strip() for line in f if line.strip()]
        
        # Map to MITRE techniques
        mappings = self.mitre.map_logs_to_techniques(log_entries)
        
        if not mappings:
            print_warning("No MITRE techniques detected in logs")
            return
        
        table = Table(title="Attack Mapping Results")
        table.add_column("Technique ID", style="cyan")
        table.add_column("Technique Name", style="green")
        table.add_column("Matches", style="yellow")
        
        for tech_id, matches in mappings.items():
            technique = self.mitre.get_technique(tech_id)
            if technique:
                table.add_row(tech_id, technique.name, str(len(matches)))
        
        self.console.print(table)
    
    def handle_cve_query(self):
        """Handle CVE query"""
        cve = self.cve.get_cve(self.args.cve)
        
        if not cve:
            print_error(f"CVE {self.args.cve} not found")
            return
        
        # Display CVE information
        table = Table(title=f"CVE Information: {cve.cve_id}", show_header=False)
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        table.add_row("CVE ID", cve.cve_id)
        table.add_row("Severity", f"[bold {self._severity_color(cve.severity)}]{cve.severity}[/]")
        table.add_row("CVSS Score", f"{cve.score}")
        table.add_row("Published", cve.published_date.strftime('%Y-%m-%d'))
        table.add_row("Description", cve.description[:200] + "...")
        
        if cve.cwe_ids:
            table.add_row("CWE IDs", ", ".join(cve.cwe_ids))
        
        if cve.vulnerable_products:
            table.add_row("Products", ", ".join(cve.vulnerable_products[:5]))
        
        table.add_row("Exploit Available", "Yes" if cve.exploit_available else "No")
        
        self.console.print(table)
        
        # Show risk assessment
        risk_info = self.cve.calculate_risk_score(cve)
        self.console.print(f"\n[bold]Risk Score:[/bold] {risk_info['risk_score']}")
        self.console.print(f"[bold]Priority:[/bold] {risk_info['priority']}")
    
    def handle_cve_search(self):
        """Search CVEs"""
        results = self.cve.search_cves(query=self.args.cve_search, limit=20)
        
        if not results:
            print_warning("No CVEs found matching query")
            return
        
        table = Table(title=f"CVE Search Results: '{self.args.cve_search}'")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Score", style="white")
        table.add_column("Description", style="white", max_width=50)
        
        for cve, score in results[:15]:
            table.add_row(
                cve.cve_id,
                cve.severity,
                f"{cve.score:.1f}",
                cve.description[:80] + "..."
            )
        
        self.console.print(table)
        print_info(f"Showing {min(15, len(results))} of {len(results)} results")
    
    def handle_cve_update(self):
        """Update CVE database"""
        print_info("Updating CVE database...")
        count = self.cve.update_database()
        print_success(f"Updated {count} CVEs")
    
    def handle_cve_recent(self):
        """Show recent CVEs"""
        recent = self.cve.get_recent_cves(days=self.args.cve_recent)
        
        table = Table(title=f"Recent CVEs (Last {self.args.cve_recent} days)")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Published", style="white")
        table.add_column("Description", style="white", max_width=50)
        
        for cve in recent[:20]:
            table.add_row(
                cve.cve_id,
                cve.severity,
                cve.published_date.strftime('%Y-%m-%d'),
                cve.description[:80] + "..."
            )
        
        self.console.print(table)
    
    def handle_schema_query(self):
        """Query attack schema"""
        schemas = self.attack_schema.search_schemas(self.args.schema)
        
        if not schemas:
            print_error(f"Schema not found: {self.args.schema}")
            return
        
        for schema in schemas[:5]:
            panel = Panel(
                f"[bold]Description:[/bold] {schema.description}\n"
                f"[bold]Phases:[/bold] {', '.join(p.value for p in schema.attack_phases)}\n"
                f"[bold]MITRE Techniques:[/bold] {', '.join(schema.mitre_techniques)}\n"
                f"[bold]Indicators:[/bold] {len(schema.indicators)}\n"
                f"[bold]Detection Rules:[/bold] {len(schema.detection_rules)}",
                title=f"[cyan]{schema.name}[/cyan]",
                border_style="blue"
            )
            self.console.print(panel)
    
    def handle_validate_schema(self):
        """Validate attack schema"""
        schema_file = Path(self.args.validate)
        if not schema_file.exists():
            print_error(f"Schema file not found: {schema_file}")
            return
        
        import json
        with open(schema_file, 'r') as f:
            schema_data = json.load(f)
        
        is_valid, errors = self.attack_schema.validate_schema(schema_data)
        
        if is_valid:
            print_success("Schema is valid!")
        else:
            print_error("Schema validation failed:")
            for error in errors:
                print_error(f"  • {error}")
    
    def handle_generate_rules(self):
        """Generate detection rules"""
        print_info("Generating detection rules for all schemas...")
        
        count = 0
        for schema in self.attack_schema.schemas.values():
            # Generate Sigma rules
            sigma_rule = self.attack_schema.generate_detection_rule(
                schema.schema_id, 'sigma'
            )
            if sigma_rule:
                count += 1
        
        print_success(f"Generated {count} detection rules")
    
    def handle_timeline_view(self):
        """View timeline"""
        timelines = self.timeline.get_timelines_by_type(self.args.timeline)
        
        if not timelines:
            print_warning(f"No {self.args.timeline} timelines found")
            return
        
        # Show most recent timeline
        timeline = timelines[0]
        
        self.console.print(self.timeline.visualize_timeline(timeline.timeline_id))
        
        # Show summary
        summary = self.timeline.generate_timeline_summary(timeline.timeline_id)
        self.console.print(f"\n[bold]Summary:[/bold]")
        self.console.print(f"Events: {summary['event_count']}")
        self.console.print(f"Duration: {summary['duration']}")
    
    def handle_add_event(self):
        """Add event to timeline"""
        event_type, action, details = self.args.add_event
        
        # Get or create timeline
        timelines = self.timeline.get_timelines_by_type(event_type)
        if not timelines:
            timeline = self.timeline.create_timeline(
                name=f"{event_type.title()} Timeline",
                timeline_type=event_type
            )
        else:
            timeline = timelines[0]
        
        # Add event
        event = self.timeline.add_event(
            timeline.timeline_id,
            title=action,
            description=details,
            severity="medium"
        )
        
        if event:
            print_success(f"Event added to timeline: {event.event_id}")
        else:
            print_error("Failed to add event")
    
    def handle_export_timeline(self):
        """Export timeline"""
        timelines = list(self.timeline.timelines.values())
        if not timelines:
            print_error("No timelines to export")
            return
        
        output_path = Path(self.args.export_timeline)
        
        # Export first timeline
        success = self.timeline.export_to_json(timelines[0].timeline_id, output_path)
        
        if success:
            print_success(f"Timeline exported to {output_path}")
        else:
            print_error("Failed to export timeline")
    
    def handle_siem_parse(self):
        """Parse SIEM logs"""
        log_file = Path(self.args.siem_parse)
        if not log_file.exists():
            print_error(f"Log file not found: {log_file}")
            return
        
        print_info(f"Parsing logs from {log_file}...")
        
        logs = self.siem.parse_file(log_file, self.args.siem_format)
        
        print_success(f"Parsed {len(logs)} log entries")
        
        # Analyze logs
        analysis = self.siem.analyze_logs(logs)
        
        self.console.print("\n[bold]Analysis Results:[/bold]")
        self.console.print(f"Total Logs: {analysis['total_logs']}")
        self.console.print(f"Time Span: {analysis['time_span']}")
        self.console.print(f"Critical Events: {analysis['critical_events']}")
        
        # Export if requested
        if self.args.siem_export:
            output_path = Path(self.args.siem_export)
            self.siem.export_logs(logs, output_path, format='json')
            print_success(f"Logs exported to {output_path}")
    
    def handle_generate_logs(self):
        """Generate sample logs"""
        print_info(f"Generating {self.args.generate_logs} scenario logs...")
        
        logs = self.siem.generate_logs(self.args.generate_logs, count=100)
        
        print_success(f"Generated {len(logs)} log entries")
        
        # Save to file
        output_path = Path(f"logs_{self.args.generate_logs}.json")
        self.siem.export_logs(logs, output_path, format='json')
        print_success(f"Logs saved to {output_path}")
    
    def handle_generate_report(self):
        """Generate comprehensive report"""
        print_info("Generating comprehensive report...")
        
        # Collect data
        stats = self.db.get_statistics()
        
        # Create report content
        report_content = f"""
# PUPMAS Security Report

Generated: {self.siem._generate_normal_logs.__globals__['datetime'].now().isoformat()}

## Statistics

- Total Operations: {stats['total_operations']}
- Active Operations: {stats['active_operations']}
- Total Scans: {stats['total_scans']}
- Total Vulnerabilities: {stats['total_vulnerabilities']}
- Open Vulnerabilities: {stats['open_vulnerabilities']}
- Critical Vulnerabilities: {stats['critical_vulnerabilities']}
- Total Artifacts: {stats['total_artifacts']}

## Findings

[Report findings would be listed here]

## Recommendations

[Security recommendations would be listed here]
"""
        
        output_file = self.args.output or f"pupmas_report.{self.args.format}"
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print_success(f"Report generated: {output_path}")
    
    def handle_recon(self):
        """Handle reconnaissance scan"""
        target = getattr(self.args, 'recon_target', None)
        if not target:
            print_error("Target required for reconnaissance")
            return
        
        from modules.reconnaissance import ReconnaissanceEngine
        
        print_info(f"Starting reconnaissance on {target}...")
        print_info(f"Profile: {self.args.recon_profile}")
        
        recon = ReconnaissanceEngine()
        results = recon.full_scan(target, self.args.recon_profile)
        
        # Display results
        table = Table(title=f"Reconnaissance Results: {target}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("IP Address", results.ip)
        table.add_row("Status", "✓ Alive" if results.alive else "✗ Down")
        table.add_row("Open Ports", str(len(results.open_ports)))
        table.add_row("Services", str(len(results.services)))
        table.add_row("Subdomains", str(len(results.subdomain)))
        
        self.console.print(table)
        
        if results.open_ports:
            ports_table = Table(title="Open Ports")
            ports_table.add_column("Port", style="cyan")
            ports_table.add_column("Service", style="green")
            ports_table.add_column("Banner", style="white")
            
            for port in results.open_ports[:20]:
                ports_table.add_row(
                    str(port.port),
                    port.service,
                    port.banner[:50] if port.banner else "-"
                )
            
            self.console.print(ports_table)
        
        print_success(f"Reconnaissance complete for {target}")
    
    def handle_exfil_test(self):
        """Handle exfiltration testing"""
        if not self.args.method:
            print_error("Exfiltration method required (--method dns|http|https|icmp|smtp)")
            return
        
        print_info(f"Testing {self.args.method.upper()} exfiltration method...")
        print_warning("This is a simulated test - no actual data will be exfiltrated")
        
        # Simulate exfiltration test
        import time
        time.sleep(1)
        
        table = Table(title=f"{self.args.method.upper()} Exfiltration Test")
        table.add_column("Test", style="cyan")
        table.add_column("Result", style="white")
        
        table.add_row("Method", self.args.method.upper())
        table.add_row("Detection", "✓ Method available")
        table.add_row("Stealth", "Medium")
        table.add_row("Bandwidth", "Variable")
        
        self.console.print(table)
        print_success("Exfiltration test complete")
    
    def _severity_color(self, severity: str) -> str:
        """Get color for severity"""
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'NONE': 'white'
        }
        return colors.get(severity.upper(), 'white')
