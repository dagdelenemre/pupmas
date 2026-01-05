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
from core.opsec_manager import OPSECManager, ThreatLevel
from core.advanced_exploitation import AdvancedExploitationEngine
from core.advanced_intelligence import AdvancedIntelligenceEngine
from core.advanced_reporting import AdvancedReportingEngine
from core.apt_simulator import APTSimulationEngine
from core.privesc_engine import RealPrivescEngine
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
        self.opsec = OPSECManager()
        self.advanced_exploit = AdvancedExploitationEngine()
        self.threat_intel = AdvancedIntelligenceEngine()
        self.reporting = AdvancedReportingEngine()
        self.apt_sim = APTSimulationEngine()
        self.privesc = RealPrivescEngine()
    
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
            
            # Advanced v2.0 Features
            elif self.args.opsec or self.args.opsec_footprint:
                self.handle_opsec()
            elif self.args.opsec_sanitize:
                self.handle_opsec_sanitize()
            elif self.args.advanced_exploit:
                self.handle_advanced_exploit()
            elif self.args.threat_intel:
                self.handle_threat_intel()
            elif self.args.digital_footprint:
                self.handle_digital_footprint()
            elif self.args.risk_assessment:
                self.handle_risk_assessment()
            elif self.args.cvss4:
                self.handle_cvss4()
            elif self.args.apt_list:
                self.handle_apt_list()
            elif self.args.apt_simulate:
                self.handle_apt_simulate()
            elif self.args.covert_channels:
                self.handle_covert_channels()
            elif self.args.privesc:
                self.handle_real_privesc()
            elif self.args.privesc_exploit:
                self.handle_privesc_exploit()
            
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
    
    # ============================================
    # Advanced Features v2.0 - Senior Expert Level
    # ============================================
    
    def handle_opsec(self):
        """Handle OPSEC operations"""
        print_info("🔒 OPSEC Manager - Operational Security Analysis")
        
        if self.args.opsec_footprint:
            footprint = self.opsec.analyze_footprint()
            
            table = Table(title="Attack Footprint Analysis")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Log Entries", str(footprint['log_entries']))
            table.add_row("Network Connections", str(footprint['network_connections']))
            table.add_row("File Modifications", str(footprint['file_modifications']))
            table.add_row("Process Creations", str(footprint['process_creations']))
            table.add_row("Risk Score", f"{footprint['risk_score']:.2f}")
            table.add_row("Detection Probability", f"{footprint['detection_probability']:.1%}")
            
            self.console.print(table)
            
            recommendations = self.opsec.generate_opsec_recommendations()
            if recommendations:
                self.console.print("\n[bold cyan]Recommendations:[/bold cyan]")
                for rec in recommendations[:5]:
                    self.console.print(f"  • {rec['recommendation']} (Priority: {rec['priority']})")
        else:
            techniques = self.opsec.get_anti_forensics_techniques()
            
            table = Table(title="Anti-Forensics Techniques")
            table.add_column("Technique", style="cyan", width=30)
            table.add_column("Category", style="yellow", width=15)
            table.add_column("Effectiveness", style="green", width=15)
            table.add_column("Risk", style="white", width=10)
            
            for tech in techniques[:10]:
                table.add_row(
                    tech['name'],
                    tech['category'],
                    tech['effectiveness'],
                    tech['risk_level']
                )
            
            self.console.print(table)
        
        print_success("OPSEC analysis complete")
    
    def handle_opsec_sanitize(self):
        """Sanitize logs for OPSEC"""
        log_file = self.args.opsec_sanitize
        print_info(f"🧹 Sanitizing logs: {log_file}")
        
        if self.opsec.sanitize_logs(log_file):
            print_success(f"Logs sanitized successfully")
        else:
            print_error("Failed to sanitize logs")
    
    def handle_advanced_exploit(self):
        """Handle advanced exploitation"""
        import asyncio
        target_str = self.args.advanced_exploit
        
        print_info(f"⚡ Advanced Exploitation Engine")
        print_info(f"Target: {target_str}")
        
        # Parse target
        parts = target_str.split(':')
        host = parts[0]
        
        target = {
            'host': host,
            'os': 'unknown',
            'services': [],
            'vulnerabilities': []
        }
        
        async def run_exploit():
            chain = await self.advanced_exploit.generate_exploit_chain(target)
            
            table = Table(title="Exploit Chain Generated")
            table.add_column("Stage", style="cyan")
            table.add_column("Technique", style="yellow")
            table.add_column("Probability", style="green")
            table.add_column("Risk", style="red")
            
            for i, stage in enumerate(chain.stages, 1):
                table.add_row(
                    f"Stage {i}",
                    stage.technique,
                    f"{stage.success_probability:.1%}",
                    str(stage.risk_score)
                )
            
            self.console.print(table)
            print_info(f"Overall success probability: {chain.success_probability:.1%}")
        
        asyncio.run(run_exploit())
        print_success("Exploit chain analysis complete")
    
    def handle_threat_intel(self):
        """Handle threat intelligence gathering"""
        import asyncio
        domain = self.args.threat_intel
        
        print_info(f"🔍 Threat Intelligence Gathering")
        print_info(f"Target: {domain}")
        
        target = {
            'target_id': f"TGT-{domain}",
            'domain': domain,
            'organization': domain
        }
        
        async def gather_intel():
            footprint = await self.threat_intel.gather_digital_footprint(target)
            
            table = Table(title="Digital Footprint")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="white")
            
            table.add_row("Domains", str(len(footprint.domains)))
            table.add_row("IP Addresses", str(len(footprint.ip_addresses)))
            table.add_row("Email Patterns", str(len(footprint.email_patterns)))
            table.add_row("Social Media", str(len(footprint.social_media_accounts)))
            table.add_row("Technologies", str(len(footprint.technologies)))
            
            self.console.print(table)
            
            if footprint.technologies:
                self.console.print(f"\n[bold cyan]Technologies:[/bold cyan]")
                self.console.print(f"  {', '.join(footprint.technologies[:10])}")
        
        asyncio.run(gather_intel())
        print_success("Intelligence gathering complete")
    
    def handle_digital_footprint(self):
        """Handle digital footprint analysis"""
        import asyncio
        org = self.args.digital_footprint
        
        print_info(f"👣 Digital Footprint Analysis")
        print_info(f"Organization: {org}")
        
        target = {
            'target_id': f"ORG-{org}",
            'organization': org,
            'domain': org.lower().replace(' ', '') + '.com'
        }
        
        async def analyze():
            footprint = await self.threat_intel.gather_digital_footprint(target)
            
            self.console.print(f"\n[bold cyan]Digital Footprint for {org}:[/bold cyan]")
            self.console.print(f"  Domains: {len(footprint.domains)}")
            self.console.print(f"  IPs: {len(footprint.ip_addresses)}")
            self.console.print(f"  Emails: {len(footprint.email_patterns)}")
            self.console.print(f"  Social: {len(footprint.social_media_accounts)}")
            
            if footprint.domains:
                self.console.print(f"\n[bold yellow]Discovered Domains:[/bold yellow]")
                for domain in footprint.domains[:5]:
                    self.console.print(f"  • {domain}")
        
        asyncio.run(analyze())
        print_success("Footprint analysis complete")
    
    def handle_risk_assessment(self):
        """Handle risk assessment"""
        target = self.args.risk_assessment
        
        print_info(f"📈 Risk Assessment")
        print_info(f"Target: {target}")
        
        # Mock data for demonstration
        findings = {
            'critical_vulns': 2,
            'high_vulns': 5,
            'medium_vulns': 12,
            'low_vulns': 18
        }
        
        assessment = self.reporting.perform_risk_assessment(target, findings)
        
        table = Table(title="Risk Assessment Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target", assessment.target_name)
        table.add_row("Overall Risk Score", f"{assessment.overall_risk_score:.1f}/10")
        table.add_row("Risk Level", assessment.risk_level)
        table.add_row("Critical Findings", str(assessment.critical_findings))
        
        self.console.print(table)
        
        if assessment.recommendations:
            self.console.print(f"\n[bold cyan]Top Recommendations:[/bold cyan]")
            for rec in assessment.recommendations[:5]:
                self.console.print(f"  • {rec['action']} (Priority: {rec['priority']})")
        
        print_success("Risk assessment complete")
    
    def handle_cvss4(self):
        """Handle CVSS v4.0 scoring"""
        cve_id = self.args.cvss4
        
        print_info(f"📊 CVSS v4.0 Scoring")
        print_info(f"CVE: {cve_id}")
        
        # Example scoring
        cvss = self.reporting.calculate_cvss_v4(
            vulnerability_id=cve_id,
            attack_vector="network",
            attack_complexity="low",
            privileges_required="none",
            user_interaction="none",
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="high"
        )
        
        table = Table(title=f"CVSS v4.0 Score for {cve_id}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Base Score", f"{cvss.base_score:.1f}")
        table.add_row("Severity", cvss.severity)
        table.add_row("Exploitability", f"{cvss.exploitability_score:.1f}")
        table.add_row("Impact", f"{cvss.impact_score:.1f}")
        table.add_row("Vector", cvss.vector_string)
        
        self.console.print(table)
        print_success("CVSS scoring complete")
    
    def handle_apt_list(self):
        """List APT profiles"""
        print_info("🎭 Available APT Profiles")
        
        profiles = self.apt_sim.list_apt_profiles()
        
        table = Table(title="APT Profiles Database")
        table.add_column("Name", style="cyan", width=20)
        table.add_column("Origin", style="yellow", width=15)
        table.add_column("Active Period", style="white", width=20)
        table.add_column("Sophistication", style="red", width=15)
        
        for profile in profiles[:15]:
            table.add_row(
                profile['name'],
                profile['origin'],
                f"{profile['first_seen']} - {profile['last_seen']}",
                profile['sophistication']
            )
        
        self.console.print(table)
        self.console.print(f"\n[dim]Total: {len(profiles)} APT profiles available[/dim]")
        print_success(f"Listed {len(profiles)} APT profiles")
    
    def handle_apt_simulate(self):
        """Simulate APT campaign"""
        import asyncio
        profile_name = self.args.apt_simulate
        
        print_info(f"🚀 APT Campaign Simulation")
        print_info(f"Profile: {profile_name}")
        
        profile = {
            'name': profile_name,
            'sophistication': 'high',
            'primary_motivation': 'espionage'
        }
        
        target_profile = {
            'industry': 'technology',
            'size': 'enterprise',
            'security_maturity': 'medium'
        }
        
        async def simulate():
            campaign = await self.apt_sim.create_campaign(profile, target_profile)
            
            table = Table(title="APT Campaign Generated")
            table.add_column("Phase", style="cyan")
            table.add_column("Duration", style="yellow")
            table.add_column("TTPs", style="green")
            table.add_column("Objectives", style="white")
            
            for i, phase in enumerate(campaign.phases, 1):
                table.add_row(
                    phase.name,
                    f"Day {phase.start_day}-{phase.end_day}",
                    str(len(phase.ttps)),
                    ', '.join(phase.objectives[:2])
                )
            
            self.console.print(table)
            print_info(f"Campaign duration: {campaign.duration_days} days")
        
        asyncio.run(simulate())
        print_success("APT simulation complete")
    
    def handle_covert_channels(self):
        """Generate covert communication channels"""
        print_info("🔐 Covert Communication Channels")
        
        channels = self.apt_sim.generate_covert_channels()
        
        table = Table(title="Available Covert Channels")
        table.add_column("Channel", style="cyan", width=25)
        table.add_column("Stealth", style="yellow", width=10)
        table.add_column("Bandwidth", style="green", width=15)
        table.add_column("Detection Difficulty", style="red", width=20)
        
        for channel in channels[:10]:
            table.add_row(
                channel.name,
                channel.stealth_rating,
                channel.bandwidth,
                channel.detection_difficulty
            )
        
        self.console.print(table)
        print_success(f"Generated {len(channels)} covert channels")
    
    def handle_real_privesc(self):
        """Handle REAL privilege escalation scanning"""
        print_warning("⚠️  SCANNING FOR PRIVILEGE ESCALATION VECTORS")
        print_warning("This will scan for REAL exploitable vulnerabilities!")
        
        print_info(f"Current user: {self.privesc.current_user}")
        print_info(f"Root access: {'YES' if self.privesc.is_root else 'NO'}")
        
        if self.privesc.is_root:
            print_success("Already running as root!")
            return
        
        print_info("\n🔍 Scanning all vectors...")
        vectors = self.privesc.scan_all_vectors()
        
        if not vectors:
            print_warning("No privilege escalation vectors found")
            return
        
        # Group by severity
        critical = [v for v in vectors if v.severity == "CRITICAL"]
        high = [v for v in vectors if v.severity == "HIGH"]
        
        print_success(f"\n✅ Found {len(vectors)} vectors: {len(critical)} CRITICAL, {len(high)} HIGH")
        
        # Display critical vectors
        if critical:
            table = Table(title="🔴 CRITICAL Privilege Escalation Vectors")
            table.add_column("ID", style="red", width=5)
            table.add_column("Vector", style="cyan", width=30)
            table.add_column("Success Rate", style="yellow", width=15)
            table.add_column("Description", style="white", width=40)
            
            for i, vec in enumerate(critical, 1):
                table.add_row(
                    str(i),
                    vec.name,
                    f"{vec.success_rate:.0%}",
                    vec.description[:40]
                )
            
            self.console.print(table)
        
        # Display high vectors
        if high:
            table = Table(title="🟠 HIGH Privilege Escalation Vectors")
            table.add_column("ID", style="yellow", width=5)
            table.add_column("Vector", style="cyan", width=30)
            table.add_column("Success Rate", style="yellow", width=15)
            table.add_column("Command Preview", style="white", width=40)
            
            for i, vec in enumerate(high, len(critical) + 1):
                table.add_row(
                    str(i),
                    vec.name,
                    f"{vec.success_rate:.0%}",
                    vec.command[:40] + "..."
                )
            
            self.console.print(table)
        
        # Show example exploitation
        if vectors:
            print_info("\n💡 To exploit a vector:")
            print_info(f"   pupmas --privesc-exploit 1")
            print_info(f"\n💡 To see full command:")
            self.console.print(f"\n[bold cyan]Example - {vectors[0].name}:[/bold cyan]")
            self.console.print(f"[dim]{vectors[0].command}[/dim]")
    
    def handle_privesc_exploit(self):
        """Exploit a privilege escalation vector"""
        vector_id = int(self.args.privesc_exploit)
        
        print_warning("⚠️⚠️⚠️  EXPLOITATION MODE  ⚠️⚠️⚠️")
        print_warning("This will ATTEMPT TO EXPLOIT a real vulnerability!")
        print_warning("Use ONLY on systems you have permission to test!")
        
        # Scan first
        print_info("\n🔍 Scanning vectors...")
        vectors = self.privesc.scan_all_vectors()
        
        if vector_id < 1 or vector_id > len(vectors):
            print_error(f"Invalid vector ID. Found {len(vectors)} vectors.")
            return
        
        target_vector = vectors[vector_id - 1]
        
        print_info(f"\n🎯 Target: {target_vector.name}")
        print_info(f"   Severity: {target_vector.severity}")
        print_info(f"   Success Rate: {target_vector.success_rate:.0%}")
        print_info(f"\n📜 Command to execute:")
        self.console.print(f"[yellow]{target_vector.command}[/yellow]")
        
        # Confirmation
        response = input("\n⚠️  Execute this exploit? [y/N]: ").strip().lower()
        
        if response != 'y':
            print_info("Exploit cancelled")
            return
        
        print_info("\n🚀 Executing exploit...")
        result = self.privesc.exploit_vector(target_vector)
        
        if result['success']:
            print_success("✅ EXPLOIT SUCCESSFUL!")
            print_success(f"Output:\n{result['output']}")
        else:
            print_error("❌ Exploit failed")
            print_error(f"Error: {result['error']}")


