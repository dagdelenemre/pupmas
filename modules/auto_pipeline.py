#!/usr/bin/env python3
"""
Automated Pipeline Module
One-command full reconnaissance, exploitation, and reporting
"""

import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from modules.reconnaissance import ReconnaissanceEngine, HostInfo
from modules.exploitation import ExploitationEngine, ExploitationResult
from core.mitre_handler import MITREHandler
from core.cve_handler import CVEHandler
from core.attack_schemas import AttackSchemaEngine
from core.timeline_manager import TimelineManager
from core.siem_handler import SIEMHandler
from utils.db_manager import DatabaseManager
from utils.helpers import print_info, print_success, print_warning, print_error

@dataclass
class PipelineConfig:
    """Pipeline configuration"""
    target: str
    operation_type: str = "pentest"  # pentest, ctf, redteam, blueTeam
    recon_profile: str = "active"  # passive, active, aggressive
    enable_exploitation: bool = True
    enable_timeline: bool = True
    enable_siem: bool = True
    generate_report: bool = True
    report_format: str = "html"  # html, pdf, json
    database_save: bool = True
    session_id: Optional[str] = None

@dataclass
class PipelineResult:
    """Complete pipeline results"""
    target: str
    recon_results: Optional[HostInfo] = None
    exploitation_results: Optional[ExploitationResult] = None
    timeline_id: Optional[str] = None
    report_path: Optional[str] = None
    vulnerabilities_found: int = 0
    cves_found: int = 0
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    duration: float = 0.0

class AutomatedPipeline:
    """Fully automated scanning and exploitation pipeline"""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.result = PipelineResult(target=config.target)
        
        # Initialize all engines
        self.recon = ReconnaissanceEngine()
        self.exploit = ExploitationEngine()
        self.mitre = MITREHandler()
        self.cve = CVEHandler()
        self.schemas = AttackSchemaEngine()
        self.timeline_mgr = TimelineManager()
        self.siem = SIEMHandler()
        self.db = DatabaseManager()
        
        self.start_time = time.time()
    
    def run(self) -> PipelineResult:
        """Run complete automated pipeline"""
        try:
            print("\n" + "="*70)
            print("PUPMAS AUTOMATED PIPELINE".center(70))
            print("="*70 + "\n")
            
            print_info(f"Target: {self.config.target}")
            print_info(f"Operation Type: {self.config.operation_type}")
            print_info(f"Profile: {self.config.recon_profile}\n")
            
            # Phase 1: Reconnaissance
            self._phase_reconnaissance()
            
            # Phase 2: Exploitation
            if self.config.enable_exploitation:
                self._phase_exploitation()
            
            # Phase 3: CVE Analysis
            self._phase_cve_analysis()
            
            # Phase 4: Timeline & MITRE Mapping
            if self.config.enable_timeline:
                self._phase_timeline_mitre()
            
            # Phase 5: SIEM Analysis
            if self.config.enable_siem:
                self._phase_siem()
            
            # Phase 6: Database & Reporting
            self._phase_finalization()
            
            # Calculate duration
            self.result.end_time = datetime.now().isoformat()
            self.result.duration = time.time() - self.start_time
            
            # Print summary
            self._print_summary()
            
            return self.result
            
        except Exception as e:
            print_error(f"Pipeline error: {e}")
            import traceback
            traceback.print_exc()
            return self.result
    
    def _phase_reconnaissance(self):
        """Phase 1: Full network reconnaissance"""
        print("\n" + "="*70)
        print("PHASE 1: RECONNAISSANCE".center(70))
        print("="*70 + "\n")
        
        print_info("Starting reconnaissance scan...")
        self.result.recon_results = self.recon.full_scan(
            self.config.target,
            self.config.recon_profile
        )
        
        if self.result.recon_results.alive:
            print_success(f"[✓] Host is alive: {self.result.recon_results.ip}")
            print_success(f"[✓] Found {len(self.result.recon_results.open_ports)} open ports")
            
            # Print port details
            if self.result.recon_results.open_ports:
                print("\n  Open Ports:")
                for port in self.result.recon_results.open_ports:
                    banner_preview = port.banner[:50] if port.banner else ""
                    print(f"    {port.port}/{port.protocol} - {port.service} - {banner_preview}")
            
            # Print services
            if self.result.recon_results.services:
                print("\n  Detected Services:")
                for service, version in self.result.recon_results.services.items():
                    print(f"    {service}: {version}")
            
            # Print subdomains
            if self.result.recon_results.subdomain:
                print("\n  Subdomains Found:")
                for subdomain in self.result.recon_results.subdomain[:10]:
                    print(f"    {subdomain}")
        else:
            print_warning("[!] Target not reachable")
    
    def _phase_exploitation(self):
        """Phase 2: Web vulnerability exploitation"""
        print("\n" + "="*70)
        print("PHASE 2: EXPLOITATION TESTING".center(70))
        print("="*70 + "\n")
        
        if not self.result.recon_results or not self.result.recon_results.open_ports:
            print_warning("[!] No web services found, skipping exploitation")
            return
        
        # Find HTTP services
        http_ports = [p for p in self.result.recon_results.open_ports 
                     if p.port in [80, 8080, 443, 8443]]
        
        if not http_ports:
            print_warning("[!] No HTTP services found")
            return
        
        for port_info in http_ports:
            protocol = "https" if port_info.port in [443, 8443] else "http"
            # Use domain name instead of IP for proper testing
            target_host = self.config.target if not self.config.target.replace('.','').isdigit() else self.result.recon_results.ip
            # Don't show port for standard ports
            if (protocol == "http" and port_info.port == 80) or (protocol == "https" and port_info.port == 443):
                target_url = f"{protocol}://{target_host}"
            else:
                target_url = f"{protocol}://{target_host}:{port_info.port}"
            
            print_info(f"Testing {target_url}...")
            
            try:
                exploitation_result = self.exploit.full_website_scan(target_url)
                self.result.exploitation_results = exploitation_result
                self.result.vulnerabilities_found = len(exploitation_result.vulnerabilities)
                
                if exploitation_result.vulnerabilities:
                    print_success(f"[✓] Found {len(exploitation_result.vulnerabilities)} vulnerabilities")
                    
                    for vuln in exploitation_result.vulnerabilities[:5]:
                        print(f"    {vuln.vuln_type} ({vuln.severity}): {vuln.parameter}")
                else:
                    print_info("[*] No vulnerabilities found in automated tests")
            
            except Exception as e:
                print_warning(f"[!] Exploitation test failed: {e}")
    
    def _phase_cve_analysis(self):
        """Phase 3: CVE and vulnerability analysis"""
        print("\n" + "="*70)
        print("PHASE 3: CVE ANALYSIS".center(70))
        print("="*70 + "\n")
        
        if not self.result.recon_results or not self.result.recon_results.services:
            print_info("[*] No services to analyze for CVEs")
            return
        
        print_info("Analyzing services for known CVEs...")
        
        total_cves = 0
        for port_info in self.result.recon_results.open_ports:
            if port_info.cves:
                for cve_id in port_info.cves[:3]:
                    cve_info = self.cve.search_cves(cve_id, limit=1)
                    if cve_info:
                        total_cves += 1
                        cve_entry = cve_info[0][0]
                        print_success(f"[✓] {cve_id}: {cve_entry.description[:60]}")
        
        self.result.cves_found = total_cves
        
        if total_cves > 0:
            print_success(f"[✓] Found {total_cves} known CVEs in services")
        else:
            print_info("[*] No known CVEs found in automated search")
    
    def _phase_timeline_mitre(self):
        """Phase 4: Timeline creation and MITRE mapping"""
        print("\n" + "="*70)
        print("PHASE 4: TIMELINE & MITRE MAPPING".center(70))
        print("="*70 + "\n")
        
        # Create timeline
        timeline_name = f"Auto Pipeline - {self.config.target}"
        timeline = self.timeline_mgr.create_timeline(
            name=timeline_name,
            timeline_type=self.config.operation_type,
            description=f"Automated {self.config.operation_type} scan"
        )
        self.result.timeline_id = timeline.timeline_id
        
        print_success(f"[✓] Created timeline: {timeline_name}")
        
        # Add reconnaissance events
        if self.result.recon_results:
            self.timeline_mgr.add_event(
                timeline.timeline_id,
                title="Reconnaissance Complete",
                description=f"Found {len(self.result.recon_results.open_ports)} open ports, {len(self.result.recon_results.services)} services",
                severity="info",
                technique="T1592"
            )
        
        # Add exploitation events
        if self.result.exploitation_results and self.result.vulnerabilities_found > 0:
            self.timeline_mgr.add_event(
                timeline.timeline_id,
                title="Vulnerabilities Discovered",
                description=f"Found {self.result.vulnerabilities_found} web vulnerabilities",
                severity="high" if self.result.vulnerabilities_found > 3 else "medium",
                technique="T1190"
            )
        
        # Add CVE events
        if self.result.cves_found > 0:
            self.timeline_mgr.add_event(
                timeline.timeline_id,
                title="CVE Analysis Complete",
                description=f"Identified {self.result.cves_found} relevant CVEs",
                severity="critical" if self.result.cves_found > 5 else "high",
                technique="T1190"
            )
        
        # MITRE mapping
        print_info("Mapping to MITRE ATT&CK framework...")
        techniques = ["T1592", "T1190", "T1190", "T1548"]  # Common techniques
        for technique in techniques:
            mitre = self.mitre.get_technique(technique)
            if mitre:
                print(f"    {mitre.id}: {mitre.name}")
    
    def _phase_siem(self):
        """Phase 5: SIEM and log analysis"""
        print("\n" + "="*70)
        print("PHASE 5: SIEM ANALYSIS".center(70))
        print("="*70 + "\n")
        
        print_info("Generating simulated SIEM logs...")
        
        # Generate appropriate logs based on findings
        log_type = "reconnaissance"
        if self.result.vulnerabilities_found > 0:
            log_type = "exploitation"
        if self.result.cves_found > 0:
            log_type = "attack"
        
        logs = self.siem.generate_logs(log_type, count=20)
        print_success(f"[✓] Generated {len(logs)} log entries")
        
        # Analyze logs
        analysis = self.siem.analyze_logs(logs)
        print(f"    Event Types: {list(analysis['event_types'].keys())}")
        print(f"    Critical Events: {analysis['critical_events']}")
        
        # Generate detection rules
        print_info("Generating detection rules...")
        if "exploitation" in log_type or self.result.vulnerabilities_found > 0:
            rule = self.schemas.generate_detection_rule(
                "sql-injection-pattern",
                "sigma"
            )
            if rule:
                print_success(f"[✓] Generated Sigma rule: {rule.rule_id}")
    
    def _phase_finalization(self):
        """Phase 6: Database and report generation"""
        print("\n" + "="*70)
        print("PHASE 6: FINALIZATION".center(70))
        print("="*70 + "\n")
        
        # Save to database
        if self.config.database_save:
            session_id = self.config.session_id or f"auto_{int(time.time())}"
            operation = self.db.create_operation(
                session_id=session_id,
                operation_type=self.config.operation_type,
                name=f"Auto Scan - {self.config.target}",
                metadata={
                    "target": self.config.target,
                    "profile": self.config.recon_profile,
                    "open_ports": len(self.result.recon_results.open_ports) if self.result.recon_results else 0,
                    "vulnerabilities": self.result.vulnerabilities_found,
                    "cves": self.result.cves_found
                }
            )
            print_success(f"[✓] Saved to database: {session_id}")
        
        # Generate report
        if self.config.generate_report:
            print_info("Generating comprehensive report...")
            report_path = f"reports/pupmas_report_{int(time.time())}.{self.config.report_format}"
            Path("reports").mkdir(exist_ok=True)
            
            # Create report content
            report_content = self._generate_report()
            
            with open(report_path, 'w') as f:
                if self.config.report_format == "json":
                    import json
                    f.write(json.dumps(report_content, indent=2, default=str))
                else:
                    f.write(report_content)
            
            self.result.report_path = report_path
            print_success(f"[✓] Report generated: {report_path}")
    
    def _generate_report(self) -> str:
        """Generate HTML/JSON report"""
        if self.config.report_format == "html":
            return self._generate_html_report()
        else:
            return self._generate_json_report()
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PUPMAS Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #555; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .critical {{ color: red; }}
        .high {{ color: orange; }}
        .medium {{ color: #ffaa00; }}
        .low {{ color: blue; }}
        .summary {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>PUPMAS Automated Scan Report</h1>
    
    <div class="summary">
        <p><strong>Target:</strong> {self.config.target}</p>
        <p><strong>Operation Type:</strong> {self.config.operation_type}</p>
        <p><strong>Start Time:</strong> {self.result.start_time}</p>
        <p><strong>Duration:</strong> {self.result.duration:.2f}s</p>
    </div>
    
    <h2>Reconnaissance Results</h2>
    """
        
        if self.result.recon_results:
            html += f"""
    <table>
        <tr><th>IP Address</th><td>{self.result.recon_results.ip}</td></tr>
        <tr><th>Open Ports</th><td>{len(self.result.recon_results.open_ports)}</td></tr>
        <tr><th>Services Detected</th><td>{len(self.result.recon_results.services)}</td></tr>
    </table>
    
    <h3>Open Ports</h3>
    <table>
        <tr><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th></tr>
    """
            for port in self.result.recon_results.open_ports:
                cve_count = len(port.cves)
                html += f"<tr><td>{port.port}</td><td>{port.service}</td><td>{port.version}</td><td class='critical'>{cve_count}</td></tr>"
            html += "</table>"
        
        html += f"""
    <h2>Exploitation Results</h2>
    <p>Vulnerabilities Found: <span class='critical'>{self.result.vulnerabilities_found}</span></p>
    
    <h2>CVE Analysis</h2>
    <p>Known CVEs: <span class='high'>{self.result.cves_found}</span></p>
    
    <h2>Summary</h2>
    <ul>
        <li>Operation Duration: {self.result.duration:.2f} seconds</li>
        <li>Total Hosts Scanned: 1</li>
        <li>Total Vulnerabilities: {self.result.vulnerabilities_found}</li>
        <li>Total CVEs: {self.result.cves_found}</li>
    </ul>
    
    <footer>
        <p>Generated by PUPMAS {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </footer>
</body>
</html>
    """
        return html
    
    def _generate_json_report(self) -> dict:
        """Generate JSON report"""
        return {
            "target": self.config.target,
            "operation_type": self.config.operation_type,
            "start_time": self.result.start_time,
            "end_time": self.result.end_time,
            "duration": self.result.duration,
            "reconnaissance": {
                "ip": self.result.recon_results.ip if self.result.recon_results else None,
                "open_ports": len(self.result.recon_results.open_ports) if self.result.recon_results else 0,
                "services": self.result.recon_results.services if self.result.recon_results else {}
            },
            "exploitation": {
                "vulnerabilities_found": self.result.vulnerabilities_found
            },
            "cve_analysis": {
                "cves_found": self.result.cves_found
            }
        }
    
    def _print_summary(self):
        """Print pipeline summary"""
        print("\n" + "="*70)
        print("PIPELINE SUMMARY".center(70))
        print("="*70 + "\n")
        
        print(f"Target: {self.config.target}")
        print(f"Duration: {self.result.duration:.2f} seconds\n")
        
        print("Results:")
        print(f"  • Open Ports: {len(self.result.recon_results.open_ports) if self.result.recon_results else 0}")
        print(f"  • Services: {len(self.result.recon_results.services) if self.result.recon_results else 0}")
        print(f"  • Vulnerabilities: {self.result.vulnerabilities_found}")
        print(f"  • CVEs: {self.result.cves_found}")
        
        if self.result.report_path:
            print(f"  • Report: {self.result.report_path}")
        
        print("\n" + "="*70 + "\n")
