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
from modules.technology_detection import TechnologyDetector, TechStack
from modules.waf_bypass import WAFBypass, WAFInfo
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
    tech_stack: Optional[TechStack] = None
    waf_info: Optional[WAFInfo] = None
    exploitation_results: Optional[ExploitationResult] = None
    mitre_techniques: list = field(default_factory=list)
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
        self.tech_detector = TechnologyDetector()
        self.waf_bypass = WAFBypass()
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
            
            # Phase 1.5: Technology Detection & WAF/CDN Analysis
            self._phase_technology_waf()
            
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
    
    def _phase_technology_waf(self):
        """Phase 1.5: Technology detection, WAF/CDN analysis"""
        print("\n" + "="*70)
        print("PHASE 1.5: TECHNOLOGY & WAF DETECTION".center(70))
        print("="*70 + "\n")
        
        if not self.result.recon_results or not self.result.recon_results.alive:
            return
        
        # Find HTTP ports
        http_ports = [p for p in self.result.recon_results.open_ports 
                     if p.port in [80, 8080, 443, 8443]]
        
        if not http_ports:
            print_warning("[!] No HTTP services found")
            return
        
        # Use first HTTP port for analysis
        port_info = http_ports[0]
        protocol = "https" if port_info.port in [443, 8443] else "http"
        
        # Use domain name if available
        target_host = self.config.target if not self.config.target.replace('.','').isdigit() else self.result.recon_results.ip
        
        if (protocol == "http" and port_info.port == 80) or (protocol == "https" and port_info.port == 443):
            target_url = f"{protocol}://{target_host}"
        else:
            target_url = f"{protocol}://{target_host}:{port_info.port}"
        
        # Detect WAF/CDN
        print_info("[*] Detecting WAF/CDN protection...")
        self.result.waf_info = self.waf_bypass.detect_waf(target_url)
        self.result.mitre_techniques.append("T1595.002")  # Active Scanning: Vulnerability Scanning
        
        # Try WAF bypass if detected
        if self.result.waf_info.detected:
            print_info(f"[*] Attempting {self.result.waf_info.name} bypass...")
            bypass_result = self.waf_bypass.bypass_cloudflare(target_url)
            if bypass_result["bypassed"]:
                print_success(f"[+] WAF bypass successful: {bypass_result['method']}")
                target_url = bypass_result["working_url"]
                self.result.mitre_techniques.append("T1562.001")  # Impair Defenses: Disable or Modify Tools
        
        # Technology fingerprinting
        print_info("[*] Fingerprinting web technologies...")
        self.result.tech_stack = self.tech_detector.detect(target_url)
        self.result.mitre_techniques.append("T1592.002")  # Gather Victim Host Information: Software
        
        if self.result.tech_stack.technologies:
            print_success(f"[+] Detected {len(self.result.tech_stack.technologies)} technologies\n")
            
            print("  Technology Stack:")
            if self.result.tech_stack.server:
                print(f"    Server: {self.result.tech_stack.server}")
            if self.result.tech_stack.cms:
                print(f"    CMS: {self.result.tech_stack.cms}")
            if self.result.tech_stack.framework:
                print(f"    Framework: {self.result.tech_stack.framework}")
            if self.result.tech_stack.programming_language:
                print(f"    Language: {self.result.tech_stack.programming_language}")
            if self.result.tech_stack.cdn:
                print(f"    CDN: {self.result.tech_stack.cdn}")
            if self.result.tech_stack.waf:
                print(f"    WAF: {self.result.tech_stack.waf}")
            
            # Get CVEs for detected technologies
            print_info("\n[*] Searching for known CVEs in detected technologies...")
            total_cves = 0
            for tech in self.result.tech_stack.technologies:
                if tech.version:
                    cves = self.tech_detector.get_cves_for_technology(tech.name, tech.version)
                    tech.cves = cves
                    if cves:
                        total_cves += len(cves)
                        print_warning(f"[!] {tech.name} {tech.version}: {len(cves)} known CVEs")
                        for cve in cves[:3]:  # Show first 3
                            print(f"      - {cve}")
            
            self.result.cves_found = total_cves
            if total_cves > 0:
                self.result.mitre_techniques.append("T1588.006")  # Obtain Capabilities: Vulnerabilities
    
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
        
        # Test real IP if Cloudflare bypassed
        if self.result.waf_info and self.result.waf_info.real_ip:
            print_info(f"\n[*] Testing real IP directly: {self.result.waf_info.real_ip}")
            print_info("[*] Using direct IP connection to bypass Cloudflare...")
            
            # Test real IP with Host header manipulation
            for port in [80, 443]:
                protocol = "https" if port == 443 else "http"
                real_url = f"{protocol}://{self.result.waf_info.real_ip}"
                
                try:
                    print_info(f"  Testing {real_url} (bypassing CDN)...")
                    # Use IP in URL but set Host header to original domain
                    import requests
                    session = requests.Session()
                    
                    # Test with Host header set to domain
                    response = session.get(
                        real_url,
                        headers={'Host': self.config.target},
                        timeout=10,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # Check if we bypassed Cloudflare
                    if 'cloudflare' not in response.headers.get('Server', '').lower():
                        print_success(f"[+] Successfully bypassed Cloudflare on port {port}!")
                        print_info(f"    Real server: {response.headers.get('Server', 'Unknown')}")
                        
                        # Now run full scan with Host header
                        real_result = self.exploit.full_website_scan(real_url, host_header=self.config.target)
                        if real_result.vulnerabilities:
                            self.result.vulnerabilities_found += len(real_result.vulnerabilities)
                            self.result.exploitation_results.vulnerabilities.extend(real_result.vulnerabilities)
                            print_success(f"[+] Found {len(real_result.vulnerabilities)} additional vulns on real IP!")
                    else:
                        print_warning(f"[!] Still hitting Cloudflare on real IP port {port}")
                        
                except Exception as e:
                    print_warning(f"[!] Real IP test error: {e}")
            
            # Test subdomains on real IP
            if self.result.recon_results and self.result.recon_results.subdomain:
                print_info("\n[*] Testing subdomains on real IP...")
                for subdomain_info in self.result.recon_results.subdomain:
                    subdomain = subdomain_info.split('(')[0].strip()
                    subdomain_ip = subdomain_info.split('(')[1].rstrip(')') if '(' in subdomain_info else None
                    
                    # Only test if subdomain is on real IP
                    if subdomain_ip == self.result.waf_info.real_ip:
                        print_info(f"  Testing {subdomain} (on real IP)...")
                        try:
                            sub_result = self.exploit.full_website_scan(f"http://{subdomain}")
                            if sub_result.vulnerabilities:
                                self.result.vulnerabilities_found += len(sub_result.vulnerabilities)
                                self.result.exploitation_results.vulnerabilities.extend(sub_result.vulnerabilities)
                                print_success(f"[+] Found {len(sub_result.vulnerabilities)} vulns on {subdomain}!")
                        except Exception as e:
                            pass
    
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
    <title>PUPMAS Scan Report - {self.config.target}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }}
        h3 {{ color: #555; margin-top: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: 600; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #e9ecef; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        .summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .summary p {{ margin: 10px 0; }}
        .tech-badge {{ display: inline-block; background: #3498db; color: white; padding: 5px 10px; border-radius: 4px; margin: 5px; }}
        .cve-badge {{ display: inline-block; background: #e74c3c; color: white; padding: 3px 8px; border-radius: 3px; margin: 2px; font-size: 0.9em; }}
        .mitre-badge {{ display: inline-block; background: #9b59b6; color: white; padding: 3px 8px; border-radius: 3px; margin: 2px; font-size: 0.9em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; border-left: 4px solid #3498db; padding: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; font-size: 0.9em; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ PUPMAS Professional Security Assessment Report</h1>
    
    <div class="summary">
        <h3 style="margin-top:0; color:white;">Scan Configuration</h3>
        <p><strong>🎯 Target:</strong> {self.config.target}</p>
        <p><strong>📋 Operation Type:</strong> {self.config.operation_type.upper()}</p>
        <p><strong>⏰ Start Time:</strong> {self.result.start_time}</p>
        <p><strong>⏱️ Duration:</strong> {self.result.duration:.2f} seconds</p>
        <p><strong>🔍 Profile:</strong> {self.config.recon_profile.upper()}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{self.result.vulnerabilities_found}</div>
            <div class="stat-label">Vulnerabilities Found</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{self.result.cves_found}</div>
            <div class="stat-label">Known CVEs</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(self.result.recon_results.open_ports) if self.result.recon_results else 0}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(self.result.tech_stack.technologies) if self.result.tech_stack else 0}</div>
            <div class="stat-label">Technologies Detected</div>
        </div>
    </div>
"""

        # Technology Stack Section
        if self.result.tech_stack and self.result.tech_stack.technologies:
            html += """
    <h2>🔬 Technology Stack Detection</h2>
    <p>Detected web technologies, frameworks, and infrastructure components:</p>
    
    <div style="margin: 20px 0;">
"""
            if self.result.tech_stack.server:
                html += f'<span class="tech-badge">🖥️ Server: {self.result.tech_stack.server}</span>'
            if self.result.tech_stack.cms:
                html += f'<span class="tech-badge">📝 CMS: {self.result.tech_stack.cms}</span>'
            if self.result.tech_stack.framework:
                html += f'<span class="tech-badge">⚙️ Framework: {self.result.tech_stack.framework}</span>'
            if self.result.tech_stack.programming_language:
                html += f'<span class="tech-badge">💻 Language: {self.result.tech_stack.programming_language}</span>'
            if self.result.tech_stack.cdn:
                html += f'<span class="tech-badge">🌐 CDN: {self.result.tech_stack.cdn}</span>'
            if self.result.tech_stack.waf:
                html += f'<span class="tech-badge">🛡️ WAF: {self.result.tech_stack.waf}</span>'
            
            html += "</div>"
            
            # Detailed technology table with CVEs
            html += """
    <h3>Detailed Technology Analysis</h3>
    <table>
        <tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th><th>Known CVEs</th></tr>
"""
            for tech in self.result.tech_stack.technologies:
                cve_display = ""
                if tech.cves:
                    cve_display = "".join([f'<span class="cve-badge">{cve}</span>' for cve in tech.cves])
                confidence_class = "high" if tech.confidence >= 90 else "medium" if tech.confidence >= 70 else "low"
                
                html += f"""
        <tr>
            <td><strong>{tech.name}</strong></td>
            <td>{tech.version or 'N/A'}</td>
            <td>{tech.category}</td>
            <td class="{confidence_class}">{tech.confidence}%</td>
            <td>{cve_display or '<span class="info">None</span>'}</td>
        </tr>
"""
            html += "</table>"
        
        # WAF/CDN Section
        if self.result.waf_info and self.result.waf_info.detected:
            html += f"""
    <h2>🛡️ WAF/CDN Protection Analysis</h2>
    <table>
        <tr><th>Protection Type</th><td><strong>{self.result.waf_info.name}</strong></td></tr>
        <tr><th>Detected</th><td class="high">✓ Yes</td></tr>
        <tr><th>Bypass Possible</th><td class="{'high' if self.result.waf_info.bypass_possible else 'info'}">{' ✓ Yes' if self.result.waf_info.bypass_possible else '✗ No'}</td></tr>
"""
            if self.result.waf_info.real_ip:
                html += f'<tr><th>Real IP</th><td class="critical">{self.result.waf_info.real_ip}</td></tr>'
            if self.result.waf_info.bypass_methods:
                html += f'<tr><th>Bypass Methods</th><td>{", ".join(self.result.waf_info.bypass_methods)}</td></tr>'
            html += "</table>"
        
        # Reconnaissance Results
        html += "<h2>🔍 Reconnaissance Results</h2>"
        
        if self.result.recon_results:
            html += f"""
    <table>
        <tr><th>IP Address</th><td>{self.result.recon_results.ip}</td></tr>
        <tr><th>Hostname</th><td>{self.result.recon_results.target}</td></tr>
        <tr><th>Status</th><td class="high">{'✓ Alive' if self.result.recon_results.alive else '✗ Down'}</td></tr>
        <tr><th>Open Ports</th><td><strong>{len(self.result.recon_results.open_ports)}</strong></td></tr>
        <tr><th>Services Detected</th><td><strong>{len(self.result.recon_results.services)}</strong></td></tr>
        <tr><th>Subdomains Found</th><td><strong>{len(self.result.recon_results.subdomain)}</strong></td></tr>
    </table>
    
    <h3>Open Ports & Services</h3>
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th></tr>
"""
            for port in self.result.recon_results.open_ports:
                banner_preview = port.banner[:80] if port.banner else "-"
                html += f"""
        <tr>
            <td><strong>{port.port}</strong></td>
            <td>{port.protocol.upper()}</td>
            <td>{port.service}</td>
            <td>{port.version or 'N/A'}</td>
            <td style="font-size:0.85em; color:#666;">{banner_preview}</td>
        </tr>
"""
            html += "</table>"
            
            # Subdomains
            if self.result.recon_results.subdomain:
                html += """
    <h3>Discovered Subdomains</h3>
    <table>
        <tr><th>#</th><th>Subdomain</th></tr>
"""
                for idx, subdomain in enumerate(self.result.recon_results.subdomain[:20], 1):
                    html += f"<tr><td>{idx}</td><td>{subdomain}</td></tr>"
                html += "</table>"
        
        # Exploitation Results
        html += f"""
    <h2>⚔️ Exploitation & Vulnerability Assessment</h2>
    <p><strong>Total Vulnerabilities Found:</strong> <span class="critical">{self.result.vulnerabilities_found}</span></p>
"""
        
        if self.result.exploitation_results and self.result.exploitation_results.vulnerabilities:
            html += """
    <table>
        <tr><th>Type</th><th>Severity</th><th>URL</th><th>Parameter</th><th>Payload</th></tr>
"""
            for vuln in self.result.exploitation_results.vulnerabilities[:50]:  # Limit to 50
                html += f"""
        <tr>
            <td><strong>{vuln.vuln_type}</strong></td>
            <td class="{vuln.severity}">{vuln.severity.upper()}</td>
            <td style="font-size:0.85em; word-break:break-all;">{vuln.url}</td>
            <td>{vuln.parameter}</td>
            <td style="font-size:0.85em; font-family:monospace;">{vuln.payload[:50]}</td>
        </tr>
"""
            html += "</table>"
        else:
            html += '<p class="info">No vulnerabilities detected in automated tests.</p>'
        
        # MITRE ATT&CK Techniques
        if self.result.mitre_techniques:
            html += """
    <h2>🎯 MITRE ATT&CK Techniques Used</h2>
    <p>Techniques employed during this assessment:</p>
    <div style="margin: 20px 0;">
"""
            for technique in set(self.result.mitre_techniques):
                html += f'<span class="mitre-badge">{technique}</span>'
            html += "</div>"
        
        html += f"""
    <h2>📊 Assessment Summary</h2>
    <ul style="line-height: 2;">
        <li><strong>Operation Duration:</strong> {self.result.duration:.2f} seconds</li>
        <li><strong>Total Hosts Scanned:</strong> 1</li>
        <li><strong>Technologies Identified:</strong> {len(self.result.tech_stack.technologies) if self.result.tech_stack else 0}</li>
        <li><strong>Total Vulnerabilities:</strong> <span class="critical">{self.result.vulnerabilities_found}</span></li>
        <li><strong>Known CVEs:</strong> <span class="high">{self.result.cves_found}</span></li>
        <li><strong>MITRE Techniques:</strong> {len(set(self.result.mitre_techniques))}</li>
    </ul>
    
    <footer>
        <p>🛡️ Generated by <strong>PUPMAS Professional Security Framework</strong></p>
        <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p style="font-size:0.85em; color:#95a5a6;">This report is confidential and intended solely for authorized security assessment purposes.</p>
    </footer>
</div>
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
