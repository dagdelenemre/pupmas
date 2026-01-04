#!/usr/bin/env python3
"""
PUPMAS Usage Examples
Demonstrates various features and workflows
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.mitre_handler import MITREHandler
from core.cve_handler import CVEHandler
from core.attack_schemas import AttackSchemaEngine
from core.timeline_manager import TimelineManager
from core.siem_handler import SIEMHandler
from utils.db_manager import DatabaseManager
from utils.helpers import print_success, print_info, print_warning


def example_mitre_operations():
    """Example: MITRE ATT&CK operations"""
    print_info("=== MITRE ATT&CK Examples ===\n")
    
    mitre = MITREHandler()
    
    # Search for techniques
    print_info("Searching for PowerShell techniques...")
    results = mitre.search_techniques("powershell", limit=5)
    for technique, score in results:
        print(f"  • {technique.id} - {technique.name} (Score: {score:.1f})")
    
    # Get technique details
    print_info("\nGetting details for T1059.001 (PowerShell)...")
    tech = mitre.get_technique("T1059.001")
    if tech:
        print(f"  Name: {tech.name}")
        print(f"  Tactics: {', '.join(tech.tactics)}")
        print(f"  Platforms: {', '.join(tech.platforms)}")
    
    # Get detection recommendations
    print_info("\nGetting detection recommendations...")
    recommendations = mitre.get_detection_recommendations("T1059.001")
    print(f"  Data Sources: {', '.join(recommendations['data_sources'][:3])}")
    print(f"  Monitoring Points: {len(recommendations['monitoring_points'])}")
    
    print_success("MITRE examples completed!\n")


def example_cve_operations():
    """Example: CVE operations"""
    print_info("=== CVE Operations Examples ===\n")
    
    cve = CVEHandler()
    
    # Search CVEs
    print_info("Searching for remote code execution CVEs...")
    results = cve.search_cves("remote code execution", limit=5)
    for cve_entry, score in results[:3]:
        print(f"  • {cve_entry.cve_id} - Severity: {cve_entry.severity}, Score: {cve_entry.score:.1f}")
    
    # Calculate risk score
    if results:
        print_info("\nCalculating risk score for first CVE...")
        risk = cve.calculate_risk_score(results[0][0])
        print(f"  CVE: {risk['cve_id']}")
        print(f"  Risk Score: {risk['risk_score']}")
        print(f"  Priority: {risk['priority']}")
    
    print_success("CVE examples completed!\n")


def example_attack_schemas():
    """Example: Attack schema operations"""
    print_info("=== Attack Schema Examples ===\n")
    
    schema_engine = AttackSchemaEngine()
    
    # List available schemas
    print_info("Available attack schemas:")
    for schema_id, schema in schema_engine.schemas.items():
        print(f"  • {schema.name}")
        print(f"    Phases: {', '.join(p.value for p in schema.attack_phases)}")
        print(f"    Indicators: {len(schema.indicators)}")
    
    # Generate detection rules
    if schema_engine.schemas:
        first_schema = list(schema_engine.schemas.values())[0]
        print_info(f"\nGenerating Sigma rule for '{first_schema.name}'...")
        
        sigma_rule = schema_engine.generate_detection_rule(
            first_schema.schema_id,
            'sigma'
        )
        
        if sigma_rule:
            print(f"  Rule ID: {sigma_rule.rule_id}")
            print(f"  Severity: {sigma_rule.severity}")
            print_success("  Detection rule generated!")
    
    print_success("Attack schema examples completed!\n")


def example_timeline_operations():
    """Example: Timeline operations"""
    print_info("=== Timeline Examples ===\n")
    
    timeline_mgr = TimelineManager()
    
    # Create timeline
    print_info("Creating attack timeline...")
    timeline = timeline_mgr.create_timeline(
        name="Example Attack Timeline",
        timeline_type="attack",
        description="Demonstration of timeline features"
    )
    print(f"  Timeline ID: {timeline.timeline_id}")
    
    # Add events
    print_info("\nAdding events to timeline...")
    events = [
        ("Initial Reconnaissance", "Nmap scan of target network", "info"),
        ("Vulnerability Discovery", "Found unpatched Apache server", "medium"),
        ("Exploitation Attempt", "Attempted CVE-2024-1234 exploit", "high"),
        ("Access Gained", "Successfully obtained shell access", "critical"),
    ]
    
    for title, desc, severity in events:
        event = timeline_mgr.add_event(
            timeline.timeline_id,
            title=title,
            description=desc,
            severity=severity,
            technique="T1190"
        )
        if event:
            print(f"  ✓ Added: {title}")
    
    # Generate summary
    print_info("\nGenerating timeline summary...")
    summary = timeline_mgr.generate_timeline_summary(timeline.timeline_id)
    print(f"  Total Events: {summary['event_count']}")
    print(f"  Duration: {summary['duration']}")
    print(f"  Severity Distribution: {summary['severity_distribution']}")
    
    print_success("Timeline examples completed!\n")


def example_siem_operations():
    """Example: SIEM operations"""
    print_info("=== SIEM Operations Examples ===\n")
    
    siem = SIEMHandler()
    
    # Generate sample logs
    print_info("Generating brute force attack logs...")
    logs = siem.generate_logs("brute_force", count=10)
    print(f"  Generated {len(logs)} log entries")
    
    # Analyze logs
    print_info("\nAnalyzing logs...")
    analysis = siem.analyze_logs(logs)
    print(f"  Total Logs: {analysis['total_logs']}")
    print(f"  Time Span: {analysis['time_span']}")
    print(f"  Critical Events: {analysis['critical_events']}")
    print(f"  Event Types: {list(analysis['event_types'].keys())}")
    
    # Correlate events
    print_info("\nCorrelating events for threats...")
    alerts = siem.correlate_events()
    if alerts:
        print(f"  Generated {len(alerts)} alerts")
        for alert in alerts[:3]:
            print(f"    • {alert.title} ({alert.severity})")
    else:
        print("  No alerts generated")
    
    # Export logs
    print_info("\nExporting logs...")
    output_path = Path("example_logs.json")
    success = siem.export_logs(logs, output_path, format='json')
    if success:
        print(f"  ✓ Logs exported to {output_path}")
        # Clean up
        output_path.unlink()
    
    print_success("SIEM examples completed!\n")


def example_database_operations():
    """Example: Database operations"""
    print_info("=== Database Examples ===\n")
    
    db = DatabaseManager()
    
    # Create operation
    print_info("Creating operation session...")
    operation = db.create_operation(
        session_id="example_session_001",
        operation_type="pentest",
        name="Example Penetration Test",
        metadata={"target": "10.10.10.1", "scope": "full"}
    )
    print(f"  Operation ID: {operation.session_id}")
    
    # Get statistics
    print_info("\nGetting database statistics...")
    stats = db.get_statistics()
    print(f"  Total Operations: {stats['total_operations']}")
    print(f"  Active Operations: {stats['active_operations']}")
    print(f"  Total Vulnerabilities: {stats['total_vulnerabilities']}")
    
    print_success("Database examples completed!\n")


def example_full_workflow():
    """Example: Complete workflow"""
    print_info("=== Complete Workflow Example ===\n")
    
    print_info("Scenario: CTF Machine Pwning\n")
    
    # Initialize components
    mitre = MITREHandler()
    cve = CVEHandler()
    timeline_mgr = TimelineManager()
    siem = SIEMHandler()
    
    # Step 1: Create timeline
    print_info("Step 1: Creating operation timeline...")
    timeline = timeline_mgr.create_timeline(
        name="CTF Box - Example",
        timeline_type="attack",
        description="CTF machine exploitation"
    )
    
    # Step 2: Reconnaissance phase
    print_info("Step 2: Reconnaissance phase...")
    timeline_mgr.add_event(
        timeline.timeline_id,
        title="Port Scan Initiated",
        description="Nmap scan: 22, 80, 443 open",
        severity="info",
        technique="T1046"
    )
    
    # Step 3: Vulnerability identification
    print_info("Step 3: Vulnerability identification...")
    timeline_mgr.add_event(
        timeline.timeline_id,
        title="Vulnerability Discovered",
        description="Apache 2.4.49 - Path Traversal (CVE-2021-41773)",
        severity="high",
        technique="T1190"
    )
    
    # Step 4: Exploitation
    print_info("Step 4: Exploitation phase...")
    timeline_mgr.add_event(
        timeline.timeline_id,
        title="Exploitation Successful",
        description="Gained initial shell access",
        severity="critical",
        technique="T1190"
    )
    
    # Step 5: Privilege escalation
    print_info("Step 5: Privilege escalation...")
    timeline_mgr.add_event(
        timeline.timeline_id,
        title="Privilege Escalation",
        description="Exploited sudo misconfiguration",
        severity="critical",
        technique="T1548"
    )
    
    # Step 6: Flag capture
    print_info("Step 6: Objective achieved...")
    timeline_mgr.add_event(
        timeline.timeline_id,
        title="Flag Captured",
        description="Root flag obtained: {example_flag}",
        severity="info"
    )
    
    # Generate summary
    print_info("\nGenerating operation summary...")
    summary = timeline_mgr.generate_timeline_summary(timeline.timeline_id)
    
    print("\n" + "="*60)
    print("OPERATION SUMMARY")
    print("="*60)
    print(f"Timeline: {timeline.name}")
    print(f"Events: {summary['event_count']}")
    print(f"Duration: {summary['duration']}")
    print(f"Techniques Used: {', '.join(summary['techniques_used'].keys())}")
    print("="*60 + "\n")
    
    print_success("Complete workflow example finished!\n")


def main():
    """Run all examples"""
    print("\n")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                  PUPMAS USAGE EXAMPLES                        ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print("\n")
    
    try:
        example_mitre_operations()
        example_cve_operations()
        example_attack_schemas()
        example_timeline_operations()
        example_siem_operations()
        example_database_operations()
        example_full_workflow()
        
        print("="*60)
        print_success("All examples completed successfully!")
        print("="*60)
        print("\nNext steps:")
        print("  1. Run 'python3 pupmas.py --mode tui' for interactive mode")
        print("  2. Try 'python3 pupmas.py --help' for all CLI options")
        print("  3. Read QUICKSTART.md for detailed workflows")
        print("\n")
    
    except Exception as e:
        print(f"\n[ERROR] Example failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
