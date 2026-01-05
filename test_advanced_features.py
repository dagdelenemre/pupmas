#!/usr/bin/env python3
"""
PUPMAS v2.0 Senior Expert Edition - Advanced Features Demo
Test script for all 5 new advanced modules
"""

import asyncio
from datetime import datetime
from core.opsec_manager import OPSECManager, ThreatLevel
from core.advanced_exploitation import AdvancedExploitationEngine
from core.advanced_intelligence import AdvancedIntelligenceEngine
from core.advanced_reporting import AdvancedReportingEngine
from core.apt_simulator import APTSimulationEngine


def print_section(title: str):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


async def test_opsec_manager():
    """Test OPSEC Manager functionality"""
    print_section("1. OPSEC MANAGER - Operational Security")
    
    opsec = OPSECManager()
    
    # Start operation session
    print("🔒 Starting OPSEC session...")
    session_id = opsec.start_session("demo_target", ThreatLevel.HIGH)
    print(f"   Session ID: {session_id}")
    
    # Footprint analysis
    print("\n📊 Analyzing attack footprint...")
    footprint = opsec.analyze_footprint()
    print(f"   Log entries: {footprint['log_entries']}")
    print(f"   Network connections: {footprint['network_connections']}")
    print(f"   File modifications: {footprint['file_modifications']}")
    print(f"   Process creations: {footprint['process_creations']}")
    print(f"   Risk score: {footprint['risk_score']:.2f}")
    print(f"   Detection probability: {footprint['detection_probability']:.1%}")
    
    # Anti-forensics techniques
    print("\n🧹 Testing anti-forensics techniques...")
    techniques = opsec.get_anti_forensics_techniques()
    for i, technique in enumerate(techniques[:3], 1):
        print(f"   {i}. {technique['name']}")
        print(f"      Category: {technique['category']}")
        print(f"      Effectiveness: {technique['effectiveness']}")
        print(f"      Risk: {technique['risk_level']}")
    
    # Timing analysis
    print("\n⏰ Optimal timing for operations...")
    timing = opsec.calculate_optimal_timing()
    print(f"   Best time window: {timing['best_time_window']}")
    print(f"   Risk level: {timing['risk_level']}")
    print(f"   Reason: {timing['reason']}")
    
    # Recommendations
    print("\n💡 OPSEC recommendations...")
    recommendations = opsec.generate_opsec_recommendations()
    for rec in recommendations[:3]:
        print(f"   • {rec['recommendation']} (Priority: {rec['priority']})")


async def test_advanced_exploitation():
    """Test Advanced Exploitation Engine"""
    print_section("2. ADVANCED EXPLOITATION ENGINE")
    
    engine = AdvancedExploitationEngine()
    
    # Create target dict
    target = {
        'host': '192.168.1.100',
        'os': 'linux',
        'version': 'Ubuntu 20.04',
        'services': ['ssh', 'http', 'mysql'],
        'vulnerabilities': ['CVE-2021-3156', 'CVE-2021-44228']
    }
    
    print(f"🎯 Target: {target['host']} ({target['os']} {target['version']})")
    print(f"   Services: {', '.join(target['services'])}")
    print(f"   Vulnerabilities: {', '.join(target['vulnerabilities'])}")
    
    # Generate exploit chain
    print("\n⚡ Generating multi-stage exploit chain...")
    chain = await engine.generate_exploit_chain(target)
    print(f"   Chain ID: {chain.chain_id}")
    print(f"   Stages: {len(chain.stages)}")
    print(f"   Success probability: {chain.success_probability:.1%}")
    print(f"   Total risk: {chain.total_risk_score}")
    
    print("\n   Exploit stages:")
    for i, stage in enumerate(chain.stages, 1):
        print(f"   {i}. {stage.name} ({stage.technique})")
        print(f"      Probability: {stage.success_probability:.1%}, Risk: {stage.risk_score}")
    
    # Privilege escalation
    print("\n🔓 Analyzing privilege escalation paths...")
    privesc_paths = await engine.analyze_privilege_escalation(target)
    for i, path in enumerate(privesc_paths[:2], 1):
        print(f"\n   Path {i}: {path.path_id}")
        print(f"   Technique: {path.technique}")
        print(f"   Difficulty: {path.difficulty}")
        print(f"   Success rate: {path.success_rate:.1%}")
        print(f"   Steps: {' → '.join(path.steps[:3])}")
    
    # Post-exploitation
    print("\n🏴 Post-exploitation actions...")
    post_exploit = await engine.generate_post_exploitation_strategy(target)
    print(f"   Strategy: {post_exploit['strategy']}")
    print(f"   Actions ({len(post_exploit['actions'])}):")
    for action in post_exploit['actions'][:3]:
        print(f"   • {action['name']} (Priority: {action['priority']})")


async def test_advanced_intelligence():
    """Test Advanced Intelligence Engine"""
    print_section("3. ADVANCED INTELLIGENCE ENGINE")
    
    intel = AdvancedIntelligenceEngine()
    
    # Create target dict
    target = {
        'target_id': 'DEMO-001',
        'domain': 'example.com',
        'organization': 'Example Corp'
    }
    
    print(f"🔍 Target: {target['organization']}")
    print(f"   Domain: {target['domain']}")
    
    # Digital footprint
    print("\n👣 Gathering digital footprint...")
    footprint = await intel.gather_digital_footprint(target)
    print(f"   Domains: {len(footprint.domains)}")
    print(f"   IP addresses: {len(footprint.ip_addresses)}")
    print(f"   Email patterns: {len(footprint.email_patterns)}")
    print(f"   Social media: {', '.join(footprint.social_media_accounts[:3])}")
    print(f"   Technologies: {', '.join(footprint.technologies[:5])}")
    
    # DNS intelligence
    print("\n🌐 DNS intelligence gathering...")
    dns_intel = await intel.perform_dns_intelligence(target['domain'])
    print(f"   A records: {len(dns_intel['a_records'])}")
    print(f"   MX records: {len(dns_intel['mx_records'])}")
    print(f"   Name servers: {len(dns_intel['name_servers'])}")
    print(f"   Subdomains found: {len(dns_intel['subdomains'])}")
    
    # Dark web monitoring
    print("\n🕵️ Dark web intelligence...")
    darkweb = await intel.monitor_dark_web(target)
    print(f"   Mentions: {len(darkweb['mentions'])}")
    print(f"   Data breaches: {len(darkweb['data_breaches'])}")
    print(f"   Threat level: {darkweb['threat_assessment']['level']}")
    print(f"   Score: {darkweb['threat_assessment']['score']}")
    
    # Threat intelligence
    print("\n⚠️ Threat intelligence correlation...")
    threats = await intel.correlate_threat_intelligence(target)
    print(f"   Active threats: {len(threats['active_threats'])}")
    print(f"   IOCs: {len(threats['iocs'])}")
    if threats['active_threats']:
        threat = threats['active_threats'][0]
        print(f"\n   Top threat: {threat['name']}")
        print(f"   Severity: {threat['severity']}")
        print(f"   Confidence: {threat['confidence']:.1%}")


async def test_advanced_reporting():
    """Test Advanced Reporting Engine"""
    print_section("4. ADVANCED REPORTING ENGINE")
    
    reporting = AdvancedReportingEngine()
    
    # Risk assessment
    print("📈 Comprehensive risk assessment...")
    assessment_data = {
        'critical_vulns': 3,
        'high_vulns': 7,
        'medium_vulns': 15,
        'low_vulns': 22,
        'exploitable': 5,
        'has_exploit': True,
        'public_exploit': True,
        'days_since_patch': 45
    }
    
    assessment = reporting.perform_risk_assessment(
        target="demo.example.com",
        findings=assessment_data
    )
    
    print(f"\n🎯 Target: {assessment.target_name}")
    print(f"   Overall risk: {assessment.overall_risk_score:.1f}/10")
    print(f"   Risk level: {assessment.risk_level}")
    print(f"   Critical findings: {assessment.critical_findings}")
    
    print("\n   Risk factors:")
    for factor, score in assessment.risk_factors.items():
        print(f"   • {factor}: {score:.1f}")
    
    print("\n   Top recommendations:")
    for i, rec in enumerate(assessment.recommendations[:3], 1):
        print(f"   {i}. {rec['action']} (Priority: {rec['priority']})")
    
    # CVSS v4.0 scoring
    print("\n📊 CVSS v4.0 vulnerability scoring...")
    cvss = reporting.calculate_cvss_v4(
        vulnerability_id="CVE-2021-44228",
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        confidentiality_impact="high",
        integrity_impact="high",
        availability_impact="high"
    )
    
    print(f"\n   CVE-2021-44228 (Log4Shell)")
    print(f"   Base score: {cvss.base_score:.1f} ({cvss.severity})")
    print(f"   Vector: {cvss.vector_string}")
    print(f"   Exploitability: {cvss.exploitability_score:.1f}")
    print(f"   Impact: {cvss.impact_score:.1f}")
    
    # Compliance report
    print("\n📋 Compliance gap analysis...")
    compliance = reporting.generate_compliance_report(
        findings=[
            {'severity': 'critical', 'category': 'authentication'},
            {'severity': 'high', 'category': 'encryption'},
            {'severity': 'medium', 'category': 'logging'}
        ],
        framework="OWASP"
    )
    
    print(f"   Framework: {compliance['framework']}")
    print(f"   Compliance score: {compliance['compliance_score']:.1f}%")
    print(f"   Total gaps: {compliance['total_gaps']}")
    print(f"   Critical gaps: {compliance['critical_gaps']}")
    
    print("\n   Top gaps:")
    for gap in compliance['gaps'][:3]:
        print(f"   • {gap['control_id']}: {gap['description']}")
        print(f"     Severity: {gap['severity']}, Status: {gap['status']}")


async def test_apt_simulator():
    """Test APT Simulation Engine"""
    print_section("5. APT SIMULATION ENGINE")
    
    apt = APTSimulationEngine()
    
    # List APT profiles
    print("🎭 Available APT profiles:")
    profiles = apt.list_apt_profiles()
    for profile in profiles[:5]:
        print(f"   • {profile['name']}")
        print(f"     Origin: {profile['origin']}")
        print(f"     Active: {profile['first_seen']} - {profile['last_seen']}")
        print(f"     Sophistication: {profile['sophistication']}")
        print()
    
    # Create campaign
    print("🚀 Creating APT campaign...")
    profile = {
        'name': 'APT-DEMO',
        'sophistication': 'high',
        'primary_motivation': 'espionage'
    }
    
    campaign = await apt.create_campaign(
        profile=profile,
        target_profile={
            'industry': 'technology',
            'size': 'enterprise',
            'security_maturity': 'medium'
        }
    )
    
    print(f"   Campaign: {campaign.campaign_id}")
    print(f"   Name: {campaign.name}")
    print(f"   Objective: {campaign.objective}")
    print(f"   Duration: {campaign.duration_days} days")
    print(f"   Phases: {len(campaign.phases)}")
    
    print("\n   Campaign phases:")
    for i, phase in enumerate(campaign.phases, 1):
        print(f"   {i}. {phase.name} (Day {phase.start_day}-{phase.end_day})")
        print(f"      TTPs: {len(phase.ttps)}")
        print(f"      Objectives: {', '.join(phase.objectives[:2])}")
    
    # C2 infrastructure
    print("\n🖧 Command & Control infrastructure...")
    c2 = await apt.setup_c2_infrastructure(campaign)
    print(f"   Infrastructure ID: {c2['infrastructure_id']}")
    print(f"   Servers: {len(c2['c2_servers'])}")
    print(f"   Domains: {len(c2['domains'])}")
    
    print("\n   C2 servers:")
    for server in c2['c2_servers'][:2]:
        print(f"   • {server['type']} at {server['location']}")
        print(f"     Protocols: {', '.join(server['protocols'])}")
    
    # Covert channels
    print("\n🔐 Covert communication channels...")
    channels = apt.generate_covert_channels()
    for i, channel in enumerate(channels[:3], 1):
        print(f"\n   {i}. {channel.name}")
        print(f"      Stealth: {channel.stealth_rating}")
        print(f"      Bandwidth: {channel.bandwidth}")
        print(f"      Detection difficulty: {channel.detection_difficulty}")
        print(f"      Implementation: {channel.implementation_details}")


async def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("  PUPMAS v2.0 - Senior Expert Edition")
    print("  Advanced Features Demonstration")
    print("="*60)
    
    try:
        # Test each module
        await test_opsec_manager()
        await test_advanced_exploitation()
        await test_advanced_intelligence()
        await test_advanced_reporting()
        await test_apt_simulator()
        
        print("\n" + "="*60)
        print("  ✅ All tests completed successfully!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
