#!/usr/bin/env python3
"""
PUPMAS Quick Reference & Troubleshooting
"""

QUICK_COMMANDS = {
    "Hızlı CTF": "python3 pupmas.py --auto-scan --auto-target 10.10.10.50",
    
    "Detaylı Pentest": "python3 pupmas.py --auto-scan --auto-target target.com --auto-profile aggressive --auto-type pentest",
    
    "Red Team": "python3 pupmas.py --auto-scan --auto-target 10.0.0.1 --auto-profile aggressive --auto-type redteam",
    
    "Blue Team": "python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-no-exploit --auto-type blueteam",
    
    "Passive Scan": "python3 pupmas.py --auto-scan --auto-target target --auto-profile passive",
    
    "JSON Report": "python3 pupmas.py --auto-scan --auto-target target --auto-report json",
    
    "No Database": "python3 pupmas.py --auto-scan --auto-target target --auto-no-db",
    
    "Recon Only": "python3 pupmas.py --auto-scan --auto-target target --auto-no-exploit",
}

ZAFIYETLER = {
    "SQL Injection": ["' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY--"],
    "XSS": ["<script>alert('XSS')</script>", "<img src=x onerror='alert(1)'>", "<svg onload=alert('XSS')>"],
    "RCE": ["; id", "| whoami", "& whoami", "`id`", "$(id)"],
    "LFI/RFI": ["../../etc/passwd", "..\\\\..\\\\windows\\\\system32", "file:///etc/passwd"],
    "Auth Bypass": ["admin' OR '1'='1", "' OR 1=1--", "*"],
    "Default Creds": ["admin:admin", "admin:password", "root:root", "test:test"],
}

PROFILER = {
    "passive": {
        "description": "Stealthy, DNS only",
        "time": "30s - 2m",
        "ports": "None",
    },
    "active": {
        "description": "Balanced (default)",
        "time": "2-5m",
        "ports": "Common (20)",
    },
    "aggressive": {
        "description": "Full scan",
        "time": "5-15m",
        "ports": "Top 1000",
    }
}

TYPES = {
    "pentest": "Penetration testing + timeline",
    "ctf": "Fast CTF solving",
    "redteam": "Red team operations",
    "blueteam": "Blue team/defense analysis",
}

PHASES = [
    "1. Reconnaissance (Recon)",
    "2. Exploitation Testing",
    "3. CVE Analysis",
    "4. Timeline & MITRE",
    "5. SIEM Analysis",
    "6. Report Generation",
]

OUTPUTS = [
    "📄 HTML Report",
    "📊 JSON Report", 
    "🗄️ Database Entry",
    "📋 Timeline Events",
    "🎯 Vulnerability List",
    "🔐 CVE Details",
    "📡 MITRE Mapping",
]

def print_menu():
    """Print quick reference menu"""
    print("\n" + "="*70)
    print("PUPMAS - QUICK REFERENCE".center(70))
    print("="*70 + "\n")
    
    print("🚀 QUICK COMMANDS:\n")
    for name, cmd in QUICK_COMMANDS.items():
        print(f"  {name}:")
        print(f"    {cmd}\n")
    
    print("\n" + "-"*70 + "\n")
    
    print("🎯 PARAMETRELER:\n")
    print("  --auto-scan              # Otomatik tarama (ZORUNLU)")
    print("  --auto-target TARGET     # Hedef IP/domain (ZORUNLU)")
    print("  --auto-profile [passive|active|aggressive]  # Seviye")
    print("  --auto-type [pentest|ctf|redteam|blueteam]  # Tip")
    print("  --auto-report [html|json]  # Report formatı")
    print("  --auto-no-exploit        # Exploitation fazını atla")
    print("  --auto-no-db             # Veritabanına kaydetme\n")
    
    print("-"*70 + "\n")
    
    print("📊 PROFILLER:\n")
    for profile, info in PROFILER.items():
        print(f"  {profile.upper()}: {info['description']}")
        print(f"    ⏱️  Süre: {info['time']}")
        print(f"    🔌 Ports: {info['ports']}\n")
    
    print("-"*70 + "\n")
    
    print("🔨 ZAFİYETLERİ TEST ET:\n")
    for vuln, payloads in ZAFIYETLER.items():
        print(f"  ✓ {vuln}:")
        for p in payloads[:2]:
            print(f"    - {p}")
        print(f"    ... ve daha fazla\n")
    
    print("-"*70 + "\n")
    
    print("📋 İŞLEM FAZLARI:\n")
    for phase in PHASES:
        print(f"  {phase}")
    
    print("\n" + "-"*70 + "\n")
    
    print("📤 ÇIKTILARI:\n")
    for output in OUTPUTS:
        print(f"  {output}")
    
    print("\n" + "="*70 + "\n")


def troubleshooting():
    """Print troubleshooting guide"""
    print("\n" + "="*70)
    print("TROUBLESHOOTING".center(70))
    print("="*70 + "\n")
    
    issues = {
        "Tarama çok yavaş": {
            "Çözüm": "Passive profile kullan",
            "Komut": "python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile passive"
        },
        "Timeout hatası": {
            "Çözüm": "Hedefi ve network'ü kontrol et",
            "Komut": "ping TARGET"
        },
        "Import hatası": {
            "Çözüm": "Kütüphaneleri yükle",
            "Komut": "pip3 install -r requirements.txt"
        },
        "Permission denied": {
            "Çözüm": "Python versiyonunu kontrol et",
            "Komut": "python3 pupmas.py --version"
        },
        "Report oluşmuyor": {
            "Çözüm": "reports/ dizinini oluştur",
            "Komut": "mkdir -p reports"
        },
    }
    
    for issue, solution in issues.items():
        print(f"❌ {issue}")
        print(f"   ✓ {solution['Çözüm']}")
        print(f"   $ {solution['Komut']}\n")
    
    print("="*70 + "\n")


def examples():
    """Print practical examples"""
    print("\n" + "="*70)
    print("KULLANIM ÖRNEKLERI".center(70))
    print("="*70 + "\n")
    
    examples_dict = {
        "Örnek 1: HTB Box Çözmek": {
            "target": "10.10.10.50",
            "command": "python3 pupmas.py --auto-scan --auto-target 10.10.10.50 --auto-type ctf",
            "duration": "3-5 dakika",
            "what": "Port scan + Service detection + Web vuln test + CVE + Report"
        },
        "Örnek 2: Pentest": {
            "target": "target.com",
            "command": "python3 pupmas.py --auto-scan --auto-target target.com --auto-profile aggressive --auto-type pentest",
            "duration": "5-10 dakika",
            "what": "Full recon + Subdomain + Aggressive scan + All exploit tests + Timeline"
        },
        "Örnek 3: Red Team": {
            "target": "192.168.1.0/24",
            "command": "python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-profile aggressive --auto-type redteam",
            "duration": "10-15 dakika",
            "what": "Network enum + Full exploitation + MITRE mapping + Timeline"
        },
        "Örnek 4: Blue Team": {
            "target": "10.0.0.1",
            "command": "python3 pupmas.py --auto-scan --auto-target 10.0.0.1 --auto-no-exploit --auto-type blueteam",
            "duration": "2-3 dakika",
            "what": "Recon + CVE analysis + SIEM rules (No exploitation)"
        },
    }
    
    for name, example in examples_dict.items():
        print(f"📍 {name}")
        print(f"   Target: {example['target']}")
        print(f"   Command: {example['command']}")
        print(f"   Duration: {example['duration']}")
        print(f"   What: {example['what']}\n")
    
    print("="*70 + "\n")


def comparison():
    """Print before/after comparison"""
    print("\n" + "="*70)
    print("ÖNCE vs SONRA".center(70))
    print("="*70 + "\n")
    
    print("BEFORE (Eski Yöntem):")
    print("$ nmap -sV target")
    print("$ nikto -h target")
    print("$ sqlmap -u 'http://target' --dbs")
    print("$ gobuster dir -u http://target")
    print("$ [manual testing...]")
    print("$ [write report manually...]")
    print("\n⏱️  Süre: 15-30 dakika")
    print("📋 Komut Sayısı: 8-15+")
    print("🔧 Araç Sayısı: 5+\n")
    
    print("-"*70 + "\n")
    
    print("AFTER (PUPMAS):")
    print("$ python3 pupmas.py --auto-scan --auto-target target\n")
    print("✓ Port scan")
    print("✓ Service detection")
    print("✓ Web vulnerability test")
    print("✓ CVE analysis")
    print("✓ Timeline creation")
    print("✓ MITRE mapping")
    print("✓ Report generation")
    print("✓ Database saving\n")
    
    print("⏱️  Süre: 2-5 dakika")
    print("📋 Komut Sayısı: 1")
    print("🔧 Araç Sayısı: 1 (PUPMAS)")
    
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    print("\n🚀 PUPMAS - QUICK REFERENCE TOOL\n")
    
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "menu":
            print_menu()
        elif command == "troubleshoot":
            troubleshooting()
        elif command == "examples":
            examples()
        elif command == "comparison":
            comparison()
        else:
            print(f"Unknown command: {command}")
            print("\nUsage: python3 reference.py [menu|troubleshoot|examples|comparison]")
    else:
        # Print everything
        print_menu()
        examples()
        comparison()
        troubleshooting()
