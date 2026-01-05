# PUPMAS - Puppeteer Master

<div align="center">

```
 ____  _   _ ____  __  __    _    ____  
|  _ \| | | |  _ \|  \/  |  / \  / ___| 
| |_) | | | | |_) | |\/| | / _ \ \___ \ 
|  __/| |_| |  __/| |  | |/ ___ \ ___) |
|_|    \___/|_|   |_|  |_/_/   \_\____/ 
                                         
Advanced Cybersecurity Operations Framework
```

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20|%203.13-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20|%20Windows-red.svg)](https://www.kali.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/dagdelenemre/pupmas)

</div>

## 📋 Overview

PUPMAS (Puppeteer Master) is a comprehensive cybersecurity operations and intelligence framework designed for penetration testing, CTF competitions, vulnerability assessments, and security research. Built for professionals and enthusiasts alike, PUPMAS integrates multiple security frameworks and tools into a unified, intuitive interface.

## ✨ Features

### 🎯 MITRE ATT&CK Integration
- **Complete Framework Coverage**: Access to all MITRE ATT&CK tactics, techniques, and sub-techniques
- **Attack Mapping**: Automatically map security events to ATT&CK framework
- **Technique Analysis**: Detailed breakdown of attack techniques with detection methods
- **Matrix Visualization**: Interactive visualization of the attack matrix

### 🔍 CVE Management
- **Comprehensive Database**: Integrated CVE database with automatic updates
- **Advanced Search**: Search by CVE ID, keyword, CVSS score, or affected software
- **Vulnerability Tracking**: Track and manage identified vulnerabilities
- **Exploit Mapping**: Link CVEs to available exploits and proof-of-concepts

### 📊 Attack Schemas & Rules
- **Schema Templates**: Pre-built templates for common attack patterns
- **Detection Rules**: Generate SIEM detection rules automatically
- **Custom Schemas**: Create and validate custom attack schemas
- **Rule Engine**: Sophisticated rule matching and alert generation

### ⏱️ Timeline Management
- **Attack Timeline**: Document complete attack chain chronology
- **Pentest Timeline**: Track penetration testing activities
- **Reconnaissance Timeline**: Log information gathering activities
- **Exfiltration Timeline**: Monitor data exfiltration attempts
- **Visual Timeline**: Interactive timeline visualization

### 🔬 Reconnaissance Module
- **Passive Reconnaissance**: OSINT gathering without target interaction
- **Active Reconnaissance**: Network scanning and enumeration
- **Service Detection**: Identify running services and versions
- **Vulnerability Scanning**: Automated vulnerability detection
- **Report Generation**: Comprehensive reconnaissance reports

### 💉 Exploitation Module
- **Advanced Vulnerability Testing**: SQL Injection, XSS, RCE, IDOR, XXE, SSRF, SSTI
- **Web Security**: Open Redirect, Blind SQLi, CORS Misconfiguration detection
- **Security Headers**: Automatic security header analysis
- **Exploit Database**: Integrated exploit repository
- **Payload Generation**: Custom payload creation
- **Post-Exploitation**: Privilege escalation and persistence modules
- **Session Management**: Handle multiple exploitation sessions
- **Cloudflare Detection**: Automatic WAF detection and bypass attempts
- **Deduplication**: Smart vulnerability deduplication across multiple scans

### 📤 Data Exfiltration
- **Multiple Channels**: DNS, HTTP(S), ICMP, SMTP exfiltration methods
- **Stealth Techniques**: Obfuscation and evasion capabilities
- **Bandwidth Management**: Throttling and scheduling options
- **Testing Framework**: Safe exfiltration testing environment

### 📝 SIEM Integration
- **Multi-Format Support**: JSON, Syslog, CEF, LEEF formats
- **Log Parsing**: Advanced log parsing and normalization
- **Event Correlation**: Intelligent event correlation engine
- **Alert Generation**: Automated alert creation and management
- **Log Generation**: Create realistic log data for testing

### 📈 Reporting
- **Multiple Formats**: PDF, HTML, Markdown, JSON reports
- **Customizable Templates**: Create custom report templates
- **Executive Summaries**: High-level overviews for management
- **Technical Details**: In-depth technical documentation
- **Chain of Evidence**: Maintain complete audit trail

## 🚀 Installation

### Prerequisites
- Kali Linux / BlackArch / Windows (recommended)
- Python 3.9+ or Python 3.13+ (fully tested)
- Root/sudo access for certain operations
- SQLAlchemy 2.0.45+ (for Python 3.13 compatibility)

### Quick Install (One-Line)

**Fastest way - just copy and paste:**

```bash
# Install and run PUPMAS
curl -sSL https://raw.githubusercontent.com/dagdelenemre/pupmas/main/install.sh | bash && python3 pupmas.py --mode tui
```

**With automatic updates included:**

```bash
# Install, update, and run
curl -sSL https://raw.githubusercontent.com/dagdelenemre/pupmas/main/install.sh | bash && \
curl -sSL https://raw.githubusercontent.com/dagdelenemre/pupmas/main/update.sh | bash && \
python3 pupmas.py --mode tui
```

### Manual Install

```bash
# Clone repository
git clone https://github.com/dagdelenemre/pupmas.git
cd pupmas

# Install dependencies
pip3 install -r requirements.txt

# For Python 3.13 users, ensure latest packages:
pip3 install --upgrade sqlalchemy textual dnspython rich

# Launch PUPMAS
python3 pupmas.py --help
```

### Update PUPMAS

```bash
# Update from main branch
curl -sSL https://raw.githubusercontent.com/dagdelenemre/pupmas/main/update.sh | bash
```

### Requirements
- requests
- beautifulsoup4
- lxml
- sqlalchemy>=2.0.45
- colorama
- textual
- dnspython
- rich>=14.2.0

### Docker Installation

```bash
# Build Docker image
docker build -t pupmas:latest .

# Run container
docker run -it --rm --network host pupmas:latest
```

## 📖 Usage

### Interactive TUI Mode (Default)
```bash
python3 pupmas.py --mode tui
```

### Command Line Interface
```bash
# Automated full scan (RECOMMENDED)
python3 pupmas.py -auS example.com

# Quick scan modes
python3 pupmas.py -M1 example.com  # Fast scan
python3 pupmas.py -M2 example.com  # Balanced scan
python3 pupmas.py -M3 example.com  # Deep scan

# Query MITRE technique
python3 pupmas.py --mitre T1059.001

# Search CVE
python3 pupmas.py --cve CVE-2024-1234

# View attack timeline
python3 pupmas.py --timeline attack

# Start reconnaissance (FIXED)
python3 pupmas.py --recon --target scanme.nmap.org --recon-profile passive
python3 pupmas.py --recon --target 10.10.10.1 --recon-profile aggressive

# Test exfiltration (FIXED)
python3 pupmas.py --exfil-test --method dns
python3 pupmas.py --exfil-test --method http

# Parse SIEM logs
python3 pupmas.py --siem-parse logs.json --siem-format json

# Generate logs
python3 pupmas.py --generate-logs attack

# Generate report
python3 pupmas.py --report --format html --output pentest_report.html
```

### TUI Interface

The Terminal User Interface provides:
- **Dashboard**: Overview of current operations and statistics
- **MITRE Explorer**: Navigate the ATT&CK framework
- **CVE Browser**: Search and analyze vulnerabilities
- **Timeline Viewer**: Visualize operation timelines
- **Module Launcher**: Start operational modules
- **Log Analyzer**: Real-time log analysis
- **Report Builder**: Interactive report creation

## 🏗️ Architecture

```
pupmas/
├── pupmas.py              # Main entry point
├── config/                # Configuration files
│   ├── config.yaml        # Main configuration
│   └── mitre_attack.json  # MITRE ATT&CK data
├── core/                  # Core functionality
│   ├── mitre_handler.py   # MITRE ATT&CK integration
│   ├── cve_handler.py     # CVE management
│   ├── attack_schemas.py  # Attack schema engine
│   ├── timeline_manager.py # Timeline management
│   └── siem_handler.py    # SIEM integration
├── modules/               # Operational modules
│   ├── reconnaissance.py  # Recon module
│   ├── exploitation.py    # Exploitation module
│   ├── exfiltration.py    # Exfiltration module
│   └── persistence.py     # Persistence module
├── ui/                    # User interfaces
│   ├── cli.py            # Command-line interface
│   └── tui.py            # Terminal UI
├── utils/                 # Utilities
│   ├── db_manager.py     # Database management
│   ├── api_client.py     # API clients
│   └── helpers.py        # Helper functions
└── data/                  # Data storage
    ├── templates/         # Attack templates
    ├── logs/             # Log files
    └── reports/          # Generated reports
```

## 🎓 Use Cases

### CTF Competitions
- Track discovered flags and vulnerabilities
- Document exploitation attempts
- Generate timeline of activities
- Create comprehensive write-ups

### Penetration Testing
- Systematic vulnerability assessment
- Attack chain documentation
- Client reporting
- Compliance mapping (MITRE ATT&CK)

### Security Research
- CVE tracking and analysis
- Attack pattern research
- Detection rule development
- Log analysis and correlation

### Training & Education
- Hands-on security training
- Attack simulation
- Log analysis practice
- Report writing templates

## 🎯 Vulnerability Detection

PUPMAS includes advanced detection for:

### Web Application Vulnerabilities
- **SQL Injection** - Time-based and error-based detection
- **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based
- **Remote Code Execution (RCE)** - OS command injection
- **IDOR (Insecure Direct Object References)** - Parameter tampering
- **XXE (XML External Entity)** - XML injection attacks
- **SSRF (Server-Side Request Forgery)** - Internal network probing
- **SSTI (Server-Side Template Injection)** - Template engine exploitation
- **Open Redirect** - Unvalidated redirect detection
- **Blind SQL Injection** - Time-based inference attacks
- **CORS Misconfiguration** - Cross-origin resource sharing issues
- **Security Headers** - Missing or misconfigured security headers

### Network & Infrastructure
- **Port Scanning** - Fast and comprehensive port discovery
- **Service Detection** - Banner grabbing and version detection
- **Subdomain Enumeration** - DNS-based subdomain discovery
- **Cloudflare Detection** - CDN and WAF identification
- **TLS/SSL Analysis** - Certificate and cipher suite checks

## 🚀 Quick Start Examples

### Example 1: Full Automated Scan
```bash
# Scan a target with all features enabled
python3 pupmas.py -auS example.com

# Fast scan (only common vulnerabilities)
python3 pupmas.py -M1 example.com

# Deep scan (comprehensive testing)
python3 pupmas.py -M3 example.com
```

### Example 2: Reconnaissance Only
```bash
# Passive reconnaissance (no port scanning)
python3 pupmas.py --recon --target example.com --recon-profile passive

# Active reconnaissance (with port scanning)
python3 pupmas.py --recon --target example.com --recon-profile active

# Aggressive reconnaissance (all ports + service detection)
python3 pupmas.py --recon --target example.com --recon-profile aggressive
```

### Example 3: Specific Vulnerability Testing
```bash
# Test for SQL injection on a specific URL
python3 pupmas.py -auS http://testphp.vulnweb.com/

# Results will show detected vulnerabilities with severity ratings
```

### Example 4: Generate Reports
```bash
# HTML report (recommended)
python3 pupmas.py -auS example.com --auto-report html

# JSON report (for automation)
python3 pupmas.py -auS example.com --auto-report json

# Skip opening report automatically
python3 pupmas.py -auS example.com -n
```

## 🔒 Security Considerations

⚠️ **IMPORTANT**: PUPMAS is a powerful security tool. Use responsibly and ethically.

- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use in isolated lab environments when testing
- Some features require root/administrator privileges

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE Corporation for the ATT&CK framework
- CVE Program and NVD
- The cybersecurity community
- All contributors and testers

## 📞 Support

- **Email**: kadiremredagdelen@gmail.com

## 🗺️ Roadmap

- [ ] Web-based interface
- [ ] Machine learning-based attack detection
- [ ] Integration with additional security frameworks (NIST, CIS)
- [ ] Cloud security modules (AWS, Azure, GCP)
- [ ] Mobile app companion
- [ ] Collaborative features for team operations

---

<div align="center">

**Made with ❤️ by the PUPMAS Team**

*Empowering security professionals worldwide*

</div>
