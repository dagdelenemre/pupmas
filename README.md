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
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red.svg)](https://www.kali.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/yourusername/pupmas)

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
- **Exploit Database**: Integrated exploit repository
- **Payload Generation**: Custom payload creation
- **Post-Exploitation**: Privilege escalation and persistence modules
- **Session Management**: Handle multiple exploitation sessions

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
- Kali Linux / BlackArch (recommended)
- Python 3.9 or higher
- Root/sudo access for certain operations

### Quick Install

```bash
# Clone repository
git clone https://github.com/yourusername/pupmas.git
cd pupmas

# Install dependencies
pip3 install -r requirements.txt

# Run setup
python3 setup.py install

# Launch PUPMAS
python3 pupmas.py
```

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
# Query MITRE technique
python3 pupmas.py --mitre T1059.001

# Search CVE
python3 pupmas.py --cve CVE-2024-1234

# View attack timeline
python3 pupmas.py --timeline attack

# Start reconnaissance
python3 pupmas.py --recon --target 10.10.10.1 --recon-profile active

# Test exfiltration
python3 pupmas.py --exfil-test --method dns --payload data.txt

# Parse SIEM logs
python3 pupmas.py --siem-parse logs.json --siem-format json

# Generate report
python3 pupmas.py --report --format pdf --output pentest_report.pdf
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

- **Documentation**: [docs.pupmas.io](https://docs.pupmas.io)
- **Issues**: [GitHub Issues](https://github.com/yourusername/pupmas/issues)
- **Discord**: [PUPMAS Community](https://discord.gg/pupmas)
- **Email**: support@pupmas.io

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
