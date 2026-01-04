# PUPMAS Quick Start Guide

## Installation

### On Kali Linux (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/pupmas.git
cd pupmas

# Install dependencies
pip3 install -r requirements.txt

# Run setup
python3 setup.py install

# Verify installation
python3 pupmas.py --version
```

### Using Docker

```bash
# Build Docker image
docker build -t pupmas:latest .

# Run container
docker run -it --rm --network host pupmas:latest
```

## First Run

### Interactive TUI Mode (Recommended for beginners)

```bash
python3 pupmas.py --mode tui
```

This launches the interactive Terminal User Interface with:
- Dashboard overview
- MITRE ATT&CK explorer
- CVE browser
- Timeline viewer
- SIEM log analyzer

### Command-Line Mode

```bash
# View help
python3 pupmas.py --help

# Query MITRE technique
python3 pupmas.py --mitre T1059.001

# Search CVEs
python3 pupmas.py --cve-search "remote code execution"

# Generate SIEM logs
python3 pupmas.py --generate-logs brute_force
```

## Basic Workflows

### CTF Competition Workflow

```bash
# 1. Create attack timeline
python3 pupmas.py --timeline attack

# 2. Start reconnaissance
python3 pupmas.py --recon --target 10.10.10.1 --recon-profile active

# 3. Track findings
python3 pupmas.py --add-event attack "Port Scan Complete" "Found 5 open ports"

# 4. Generate report
python3 pupmas.py --report --format html --output ctf_report.html
```

### Vulnerability Assessment

```bash
# 1. Search for vulnerabilities
python3 pupmas.py --cve-search "apache 2.4"

# 2. Get CVE details
python3 pupmas.py --cve CVE-2024-1234

# 3. Create timeline
python3 pupmas.py --timeline pentest

# 4. Generate vulnerability report
python3 pupmas.py --report --format pdf
```

### SIEM Log Analysis

```bash
# 1. Parse logs
python3 pupmas.py --siem-parse access.log --siem-format apache

# 2. Generate test logs
python3 pupmas.py --generate-logs web_attack

# 3. Export analysis
python3 pupmas.py --siem-parse logs.json --siem-export analysis.json
```

### Attack Schema Development

```bash
# 1. View available schemas
python3 pupmas.py --schema "powershell"

# 2. Generate detection rules
python3 pupmas.py --generate-rules

# 3. Validate custom schema
python3 pupmas.py --validate custom_attack.json
```

## TUI Navigation

### Keyboard Shortcuts

- `Q` - Quit application
- `D` - Dashboard view
- `M` - MITRE ATT&CK explorer
- `C` - CVE browser
- `T` - Timeline viewer
- `S` - SIEM logs
- `R` - Refresh current view
- `Tab` - Navigate between tabs
- `Enter` - Select/Execute

### Dashboard Features

The dashboard displays:
- Active operations count
- Scan statistics
- Vulnerability metrics
- Critical alerts
- System status

### MITRE ATT&CK Explorer

- Browse tactics and techniques
- View technique details
- Search by keyword
- Map logs to techniques
- Generate detection rules

### CVE Browser

- Search vulnerabilities
- Filter by severity
- View CVSS scores
- Check exploit availability
- Calculate risk scores

### Timeline Viewer

- View attack chronology
- Track pentest activities
- Document reconnaissance
- Monitor exfiltration
- Export timelines

### SIEM Log Viewer

- Parse multiple log formats
- Generate sample logs
- Correlate events
- Generate alerts
- Export analysis

## Configuration

Edit `config/config.yaml`:

```yaml
# Enable debug mode
app:
  debug: true
  log_level: "DEBUG"

# Add API keys
api_keys:
  shodan_api_key: "your-key-here"
  virustotal_api_key: "your-key-here"

# Adjust SIEM settings
siem:
  correlation_enabled: true
  alert_threshold: 3
```

## Common Tasks

### Add MITRE Technique to Analysis

```bash
python3 pupmas.py --mitre T1566.001
```

### Search Recent CVEs

```bash
python3 pupmas.py --cve-recent 7
```

### Create Attack Timeline

```bash
python3 pupmas.py --add-event attack "Initial Access" "Phishing email delivered"
python3 pupmas.py --add-event attack "Execution" "Payload executed"
python3 pupmas.py --add-event attack "Persistence" "Registry key created"
```

### Generate Comprehensive Report

```bash
python3 pupmas.py --report --format html --output full_assessment.html
```

## Tips & Best Practices

1. **Start with TUI**: The interactive interface is best for learning
2. **Use Timelines**: Document every step of your operations
3. **Link to MITRE**: Always map activities to ATT&CK techniques
4. **Regular Exports**: Export timelines and reports frequently
5. **API Keys**: Add API keys for enhanced CVE and threat intelligence
6. **Safe Mode**: Keep exploitation safe_mode enabled by default
7. **Test Logs**: Use generated logs to test detection rules
8. **Version Control**: Track your custom schemas and configs in git

## Troubleshooting

### Python Dependencies

```bash
# If imports fail, reinstall dependencies
pip3 install --force-reinstall -r requirements.txt
```

### Database Issues

```bash
# Reset database
rm data/pupmas.db
python3 pupmas.py --mode tui
```

### Permission Errors

```bash
# Some operations require root
sudo python3 pupmas.py --recon --target 10.10.10.1
```

### TUI Display Issues

```bash
# Use CLI mode if TUI has rendering issues
python3 pupmas.py --mode cli --help
```

## Next Steps

1. Explore the TUI interface
2. Try generating different log scenarios
3. Create your first attack timeline
4. Customize attack schemas
5. Generate detection rules
6. Build comprehensive reports

## Getting Help

- Documentation: [docs.pupmas.io](https://docs.pupmas.io)
- Issues: [GitHub Issues](https://github.com/yourusername/pupmas/issues)
- Discord: [PUPMAS Community](https://discord.gg/pupmas)

## Security Notice

⚠️ **IMPORTANT**: PUPMAS is a powerful security tool. Always:
- Get explicit permission before testing systems
- Use only on authorized infrastructure
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Keep logs for accountability

Happy hacking! 🎯
