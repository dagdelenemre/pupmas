#!/bin/bash
# PUPMAS Quick Command Reference
# Copy & paste ready commands

# =============================================================================
# 🚀 QUICK SCANS (Copy-Paste Ready)
# =============================================================================

# 1. FASTEST (3-5 minutes) - Change TARGET
python3 pupmas.py --auto-scan --auto-target TARGET

# 2. CTF MODE (3-5 minutes)
python3 pupmas.py --auto-scan --auto-target TARGET --auto-type ctf

# 3. PENETRATION TEST (5-10 minutes) - Most detailed
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile aggressive --auto-type pentest

# 4. RED TEAM (10-15 minutes) - Full exploitation
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile aggressive --auto-type redteam

# 5. BLUE TEAM (2-3 minutes) - No exploitation
python3 pupmas.py --auto-scan --auto-target TARGET --auto-no-exploit --auto-type blueteam

# 6. PASSIVE MODE (30s-2 min) - Stealthy, DNS only
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile passive

# 7. RECON ONLY (2-3 minutes) - No exploitation tests
python3 pupmas.py --auto-scan --auto-target TARGET --auto-no-exploit

# 8. JSON REPORT (3-5 minutes)
python3 pupmas.py --auto-scan --auto-target TARGET --auto-report json

# 9. NO DATABASE (3-5 minutes) - Don't save to DB
python3 pupmas.py --auto-scan --auto-target TARGET --auto-no-db

# 10. EVERYTHING + AGGRESSIVE (15+ minutes)
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile aggressive --auto-type redteam

# =============================================================================
# 📚 DOCUMENTATION
# =============================================================================

# Quick reference menu
python3 reference.py menu

# Show all examples
python3 reference.py examples

# Feature showcase
python3 demo.py

# Troubleshooting
python3 reference.py troubleshoot

# Before/after comparison
python3 reference.py comparison

# =============================================================================
# 🔍 VIEW RESULTS
# =============================================================================

# View HTML report (after scan)
cat reports/pupmas_report_*.html

# View latest JSON report
cat reports/pupmas_report_*.json

# List all reports
ls -la reports/

# View database stats
python3 pupmas.py --db-stats

# =============================================================================
# 📖 DOCUMENTATION FILES
# =============================================================================

# Start here
cat READY.md

# Full overview
cat INDEX.md

# Pipeline guide
cat AUTOMATED_PIPELINE.md

# What changed (technical)
cat SCANNER_UPGRADE.md

# Full summary
cat UPGRADE_COMPLETE.md

# Complete technical reference
cat COMPLETE_SUMMARY.md

# =============================================================================
# 🎯 REAL-WORLD EXAMPLES
# =============================================================================

# HTB Box (Hack The Box)
python3 pupmas.py --auto-scan --auto-target 10.10.10.50 --auto-type ctf

# Target domain (pentest)
python3 pupmas.py --auto-scan --auto-target acme.com --auto-profile aggressive --auto-type pentest

# Local network (blue team)
python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-no-exploit

# Red team operation
python3 pupmas.py --auto-scan --auto-target 10.0.0.1 --auto-profile aggressive --auto-type redteam

# Quick reconnaissance
python3 pupmas.py --auto-scan --auto-target target.local --auto-profile passive

# =============================================================================
# ⚙️ PARAMETERS EXPLAINED
# =============================================================================

# --auto-scan              : Start automated pipeline (REQUIRED)
# --auto-target TARGET     : IP address or domain (REQUIRED)
#                           Examples: 10.10.10.5, target.com, 192.168.1.1
#
# --auto-profile LEVEL     : Scan aggressiveness level
#                           passive      : DNS enumeration only (stealthy)
#                           active       : Common ports + services (default, balanced)
#                           aggressive   : Top 1000 ports + all tests (thorough)
#
# --auto-type TYPE         : Operation type for timeline
#                           pentest      : Penetration testing (default)
#                           ctf          : CTF/vulnerable machine
#                           redteam      : Red team operation
#                           blueteam     : Blue team/defense analysis
#
# --auto-report FORMAT     : Report output format
#                           html         : HTML report (default, interactive)
#                           json         : JSON structured data
#
# --auto-no-exploit        : Skip exploitation phase
#                           Useful for: Blue team, recon-only scans
#
# --auto-no-db             : Don't save to database
#                           Useful for: Quick scans, privacy

# =============================================================================
# 📊 WHAT EACH PROFILE DOES
# =============================================================================

# PASSIVE (30s - 2 min)
# - DNS enumeration
# - Subdomain finding (passive DNS)
# - No port scanning
# - No active probing
# - Completely stealthy
# Use for: Reconnaissance without triggering alerts

# ACTIVE (2-5 min) - DEFAULT
# - Port scanning (common ports only: 22, 80, 443, 3306, etc.)
# - Service detection
# - Banner grabbing
# - DNS enumeration
# - Subdomain finding
# - Web vulnerability testing
# Use for: Balanced, normal penetration testing

# AGGRESSIVE (5-15 min)
# - Port scanning (top 1000 ports)
# - Extended service fingerprinting
# - Full vulnerability testing
# - DNS enumeration
# - Extended subdomain wordlist
# - All exploitation tests
# Use for: Thorough assessment, red team, CTF

# =============================================================================
# 📈 EXPECTED RESULTS
# =============================================================================

# After scan you'll get:
# 1. HTML Report       : reports/pupmas_report_TIMESTAMP.html
# 2. JSON Report       : reports/pupmas_report_TIMESTAMP.json (if --auto-report json)
# 3. Recon Data        : recon_results.json
# 4. Database Entry    : Saved in SQLite
# 5. Timeline          : Automatic event creation
# 6. MITRE Mapping     : Technique correlation
# 7. Console Summary   : Quick overview

# =============================================================================
# 🔥 COMMON SCENARIOS
# =============================================================================

# Scenario 1: Penetration Testing
# Goal: Complete vulnerability assessment
# Command:
python3 pupmas.py --auto-scan --auto-target target.com --auto-profile aggressive --auto-type pentest
# Duration: 5-10 minutes
# Includes: Recon + Full exploitation + Timeline + Report

# Scenario 2: CTF / Vulnerable Box
# Goal: Quick exploitation of known vulnerable machine
# Command:
python3 pupmas.py --auto-scan --auto-target 10.10.10.50 --auto-type ctf
# Duration: 3-5 minutes
# Includes: Port scan + Service detection + Web testing + Report

# Scenario 3: Red Team Operation
# Goal: Comprehensive attack chain
# Command:
python3 pupmas.py --auto-scan --auto-target 10.0.0.1 --auto-profile aggressive --auto-type redteam
# Duration: 10-15 minutes
# Includes: Full recon + Full exploitation + MITRE mapping + Timeline

# Scenario 4: Blue Team Defensive Analysis
# Goal: Vulnerability assessment without active exploitation
# Command:
python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-no-exploit --auto-type blueteam
# Duration: 2-3 minutes
# Includes: Recon + CVE analysis + SIEM rules (no actual exploitation)

# Scenario 5: Quick Reconnaissance
# Goal: Fast information gathering
# Command:
python3 pupmas.py --auto-scan --auto-target target --auto-profile passive
# Duration: 30 seconds - 2 minutes
# Includes: DNS enumeration + Subdomain finding (stealthy)

# =============================================================================
# 🆘 TROUBLESHOOTING
# =============================================================================

# Problem: Scan is too slow
# Solution: Use passive profile
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile passive

# Problem: Too many false positives
# Solution: Use active profile (balanced)
python3 pupmas.py --auto-scan --auto-target TARGET --auto-profile active

# Problem: Want only reconnaissance
# Solution: Use --auto-no-exploit
python3 pupmas.py --auto-scan --auto-target TARGET --auto-no-exploit

# Problem: Don't want to save to database
# Solution: Use --auto-no-db
python3 pupmas.py --auto-scan --auto-target TARGET --auto-no-db

# Problem: Need structured JSON data
# Solution: Use --auto-report json
python3 pupmas.py --auto-scan --auto-target TARGET --auto-report json

# Problem: Python not found
# Solution: Use full path to Python
/usr/bin/python3 pupmas.py --auto-scan --auto-target TARGET

# Problem: Module not found
# Solution: Install requirements
pip3 install -r requirements.txt

# =============================================================================
# 📋 VERIFICATION CHECKLIST
# =============================================================================

# After installation, verify everything works:

# 1. Check Python version
python3 --version

# 2. Check dependencies
pip3 list | grep -i "requests\|rich\|sqlalchemy"

# 3. Test import
python3 -c "from modules.reconnaissance import ReconnaissanceEngine; print('✓ OK')"

# 4. Test help
python3 pupmas.py --help

# 5. Test quick reference
python3 reference.py menu

# 6. Run demo
python3 demo.py

# =============================================================================
# 🎯 NEXT STEPS
# =============================================================================

# 1. Read documentation
cat READY.md
cat INDEX.md

# 2. Run first scan
python3 pupmas.py --auto-scan --auto-target 10.10.10.5

# 3. View results
cat reports/pupmas_report_*.html

# 4. Explore features
python3 reference.py examples

# 5. Try different scenarios
python3 pupmas.py --auto-scan --auto-target target --auto-profile aggressive
python3 pupmas.py --auto-scan --auto-target target --auto-type redteam
python3 pupmas.py --auto-scan --auto-target target --auto-no-exploit

# =============================================================================
# 📞 GET HELP
# =============================================================================

# View quick reference
python3 reference.py menu

# View examples
python3 reference.py examples

# View troubleshooting
python3 reference.py troubleshoot

# View feature showcase
python3 demo.py

# Read full documentation
cat AUTOMATED_PIPELINE.md
cat COMPLETE_SUMMARY.md

# =============================================================================
# 🚀 START NOW!
# =============================================================================

# Simplest possible command:
python3 pupmas.py --auto-scan --auto-target TARGET

# Replace TARGET with actual target:
# - IP address: 10.10.10.5
# - Domain: target.com
# - Local IP: 192.168.1.100

# Then wait 2-5 minutes for results!

# =============================================================================
