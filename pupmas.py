#!/usr/bin/env python3
"""
PUPMAS - Puppeteer Master
Advanced Cybersecurity Operations and Intelligence Framework
Author: Security Research Team
Version: 1.0.0
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

from ui.cli import CLI
from ui.tui import TUI
from core.mitre_handler import MITREHandler
from core.cve_handler import CVEHandler
from core.attack_schemas import AttackSchemaEngine
from core.timeline_manager import TimelineManager
from core.siem_handler import SIEMHandler
from utils.db_manager import DatabaseManager
from utils.helpers import setup_logging, banner
from modules.auto_pipeline import AutomatedPipeline, PipelineConfig

__version__ = "1.0.0"
__author__ = "PUPMAS Team"


def main():
    """Main entry point for PUPMAS"""
    parser = argparse.ArgumentParser(
        description="PUPMAS - Advanced Cybersecurity Operations Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pupmas.py --mode tui                    # Launch interactive TUI
  pupmas.py --mitre T1059.001             # Query MITRE technique
  pupmas.py --cve CVE-2024-1234           # Search CVE database
  pupmas.py --timeline attack             # View attack timeline
  pupmas.py --recon --target 10.10.10.1   # Start reconnaissance
  pupmas.py --exfil-test --method dns     # Test data exfiltration
  pupmas.py --siem-parse logs.json        # Parse SIEM logs
  pupmas.py --report --format pdf         # Generate comprehensive report
        """
    )
    
    # Operational modes
    mode_group = parser.add_argument_group('Operational Modes')
    mode_group.add_argument('--mode', choices=['cli', 'tui'], default='tui',
                           help='Interface mode (default: tui)')
    mode_group.add_argument('--interactive', '-i', action='store_true',
                           help='Start interactive mode')
    
    # MITRE ATT&CK operations
    mitre_group = parser.add_argument_group('MITRE ATT&CK Operations')
    mitre_group.add_argument('--mitre', metavar='TECHNIQUE',
                            help='Query MITRE ATT&CK technique (e.g., T1059.001)')
    mitre_group.add_argument('--tactics', action='store_true',
                            help='List all MITRE tactics')
    mitre_group.add_argument('--techniques', metavar='TACTIC',
                            help='List techniques for specific tactic')
    mitre_group.add_argument('--map-attack', metavar='LOG_FILE',
                            help='Map attack logs to MITRE framework')
    
    # CVE operations
    cve_group = parser.add_argument_group('CVE Operations')
    cve_group.add_argument('--cve', metavar='CVE_ID',
                          help='Search CVE by ID')
    cve_group.add_argument('--cve-search', metavar='KEYWORD',
                          help='Search CVEs by keyword')
    cve_group.add_argument('--cve-update', action='store_true',
                          help='Update CVE database')
    cve_group.add_argument('--cve-recent', type=int, metavar='N',
                          help='Show N most recent CVEs')
    
    # Attack schemas and rules
    schema_group = parser.add_argument_group('Attack Schema Operations')
    schema_group.add_argument('--schema', metavar='ATTACK_TYPE',
                             help='Load attack schema template')
    schema_group.add_argument('--validate', metavar='ATTACK_FILE',
                             help='Validate attack configuration against schema')
    schema_group.add_argument('--generate-rules', action='store_true',
                             help='Generate detection rules from schema')
    
    # Timeline operations
    timeline_group = parser.add_argument_group('Timeline Operations')
    timeline_group.add_argument('--timeline', choices=['attack', 'pentest', 'recon', 'exfil'],
                               help='View operation timeline')
    timeline_group.add_argument('--add-event', nargs=3, metavar=('TYPE', 'ACTION', 'DETAILS'),
                               help='Add timeline event')
    timeline_group.add_argument('--export-timeline', metavar='FILE',
                               help='Export timeline to file')
    
    # Reconnaissance operations
    recon_group = parser.add_argument_group('Reconnaissance Operations')
    recon_group.add_argument('--recon', action='store_true',
                            help='Start reconnaissance module')
    recon_group.add_argument('--target', metavar='TARGET',
                            help='Target IP/domain for reconnaissance')
    recon_group.add_argument('--recon-profile', choices=['passive', 'active', 'aggressive'],
                            default='passive', help='Reconnaissance profile')
    
    # Exfiltration operations
    exfil_group = parser.add_argument_group('Exfiltration Operations')
    exfil_group.add_argument('--exfil-test', action='store_true',
                            help='Test data exfiltration methods')
    exfil_group.add_argument('--method', choices=['dns', 'http', 'https', 'icmp', 'smtp'],
                            help='Exfiltration method to test')
    exfil_group.add_argument('--payload', metavar='FILE',
                            help='Payload file for exfiltration test')
    
    # SIEM operations
    siem_group = parser.add_argument_group('SIEM Operations')
    siem_group.add_argument('--siem-parse', metavar='LOG_FILE',
                           help='Parse log file')
    siem_group.add_argument('--siem-format', choices=['json', 'syslog', 'cef', 'leef'],
                           default='json', help='Log format')
    siem_group.add_argument('--siem-export', metavar='OUTPUT',
                           help='Export parsed logs')
    siem_group.add_argument('--generate-logs', metavar='SCENARIO',
                           help='Generate sample logs for scenario')
    
    # Reporting
    report_group = parser.add_argument_group('Reporting')
    report_group.add_argument('--report', action='store_true',
                             help='Generate comprehensive report')
    report_group.add_argument('--format', choices=['pdf', 'html', 'markdown', 'json'],
                             default='html', help='Report format')
    report_group.add_argument('--output', metavar='FILE',
                             help='Output file path')
    
    # Automated Pipeline (NEW) - One command to do everything!
    pipeline_group = parser.add_argument_group('Automated Pipeline (NEW - Do Everything!)')
    pipeline_group.add_argument('--auto-scan', action='store_true',
                               help='🚀 RUN FULL AUTOMATED SCAN: Recon + Exploit + CVE + Timeline + Report')
    pipeline_group.add_argument('--auto-target', metavar='TARGET',
                               help='Target IP/domain for automated scan')
    pipeline_group.add_argument('--auto-profile', choices=['passive', 'active', 'aggressive'],
                               default='active', help='Scan aggressiveness level')
    pipeline_group.add_argument('--auto-type', choices=['pentest', 'ctf', 'redteam', 'blueteam'],
                               default='pentest', help='Operation type for timeline')
    pipeline_group.add_argument('--auto-report', choices=['html', 'json'],
                               default='html', help='Report format')
    pipeline_group.add_argument('--auto-no-exploit', action='store_true',
                               help='Skip exploitation/vulnerability testing')
    pipeline_group.add_argument('--auto-no-db', action='store_true',
                               help='Skip database saving')
    pipeline_group.add_argument('--auto-open', action='store_true',
                               help='Automatically open report in browser when complete')
    pipeline_group.add_argument('--no-prompt', '-n', action='store_true',
                               help='Skip interactive prompts (e.g., report opening question)')
    
    # General options
    parser.add_argument('--config', metavar='FILE',
                       help='Custom configuration file')
    parser.add_argument('--update', action='store_true',
                       help='Update PUPMAS to latest version')
    parser.add_argument('--open-report', action='store_true',
                       help='Open the most recent report in browser')
    parser.add_argument('--verbose', '-v', action='count', default=0,
                       help='Increase verbosity level')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress output')
    parser.add_argument('--version', action='version',
                       version=f'PUPMAS v{__version__}')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = setup_logging(args.verbose, args.quiet)
    
    # Initialize core components
    db_manager = DatabaseManager()
    
    # Handle open-report request
    if args.open_report:
        import subprocess
        import platform
        import glob
        try:
            reports_dir = Path(__file__).parent / 'reports'
            html_reports = sorted(reports_dir.glob('pupmas_report_*.html'), key=lambda p: p.stat().st_mtime, reverse=True)
            if not html_reports:
                print("[!] No reports found in reports/ directory")
                sys.exit(1)
            latest_report = html_reports[0]
            print(f"[+] Opening report: {latest_report.name}")
            if platform.system() == 'Darwin':
                subprocess.run(['open', str(latest_report)])
            elif platform.system() == 'Windows':
                subprocess.run(['start', str(latest_report)], shell=True)
            else:
                subprocess.run(['xdg-open', str(latest_report)])
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error opening report: {e}")
            sys.exit(1)
    
    # Handle update request
    if args.update:
        import subprocess
        import os
        print("[+] Updating PUPMAS...")
        install_dir = Path(__file__).parent.absolute()
        try:
            os.chdir(install_dir)
            subprocess.run(['git', 'pull', 'origin', 'main'], check=True)
            if (install_dir / 'venv').exists():
                venv_python = install_dir / 'venv' / 'bin' / 'python'
                if venv_python.exists():
                    subprocess.run([str(venv_python), '-m', 'pip', 'install', '-q', '--upgrade', 'pip'], check=True)
                    subprocess.run([str(venv_python), '-m', 'pip', 'install', '-q', '-r', 'requirements.txt'], check=True)
            print("[✓] Update complete!")
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            print(f"[!] Update failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
    
    # Display banner unless quiet mode
    if not args.quiet:
        banner()
    
    # ============================================
    # AUTOMATED PIPELINE - One command does it all!
    # ============================================
    if args.auto_scan:
        if not args.target:
            print("[!] Error: TARGET required for automated scan")
            print("[*] Example: pupmas --auto-scan 10.10.10.50")
            print("[*] Example: pupmas --auto-scan example.com -n")
            sys.exit(1)
        
        config = PipelineConfig(
            target=args.target,
            operation_type=args.auto_type,
            recon_profile=args.auto_profile,
            enable_exploitation=not args.auto_no_exploit,
            enable_timeline=True,
            enable_siem=True,
            generate_report=True,
            report_format=args.auto_report,
            database_save=not args.auto_no_db,
            session_id=None
        )
        
        pipeline = AutomatedPipeline(config)
        result = pipeline.run()
        
        if result.report_path:
            print(f"\n✅ Report saved: {result.report_path}\n")
            
            # Auto-open report if requested
            if args.auto_open:
                import subprocess
                import platform
                try:
                    if platform.system() == 'Darwin':  # macOS
                        subprocess.run(['open', result.report_path])
                    elif platform.system() == 'Windows':
                        subprocess.run(['start', result.report_path], shell=True)
                    else:  # Linux
                        subprocess.run(['xdg-open', result.report_path])
                    print(f"🌐 Opening report in browser...\n")
                except Exception as e:
                    print(f"⚠ Could not auto-open: {e}\n")
            # Ask if user wants to open report (only for HTML, TTY, and no --no-prompt)
            elif args.auto_report == 'html' and sys.stdin.isatty() and not args.no_prompt:
                try:
                    response = input("📄 Open report in browser? [Y/n]: ").strip().lower()
                    if response in ['', 'y', 'yes']:
                        import subprocess
                        import platform
                        if platform.system() == 'Darwin':
                            subprocess.run(['open', result.report_path])
                        elif platform.system() == 'Windows':
                            subprocess.run(['start', result.report_path], shell=True)
                        else:
                            subprocess.run(['xdg-open', result.report_path])
                        print("🌐 Opening...\n")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
        sys.exit(0)
    
    # Route to appropriate handler
    if args.mode == 'tui' and not any([
        args.mitre, args.cve, args.timeline, args.recon,
        args.exfil_test, args.siem_parse, args.report, args.auto_scan
    ]):
        # Launch TUI if no specific command given
        tui = TUI(db_manager)
        tui.run()
    elif args.mode == 'cli' or any([
        args.mitre, args.cve, args.timeline, args.recon,
        args.exfil_test, args.siem_parse, args.report
    ]):
        # Handle CLI commands
        cli = CLI(db_manager, args)
        cli.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)
