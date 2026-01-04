"""
Helper utilities for PUPMAS
Logging, banners, and common functions
"""

import logging
import sys
from pathlib import Path
from typing import Optional
import colorlog


def setup_logging(verbosity: int = 0, quiet: bool = False) -> int:
    """
    Setup logging configuration
    
    Args:
        verbosity: Verbosity level (0=WARNING, 1=INFO, 2=DEBUG)
        quiet: Suppress all output
    
    Returns:
        Log level as integer
    """
    if quiet:
        log_level = logging.CRITICAL
    else:
        levels = [logging.WARNING, logging.INFO, logging.DEBUG]
        log_level = levels[min(verbosity, len(levels) - 1)]
    
    # Create logs directory
    log_dir = Path(__file__).parent.parent / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Color formatter for console
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s[%(levelname)s]%(reset)s %(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    
    # File formatter
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    
    # File handler
    log_file = log_dir / "pupmas.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    return log_level


def banner():
    """Display PUPMAS banner"""
    try:
        from pyfiglet import figlet_format
        from rich.console import Console
        from rich.panel import Panel
        
        console = Console()
        
        # ASCII art banner
        ascii_art = figlet_format("PUPMAS", font="slant")
        
        banner_text = f"""[bold cyan]{ascii_art}[/bold cyan]
[bold white]Puppeteer Master - Advanced Cybersecurity Operations Framework[/bold white]

[yellow]Version:[/yellow] 1.0.0
[yellow]Author:[/yellow] PUPMAS Security Research Team
[yellow]Purpose:[/yellow] Penetration Testing, CTF, Security Research

[green]Features:[/green]
  • MITRE ATT&CK Integration    • CVE Database Management
  • Attack Schema Engine         • Timeline Tracking
  • SIEM Log Analysis           • Multi-format Report Generation
  • Reconnaissance Tools        • Exploitation Framework
  • Data Exfiltration Testing   • Persistence Mechanisms

[red]⚠ WARNING: Use responsibly and only on authorized systems ⚠[/red]
"""
        
        panel = Panel(
            banner_text,
            border_style="bold blue",
            padding=(1, 2)
        )
        
        console.print(panel)
        
    except ImportError:
        # Fallback if pyfiglet or rich not available
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ____  _   _ ____  __  __    _    ____                          ║
║  |  _ \\| | | |  _ \\|  \\/  |  / \\  / ___|                         ║
║  | |_) | | | | |_) | |\\/| | / _ \\ \\___ \\                         ║
║  |  __/| |_| |  __/| |  | |/ ___ \\ ___) |                        ║
║  |_|    \\___/|_|   |_|  |_/_/   \\_\\____/                         ║
║                                                                   ║
║          Advanced Cybersecurity Operations Framework             ║
║                                                                   ║
║  Version: 1.0.0                                                   ║
║  Purpose: Penetration Testing, CTF, Security Research            ║
║                                                                   ║
║  ⚠ WARNING: Use responsibly and only on authorized systems ⚠    ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""")


def format_bytes(bytes_count: int) -> str:
    """Format bytes to human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format seconds to human-readable duration"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def validate_ip(ip: str) -> bool:
    """Validate IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def generate_id(prefix: str = "", length: int = 8) -> str:
    """Generate unique ID"""
    import hashlib
    import time
    
    data = f"{prefix}{time.time()}"
    hash_obj = hashlib.md5(data.encode())
    return hash_obj.hexdigest()[:length]


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    import re
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename


def chunks(lst: list, n: int):
    """Yield successive n-sized chunks from list"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def create_table(headers: list, rows: list) -> str:
    """Create ASCII table from data"""
    from tabulate import tabulate
    return tabulate(rows, headers=headers, tablefmt='grid')


def progress_bar(iterable, desc: str = "", total: Optional[int] = None):
    """Display progress bar for iterable"""
    try:
        from tqdm import tqdm
        return tqdm(iterable, desc=desc, total=total)
    except ImportError:
        # Fallback without progress bar
        return iterable


def confirm_action(message: str, default: bool = False) -> bool:
    """Ask user for confirmation"""
    default_str = "[Y/n]" if default else "[y/N]"
    response = input(f"{message} {default_str}: ").strip().lower()
    
    if not response:
        return default
    
    return response in ['y', 'yes']


def print_success(message: str):
    """Print success message"""
    try:
        from rich.console import Console
        console = Console()
        console.print(f"[green]✓[/green] {message}")
    except ImportError:
        print(f"[+] {message}")


def print_error(message: str):
    """Print error message"""
    try:
        from rich.console import Console
        console = Console()
        console.print(f"[red]✗[/red] {message}")
    except ImportError:
        print(f"[-] {message}")


def print_warning(message: str):
    """Print warning message"""
    try:
        from rich.console import Console
        console = Console()
        console.print(f"[yellow]⚠[/yellow] {message}")
    except ImportError:
        print(f"[!] {message}")


def print_info(message: str):
    """Print info message"""
    try:
        from rich.console import Console
        console = Console()
        console.print(f"[blue]ℹ[/blue] {message}")
    except ImportError:
        print(f"[*] {message}")


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def colorize(text: str, color: str) -> str:
    """Colorize text with ANSI codes"""
    color_map = {
        'red': Colors.FAIL,
        'green': Colors.OKGREEN,
        'yellow': Colors.WARNING,
        'blue': Colors.OKBLUE,
        'cyan': Colors.OKCYAN,
        'bold': Colors.BOLD
    }
    
    color_code = color_map.get(color.lower(), '')
    return f"{color_code}{text}{Colors.ENDC}" if color_code else text


def get_terminal_size() -> tuple:
    """Get terminal size (width, height)"""
    import shutil
    size = shutil.get_terminal_size((80, 24))
    return (size.columns, size.lines)


def clear_screen():
    """Clear terminal screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def parse_target(target: str) -> dict:
    """Parse target string into components"""
    import urllib.parse
    
    result = {
        'original': target,
        'type': 'unknown',
        'host': None,
        'port': None,
        'protocol': None
    }
    
    # Check if it's a URL
    if '://' in target:
        parsed = urllib.parse.urlparse(target)
        result['type'] = 'url'
        result['protocol'] = parsed.scheme
        result['host'] = parsed.hostname
        result['port'] = parsed.port
    # Check if it's IP:PORT
    elif ':' in target and not validate_domain(target):
        parts = target.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            result['type'] = 'ip_port'
            result['host'] = parts[0]
            result['port'] = int(parts[1])
    # Check if it's an IP
    elif validate_ip(target):
        result['type'] = 'ip'
        result['host'] = target
    # Check if it's a domain
    elif validate_domain(target):
        result['type'] = 'domain'
        result['host'] = target
    
    return result


def load_wordlist(wordlist_path: Path) -> list:
    """Load wordlist from file"""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Error loading wordlist: {e}")
        return []


def save_json(data: dict, output_path: Path, indent: int = 2):
    """Save data to JSON file"""
    import json
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, default=str)


def load_json(input_path: Path) -> dict:
    """Load data from JSON file"""
    import json
    with open(input_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_timestamp(format: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Get current timestamp as formatted string"""
    from datetime import datetime
    return datetime.now().strftime(format)


def retry_on_failure(func, max_attempts: int = 3, delay: float = 1.0):
    """Retry function on failure"""
    import time
    
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception as e:
            if attempt == max_attempts - 1:
                raise
            print_warning(f"Attempt {attempt + 1} failed: {e}. Retrying...")
            time.sleep(delay)


def check_root():
    """Check if running with root/admin privileges"""
    import os
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def get_local_ip() -> str:
    """Get local IP address"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"


def get_system_info() -> dict:
    """Get system information"""
    import platform
    import psutil
    
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'cpu_count': psutil.cpu_count(),
        'memory_total': format_bytes(psutil.virtual_memory().total),
        'memory_available': format_bytes(psutil.virtual_memory().available),
        'disk_total': format_bytes(psutil.disk_usage('/').total),
        'disk_free': format_bytes(psutil.disk_usage('/').free)
    }
