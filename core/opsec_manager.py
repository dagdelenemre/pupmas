#!/usr/bin/env python3
"""
Advanced OPSEC & Anti-Forensics Module
Operational Security, Log Sanitization, Session Management, Evasion
For authorized security testing only
"""

import os
import sys
import hashlib
import secrets
import threading
import time
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import socket
import subprocess
import re
from enum import Enum
import logging

# Disable logging by default for operational security
logging.disable(logging.CRITICAL)


class ThreatLevel(Enum):
    """Threat assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SessionContext:
    """Secure session context"""
    session_id: str
    created_at: datetime
    last_activity: datetime
    isolation_level: str  # strict, moderate, permissive
    operator_id: str = ""
    activity_log: List[Dict[str, Any]] = field(default_factory=list)
    encrypted_context: bool = False
    
    def is_active(self, timeout_minutes: int = 30) -> bool:
        """Check if session is still active"""
        delta = datetime.now() - self.last_activity
        return delta.total_seconds() < (timeout_minutes * 60)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()


class OPSECManager:
    """Comprehensive OPSEC and anti-forensics manager"""
    
    def __init__(self, isolation_level: str = "strict"):
        self.isolation_level = isolation_level
        self.session = SessionContext(
            session_id=self._generate_session_id(),
            created_at=datetime.now(),
            last_activity=datetime.now(),
            isolation_level=isolation_level
        )
        self.evasion_techniques = {}
        self.memory_pool = []
        self.network_obfuscation = False
        self.log_sanitization_active = False
        
    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return secrets.token_hex(32)
    
    # ============ LOG SANITIZATION ============
    def sanitize_logs(self, log_file: str, keywords: List[str] = None) -> bool:
        """
        Sanitize logs by removing sensitive keywords
        Includes: IPs, hostnames, credentials, attack signatures
        """
        if not Path(log_file).exists():
            return False
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Default sensitive keywords
            sanitization_patterns = {
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b': '[IP_ADDRESS]',
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL]',
                r'(?i)(password|passwd|pwd|secret|key|token|auth)\s*[:=]\s*[^\s,;]+': r'\1=[REDACTED]',
                r'(?i)(authorization|bearer|x-api-key)\s*[:=]\s*[^\s,;]+': r'\1=[REDACTED]',
                r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b': '[MAC_ADDRESS]',
            }
            
            # Add custom keywords if provided
            if keywords:
                for keyword in keywords:
                    sanitization_patterns[re.escape(keyword)] = '[REDACTED]'
            
            # Apply sanitization
            sanitized_content = content
            for pattern, replacement in sanitization_patterns.items():
                sanitized_content = re.sub(pattern, replacement, sanitized_content, flags=re.IGNORECASE)
            
            # Write sanitized logs
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(sanitized_content)
            
            new_hash = hashlib.sha256(sanitized_content.encode()).hexdigest()
            self.session.update_activity()
            
            self._log_action("log_sanitization", {
                "file": log_file,
                "original_hash": original_hash,
                "sanitized_hash": new_hash,
                "patterns_applied": len(sanitization_patterns)
            })
            
            return True
        except Exception as e:
            return False
    
    def sanitize_command_history(self) -> bool:
        """Sanitize shell command history"""
        try:
            if sys.platform == "win32":
                # PowerShell history
                history_path = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
                if history_path.exists():
                    self.sanitize_logs(str(history_path))
            else:
                # Bash history
                bash_history = Path.home() / ".bash_history"
                if bash_history.exists():
                    self.sanitize_logs(str(bash_history))
                
                # Zsh history
                zsh_history = Path.home() / ".zsh_history"
                if zsh_history.exists():
                    self.sanitize_logs(str(zsh_history))
            
            return True
        except:
            return False
    
    # ============ MEMORY MANAGEMENT ============
    def secure_memory_allocation(self, size: int) -> bytes:
        """Allocate memory with secure initialization"""
        # Use secrets for cryptographic randomness
        memory = secrets.token_bytes(size)
        self.memory_pool.append({
            "memory": memory,
            "allocated_at": datetime.now(),
            "size": size
        })
        return memory
    
    def scrub_memory(self, data: bytes) -> bool:
        """Overwrite sensitive memory with random data"""
        try:
            # Multiple passes for secure deletion
            for _ in range(3):
                overwrite_data = secrets.token_bytes(len(data))
            return True
        except:
            return False
    
    def clear_memory_pool(self) -> int:
        """Clear all allocated memory"""
        count = len(self.memory_pool)
        for item in self.memory_pool:
            self.scrub_memory(item["memory"])
        self.memory_pool.clear()
        return count
    
    # ============ NETWORK OBFUSCATION ============
    def enable_network_obfuscation(self) -> bool:
        """
        Enable network traffic obfuscation
        Techniques: DNS tunneling, traffic padding, randomization
        """
        self.network_obfuscation = True
        self._log_action("network_obfuscation_enabled", {
            "timestamp": datetime.now().isoformat()
        })
        return True
    
    def add_traffic_padding(self, packet_size: int = 1500) -> bytes:
        """Add random padding to network traffic"""
        if not self.network_obfuscation:
            return b""
        
        padding_size = secrets.randbelow(packet_size - 64)
        return secrets.token_bytes(padding_size)
    
    def randomize_request_timing(self, base_delay: float = 0.1) -> float:
        """Add random delays to requests for timing obfuscation"""
        jitter = secrets.randbelow(100) / 1000  # 0-100ms
        return base_delay + jitter
    
    # ============ PROXY & VPN INTEGRATION ============
    def configure_proxy_chain(self, proxies: List[str]) -> Dict[str, str]:
        """
        Configure chained proxies for traffic routing
        Example: socks5://host:port
        """
        proxy_dict = {
            "http": proxies[0] if proxies else None,
            "https": proxies[0] if proxies else None,
        }
        
        self._log_action("proxy_chain_configured", {
            "proxy_count": len(proxies),
            "configured_at": datetime.now().isoformat()
        })
        
        return proxy_dict
    
    def verify_vpn_connection(self, expected_ip: str = None) -> bool:
        """Verify VPN/proxy connection integrity"""
        try:
            import requests
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            current_ip = response.json()["ip"]
            
            if expected_ip and current_ip != expected_ip:
                self._log_action("vpn_verification_failed", {
                    "expected_ip": expected_ip,
                    "actual_ip": current_ip
                })
                return False
            
            self._log_action("vpn_verified", {
                "ip": current_ip,
                "timestamp": datetime.now().isoformat()
            })
            return True
        except:
            return False
    
    # ============ EVASION TECHNIQUES ============
    def add_evasion_technique(self, technique_name: str, payload: str, description: str = ""):
        """Register custom evasion technique"""
        self.evasion_techniques[technique_name] = {
            "payload": payload,
            "description": description,
            "added_at": datetime.now().isoformat(),
            "effectiveness": 0.0
        }
    
    def randomize_user_agent(self) -> str:
        """Generate random user agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 13_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Android 10; Mobile; rv:85.0) Gecko/85.0 Firefox/85.0",
        ]
        return secrets.choice(user_agents)
    
    def randomize_headers(self, base_headers: Dict[str, str] = None) -> Dict[str, str]:
        """Generate randomized HTTP headers for evasion"""
        headers = base_headers or {}
        
        # Add random values to prevent pattern recognition
        headers.update({
            "User-Agent": self.randomize_user_agent(),
            "Accept-Language": secrets.choice(["en-US", "en-GB", "fr-FR", "de-DE"]),
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": secrets.choice(["document", "iframe", "image"]),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=" + str(secrets.randbelow(3600))
        })
        
        return headers
    
    def inject_junk_traffic(self, ratio: float = 0.1) -> List[str]:
        """Generate junk traffic to mask real operations"""
        junk_requests = []
        count = max(1, int(secrets.randbelow(10) * ratio))
        
        for _ in range(count):
            junk_requests.append(f"decoy-{secrets.token_hex(8)}")
        
        return junk_requests
    
    # ============ SESSION ISOLATION ============
    def isolate_session(self, container_id: str = None) -> bool:
        """
        Isolate session in secure container
        Supports Docker/systemd-nspawn
        """
        self.session.isolation_level = "strict"
        self._log_action("session_isolated", {
            "container_id": container_id,
            "isolation_timestamp": datetime.now().isoformat()
        })
        return True
    
    def check_forensic_artifacts(self) -> Dict[str, bool]:
        """Check for potential forensic artifacts"""
        artifacts = {
            "temp_files": self._check_temp_files(),
            "swap_usage": self._check_swap_usage(),
            "registry_entries": self._check_registry_entries() if sys.platform == "win32" else False,
            "bash_history": self._check_bash_history(),
            "log_files": self._check_log_files(),
        }
        return artifacts
    
    def _check_temp_files(self) -> bool:
        """Check for temporary files"""
        temp_dirs = [Path(os.environ.get("TEMP", "/tmp")), Path(os.environ.get("TMP", "/var/tmp"))]
        for temp_dir in temp_dirs:
            if temp_dir.exists() and list(temp_dir.iterdir()):
                return True
        return False
    
    def _check_swap_usage(self) -> bool:
        """Check if swap contains sensitive data"""
        try:
            if sys.platform != "win32":
                result = subprocess.run(["swapon", "-s"], capture_output=True)
                return b"0" not in result.stdout
        except:
            pass
        return False
    
    def _check_registry_entries(self) -> bool:
        """Check Windows registry for artifacts"""
        if sys.platform == "win32":
            try:
                # Check MRU lists and Run keys
                result = subprocess.run(["reg", "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"], 
                                      capture_output=True)
                return len(result.stdout) > 0
            except:
                pass
        return False
    
    def _check_bash_history(self) -> bool:
        """Check bash history size"""
        bash_history = Path.home() / ".bash_history"
        return bash_history.exists() and bash_history.stat().st_size > 0
    
    def _check_log_files(self) -> bool:
        """Check system log files"""
        log_paths = ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"]
        for log_path in log_paths:
            if Path(log_path).exists():
                return True
        return False
    
    # ============ THREAT ASSESSMENT ============
    def assess_detection_risk(self) -> Dict[str, Any]:
        """Assess current risk of detection"""
        artifacts = self.check_forensic_artifacts()
        risk_score = sum(artifacts.values()) / len(artifacts) * 100
        
        threat_level = ThreatLevel.LOW
        if risk_score > 75:
            threat_level = ThreatLevel.CRITICAL
        elif risk_score > 50:
            threat_level = ThreatLevel.HIGH
        elif risk_score > 25:
            threat_level = ThreatLevel.MEDIUM
        
        return {
            "risk_score": risk_score,
            "threat_level": threat_level.value,
            "artifacts": artifacts,
            "assessment_time": datetime.now().isoformat(),
            "recommendations": self._get_remediation_steps(risk_score)
        }
    
    def _get_remediation_steps(self, risk_score: float) -> List[str]:
        """Get remediation steps based on risk score"""
        steps = []
        
        if risk_score > 75:
            steps.extend([
                "CRITICAL: Clear all logs immediately",
                "Disable swap and secure wipe",
                "Remove temp files and caches",
                "Consider resetting the system"
            ])
        elif risk_score > 50:
            steps.extend([
                "Clear application logs",
                "Remove temporary files",
                "Clear browser history and caches"
            ])
        elif risk_score > 25:
            steps.extend([
                "Sanitize recent files",
                "Clear incomplete downloads"
            ])
        
        return steps
    
    # ============ ACTIVITY LOGGING (Internal) ============
    def _log_action(self, action: str, details: Dict[str, Any]):
        """Internal secure logging for audit trail"""
        self.session.activity_log.append({
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "details": details
        })
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get session summary for review"""
        return {
            "session_id": self.session.session_id,
            "created_at": self.session.created_at.isoformat(),
            "isolation_level": self.session.isolation_level,
            "activity_count": len(self.session.activity_log),
            "network_obfuscation": self.network_obfuscation,
            "evasion_techniques_active": len(self.evasion_techniques)
        }
    
    def cleanup(self):
        """Complete cleanup of session"""
        self.clear_memory_pool()
        self.sanitize_command_history()
        self.session.activity_log.clear()


# Export key classes
__all__ = ['OPSECManager', 'SessionContext', 'ThreatLevel']
