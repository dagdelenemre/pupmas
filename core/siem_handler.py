"""
SIEM Handler - Comprehensive log management and security event correlation
Supports multiple log formats, parsing, generation, and SIEM integration
"""

import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import random


class LogFormat(Enum):
    """Supported log formats"""
    JSON = "json"
    SYSLOG = "syslog"
    CEF = "cef"  # Common Event Format
    LEEF = "leef"  # Log Event Extended Format
    WINDOWS_EVENT = "windows_event"
    APACHE = "apache"
    NGINX = "nginx"
    CUSTOM = "custom"


class LogSeverity(Enum):
    """Log severity levels"""
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ALERT = 6
    EMERGENCY = 7


@dataclass
class LogEntry:
    """Standardized log entry"""
    log_id: str
    timestamp: datetime
    source: str
    severity: LogSeverity
    event_type: str
    message: str
    raw_log: str
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'LogEntry':
        """Create from dictionary"""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        data['severity'] = LogSeverity(data['severity'])
        return cls(**data)


@dataclass
class CorrelationRule:
    """Event correlation rule"""
    rule_id: str
    name: str
    description: str
    event_types: List[str]
    time_window: int  # seconds
    threshold: int
    condition: str
    severity: str
    actions: List[str] = field(default_factory=list)


@dataclass
class Alert:
    """Security alert from correlation"""
    alert_id: str
    rule_id: str
    timestamp: datetime
    severity: str
    title: str
    description: str
    events: List[LogEntry]
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)


class SIEMHandler:
    """
    Advanced SIEM integration handler with log parsing, generation,
    correlation, and alert management capabilities
    """
    
    def __init__(self, data_path: Optional[Path] = None):
        """Initialize SIEM handler"""
        self.data_path = data_path or Path(__file__).parent.parent / "data"
        self.logs_path = self.data_path / "logs"
        self.logs_path.mkdir(parents=True, exist_ok=True)
        
        self.log_buffer: List[LogEntry] = []
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        self.alerts: List[Alert] = []
        self.event_cache: Dict[str, List[LogEntry]] = defaultdict(list)
        
        self._load_correlation_rules()
        self._initialize_parsers()
    
    def _load_correlation_rules(self):
        """Load correlation rules"""
        # Default correlation rules
        default_rules = [
            {
                'rule_id': 'brute_force_detect',
                'name': 'Brute Force Attack Detection',
                'description': 'Multiple failed login attempts from same source',
                'event_types': ['authentication_failure'],
                'time_window': 300,  # 5 minutes
                'threshold': 5,
                'condition': 'count > threshold',
                'severity': 'high',
                'actions': ['block_ip', 'alert_soc']
            },
            {
                'rule_id': 'data_exfiltration',
                'name': 'Potential Data Exfiltration',
                'description': 'Large data transfer to external destination',
                'event_types': ['network_connection', 'file_access'],
                'time_window': 600,
                'threshold': 3,
                'condition': 'data_size > 100MB AND external_ip',
                'severity': 'critical',
                'actions': ['isolate_host', 'alert_soc']
            },
            {
                'rule_id': 'privilege_escalation',
                'name': 'Privilege Escalation Attempt',
                'description': 'User attempting to gain elevated privileges',
                'event_types': ['privilege_use', 'process_creation'],
                'time_window': 180,
                'threshold': 2,
                'condition': 'suspicious_process AND admin_privilege',
                'severity': 'high',
                'actions': ['terminate_process', 'alert_soc']
            },
            {
                'rule_id': 'lateral_movement',
                'name': 'Lateral Movement Detection',
                'description': 'Unusual network activity indicating lateral movement',
                'event_types': ['network_connection', 'authentication_success'],
                'time_window': 300,
                'threshold': 4,
                'condition': 'internal_connections > threshold',
                'severity': 'high',
                'actions': ['alert_soc', 'network_segmentation']
            }
        ]
        
        for rule_data in default_rules:
            rule = CorrelationRule(**rule_data)
            self.correlation_rules[rule.rule_id] = rule
    
    def _initialize_parsers(self):
        """Initialize log parsers for different formats"""
        # Regex patterns for common log formats
        self.parser_patterns = {
            'syslog': re.compile(
                r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
                r'(?P<hostname>\S+)\s+'
                r'(?P<process>\S+)(\[(?P<pid>\d+)\])?: '
                r'(?P<message>.+)$'
            ),
            'apache': re.compile(
                r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
                r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
                r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
            ),
            'windows_event': re.compile(
                r'EventID:\s*(?P<event_id>\d+).*?'
                r'Computer:\s*(?P<computer>\S+).*?'
                r'Message:\s*(?P<message>.+)',
                re.DOTALL
            )
        }
    
    def parse_log(self, log_line: str, log_format: str) -> Optional[LogEntry]:
        """Parse log line into structured LogEntry"""
        try:
            if log_format == 'json':
                return self._parse_json_log(log_line)
            elif log_format == 'syslog':
                return self._parse_syslog(log_line)
            elif log_format == 'cef':
                return self._parse_cef_log(log_line)
            elif log_format == 'leef':
                return self._parse_leef_log(log_line)
            elif log_format == 'windows_event':
                return self._parse_windows_event(log_line)
            elif log_format == 'apache':
                return self._parse_apache_log(log_line)
            else:
                return self._parse_custom_log(log_line)
        except Exception as e:
            print(f"Error parsing log: {e}")
            return None
    
    def _parse_json_log(self, log_line: str) -> LogEntry:
        """Parse JSON formatted log"""
        data = json.loads(log_line)
        
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        timestamp = data.get('timestamp')
        if timestamp:
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                timestamp = datetime.fromtimestamp(timestamp)
        else:
            timestamp = datetime.now()
        
        severity_map = {
            'debug': LogSeverity.DEBUG,
            'info': LogSeverity.INFO,
            'warning': LogSeverity.WARNING,
            'error': LogSeverity.ERROR,
            'critical': LogSeverity.CRITICAL
        }
        severity = severity_map.get(
            data.get('severity', 'info').lower(),
            LogSeverity.INFO
        )
        
        return LogEntry(
            log_id=log_id,
            timestamp=timestamp,
            source=data.get('source', 'unknown'),
            severity=severity,
            event_type=data.get('event_type', 'unknown'),
            message=data.get('message', ''),
            raw_log=log_line,
            parsed_fields=data,
            tags=data.get('tags', [])
        )
    
    def _parse_syslog(self, log_line: str) -> Optional[LogEntry]:
        """Parse syslog format"""
        match = self.parser_patterns['syslog'].match(log_line)
        if not match:
            return None
        
        groups = match.groupdict()
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        # Parse timestamp
        timestamp_str = groups['timestamp']
        try:
            timestamp = datetime.strptime(
                f"{datetime.now().year} {timestamp_str}",
                "%Y %b %d %H:%M:%S"
            )
        except:
            timestamp = datetime.now()
        
        return LogEntry(
            log_id=log_id,
            timestamp=timestamp,
            source=groups.get('hostname', 'unknown'),
            severity=LogSeverity.INFO,
            event_type='syslog',
            message=groups.get('message', ''),
            raw_log=log_line,
            parsed_fields=groups
        )
    
    def _parse_cef_log(self, log_line: str) -> Optional[LogEntry]:
        """Parse CEF (Common Event Format) log"""
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        if not log_line.startswith('CEF:'):
            return None
        
        parts = log_line.split('|')
        if len(parts) < 8:
            return None
        
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        severity_num = int(parts[6]) if parts[6].isdigit() else 1
        severity = LogSeverity(min(severity_num, 7))
        
        # Parse extension fields
        extension = parts[7] if len(parts) > 7 else ''
        ext_fields = {}
        for field in extension.split():
            if '=' in field:
                key, value = field.split('=', 1)
                ext_fields[key] = value
        
        return LogEntry(
            log_id=log_id,
            timestamp=datetime.now(),
            source=f"{parts[1]} {parts[2]}",
            severity=severity,
            event_type=parts[5],  # Name
            message=parts[5],
            raw_log=log_line,
            parsed_fields={
                'vendor': parts[1],
                'product': parts[2],
                'version': parts[3],
                'signature_id': parts[4],
                'extension': ext_fields
            }
        )
    
    def _parse_leef_log(self, log_line: str) -> Optional[LogEntry]:
        """Parse LEEF (Log Event Extended Format) log"""
        # LEEF format: LEEF:Version|Vendor|Product|Version|EventID|
        if not log_line.startswith('LEEF:'):
            return None
        
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        # Simple LEEF parsing
        parts = log_line.split('\t')
        header = parts[0].split('|') if parts else []
        
        fields = {}
        if len(parts) > 1:
            for field in parts[1:]:
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key] = value
        
        return LogEntry(
            log_id=log_id,
            timestamp=datetime.now(),
            source=header[2] if len(header) > 2 else 'unknown',
            severity=LogSeverity.INFO,
            event_type=header[4] if len(header) > 4 else 'unknown',
            message=log_line,
            raw_log=log_line,
            parsed_fields=fields
        )
    
    def _parse_windows_event(self, log_line: str) -> Optional[LogEntry]:
        """Parse Windows Event log"""
        match = self.parser_patterns['windows_event'].search(log_line)
        if not match:
            return None
        
        groups = match.groupdict()
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        event_id = groups.get('event_id', '0')
        
        # Map Windows event IDs to severity
        critical_events = ['4625', '4720', '4732', '4756']
        severity = LogSeverity.CRITICAL if event_id in critical_events else LogSeverity.INFO
        
        return LogEntry(
            log_id=log_id,
            timestamp=datetime.now(),
            source=groups.get('computer', 'windows'),
            severity=severity,
            event_type=f"windows_event_{event_id}",
            message=groups.get('message', ''),
            raw_log=log_line,
            parsed_fields=groups
        )
    
    def _parse_apache_log(self, log_line: str) -> Optional[LogEntry]:
        """Parse Apache access log"""
        match = self.parser_patterns['apache'].match(log_line)
        if not match:
            return None
        
        groups = match.groupdict()
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        # Parse timestamp
        timestamp_str = groups['timestamp']
        try:
            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except:
            timestamp = datetime.now()
        
        # Determine severity based on status code
        status_code = int(groups['status'])
        if status_code >= 500:
            severity = LogSeverity.ERROR
        elif status_code >= 400:
            severity = LogSeverity.WARNING
        else:
            severity = LogSeverity.INFO
        
        return LogEntry(
            log_id=log_id,
            timestamp=timestamp,
            source=groups['ip'],
            severity=severity,
            event_type='http_request',
            message=f"{groups['method']} {groups['path']} {groups['status']}",
            raw_log=log_line,
            parsed_fields=groups
        )
    
    def _parse_custom_log(self, log_line: str) -> LogEntry:
        """Parse custom/unknown log format"""
        log_id = hashlib.md5(log_line.encode()).hexdigest()[:16]
        
        return LogEntry(
            log_id=log_id,
            timestamp=datetime.now(),
            source='unknown',
            severity=LogSeverity.INFO,
            event_type='custom',
            message=log_line,
            raw_log=log_line,
            parsed_fields={}
        )
    
    def parse_file(self, file_path: Path, log_format: str) -> List[LogEntry]:
        """Parse entire log file"""
        logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = self.parse_log(line, log_format)
                    if log_entry:
                        logs.append(log_entry)
                        self.log_buffer.append(log_entry)
        except Exception as e:
            print(f"Error parsing file: {e}")
        
        return logs
    
    def correlate_events(self) -> List[Alert]:
        """Correlate events based on rules"""
        new_alerts = []
        
        for rule_id, rule in self.correlation_rules.items():
            # Get relevant events within time window
            cutoff_time = datetime.now() - timedelta(seconds=rule.time_window)
            
            relevant_events = []
            for event_type in rule.event_types:
                events = [
                    e for e in self.log_buffer
                    if e.event_type == event_type and e.timestamp >= cutoff_time
                ]
                relevant_events.extend(events)
            
            # Check if threshold is met
            if len(relevant_events) >= rule.threshold:
                alert = self._create_alert(rule, relevant_events)
                new_alerts.append(alert)
                self.alerts.append(alert)
        
        return new_alerts
    
    def _create_alert(self, rule: CorrelationRule, events: List[LogEntry]) -> Alert:
        """Create alert from correlated events"""
        alert_id = hashlib.md5(
            f"{rule.rule_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        # Extract indicators from events
        indicators = []
        for event in events:
            indicators.extend(event.indicators)
        
        return Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            timestamp=datetime.now(),
            severity=rule.severity,
            title=rule.name,
            description=rule.description,
            events=events[:10],  # Limit to first 10 events
            indicators=list(set(indicators)),
            recommended_actions=rule.actions
        )
    
    def generate_logs(
        self,
        scenario: str,
        count: int = 100,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> List[LogEntry]:
        """Generate synthetic logs for testing"""
        if time_range:
            start_time, end_time = time_range
        else:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
        
        scenarios = {
            'normal': self._generate_normal_logs,
            'brute_force': self._generate_brute_force_logs,
            'data_exfiltration': self._generate_exfiltration_logs,
            'malware': self._generate_malware_logs,
            'web_attack': self._generate_web_attack_logs
        }
        
        generator = scenarios.get(scenario, self._generate_normal_logs)
        return generator(count, start_time, end_time)
    
    def _generate_normal_logs(
        self,
        count: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[LogEntry]:
        """Generate normal activity logs"""
        logs = []
        time_delta = (end_time - start_time).total_seconds() / count
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * time_delta)
            
            log_id = hashlib.md5(f"normal_{i}_{timestamp}".encode()).hexdigest()[:16]
            
            event_types = ['login_success', 'file_access', 'process_start', 'network_connection']
            event_type = random.choice(event_types)
            
            logs.append(LogEntry(
                log_id=log_id,
                timestamp=timestamp,
                source=f"host-{random.randint(1, 10)}",
                severity=LogSeverity.INFO,
                event_type=event_type,
                message=f"Normal {event_type} activity",
                raw_log=f"[{timestamp.isoformat()}] {event_type}: Normal activity",
                parsed_fields={'normal': True}
            ))
        
        return logs
    
    def _generate_brute_force_logs(
        self,
        count: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[LogEntry]:
        """Generate brute force attack logs"""
        logs = []
        attacker_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        time_delta = (end_time - start_time).total_seconds() / count
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * time_delta)
            
            log_id = hashlib.md5(f"bruteforce_{i}_{timestamp}".encode()).hexdigest()[:16]
            
            # Most attempts fail
            success = i == count - 1  # Last one succeeds
            event_type = 'authentication_success' if success else 'authentication_failure'
            severity = LogSeverity.WARNING if not success else LogSeverity.CRITICAL
            
            logs.append(LogEntry(
                log_id=log_id,
                timestamp=timestamp,
                source=attacker_ip,
                severity=severity,
                event_type=event_type,
                message=f"Login attempt from {attacker_ip}",
                raw_log=f"[{timestamp.isoformat()}] {event_type}: {attacker_ip}",
                parsed_fields={'source_ip': attacker_ip, 'attempt': i + 1},
                indicators=[attacker_ip],
                tags=['brute_force', 'authentication']
            ))
        
        return logs
    
    def _generate_exfiltration_logs(
        self,
        count: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[LogEntry]:
        """Generate data exfiltration logs"""
        logs = []
        external_ip = f"192.0.2.{random.randint(1, 255)}"  # RFC 5737 TEST-NET-1
        
        time_delta = (end_time - start_time).total_seconds() / count
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * time_delta)
            
            log_id = hashlib.md5(f"exfil_{i}_{timestamp}".encode()).hexdigest()[:16]
            
            data_size = random.randint(50, 500) * 1024 * 1024  # 50-500 MB
            
            logs.append(LogEntry(
                log_id=log_id,
                timestamp=timestamp,
                source='internal-host',
                severity=LogSeverity.CRITICAL,
                event_type='network_connection',
                message=f"Large data transfer to {external_ip}: {data_size} bytes",
                raw_log=f"[{timestamp.isoformat()}] network_connection: {external_ip} {data_size}",
                parsed_fields={
                    'destination_ip': external_ip,
                    'data_size': data_size,
                    'protocol': 'HTTPS'
                },
                indicators=[external_ip],
                tags=['exfiltration', 'network']
            ))
        
        return logs
    
    def _generate_malware_logs(
        self,
        count: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[LogEntry]:
        """Generate malware activity logs"""
        logs = []
        malicious_processes = ['mimikatz.exe', 'psexec.exe', 'procdump.exe']
        
        time_delta = (end_time - start_time).total_seconds() / count
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * time_delta)
            
            log_id = hashlib.md5(f"malware_{i}_{timestamp}".encode()).hexdigest()[:16]
            
            process = random.choice(malicious_processes)
            
            logs.append(LogEntry(
                log_id=log_id,
                timestamp=timestamp,
                source='compromised-host',
                severity=LogSeverity.CRITICAL,
                event_type='process_creation',
                message=f"Suspicious process created: {process}",
                raw_log=f"[{timestamp.isoformat()}] process_creation: {process}",
                parsed_fields={'process_name': process, 'suspicious': True},
                indicators=[process],
                mitre_techniques=['T1003.001'],
                tags=['malware', 'credential_dumping']
            ))
        
        return logs
    
    def _generate_web_attack_logs(
        self,
        count: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[LogEntry]:
        """Generate web attack logs"""
        logs = []
        attack_patterns = [
            "' OR '1'='1",  # SQL injection
            "<script>alert('XSS')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "../../windows/system32/config/sam"  # Windows path traversal
        ]
        
        time_delta = (end_time - start_time).total_seconds() / count
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * time_delta)
            
            log_id = hashlib.md5(f"webattack_{i}_{timestamp}".encode()).hexdigest()[:16]
            
            pattern = random.choice(attack_patterns)
            attacker_ip = f"203.0.113.{random.randint(1, 255)}"  # RFC 5737 TEST-NET-3
            
            logs.append(LogEntry(
                log_id=log_id,
                timestamp=timestamp,
                source=attacker_ip,
                severity=LogSeverity.ERROR,
                event_type='http_request',
                message=f"Malicious HTTP request: {pattern}",
                raw_log=f"[{timestamp.isoformat()}] http_request: {attacker_ip} {pattern}",
                parsed_fields={
                    'source_ip': attacker_ip,
                    'payload': pattern,
                    'status': 403
                },
                indicators=[attacker_ip, pattern],
                tags=['web_attack', 'injection']
            ))
        
        return logs
    
    def export_logs(
        self,
        logs: List[LogEntry],
        output_path: Path,
        format: str = 'json'
    ) -> bool:
        """Export logs to file"""
        try:
            if format == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump([log.to_dict() for log in logs], f, indent=2, default=str)
            elif format == 'csv':
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Source', 'Severity', 'Event Type', 'Message'])
                    for log in logs:
                        writer.writerow([
                            log.timestamp.isoformat(),
                            log.source,
                            log.severity.name,
                            log.event_type,
                            log.message
                        ])
            else:
                with open(output_path, 'w', encoding='utf-8') as f:
                    for log in logs:
                        f.write(f"{log.raw_log}\n")
            
            return True
        except Exception as e:
            print(f"Error exporting logs: {e}")
            return False
    
    def analyze_logs(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze logs and generate statistics"""
        if not logs:
            return {}
        
        severity_counts = defaultdict(int)
        event_type_counts = defaultdict(int)
        source_counts = defaultdict(int)
        indicators_found = set()
        techniques_found = set()
        
        for log in logs:
            severity_counts[log.severity.name] += 1
            event_type_counts[log.event_type] += 1
            source_counts[log.source] += 1
            indicators_found.update(log.indicators)
            techniques_found.update(log.mitre_techniques)
        
        # Time analysis
        timestamps = [log.timestamp for log in logs]
        time_span = max(timestamps) - min(timestamps)
        
        return {
            'total_logs': len(logs),
            'time_span': str(time_span),
            'first_log': min(timestamps).isoformat(),
            'last_log': max(timestamps).isoformat(),
            'severity_distribution': dict(severity_counts),
            'event_types': dict(sorted(
                event_type_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_sources': dict(sorted(
                source_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'unique_indicators': len(indicators_found),
            'indicators': list(indicators_found)[:20],
            'mitre_techniques': list(techniques_found),
            'critical_events': sum(1 for log in logs if log.severity in [
                LogSeverity.CRITICAL, LogSeverity.ALERT, LogSeverity.EMERGENCY
            ])
        }
