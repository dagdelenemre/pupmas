"""
MITRE ATT&CK Framework Handler
Comprehensive integration with MITRE ATT&CK framework for threat intelligence
and attack mapping capabilities.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique"""
    id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection: str
    mitigations: List[Dict[str, str]]
    subtechniques: List[str]
    url: str
    version: str


@dataclass
class MITRETactic:
    """Represents a MITRE ATT&CK tactic"""
    id: str
    name: str
    short_name: str
    description: str
    url: str


class MITREHandler:
    """
    Advanced MITRE ATT&CK Framework handler with comprehensive
    technique analysis, mapping, and correlation capabilities.
    """
    
    MITRE_VERSION = "14.1"
    TACTICS_ORDER = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    ]
    
    def __init__(self, data_path: Optional[Path] = None):
        """Initialize MITRE handler with data loading"""
        self.data_path = data_path or Path(__file__).parent.parent / "config"
        self.techniques: Dict[str, MITRETechnique] = {}
        self.tactics: Dict[str, MITRETactic] = {}
        self.tactic_to_techniques: Dict[str, List[str]] = defaultdict(list)
        self.technique_patterns: Dict[str, List[str]] = {}
        
        self._load_mitre_data()
        self._build_detection_patterns()
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data from JSON"""
        mitre_file = self.data_path / "mitre_attack.json"
        
        if not mitre_file.exists():
            # Generate default MITRE data if not exists
            self._generate_default_data()
            return
        
        with open(mitre_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Load tactics
        for tactic_data in data.get('tactics', []):
            tactic = MITRETactic(**tactic_data)
            self.tactics[tactic.id] = tactic
        
        # Load techniques
        for tech_data in data.get('techniques', []):
            technique = MITRETechnique(**tech_data)
            self.techniques[technique.id] = technique
            
            # Map techniques to tactics
            for tactic in technique.tactics:
                self.tactic_to_techniques[tactic].append(technique.id)
    
    def _build_detection_patterns(self):
        """Build regex patterns for technique detection in logs"""
        for tech_id, technique in self.techniques.items():
            patterns = []
            
            # Extract keywords from technique name and description
            keywords = self._extract_keywords(
                f"{technique.name} {technique.description}"
            )
            
            # Build regex patterns
            for keyword in keywords:
                # Case-insensitive word boundary pattern
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                patterns.append(pattern)
            
            self.technique_patterns[tech_id] = patterns
    
    def _extract_keywords(self, text: str, min_length: int = 4) -> List[str]:
        """Extract meaningful keywords from text"""
        # Remove common words
        stop_words = {
            'this', 'that', 'with', 'from', 'have', 'been', 'will',
            'their', 'which', 'these', 'those', 'into', 'through'
        }
        
        # Extract words
        words = re.findall(r'\b[a-z]+\b', text.lower())
        keywords = [
            w for w in words 
            if len(w) >= min_length and w not in stop_words
        ]
        
        return list(set(keywords))
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get detailed information about a technique"""
        # Normalize technique ID
        tech_id = technique_id.upper()
        if not tech_id.startswith('T'):
            tech_id = f'T{tech_id}'
        
        return self.techniques.get(tech_id)
    
    def get_tactic(self, tactic_name: str) -> Optional[MITRETactic]:
        """Get information about a tactic"""
        # Try exact match first
        if tactic_name in self.tactics:
            return self.tactics[tactic_name]
        
        # Try case-insensitive match
        tactic_lower = tactic_name.lower()
        for tactic_id, tactic in self.tactics.items():
            if (tactic.name.lower() == tactic_lower or 
                tactic.short_name.lower() == tactic_lower):
                return tactic
        
        return None
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic"""
        tactic_normalized = tactic.lower().replace(' ', '-')
        technique_ids = self.tactic_to_techniques.get(tactic_normalized, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def search_techniques(self, query: str, limit: int = 10) -> List[Tuple[MITRETechnique, float]]:
        """
        Search techniques using fuzzy matching with relevance scoring
        Returns list of (technique, score) tuples sorted by relevance
        """
        query_lower = query.lower()
        query_words = set(query_lower.split())
        results = []
        
        for tech_id, technique in self.techniques.items():
            score = 0.0
            
            # Exact ID match - highest priority
            if tech_id.lower() == query_lower:
                score += 100.0
            
            # Technique name matching
            name_lower = technique.name.lower()
            if query_lower in name_lower:
                score += 50.0
            
            # Word-by-word matching in name
            name_words = set(name_lower.split())
            common_words = query_words & name_words
            score += len(common_words) * 10.0
            
            # Description matching
            desc_lower = technique.description.lower()
            if query_lower in desc_lower:
                score += 20.0
            
            # Tactic matching
            for tactic in technique.tactics:
                if query_lower in tactic.lower():
                    score += 15.0
            
            # Platform matching
            for platform in technique.platforms:
                if query_lower in platform.lower():
                    score += 10.0
            
            if score > 0:
                results.append((technique, score))
        
        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]
    
    def map_logs_to_techniques(self, log_entries: List[str]) -> Dict[str, List[str]]:
        """
        Analyze log entries and map them to MITRE techniques
        Returns dict of technique_id -> list of matching log entries
        """
        mappings = defaultdict(list)
        
        for log_entry in log_entries:
            log_lower = log_entry.lower()
            
            # Check each technique's patterns
            for tech_id, patterns in self.technique_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, log_lower):
                        mappings[tech_id].append(log_entry)
                        break  # One match per technique per log
        
        return dict(mappings)
    
    def build_attack_chain(self, technique_ids: List[str]) -> Dict[str, List[str]]:
        """
        Build attack chain by organizing techniques into tactic phases
        Returns dict of tactic -> list of techniques
        """
        attack_chain = {tactic: [] for tactic in self.TACTICS_ORDER}
        
        for tech_id in technique_ids:
            technique = self.get_technique(tech_id)
            if technique:
                for tactic in technique.tactics:
                    if tactic in attack_chain:
                        attack_chain[tactic].append(technique.id)
        
        # Remove empty tactics
        return {k: v for k, v in attack_chain.items() if v}
    
    def get_detection_recommendations(self, technique_id: str) -> Dict[str, any]:
        """
        Get comprehensive detection recommendations for a technique
        """
        technique = self.get_technique(technique_id)
        if not technique:
            return {}
        
        recommendations = {
            'technique': technique.id,
            'name': technique.name,
            'data_sources': technique.data_sources,
            'detection_methods': self._parse_detection_text(technique.detection),
            'monitoring_points': self._generate_monitoring_points(technique),
            'siem_queries': self._generate_siem_queries(technique),
            'indicators': self._extract_indicators(technique)
        }
        
        return recommendations
    
    def _parse_detection_text(self, detection_text: str) -> List[str]:
        """Parse detection text into actionable methods"""
        if not detection_text:
            return []
        
        # Split by common separators
        methods = re.split(r'[.;]\s+', detection_text)
        return [m.strip() for m in methods if m.strip()]
    
    def _generate_monitoring_points(self, technique: MITRETechnique) -> List[str]:
        """Generate specific monitoring points based on technique"""
        points = []
        
        # Platform-specific monitoring
        if 'Windows' in technique.platforms:
            points.extend([
                'Windows Event Logs (Security, System, Application)',
                'Sysmon logs',
                'PowerShell logs',
                'Process creation events'
            ])
        
        if 'Linux' in technique.platforms:
            points.extend([
                'auditd logs',
                'syslog',
                'bash history',
                '/var/log monitoring'
            ])
        
        # Tactic-specific monitoring
        if 'credential-access' in technique.tactics:
            points.append('Credential access attempts and failures')
        
        if 'lateral-movement' in technique.tactics:
            points.append('Network connections and authentication events')
        
        if 'exfiltration' in technique.tactics:
            points.append('Outbound network traffic and data transfer volumes')
        
        return list(set(points))
    
    def _generate_siem_queries(self, technique: MITRETechnique) -> List[Dict[str, str]]:
        """Generate SIEM query templates for technique detection"""
        queries = []
        
        # Generic query based on technique keywords
        keywords = self._extract_keywords(technique.name)
        if keywords:
            queries.append({
                'platform': 'Generic',
                'query': f"EventData contains ({' OR '.join(keywords[:5])})",
                'description': f'Detect {technique.name} activity'
            })
        
        # Platform-specific queries
        if 'Windows' in technique.platforms:
            queries.append({
                'platform': 'Splunk',
                'query': f'index=windows source="WinEventLog:Security" | search {" OR ".join(keywords[:3])}',
                'description': f'Windows security log search for {technique.name}'
            })
        
        return queries
    
    def _extract_indicators(self, technique: MITRETechnique) -> List[str]:
        """Extract potential indicators of compromise"""
        indicators = []
        
        # Extract from description
        desc_lower = technique.description.lower()
        
        # Common IOC patterns
        if 'file' in desc_lower:
            indicators.append('Suspicious file creation/modification')
        if 'registry' in desc_lower:
            indicators.append('Registry key modifications')
        if 'process' in desc_lower:
            indicators.append('Abnormal process execution')
        if 'network' in desc_lower:
            indicators.append('Unusual network connections')
        if 'command' in desc_lower or 'cmd' in desc_lower:
            indicators.append('Command-line execution')
        
        return indicators
    
    def generate_attack_matrix(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Generate the full ATT&CK matrix organized by tactic
        Returns nested dict: tactic -> platform -> list of technique IDs
        """
        matrix = {}
        
        for tactic in self.TACTICS_ORDER:
            matrix[tactic] = defaultdict(list)
            technique_ids = self.tactic_to_techniques.get(tactic, [])
            
            for tech_id in technique_ids:
                technique = self.techniques.get(tech_id)
                if technique:
                    for platform in technique.platforms:
                        matrix[tactic][platform].append(tech_id)
        
        # Convert defaultdict to regular dict
        return {k: dict(v) for k, v in matrix.items()}
    
    def get_mitigation_strategies(self, technique_id: str) -> List[Dict[str, str]]:
        """Get mitigation strategies for a technique"""
        technique = self.get_technique(technique_id)
        if not technique:
            return []
        
        return technique.mitigations
    
    def get_related_techniques(self, technique_id: str, limit: int = 5) -> List[MITRETechnique]:
        """Find techniques related by tactics or keywords"""
        technique = self.get_technique(technique_id)
        if not technique:
            return []
        
        related = []
        keywords = set(self._extract_keywords(technique.name))
        
        for tech_id, other_tech in self.techniques.items():
            if tech_id == technique.id:
                continue
            
            score = 0
            
            # Same tactics
            common_tactics = set(technique.tactics) & set(other_tech.tactics)
            score += len(common_tactics) * 3
            
            # Similar keywords
            other_keywords = set(self._extract_keywords(other_tech.name))
            common_keywords = keywords & other_keywords
            score += len(common_keywords) * 2
            
            # Same platforms
            common_platforms = set(technique.platforms) & set(other_tech.platforms)
            score += len(common_platforms)
            
            if score > 0:
                related.append((other_tech, score))
        
        related.sort(key=lambda x: x[1], reverse=True)
        return [tech for tech, _ in related[:limit]]
    
    def _generate_default_data(self):
        """Generate comprehensive default MITRE ATT&CK data"""
        default_data = {
            "version": self.MITRE_VERSION,
            "tactics": [
                {
                    "id": "TA0043",
                    "name": "Reconnaissance",
                    "short_name": "reconnaissance",
                    "description": "The adversary is trying to gather information they can use to plan future operations.",
                    "url": "https://attack.mitre.org/tactics/TA0043"
                },
                {
                    "id": "TA0042",
                    "name": "Resource Development",
                    "short_name": "resource-development",
                    "description": "The adversary is trying to establish resources they can use to support operations.",
                    "url": "https://attack.mitre.org/tactics/TA0042"
                },
                {
                    "id": "TA0001",
                    "name": "Initial Access",
                    "short_name": "initial-access",
                    "description": "The adversary is trying to get into your network.",
                    "url": "https://attack.mitre.org/tactics/TA0001"
                },
                {
                    "id": "TA0002",
                    "name": "Execution",
                    "short_name": "execution",
                    "description": "The adversary is trying to run malicious code.",
                    "url": "https://attack.mitre.org/tactics/TA0002"
                },
                {
                    "id": "TA0003",
                    "name": "Persistence",
                    "short_name": "persistence",
                    "description": "The adversary is trying to maintain their foothold.",
                    "url": "https://attack.mitre.org/tactics/TA0003"
                },
                {
                    "id": "TA0004",
                    "name": "Privilege Escalation",
                    "short_name": "privilege-escalation",
                    "description": "The adversary is trying to gain higher-level permissions.",
                    "url": "https://attack.mitre.org/tactics/TA0004"
                },
                {
                    "id": "TA0005",
                    "name": "Defense Evasion",
                    "short_name": "defense-evasion",
                    "description": "The adversary is trying to avoid being detected.",
                    "url": "https://attack.mitre.org/tactics/TA0005"
                },
                {
                    "id": "TA0006",
                    "name": "Credential Access",
                    "short_name": "credential-access",
                    "description": "The adversary is trying to steal account names and passwords.",
                    "url": "https://attack.mitre.org/tactics/TA0006"
                },
                {
                    "id": "TA0007",
                    "name": "Discovery",
                    "short_name": "discovery",
                    "description": "The adversary is trying to figure out your environment.",
                    "url": "https://attack.mitre.org/tactics/TA0007"
                },
                {
                    "id": "TA0008",
                    "name": "Lateral Movement",
                    "short_name": "lateral-movement",
                    "description": "The adversary is trying to move through your environment.",
                    "url": "https://attack.mitre.org/tactics/TA0008"
                },
                {
                    "id": "TA0009",
                    "name": "Collection",
                    "short_name": "collection",
                    "description": "The adversary is trying to gather data of interest to their goal.",
                    "url": "https://attack.mitre.org/tactics/TA0009"
                },
                {
                    "id": "TA0011",
                    "name": "Command and Control",
                    "short_name": "command-and-control",
                    "description": "The adversary is trying to communicate with compromised systems.",
                    "url": "https://attack.mitre.org/tactics/TA0011"
                },
                {
                    "id": "TA0010",
                    "name": "Exfiltration",
                    "short_name": "exfiltration",
                    "description": "The adversary is trying to steal data.",
                    "url": "https://attack.mitre.org/tactics/TA0010"
                },
                {
                    "id": "TA0040",
                    "name": "Impact",
                    "short_name": "impact",
                    "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                    "url": "https://attack.mitre.org/tactics/TA0040"
                }
            ],
            "techniques": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                    "tactics": ["execution"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command", "Script"],
                    "detection": "Monitor executed commands and arguments. Look for unusual patterns in command-line activity.",
                    "mitigations": [
                        {"id": "M1038", "name": "Execution Prevention", "description": "Use application control to prevent execution."},
                        {"id": "M1026", "name": "Privileged Account Management", "description": "Restrict elevated privileges."}
                    ],
                    "subtechniques": ["T1059.001", "T1059.003", "T1059.005"],
                    "url": "https://attack.mitre.org/techniques/T1059",
                    "version": "1.2"
                },
                {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                    "tactics": ["execution"],
                    "platforms": ["Windows"],
                    "data_sources": ["PowerShell Logs", "Process", "Command"],
                    "detection": "Monitor PowerShell execution and command parameters. Enable PowerShell logging.",
                    "mitigations": [
                        {"id": "M1042", "name": "Disable or Remove Feature", "description": "Disable PowerShell if not required."},
                        {"id": "M1049", "name": "Antivirus/Antimalware", "description": "Use AV to detect malicious PowerShell."}
                    ],
                    "subtechniques": [],
                    "url": "https://attack.mitre.org/techniques/T1059/001",
                    "version": "1.1"
                },
                {
                    "id": "T1078",
                    "name": "Valid Accounts",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                    "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Authentication Logs", "User Account"],
                    "detection": "Monitor authentication logs for unusual access patterns, multiple failed attempts, and privilege escalations.",
                    "mitigations": [
                        {"id": "M1027", "name": "Password Policies", "description": "Enforce strong password policies."},
                        {"id": "M1032", "name": "Multi-factor Authentication", "description": "Require MFA for all accounts."}
                    ],
                    "subtechniques": ["T1078.001", "T1078.002", "T1078.003"],
                    "url": "https://attack.mitre.org/techniques/T1078",
                    "version": "2.4"
                },
                {
                    "id": "T1566",
                    "name": "Phishing",
                    "description": "Adversaries may send phishing messages to gain access to victim systems.",
                    "tactics": ["initial-access"],
                    "platforms": ["Windows", "macOS", "Linux", "Office 365", "Google Workspace"],
                    "data_sources": ["Email", "Application Log", "Network Traffic"],
                    "detection": "Monitor email gateways for suspicious attachments and links. Analyze email metadata and content.",
                    "mitigations": [
                        {"id": "M1049", "name": "Antivirus/Antimalware", "description": "Use email scanning and filtering."},
                        {"id": "M1017", "name": "User Training", "description": "Train users to identify phishing attempts."}
                    ],
                    "subtechniques": ["T1566.001", "T1566.002", "T1566.003"],
                    "url": "https://attack.mitre.org/techniques/T1566",
                    "version": "2.3"
                },
                {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                    "description": "Adversaries may communicate using application layer protocols to avoid detection.",
                    "tactics": ["command-and-control"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "Netflow"],
                    "detection": "Monitor network traffic for unusual protocols or destinations. Analyze packet contents.",
                    "mitigations": [
                        {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use IPS to detect and block malicious traffic."},
                        {"id": "M1037", "name": "Filter Network Traffic", "description": "Filter outbound traffic."}
                    ],
                    "subtechniques": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"],
                    "url": "https://attack.mitre.org/techniques/T1071",
                    "version": "2.0"
                },
                {
                    "id": "T1048",
                    "name": "Exfiltration Over Alternative Protocol",
                    "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel.",
                    "tactics": ["exfiltration"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "Netflow", "Packet Capture"],
                    "detection": "Monitor for uncommon data flows. Analyze network protocols and data transfer patterns.",
                    "mitigations": [
                        {"id": "M1037", "name": "Filter Network Traffic", "description": "Block unnecessary protocols."},
                        {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use DLP solutions."}
                    ],
                    "subtechniques": ["T1048.001", "T1048.002", "T1048.003"],
                    "url": "https://attack.mitre.org/techniques/T1048",
                    "version": "1.1"
                },
                {
                    "id": "T1082",
                    "name": "System Information Discovery",
                    "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
                    "tactics": ["discovery"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command"],
                    "detection": "Monitor process and command-line activity for actions that gather system information.",
                    "mitigations": [
                        {"id": "M1028", "name": "Operating System Configuration", "description": "Limit information available to users."}
                    ],
                    "subtechniques": [],
                    "url": "https://attack.mitre.org/techniques/T1082",
                    "version": "1.3"
                },
                {
                    "id": "T1053",
                    "name": "Scheduled Task/Job",
                    "description": "Adversaries may abuse task scheduling functionality to facilitate persistence or privilege escalation.",
                    "tactics": ["execution", "persistence", "privilege-escalation"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Scheduled Job", "Process", "File", "Windows Event Log"],
                    "detection": "Monitor scheduled task creation and modification. Look for unusual tasks or tasks created by suspicious processes.",
                    "mitigations": [
                        {"id": "M1026", "name": "Privileged Account Management", "description": "Restrict task scheduling privileges."},
                        {"id": "M1018", "name": "User Account Management", "description": "Limit accounts that can create tasks."}
                    ],
                    "subtechniques": ["T1053.002", "T1053.003", "T1053.005"],
                    "url": "https://attack.mitre.org/techniques/T1053",
                    "version": "2.1"
                },
                {
                    "id": "T1087",
                    "name": "Account Discovery",
                    "description": "Adversaries may attempt to get a listing of valid accounts.",
                    "tactics": ["discovery"],
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Process", "Command", "Cloud Service"],
                    "detection": "Monitor processes and command-line arguments for account enumeration activities.",
                    "mitigations": [
                        {"id": "M1028", "name": "Operating System Configuration", "description": "Limit account information exposure."}
                    ],
                    "subtechniques": ["T1087.001", "T1087.002", "T1087.003", "T1087.004"],
                    "url": "https://attack.mitre.org/techniques/T1087",
                    "version": "1.2"
                },
                {
                    "id": "T1110",
                    "name": "Brute Force",
                    "description": "Adversaries may use brute force techniques to gain access to accounts.",
                    "tactics": ["credential-access"],
                    "platforms": ["Windows", "Linux", "macOS", "Cloud", "Office 365"],
                    "data_sources": ["Authentication Logs", "User Account"],
                    "detection": "Monitor authentication logs for multiple failed login attempts from same source.",
                    "mitigations": [
                        {"id": "M1032", "name": "Multi-factor Authentication", "description": "Require MFA to mitigate brute force."},
                        {"id": "M1036", "name": "Account Use Policies", "description": "Implement account lockout policies."}
                    ],
                    "subtechniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
                    "url": "https://attack.mitre.org/techniques/T1110",
                    "version": "2.3"
                }
            ]
        }
        
        # Save to file
        mitre_file = self.data_path / "mitre_attack.json"
        mitre_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(mitre_file, 'w', encoding='utf-8') as f:
            json.dump(default_data, f, indent=2)
        
        # Load the data we just created
        self._load_mitre_data()
    
    def export_to_json(self, output_path: Path) -> bool:
        """Export current MITRE data to JSON"""
        try:
            data = {
                "version": self.MITRE_VERSION,
                "tactics": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "short_name": t.short_name,
                        "description": t.description,
                        "url": t.url
                    }
                    for t in self.tactics.values()
                ],
                "techniques": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "description": t.description,
                        "tactics": t.tactics,
                        "platforms": t.platforms,
                        "data_sources": t.data_sources,
                        "detection": t.detection,
                        "mitigations": t.mitigations,
                        "subtechniques": t.subtechniques,
                        "url": t.url,
                        "version": t.version
                    }
                    for t in self.techniques.values()
                ]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error exporting MITRE data: {e}")
            return False
