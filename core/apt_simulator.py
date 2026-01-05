#!/usr/bin/env python3
"""
APT & Advanced Attack Simulation Module - Senior Expert Level
Multi-stage attacks, TTPs mapping, covert C2, threat simulation
"""

import json
import time
import threading
import queue
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import uuid


class APTStage(Enum):
    """APT attack stages"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"


class TTPCategory(Enum):
    """MITRE ATT&CK TTP Categories"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class TTPMapping:
    """MITRE ATT&CK TTP mapping"""
    technique_id: str  # T1234.001
    technique_name: str
    category: TTPCategory
    platform: str  # Windows, Linux, MacOS, etc
    executes_on_stage: APTStage
    detection_difficulty: str  # Low, Medium, High
    evasion_capability: float  # 0.0-1.0
    detectability_score: float  # 0.0-1.0
    command_line: Optional[str] = None
    mitigations: List[str] = field(default_factory=list)


@dataclass
class CovertChannel:
    """Covert communication channel"""
    channel_id: str
    channel_type: str  # DNS, HTTPS, SMTP, ICMP, HTTP_header
    encoding: str  # base64, hex, steganography
    bandwidth: int  # bits per second
    latency: int  # milliseconds
    detectability: float  # 0.0-1.0
    protocol_overhead: float  # 0.0-1.0
    active: bool = False
    messages_sent: int = 0
    total_bytes_exfiltrated: int = 0


@dataclass
class APTCampaign:
    """Complete APT campaign definition"""
    campaign_id: str
    campaign_name: str
    threat_actor: str
    target_organization: str
    target_industry: str
    objectives: List[str]
    start_stage: APTStage
    current_stage: APTStage
    stages: Dict[str, List[Dict]] = field(default_factory=dict)
    ttp_chain: List[TTPMapping] = field(default_factory=list)
    covert_channels: List[CovertChannel] = field(default_factory=list)
    campaign_start: str = ""
    estimated_completion: str = ""
    success_rate: float = 0.0
    detected: bool = False


class APTSimulationEngine:
    """Advanced Persistent Threat simulation engine"""
    
    def __init__(self):
        self.campaigns = {}
        self.ttp_library = self._initialize_ttp_library()
        self.attack_queue = queue.Queue()
        self.simulation_running = False
        self.event_log = []
    
    def list_apt_profiles(self) -> List[Dict]:
        """List available APT threat actor profiles"""
        profiles = [
            {'name': 'APT28 (Fancy Bear)', 'origin': 'Russia', 'first_seen': '2004', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'espionage'},
            {'name': 'APT29 (Cozy Bear)', 'origin': 'Russia', 'first_seen': '2008', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'intelligence'},
            {'name': 'APT1 (Comment Crew)', 'origin': 'China', 'first_seen': '2006', 'last_seen': '2023', 'sophistication': 'medium', 'primary_motivation': 'espionage'},
            {'name': 'APT3 (Gothic Panda)', 'origin': 'China', 'first_seen': '2010', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'espionage'},
            {'name': 'APT10 (MenuPass)', 'origin': 'China', 'first_seen': '2009', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'espionage'},
            {'name': 'APT33 (Elfin)', 'origin': 'Iran', 'first_seen': '2013', 'last_seen': '2024', 'sophistication': 'medium', 'primary_motivation': 'destruction'},
            {'name': 'APT34 (OilRig)', 'origin': 'Iran', 'first_seen': '2014', 'last_seen': '2024', 'sophistication': 'medium', 'primary_motivation': 'espionage'},
            {'name': 'APT37 (Reaper)', 'origin': 'North Korea', 'first_seen': '2012', 'last_seen': '2024', 'sophistication': 'medium', 'primary_motivation': 'espionage'},
            {'name': 'APT38 (Lazarus)', 'origin': 'North Korea', 'first_seen': '2014', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'financial'},
            {'name': 'APT39 (Chafer)', 'origin': 'Iran', 'first_seen': '2014', 'last_seen': '2023', 'sophistication': 'medium', 'primary_motivation': 'espionage'},
            {'name': 'APT40 (Leviathan)', 'origin': 'China', 'first_seen': '2013', 'last_seen': '2024', 'sophistication': 'medium', 'primary_motivation': 'espionage'},
            {'name': 'APT41 (Winnti)', 'origin': 'China', 'first_seen': '2012', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'espionage/financial'},
            {'name': 'Turla (Snake)', 'origin': 'Russia', 'first_seen': '1996', 'last_seen': '2024', 'sophistication': 'very high', 'primary_motivation': 'espionage'},
            {'name': 'Equation Group', 'origin': 'USA', 'first_seen': '2001', 'last_seen': '2017', 'sophistication': 'very high', 'primary_motivation': 'intelligence'},
            {'name': 'Sandworm', 'origin': 'Russia', 'first_seen': '2014', 'last_seen': '2024', 'sophistication': 'high', 'primary_motivation': 'destruction'},
        ]
        return profiles
    
    async def create_campaign(self, profile: Dict, target_profile: Dict) -> APTCampaign:
        """Create APT campaign based on profile"""
        campaign_id = str(uuid.uuid4())[:8]
        
        campaign = APTCampaign(
            campaign_id=campaign_id,
            campaign_name=f"Operation {profile['name']} - {target_profile.get('industry', 'Target')}",
            threat_actor=profile['name'],
            target_organization=target_profile.get('organization', 'Unknown'),
            target_industry=target_profile.get('industry', 'Technology'),
            objectives=['Initial Access', 'Persistence', 'Credential Access', 'Data Exfiltration'],
            start_stage=APTStage.RECONNAISSANCE,
            current_stage=APTStage.RECONNAISSANCE
        )
        
        # Generate campaign phases
        campaign.stages = {
            'reconnaissance': {'duration_days': 7, 'objectives': ['Identify targets', 'Map infrastructure']},
            'initial_access': {'duration_days': 3, 'objectives': ['Spearphishing', 'Exploit public services']},
            'persistence': {'duration_days': 2, 'objectives': ['Install backdoor', 'Create scheduled tasks']},
            'privilege_escalation': {'duration_days': 1, 'objectives': ['Exploit local vulnerabilities', 'Token manipulation']},
            'lateral_movement': {'duration_days': 5, 'objectives': ['Compromise additional hosts', 'Access domain controller']},
            'exfiltration': {'duration_days': 3, 'objectives': ['Collect sensitive data', 'Exfiltrate via C2']},
        }
        
        # Generate phase objects with proper structure
        campaign.duration_days = sum(stage['duration_days'] for stage in campaign.stages.values())
        
        phases = []
        start_day = 0
        for stage_name, stage_data in campaign.stages.items():
            end_day = start_day + stage_data['duration_days']
            phase = type('CampaignPhase', (), {
                'name': stage_name.replace('_', ' ').title(),
                'start_day': start_day,
                'end_day': end_day,
                'ttps': [f"TTP-{i}" for i in range(1, 4)],
                'objectives': stage_data['objectives'],
                'duration': stage_data['duration_days']
            })()
            phases.append(phase)
            start_day = end_day
        
        campaign.phases = phases
        
        self.campaigns[campaign_id] = campaign
        return campaign
    
    def generate_covert_channels(self) -> List['CovertChannelResult']:
        """Generate covert communication channel configurations"""
        channels = [
            {'name': 'DNS Tunneling', 'stealth_rating': 'high', 'bandwidth': 'low (1-10 Kbps)', 'detection_difficulty': 'hard', 
             'implementation_details': 'Encode data in DNS queries (TXT/CNAME records)'},
            {'name': 'HTTPS Certificate Smuggling', 'stealth_rating': 'very high', 'bandwidth': 'medium (100 Kbps)', 'detection_difficulty': 'very hard',
             'implementation_details': 'Embed data in SSL/TLS certificate extensions'},
            {'name': 'ICMP Echo Data', 'stealth_rating': 'medium', 'bandwidth': 'low (5 Kbps)', 'detection_difficulty': 'medium',
             'implementation_details': 'Hide data in ICMP echo request/reply packets'},
            {'name': 'HTTP Header Steganography', 'stealth_rating': 'high', 'bandwidth': 'medium (50 Kbps)', 'detection_difficulty': 'hard',
             'implementation_details': 'Encode data in custom HTTP headers (User-Agent, Cookie)'},
            {'name': 'Cloud Storage C2', 'stealth_rating': 'very high', 'bandwidth': 'high (1 Mbps)', 'detection_difficulty': 'very hard',
             'implementation_details': 'Use legitimate cloud services (Google Drive, OneDrive) as dead drop'},
            {'name': 'Twitter/Social Media C2', 'stealth_rating': 'very high', 'bandwidth': 'low (10 Kbps)', 'detection_difficulty': 'extremely hard',
             'implementation_details': 'Commands hidden in social media posts/hashtags'},
            {'name': 'Email Exfiltration', 'stealth_rating': 'high', 'bandwidth': 'medium (100 Kbps)', 'detection_difficulty': 'medium',
             'implementation_details': 'Attach data to legitimate-looking emails'},
            {'name': 'IPv6 Covert Channel', 'stealth_rating': 'very high', 'bandwidth': 'high (500 Kbps)', 'detection_difficulty': 'very hard',
             'implementation_details': 'Embed data in IPv6 extension headers'},
            {'name': 'NTP Timing Channel', 'stealth_rating': 'extremely high', 'bandwidth': 'very low (1 Kbps)', 'detection_difficulty': 'extremely hard',
             'implementation_details': 'Encode data in NTP packet timing variations'},
            {'name': 'Blockchain C2', 'stealth_rating': 'extremely high', 'bandwidth': 'low (5 Kbps)', 'detection_difficulty': 'extremely hard',
             'implementation_details': 'Embed commands in blockchain transactions/smart contracts'},
        ]
        
        # Convert to result objects
        results = []
        for ch in channels:
            result = type('CovertChannelResult', (), ch)()
            results.append(result)
        
        return results
        
    def _initialize_ttp_library(self) -> Dict[str, TTPMapping]:
        """Initialize MITRE ATT&CK TTP library"""
        
        ttp_library = {
            # Reconnaissance
            "T1592": TTPMapping(
                technique_id="T1592",
                technique_name="Gather Victim Identity Information",
                category=TTPCategory.RECONNAISSANCE,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.RECONNAISSANCE,
                detection_difficulty="High",
                evasion_capability=0.9,
                detectability_score=0.2,
                mitigations=["M1016: Account Use Policies"]
            ),
            "T1589": TTPMapping(
                technique_id="T1589",
                technique_name="Gather Victim Identity Information",
                category=TTPCategory.RECONNAISSANCE,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.RECONNAISSANCE,
                detection_difficulty="High",
                evasion_capability=0.85,
                detectability_score=0.15,
                mitigations=["M1016: Account Use Policies"]
            ),
            # Initial Access
            "T1566.002": TTPMapping(
                technique_id="T1566.002",
                technique_name="Phishing: Spearphishing Attachment",
                category=TTPCategory.INITIAL_ACCESS,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.DELIVERY,
                detection_difficulty="Low",
                evasion_capability=0.6,
                detectability_score=0.7,
                mitigations=["M1017: User Training", "M1049: Antivirus/Antimalware"]
            ),
            # Execution
            "T1059.001": TTPMapping(
                technique_id="T1059.001",
                technique_name="PowerShell",
                category=TTPCategory.EXECUTION,
                platform="Windows",
                executes_on_stage=APTStage.EXPLOITATION,
                detection_difficulty="Medium",
                evasion_capability=0.8,
                detectability_score=0.5,
                command_line="powershell.exe -NoProfile -Execution Policy Bypass",
                mitigations=["M1045: Code Signing", "M1049: Antivirus"]
            ),
            # Persistence
            "T1547.001": TTPMapping(
                technique_id="T1547.001",
                technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
                category=TTPCategory.PERSISTENCE,
                platform="Windows",
                executes_on_stage=APTStage.INSTALLATION,
                detection_difficulty="Medium",
                evasion_capability=0.7,
                detectability_score=0.6,
                mitigations=["M1012: Data Backed up", "M1024: Restrict Registry Permissions"]
            ),
            # Privilege Escalation
            "T1134.002": TTPMapping(
                technique_id="T1134.002",
                technique_name="Access Token Manipulation: Create Process with Token",
                category=TTPCategory.PRIVILEGE_ESCALATION,
                platform="Windows",
                executes_on_stage=APTStage.EXPLOITATION,
                detection_difficulty="High",
                evasion_capability=0.75,
                detectability_score=0.4,
                mitigations=["M1015: Active Directory Configuration"]
            ),
            # Defense Evasion
            "T1140": TTPMapping(
                technique_id="T1140",
                technique_name="Deobfuscate/Decode Files or Information",
                category=TTPCategory.DEFENSE_EVASION,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.EXPLOITATION,
                detection_difficulty="High",
                evasion_capability=0.85,
                detectability_score=0.3,
                mitigations=["M1047: Audit"]
            ),
            # Credential Access
            "T1110.001": TTPMapping(
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                category=TTPCategory.CREDENTIAL_ACCESS,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.EXPLOITATION,
                detection_difficulty="Low",
                evasion_capability=0.5,
                detectability_score=0.8,
                mitigations=["M1036: Account Use Policies", "M1032: Multi-factor Authentication"]
            ),
            # Lateral Movement
            "T1570": TTPMapping(
                technique_id="T1570",
                technique_name="Lateral Tool Transfer",
                category=TTPCategory.LATERAL_MOVEMENT,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.COMMAND_AND_CONTROL,
                detection_difficulty="Medium",
                evasion_capability=0.65,
                detectability_score=0.55,
                mitigations=["M1030: Network Segmentation", "M1031: Network Intrusion Prevention"]
            ),
            # Exfiltration
            "T1041": TTPMapping(
                technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel",
                category=TTPCategory.EXFILTRATION,
                platform="Windows/Linux/MacOS",
                executes_on_stage=APTStage.EXFILTRATION,
                detection_difficulty="Medium",
                evasion_capability=0.7,
                detectability_score=0.6,
                mitigations=["M1030: Network Segmentation", "M1031: Network Intrusion Prevention"]
            ),
        }
        
        return ttp_library
    
    # ============ CAMPAIGN CREATION ============
    def create_apt_campaign(self,
                           campaign_name: str,
                           threat_actor: str,
                           target_organization: str,
                           target_industry: str,
                           objectives: List[str],
                           duration_days: int = 30) -> APTCampaign:
        """Create new APT campaign"""
        
        campaign = APTCampaign(
            campaign_id=str(uuid.uuid4()),
            campaign_name=campaign_name,
            threat_actor=threat_actor,
            target_organization=target_organization,
            target_industry=target_industry,
            objectives=objectives,
            start_stage=APTStage.RECONNAISSANCE,
            current_stage=APTStage.RECONNAISSANCE,
            campaign_start=datetime.now().isoformat(),
            estimated_completion=(datetime.now() + timedelta(days=duration_days)).isoformat()
        )
        
        # Build stage workflow
        campaign.stages = self._build_campaign_workflow(campaign)
        
        self.campaigns[campaign.campaign_id] = campaign
        return campaign
    
    def _build_campaign_workflow(self, campaign: APTCampaign) -> Dict[str, List[Dict]]:
        """Build multi-stage campaign workflow"""
        
        workflow = {
            "reconnaissance": [
                {"action": "OSINT gathering", "duration": 3600, "ttps": ["T1592", "T1589"]},
                {"action": "Target enumeration", "duration": 7200, "ttps": ["T1590"]},
                {"action": "Service enumeration", "duration": 1800, "ttps": ["T1591"]},
            ],
            "weaponization": [
                {"action": "Malware development", "duration": 86400, "ttps": []},
                {"action": "Exploit creation", "duration": 43200, "ttps": []},
                {"action": "Payload obfuscation", "duration": 3600, "ttps": ["T1027"]},
            ],
            "delivery": [
                {"action": "Email campaign setup", "duration": 1800, "ttps": ["T1583"]},
                {"action": "Phishing email sending", "duration": 3600, "ttps": ["T1566.002"]},
                {"action": "Watering hole setup", "duration": 7200, "ttps": ["T1583.001"]},
            ],
            "exploitation": [
                {"action": "Initial compromise", "duration": 300, "ttps": ["T1566.002"]},
                {"action": "Code execution", "duration": 600, "ttps": ["T1059.001"]},
                {"action": "Privilege escalation", "duration": 1800, "ttps": ["T1134.002"]},
            ],
            "installation": [
                {"action": "Persistence establishment", "duration": 1200, "ttps": ["T1547.001"]},
                {"action": "Backdoor installation", "duration": 600, "ttps": ["T1547"]},
                {"action": "Agent deployment", "duration": 300, "ttps": ["T1105"]},
            ],
            "command_and_control": [
                {"action": "C2 channel establishment", "duration": 600, "ttps": []},
                {"action": "Lateral movement", "duration": 3600, "ttps": ["T1570"]},
                {"action": "Credential harvesting", "duration": 7200, "ttps": ["T1110.001"]},
            ],
            "exfiltration": [
                {"action": "Data discovery", "duration": 3600, "ttps": ["T1083"]},
                {"action": "Data staging", "duration": 1800, "ttps": ["T1074"]},
                {"action": "Data exfiltration", "duration": 7200, "ttps": ["T1041"]},
            ]
        }
        
        return workflow
    
    # ============ TTP CHAIN EXECUTION ============
    def execute_ttp_chain(self, campaign_id: str, stage: APTStage) -> List[Dict]:
        """Execute TTP chain for specific campaign stage"""
        
        if campaign_id not in self.campaigns:
            return []
        
        campaign = self.campaigns[campaign_id]
        execution_results = []
        
        # Get TTPs for this stage
        stage_actions = campaign.stages.get(stage.value, [])
        
        for action in stage_actions:
            for ttp_id in action.get("ttps", []):
                if ttp_id in self.ttp_library:
                    ttp = self.ttp_library[ttp_id]
                    result = self._execute_ttp(campaign, ttp, action)
                    execution_results.append(result)
                    campaign.ttp_chain.append(ttp)
                    
                    # Log event
                    self._log_event(campaign_id, ttp_id, action, result)
        
        # Transition to next stage
        self._transition_stage(campaign)
        
        return execution_results
    
    def _execute_ttp(self, campaign: APTCampaign, ttp: TTPMapping, action: Dict) -> Dict:
        """Execute single TTP"""
        
        execution = {
            "technique_id": ttp.technique_id,
            "technique_name": ttp.technique_name,
            "action": action.get("action"),
            "timestamp": datetime.now().isoformat(),
            "success": True,  # In real scenario, depends on defenses
            "detection_probability": ttp.detectability_score,
            "execution_time": action.get("duration", 0),
            "evasion_tactics": self._select_evasion_tactics(ttp)
        }
        
        return execution
    
    def _select_evasion_tactics(self, ttp: TTPMapping) -> List[str]:
        """Select evasion tactics for TTP execution"""
        
        tactics = []
        
        if ttp.evasion_capability > 0.7:
            tactics.extend(["obfuscation", "timing_jitter", "proxy_chain"])
        elif ttp.evasion_capability > 0.5:
            tactics.extend(["obfuscation", "proxy_chain"])
        else:
            tactics.append("direct_execution")
        
        return tactics
    
    def _transition_stage(self, campaign: APTCampaign):
        """Transition campaign to next stage"""
        
        stage_order = [
            APTStage.RECONNAISSANCE,
            APTStage.WEAPONIZATION,
            APTStage.DELIVERY,
            APTStage.EXPLOITATION,
            APTStage.INSTALLATION,
            APTStage.COMMAND_AND_CONTROL,
            APTStage.EXFILTRATION
        ]
        
        current_index = stage_order.index(campaign.current_stage)
        
        if current_index < len(stage_order) - 1:
            campaign.current_stage = stage_order[current_index + 1]
    
    def _log_event(self, campaign_id: str, ttp_id: str, action: Dict, result: Dict):
        """Log campaign event"""
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "campaign_id": campaign_id,
            "technique_id": ttp_id,
            "action": action,
            "result": result
        }
        
        self.event_log.append(event)
    
    # ============ COVERT CHANNEL SETUP ============
    def create_covert_channel(self,
                             channel_type: str,  # DNS, HTTPS, SMTP, ICMP
                             encoding: str = "base64",
                             bandwidth_bps: int = 1024) -> CovertChannel:
        """Create covert communication channel"""
        
        # Channel characteristics
        channel_profiles = {
            "dns": {"latency": 500, "detectability": 0.7, "overhead": 0.8},
            "https": {"latency": 100, "detectability": 0.5, "overhead": 0.4},
            "smtp": {"latency": 1000, "detectability": 0.6, "overhead": 0.7},
            "icmp": {"latency": 50, "detectability": 0.8, "overhead": 0.2},
            "http_header": {"latency": 200, "detectability": 0.6, "overhead": 0.3},
        }
        
        profile = channel_profiles.get(channel_type.lower(), 
                                      {"latency": 500, "detectability": 0.6, "overhead": 0.5})
        
        channel = CovertChannel(
            channel_id=str(uuid.uuid4()),
            channel_type=channel_type,
            encoding=encoding,
            bandwidth=bandwidth_bps,
            latency=profile["latency"],
            detectability=profile["detectability"],
            protocol_overhead=profile["overhead"]
        )
        
        return channel
    
    def send_covert_message(self,
                           channel: CovertChannel,
                           message: str,
                           encryption_key: str = "") -> Dict:
        """Send message through covert channel"""
        
        # Calculate transmission time
        message_size = len(message.encode()) * (1 + channel.protocol_overhead)
        transmission_time = (message_size * 8) / channel.bandwidth  # seconds
        total_time = transmission_time + (channel.latency / 1000)
        
        result = {
            "channel_id": channel.channel_id,
            "message_sent": True,
            "message_size": len(message),
            "transmission_time": transmission_time,
            "total_time": total_time,
            "detection_risk": channel.detectability,
            "timestamp": datetime.now().isoformat()
        }
        
        # Update channel stats
        channel.messages_sent += 1
        channel.total_bytes_exfiltrated += len(message)
        
        return result
    
    # ============ CAMPAIGN SIMULATION ============
    def simulate_campaign(self, campaign_id: str, real_time: bool = False):
        """Simulate complete APT campaign"""
        
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        self.simulation_running = True
        
        stage_order = [
            APTStage.RECONNAISSANCE,
            APTStage.WEAPONIZATION,
            APTStage.DELIVERY,
            APTStage.EXPLOITATION,
            APTStage.INSTALLATION,
            APTStage.COMMAND_AND_CONTROL,
            APTStage.EXFILTRATION
        ]
        
        for stage in stage_order:
            if not self.simulation_running:
                break
            
            print(f"[*] Executing {stage.value} stage...")
            
            # Get total duration for this stage
            stage_actions = campaign.stages.get(stage.value, [])
            total_duration = sum(action.get("duration", 0) for action in stage_actions)
            
            # Execute stage
            results = self.execute_ttp_chain(campaign_id, stage)
            
            # Wait if real-time simulation
            if real_time and total_duration > 0:
                # Compressed time (e.g., 1000x faster)
                wait_time = total_duration / 1000
                time.sleep(wait_time)
            
            print(f"[+] {stage.value.capitalize()} stage completed: {len(results)} techniques executed")
        
        self.simulation_running = False
        campaign.success_rate = 0.75 + (0.25 * (1 - sum(len(campaign.stages.get(s.value, [])) or 0) / 50))
        
        return True
    
    # ============ DETECTION & EVASION METRICS ============
    def calculate_detection_probability(self, campaign_id: str) -> float:
        """Calculate probability of campaign detection"""
        
        if campaign_id not in self.campaigns:
            return 0.0
        
        campaign = self.campaigns[campaign_id]
        
        # Average detectability of executed TTPs
        if not campaign.ttp_chain:
            return 0.0
        
        detectability_scores = [ttp.detectability_score for ttp in campaign.ttp_chain]
        return sum(detectability_scores) / len(detectability_scores)
    
    def get_campaign_summary(self, campaign_id: str) -> Dict:
        """Get campaign execution summary"""
        
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        
        return {
            "campaign_id": campaign.campaign_id,
            "campaign_name": campaign.campaign_name,
            "threat_actor": campaign.threat_actor,
            "target": campaign.target_organization,
            "industry": campaign.target_industry,
            "current_stage": campaign.current_stage.value,
            "ttps_executed": len(campaign.ttp_chain),
            "techniques": [ttp.technique_id for ttp in campaign.ttp_chain],
            "success_rate": campaign.success_rate,
            "detection_probability": self.calculate_detection_probability(campaign_id),
            "campaign_start": campaign.campaign_start,
            "estimated_completion": campaign.estimated_completion,
            "events_logged": len([e for e in self.event_log if e["campaign_id"] == campaign_id])
        }


# Export key classes
__all__ = ['APTSimulationEngine', 'APTCampaign', 'TTPMapping', 'CovertChannel', 
           'APTStage', 'TTPCategory']
