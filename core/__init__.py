"""Core functionality modules for PUPMAS"""

from .mitre_handler import MITREHandler, MITRETechnique, MITRETactic
from .cve_handler import CVEHandler, CVEEntry
from .attack_schemas import AttackSchemaEngine, AttackSchema
from .timeline_manager import TimelineManager, TimelineEvent
from .siem_handler import SIEMHandler, LogEntry
from .opsec_manager import OPSECManager, SessionContext, ThreatLevel
from .advanced_exploitation import AdvancedExploitationEngine, ExploitPayload, PrivilegeEscalationPath, ExploitChain
from .advanced_intelligence import AdvancedIntelligenceEngine, DigitalFootprint, SSLCertificate, DNSRecord, ThreatIntelligenceSource
from .advanced_reporting import AdvancedReportingEngine, RiskAssessment, AttackPath, ThreatActor, CVSSv4Score
from .apt_simulator import APTSimulationEngine, APTCampaign, TTPMapping, CovertChannel, APTStage, TTPCategory

__all__ = [
    'MITREHandler', 'MITRETechnique', 'MITRETactic',
    'CVEHandler', 'CVEEntry',
    'AttackSchemaEngine', 'AttackSchema',
    'TimelineManager', 'TimelineEvent',
    'SIEMHandler', 'LogEntry',
    'OPSECManager', 'SessionContext', 'ThreatLevel',
    'AdvancedExploitationEngine', 'ExploitPayload', 'PrivilegeEscalationPath', 'ExploitChain',
    'AdvancedIntelligenceEngine', 'DigitalFootprint', 'SSLCertificate', 'DNSRecord', 'ThreatIntelligenceSource',
    'AdvancedReportingEngine', 'RiskAssessment', 'AttackPath', 'ThreatActor', 'CVSSv4Score',
    'APTSimulationEngine', 'APTCampaign', 'TTPMapping', 'CovertChannel', 'APTStage', 'TTPCategory'
]
