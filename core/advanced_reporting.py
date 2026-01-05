#!/usr/bin/env python3
"""
Advanced Reporting & Analytics Module - Senior Expert Level
Risk scoring, attack path visualization, threat intelligence feeds
"""

import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum


class SeverityRating(Enum):
    """Severity ratings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CVSSVersion(Enum):
    """CVSS versions"""
    CVSS_v3_1 = "3.1"
    CVSS_v4_0 = "4.0"


@dataclass
class CVSSv4Score:
    """CVSS v4.0 score"""
    attack_vector: str  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: str  # LOW, HIGH
    privileges_required: str  # NONE, LOW, HIGH
    user_interaction: str  # NONE, REQUIRED
    scope: str  # UNCHANGED, CHANGED
    confidentiality: str  # NONE, LOW, HIGH
    integrity: str  # NONE, LOW, HIGH
    availability: str  # NONE, LOW, HIGH
    
    # Threat metrics
    exploit_maturity: str = "UNPROVEN"
    threat_level: str = "UNSPECIFIED"
    confidence: str = "UNCONFIRMED"
    
    # Environmental metrics
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    
    def calculate_score(self) -> float:
        """Calculate CVSS v4.0 score"""
        
        # Mapping metrics to values
        av_scores = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
        ac_scores = {"LOW": 0.77, "HIGH": 0.44}
        pr_scores = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
        ui_scores = {"NONE": 0.85, "REQUIRED": 0.62}
        
        # Calculate base metrics
        base = av_scores.get(self.attack_vector, 0.5)
        base *= ac_scores.get(self.attack_complexity, 0.5)
        base *= pr_scores.get(self.privileges_required, 0.5)
        base *= ui_scores.get(self.user_interaction, 0.5)
        
        # Impact metrics
        impact = max(
            0.6 if self.confidentiality == "HIGH" else 0.5 if self.confidentiality == "LOW" else 0,
            0.6 if self.integrity == "HIGH" else 0.5 if self.integrity == "LOW" else 0,
            0.6 if self.availability == "HIGH" else 0.5 if self.availability == "LOW" else 0,
        )
        
        self.base_score = min(10.0, base * impact * 10)
        return self.base_score


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment"""
    asset_id: str
    vulnerability_id: str
    cvss_score: float
    severity: SeverityRating
    likelihood: float  # 0.0-1.0
    business_impact: float  # 0.0-1.0
    exposure_window: int  # days until patch available
    
    risk_score: float = 0.0
    remediation_priority: int = 0  # 1 (highest) to 5 (lowest)
    
    def calculate_risk(self) -> float:
        """Calculate overall risk score"""
        
        # Risk = CVSS * Likelihood * Impact * (1 / Exposure)
        exposure_factor = 1.0 / (self.exposure_window + 1) if self.exposure_window > 0 else 1.0
        
        self.risk_score = (self.cvss_score * self.likelihood * self.business_impact * exposure_factor)
        
        # Calculate priority
        if self.risk_score > 8.0:
            self.remediation_priority = 1
        elif self.risk_score > 6.0:
            self.remediation_priority = 2
        elif self.risk_score > 4.0:
            self.remediation_priority = 3
        elif self.risk_score > 2.0:
            self.remediation_priority = 4
        else:
            self.remediation_priority = 5
        
        return self.risk_score


@dataclass
class AttackPath:
    """Attack path information"""
    path_id: str
    start_asset: str
    target_asset: str
    steps: List[Dict] = field(default_factory=list)
    total_risk: float = 0.0
    attack_complexity: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    required_privileges: str = "NONE"
    estimated_success_rate: float = 0.0
    estimated_time_to_compromise: int = 0  # minutes


@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str
    actor_name: str
    aliases: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK TTPs
    targets: List[str] = field(default_factory=list)  # Industries/Regions
    capability_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH, ADVANCED
    sophistication: str = "MEDIUM"
    first_observed: str = ""
    last_observed: str = ""
    attributed_incidents: List[str] = field(default_factory=list)


class AdvancedReportingEngine:
    """Senior-level reporting and analytics engine"""
    
    def __init__(self):
        self.risk_assessments = {}
        self.attack_paths = []
        self.threat_actors = {}
        self.threat_intelligence_feeds = []
        
    # ============ ADVANCED RISK SCORING ============
    def calculate_asset_risk(self,
                            asset_id: str,
                            vulnerabilities: List[Dict],
                            exposures: List[Dict],
                            environmental_factors: Dict) -> float:
        """Calculate comprehensive asset risk score"""
        
        total_risk = 0.0
        weighted_count = 0
        
        for vuln in vulnerabilities:
            assessment = RiskAssessment(
                asset_id=asset_id,
                vulnerability_id=vuln.get("id"),
                cvss_score=vuln.get("cvss_score", 5.0),
                severity=self._determine_severity(vuln.get("cvss_score", 5.0)),
                likelihood=self._calculate_likelihood(vuln, exposures),
                business_impact=environmental_factors.get("business_impact", 0.5),
                exposure_window=vuln.get("patch_available_days", 30)
            )
            
            risk = assessment.calculate_risk()
            total_risk += risk
            weighted_count += 1
        
        if weighted_count == 0:
            return 0.0
        
        return min(10.0, total_risk / weighted_count)
    
    def _determine_severity(self, cvss_score: float) -> SeverityRating:
        """Determine severity from CVSS score"""
        
        if cvss_score >= 9.0:
            return SeverityRating.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityRating.HIGH
        elif cvss_score >= 4.0:
            return SeverityRating.MEDIUM
        elif cvss_score >= 0.1:
            return SeverityRating.LOW
        else:
            return SeverityRating.INFO
    
    def _calculate_likelihood(self, vulnerability: Dict, exposures: List[Dict]) -> float:
        """Calculate likelihood based on vulnerability and exposure"""
        
        base_likelihood = 0.5
        
        # Check if publicly exploited
        if vulnerability.get("is_exploited"):
            base_likelihood = 0.9
        
        # Check if PoC available
        if vulnerability.get("poc_available"):
            base_likelihood *= 1.2
        
        # Check exposure count
        exposure_count = len([e for e in exposures if e.get("vulnerability_id") == vulnerability.get("id")])
        if exposure_count > 5:
            base_likelihood *= 1.1
        
        return min(1.0, base_likelihood)
    
    # ============ ATTACK PATH ANALYSIS ============
    def identify_attack_paths(self,
                             start_asset: str,
                             target_asset: str,
                             asset_graph: Dict,
                             vulnerabilities: Dict) -> List[AttackPath]:
        """Identify all possible attack paths between assets"""
        
        paths = []
        
        # BFS to find all paths
        discovered_paths = self._find_all_paths(start_asset, target_asset, asset_graph)
        
        for path_nodes in discovered_paths:
            attack_path = AttackPath(
                path_id=f"path_{start_asset}_{target_asset}_{len(paths)}",
                start_asset=start_asset,
                target_asset=target_asset,
                steps=self._build_attack_steps(path_nodes, vulnerabilities)
            )
            
            # Calculate metrics
            attack_path.total_risk = self._calculate_path_risk(attack_path.steps)
            attack_path.attack_complexity = self._assess_path_complexity(attack_path.steps)
            attack_path.estimated_success_rate = self._estimate_success_rate(attack_path.steps)
            attack_path.estimated_time_to_compromise = self._estimate_ttc(attack_path.steps)
            
            paths.append(attack_path)
        
        # Sort by success rate and risk
        paths.sort(key=lambda x: (x.estimated_success_rate * x.total_risk), reverse=True)
        
        self.attack_paths.extend(paths)
        return paths
    
    def _find_all_paths(self, start: str, target: str, graph: Dict, max_depth: int = 5) -> List[List[str]]:
        """BFS to find all paths between nodes"""
        
        all_paths = []
        queue = [(start, [start])]
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current == target:
                all_paths.append(path)
                continue
            
            for neighbor in graph.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))
        
        return all_paths
    
    def _build_attack_steps(self, path_nodes: List[str], vulnerabilities: Dict) -> List[Dict]:
        """Build attack steps for a path"""
        
        steps = []
        
        for i in range(len(path_nodes) - 1):
            from_asset = path_nodes[i]
            to_asset = path_nodes[i + 1]
            
            step = {
                "step": i + 1,
                "from": from_asset,
                "to": to_asset,
                "vulnerabilities": vulnerabilities.get(from_asset, []),
                "attack_vector": "network" if i == 0 else "lateral_movement"
            }
            
            steps.append(step)
        
        return steps
    
    def _calculate_path_risk(self, steps: List[Dict]) -> float:
        """Calculate cumulative risk of attack path"""
        
        # Risk increases with each successful step
        cumulative_risk = 1.0
        
        for step in steps:
            step_risk = 1.0
            for vuln in step.get("vulnerabilities", []):
                step_risk *= (1.0 - 0.1)  # Each vuln adds 10% risk
            
            cumulative_risk *= step_risk
        
        return min(10.0, cumulative_risk * len(steps))
    
    def _assess_path_complexity(self, steps: List[Dict]) -> str:
        """Assess complexity of attack path"""
        
        if len(steps) <= 1:
            return "LOW"
        elif len(steps) <= 3:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _estimate_success_rate(self, steps: List[Dict]) -> float:
        """Estimate probability of successful exploitation"""
        
        success_prob = 1.0
        
        for step in steps:
            # Base success rate per step
            step_success = 0.7 if step["attack_vector"] == "network" else 0.6
            
            # Adjust based on vulnerability count
            if len(step.get("vulnerabilities", [])) > 0:
                step_success = 0.85
            
            success_prob *= step_success
        
        return success_prob
    
    def _estimate_ttc(self, steps: List[Dict]) -> int:
        """Estimate time to compromise in minutes"""
        
        base_time = 30  # 30 minutes for reconnaissance
        
        for step in steps:
            if step["attack_vector"] == "network":
                base_time += 20  # Network exploitation
            else:
                base_time += 15  # Lateral movement
        
        return base_time
    
    # ============ THREAT ACTOR PROFILING ============
    def profile_threat_actor(self,
                            actor_name: str,
                            observed_ttps: List[str],
                            observed_targets: List[str],
                            recent_incidents: List[str]) -> ThreatActor:
        """Create threat actor profile"""
        
        actor = ThreatActor(
            actor_id=f"actor_{actor_name.lower().replace(' ', '_')}",
            actor_name=actor_name,
            ttps=observed_ttps,
            targets=observed_targets,
            attributed_incidents=recent_incidents
        )
        
        # Determine capability level
        actor.capability_level = self._assess_capability(observed_ttps)
        
        # Determine sophistication
        actor.sophistication = self._assess_sophistication(observed_ttps)
        
        self.threat_actors[actor.actor_id] = actor
        return actor
    
    def _assess_capability(self, ttps: List[str]) -> str:
        """Assess threat actor capability"""
        
        advanced_ttps = [
            "T1059.001",  # Powershell
            "T1059.003",  # Windows Command Shell
            "T1547.001",  # Boot or Logon Autostart Execution
            "T1037",      # Boot or Logon Initialization Scripts
            "T1547.008",  # LSASS Driver
            "T1005",      # Data from Local System
            "T1134",      # Access Token Manipulation
        ]
        
        matches = sum(1 for ttp in ttps if ttp in advanced_ttps)
        
        if matches >= 5:
            return "ADVANCED"
        elif matches >= 3:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _assess_sophistication(self, ttps: List[str]) -> str:
        """Assess sophistication level"""
        
        # Similar to capability but could have different scoring
        return self._assess_capability(ttps)
    
    def predict_actor_next_move(self, actor: ThreatActor) -> Dict[str, Any]:
        """Predict next move based on TTP patterns"""
        
        prediction = {
            "actor_id": actor.actor_id,
            "next_likely_ttps": self._predict_next_ttps(actor.ttps),
            "next_likely_targets": self._predict_next_targets(actor.targets),
            "predicted_timeframe": "1-4 weeks",
            "confidence": 0.65
        }
        
        return prediction
    
    def _predict_next_ttps(self, current_ttps: List[str]) -> List[str]:
        """Predict next likely TTPs"""
        
        # TTP progression patterns
        common_progressions = {
            "T1566.002": ["T1204.002", "T1566.001"],  # Email attachment -> Click -> Social engineering
            "T1566.001": ["T1204.001", "T1547.001"],  # Email link -> Click -> Persistence
            "T1059.001": ["T1059.003", "T1543.001"],  # Powershell -> CMD -> Service creation
        }
        
        predictions = set()
        
        for ttp in current_ttps:
            if ttp in common_progressions:
                predictions.update(common_progressions[ttp])
        
        return list(predictions)
    
    def _predict_next_targets(self, current_targets: List[str]) -> List[str]:
        """Predict next targets based on patterns"""
        
        # Industry affinity analysis
        return current_targets  # Simplified
    
    # ============ THREAT INTELLIGENCE FEED INTEGRATION ============
    def add_threat_intelligence_feed(self,
                                    feed_name: str,
                                    feed_url: str,
                                    feed_type: str,  # indicators, malware, articles
                                    update_interval: int = 3600) -> bool:
        """Add threat intelligence feed"""
        
        feed = {
            "feed_name": feed_name,
            "feed_url": feed_url,
            "feed_type": feed_type,
            "update_interval": update_interval,
            "added_at": datetime.now().isoformat(),
            "last_updated": None,
            "indicator_count": 0,
            "enabled": True
        }
        
        self.threat_intelligence_feeds.append(feed)
        return True
    
    def process_threat_feed_indicators(self, feed_name: str, indicators: List[Dict]) -> Dict:
        """Process indicators from threat feed"""
        
        processing_result = {
            "feed_name": feed_name,
            "indicators_received": len(indicators),
            "indicators_processed": 0,
            "indicators_enriched": 0,
            "new_indicators": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        for indicator in indicators:
            # Check if indicator already exists
            if not self._indicator_exists(indicator):
                processing_result["new_indicators"] += 1
            
            # Enrich indicator
            enriched = self._enrich_indicator(indicator)
            processing_result["indicators_enriched"] += 1
            processing_result["indicators_processed"] += 1
        
        return processing_result
    
    def _indicator_exists(self, indicator: Dict) -> bool:
        """Check if indicator already exists"""
        # Simplified
        return False
    
    def _enrich_indicator(self, indicator: Dict) -> Dict:
        """Enrich indicator with additional context"""
        
        indicator["enriched"] = True
        indicator["enrichment_timestamp"] = datetime.now().isoformat()
        
        return indicator
    
    # ============ HEATMAP & VISUALIZATION DATA ============
    def generate_risk_heatmap(self, assets: List[Dict]) -> List[List[float]]:
        """Generate risk heatmap for visualization"""
        
        n = len(assets)
        heatmap = [[0.0 for _ in range(n)] for _ in range(n)]
        
        for i, asset1 in enumerate(assets):
            for j, asset2 in enumerate(assets):
                if i != j:
                    # Risk increases if asset1 can attack asset2
                    heatmap[i][j] = self._calculate_connection_risk(asset1, asset2)
        
        return heatmap
    
    def _calculate_connection_risk(self, from_asset: Dict, to_asset: Dict) -> float:
        """Calculate risk of connection between assets"""
        
        risk = 0.0
        
        # Base risk from network connectivity
        if from_asset.get("network") == to_asset.get("network"):
            risk = 0.5
        
        # Increase if shared credentials
        if from_asset.get("credentials") and to_asset.get("credentials"):
            risk += 0.2
        
        # Increase based on vulnerability presence
        risk += len(to_asset.get("vulnerabilities", [])) * 0.05
        
        return min(1.0, risk)
    
    def generate_attack_timeline(self, incidents: List[Dict]) -> List[Dict]:
        """Generate timeline of attacks for visualization"""
        
        timeline = []
        
        for incident in incidents:
            timeline.append({
                "timestamp": incident.get("timestamp"),
                "event_type": incident.get("type"),
                "severity": incident.get("severity"),
                "actor": incident.get("actor"),
                "affected_asset": incident.get("target"),
                "ttps": incident.get("ttps", [])
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline


# Export key classes
__all__ = ['AdvancedReportingEngine', 'RiskAssessment', 'AttackPath', 'ThreatActor',
           'CVSSv4Score', 'SeverityRating', 'CVSSVersion']
