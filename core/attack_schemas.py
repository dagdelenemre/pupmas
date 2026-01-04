"""
Attack Schema Engine - Define, validate, and generate detection rules
for various attack patterns and scenarios
"""

import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import jsonschema


class AttackPhase(Enum):
    """Attack lifecycle phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS_OBJECTIVES = "actions_on_objectives"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"


class DetectionRuleType(Enum):
    """Types of detection rules"""
    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    CUSTOM = "custom"


@dataclass
class AttackIndicator:
    """Indicator of Compromise or Attack"""
    type: str  # ip, domain, hash, file_path, registry_key, process, etc.
    value: str
    confidence: float  # 0.0 to 1.0
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class DetectionRule:
    """Detection rule for security monitoring"""
    rule_id: str
    name: str
    description: str
    rule_type: DetectionRuleType
    severity: str  # low, medium, high, critical
    rule_content: str
    references: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0


@dataclass
class AttackSchema:
    """Complete attack pattern schema"""
    schema_id: str
    name: str
    description: str
    attack_phases: List[AttackPhase]
    mitre_techniques: List[str]
    indicators: List[AttackIndicator]
    detection_rules: List[DetectionRule]
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""
    likelihood: str = ""  # low, medium, high
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class AttackSchemaEngine:
    """
    Sophisticated attack schema management system for defining,
    validating, and generating detection rules for attack patterns
    """
    
    # JSON Schema for attack pattern validation
    ATTACK_SCHEMA_DEFINITION = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["name", "description", "attack_phases"],
        "properties": {
            "name": {"type": "string", "minLength": 3},
            "description": {"type": "string", "minLength": 10},
            "attack_phases": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1
            },
            "mitre_techniques": {
                "type": "array",
                "items": {"type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$"}
            },
            "indicators": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["type", "value"],
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "description": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        }
    }
    
    def __init__(self, schemas_path: Optional[Path] = None):
        """Initialize attack schema engine"""
        self.schemas_path = schemas_path or Path(__file__).parent.parent / "data" / "schemas"
        self.schemas_path.mkdir(parents=True, exist_ok=True)
        
        self.schemas: Dict[str, AttackSchema] = {}
        self.rule_templates: Dict[str, str] = {}
        
        self._load_schemas()
        self._load_rule_templates()
        self._generate_default_schemas()
    
    def _load_schemas(self):
        """Load attack schemas from disk"""
        for schema_file in self.schemas_path.glob("*.json"):
            try:
                with open(schema_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                schema = self._dict_to_schema(data)
                self.schemas[schema.schema_id] = schema
            except Exception as e:
                print(f"Error loading schema {schema_file}: {e}")
    
    def _load_rule_templates(self):
        """Load detection rule templates"""
        self.rule_templates = {
            'sigma': '''
title: {title}
id: {rule_id}
status: experimental
description: {description}
references:
{references}
tags:
{tags}
logsource:
    product: {product}
    service: {service}
detection:
    selection:
{selection}
    condition: selection
falsepositives:
{false_positives}
level: {severity}
''',
            'yara': '''
rule {rule_name} {{
    meta:
        description = "{description}"
        author = "PUPMAS"
        date = "{date}"
        severity = "{severity}"
        
    strings:
{strings}
        
    condition:
        {condition}
}}
''',
            'snort': '''
alert {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} (
    msg:"{message}";
    {content}
    reference:{references};
    classtype:{classtype};
    sid:{sid};
    rev:1;
)
''',
            'splunk': '''
index={index} sourcetype={sourcetype}
{search_conditions}
| stats count by {group_by}
| where count > {threshold}
'''
        }
    
    def _dict_to_schema(self, data: Dict) -> AttackSchema:
        """Convert dictionary to AttackSchema object"""
        # Parse attack phases
        phases = [AttackPhase(p) for p in data.get('attack_phases', [])]
        
        # Parse indicators
        indicators = []
        for ind_data in data.get('indicators', []):
            indicators.append(AttackIndicator(**ind_data))
        
        # Parse detection rules
        rules = []
        for rule_data in data.get('detection_rules', []):
            rule_data['rule_type'] = DetectionRuleType(rule_data['rule_type'])
            rules.append(DetectionRule(**rule_data))
        
        # Parse dates
        created_at = datetime.fromisoformat(data.get('created_at', datetime.now().isoformat()))
        updated_at = datetime.fromisoformat(data.get('updated_at', datetime.now().isoformat()))
        
        return AttackSchema(
            schema_id=data['schema_id'],
            name=data['name'],
            description=data['description'],
            attack_phases=phases,
            mitre_techniques=data.get('mitre_techniques', []),
            indicators=indicators,
            detection_rules=rules,
            prerequisites=data.get('prerequisites', []),
            impact=data.get('impact', ''),
            likelihood=data.get('likelihood', 'medium'),
            tags=data.get('tags', []),
            created_at=created_at,
            updated_at=updated_at
        )
    
    def _schema_to_dict(self, schema: AttackSchema) -> Dict:
        """Convert AttackSchema to dictionary"""
        return {
            'schema_id': schema.schema_id,
            'name': schema.name,
            'description': schema.description,
            'attack_phases': [p.value for p in schema.attack_phases],
            'mitre_techniques': schema.mitre_techniques,
            'indicators': [
                {
                    'type': ind.type,
                    'value': ind.value,
                    'confidence': ind.confidence,
                    'description': ind.description,
                    'tags': ind.tags
                }
                for ind in schema.indicators
            ],
            'detection_rules': [
                {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'description': rule.description,
                    'rule_type': rule.rule_type.value,
                    'severity': rule.severity,
                    'rule_content': rule.rule_content,
                    'references': rule.references,
                    'mitre_techniques': rule.mitre_techniques,
                    'tags': rule.tags,
                    'false_positive_rate': rule.false_positive_rate
                }
                for rule in schema.detection_rules
            ],
            'prerequisites': schema.prerequisites,
            'impact': schema.impact,
            'likelihood': schema.likelihood,
            'tags': schema.tags,
            'created_at': schema.created_at.isoformat(),
            'updated_at': schema.updated_at.isoformat()
        }
    
    def validate_schema(self, schema_data: Dict) -> Tuple[bool, List[str]]:
        """Validate attack schema against JSON schema"""
        errors = []
        
        try:
            jsonschema.validate(instance=schema_data, schema=self.ATTACK_SCHEMA_DEFINITION)
            return True, []
        except jsonschema.exceptions.ValidationError as e:
            errors.append(str(e))
            return False, errors
    
    def create_schema(
        self,
        name: str,
        description: str,
        attack_phases: List[str],
        mitre_techniques: Optional[List[str]] = None
    ) -> AttackSchema:
        """Create a new attack schema"""
        import hashlib
        
        # Generate schema ID
        schema_id = hashlib.md5(name.encode()).hexdigest()[:8]
        
        phases = [AttackPhase(p) for p in attack_phases]
        
        schema = AttackSchema(
            schema_id=schema_id,
            name=name,
            description=description,
            attack_phases=phases,
            mitre_techniques=mitre_techniques or [],
            indicators=[],
            detection_rules=[]
        )
        
        self.schemas[schema_id] = schema
        self._save_schema(schema)
        
        return schema
    
    def add_indicator(
        self,
        schema_id: str,
        indicator_type: str,
        value: str,
        confidence: float = 0.8,
        description: str = "",
        tags: Optional[List[str]] = None
    ) -> bool:
        """Add an indicator to a schema"""
        schema = self.schemas.get(schema_id)
        if not schema:
            return False
        
        indicator = AttackIndicator(
            type=indicator_type,
            value=value,
            confidence=confidence,
            description=description,
            tags=tags or []
        )
        
        schema.indicators.append(indicator)
        schema.updated_at = datetime.now()
        self._save_schema(schema)
        
        return True
    
    def generate_detection_rule(
        self,
        schema_id: str,
        rule_type: str,
        **kwargs
    ) -> Optional[DetectionRule]:
        """Generate detection rule from schema"""
        schema = self.schemas.get(schema_id)
        if not schema:
            return None
        
        rule_type_enum = DetectionRuleType(rule_type)
        
        if rule_type == 'sigma':
            return self._generate_sigma_rule(schema, **kwargs)
        elif rule_type == 'yara':
            return self._generate_yara_rule(schema, **kwargs)
        elif rule_type == 'snort':
            return self._generate_snort_rule(schema, **kwargs)
        elif rule_type == 'splunk':
            return self._generate_splunk_rule(schema, **kwargs)
        
        return None
    
    def _generate_sigma_rule(self, schema: AttackSchema, **kwargs) -> DetectionRule:
        """Generate Sigma detection rule"""
        import hashlib
        
        rule_id = hashlib.md5(f"{schema.schema_id}_sigma".encode()).hexdigest()
        
        # Build selection criteria from indicators
        selection_items = []
        for indicator in schema.indicators:
            if indicator.type == 'process':
                selection_items.append(f"        Image|endswith: '{indicator.value}'")
            elif indicator.type == 'command':
                selection_items.append(f"        CommandLine|contains: '{indicator.value}'")
            elif indicator.type == 'file_path':
                selection_items.append(f"        TargetFilename: '{indicator.value}'")
        
        selection = '\n'.join(selection_items) if selection_items else '        EventID: 1'
        
        # Format references
        refs = '\n'.join(f"    - {ref}" for ref in kwargs.get('references', []))
        if not refs:
            refs = "    - https://attack.mitre.org/"
        
        # Format tags
        tags_list = schema.tags + [f"attack.{t.lower()}" for t in schema.mitre_techniques]
        tags_str = '\n'.join(f"    - {tag}" for tag in tags_list)
        
        rule_content = self.rule_templates['sigma'].format(
            title=schema.name,
            rule_id=rule_id,
            description=schema.description,
            references=refs,
            tags=tags_str,
            product=kwargs.get('product', 'windows'),
            service=kwargs.get('service', 'sysmon'),
            selection=selection,
            false_positives='    - Legitimate system administration',
            severity=kwargs.get('severity', 'high')
        )
        
        return DetectionRule(
            rule_id=rule_id,
            name=f"Sigma - {schema.name}",
            description=schema.description,
            rule_type=DetectionRuleType.SIGMA,
            severity=kwargs.get('severity', 'high'),
            rule_content=rule_content,
            references=kwargs.get('references', []),
            mitre_techniques=schema.mitre_techniques,
            tags=tags_list
        )
    
    def _generate_yara_rule(self, schema: AttackSchema, **kwargs) -> DetectionRule:
        """Generate YARA detection rule"""
        import hashlib
        
        rule_id = hashlib.md5(f"{schema.schema_id}_yara".encode()).hexdigest()
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', schema.name)
        
        # Build strings from indicators
        strings = []
        for i, indicator in enumerate(schema.indicators):
            if indicator.type in ['string', 'hex', 'regex']:
                strings.append(f'        $s{i} = "{indicator.value}"')
        
        if not strings:
            strings = ['        $s0 = "malicious"']
        
        strings_str = '\n'.join(strings)
        condition = f"any of ($s*)"
        
        rule_content = self.rule_templates['yara'].format(
            rule_name=rule_name,
            description=schema.description,
            date=datetime.now().strftime('%Y-%m-%d'),
            severity=kwargs.get('severity', 'high'),
            strings=strings_str,
            condition=condition
        )
        
        return DetectionRule(
            rule_id=rule_id,
            name=f"YARA - {schema.name}",
            description=schema.description,
            rule_type=DetectionRuleType.YARA,
            severity=kwargs.get('severity', 'high'),
            rule_content=rule_content,
            mitre_techniques=schema.mitre_techniques,
            tags=schema.tags
        )
    
    def _generate_snort_rule(self, schema: AttackSchema, **kwargs) -> DetectionRule:
        """Generate Snort IDS rule"""
        import hashlib
        
        rule_id = hashlib.md5(f"{schema.schema_id}_snort".encode()).hexdigest()
        sid = int(hashlib.md5(rule_id.encode()).hexdigest()[:6], 16) % 1000000 + 1000000
        
        # Build content matchers from indicators
        content_parts = []
        for indicator in schema.indicators:
            if indicator.type in ['string', 'pattern']:
                content_parts.append(f'content:"{indicator.value}";')
        
        content = ' '.join(content_parts) if content_parts else 'content:"";'
        
        rule_content = self.rule_templates['snort'].format(
            protocol=kwargs.get('protocol', 'tcp'),
            src_ip=kwargs.get('src_ip', 'any'),
            src_port=kwargs.get('src_port', 'any'),
            dst_ip=kwargs.get('dst_ip', 'any'),
            dst_port=kwargs.get('dst_port', 'any'),
            message=schema.name,
            content=content,
            references='url,attack.mitre.org',
            classtype=kwargs.get('classtype', 'trojan-activity'),
            sid=sid
        )
        
        return DetectionRule(
            rule_id=rule_id,
            name=f"Snort - {schema.name}",
            description=schema.description,
            rule_type=DetectionRuleType.SNORT,
            severity=kwargs.get('severity', 'high'),
            rule_content=rule_content,
            mitre_techniques=schema.mitre_techniques,
            tags=schema.tags
        )
    
    def _generate_splunk_rule(self, schema: AttackSchema, **kwargs) -> DetectionRule:
        """Generate Splunk SPL query"""
        import hashlib
        
        rule_id = hashlib.md5(f"{schema.schema_id}_splunk".encode()).hexdigest()
        
        # Build search conditions from indicators
        conditions = []
        for indicator in schema.indicators:
            if indicator.type == 'process':
                conditions.append(f'process_name="{indicator.value}"')
            elif indicator.type == 'command':
                conditions.append(f'command="{indicator.value}"')
            elif indicator.type == 'ip':
                conditions.append(f'dest_ip="{indicator.value}"')
        
        search_cond = ' OR '.join(conditions) if conditions else 'index=*'
        
        rule_content = self.rule_templates['splunk'].format(
            index=kwargs.get('index', 'main'),
            sourcetype=kwargs.get('sourcetype', 'sysmon'),
            search_conditions=search_cond,
            group_by=kwargs.get('group_by', 'host'),
            threshold=kwargs.get('threshold', 5)
        )
        
        return DetectionRule(
            rule_id=rule_id,
            name=f"Splunk - {schema.name}",
            description=schema.description,
            rule_type=DetectionRuleType.SPLUNK,
            severity=kwargs.get('severity', 'high'),
            rule_content=rule_content,
            mitre_techniques=schema.mitre_techniques,
            tags=schema.tags
        )
    
    def search_schemas(self, query: str) -> List[AttackSchema]:
        """Search schemas by name, description, or tags"""
        query_lower = query.lower()
        results = []
        
        for schema in self.schemas.values():
            if (query_lower in schema.name.lower() or
                query_lower in schema.description.lower() or
                any(query_lower in tag.lower() for tag in schema.tags)):
                results.append(schema)
        
        return results
    
    def get_schemas_by_phase(self, phase: str) -> List[AttackSchema]:
        """Get all schemas for a specific attack phase"""
        phase_enum = AttackPhase(phase)
        return [s for s in self.schemas.values() if phase_enum in s.attack_phases]
    
    def get_schemas_by_mitre(self, technique_id: str) -> List[AttackSchema]:
        """Get all schemas associated with a MITRE technique"""
        return [
            s for s in self.schemas.values()
            if technique_id in s.mitre_techniques
        ]
    
    def _save_schema(self, schema: AttackSchema):
        """Save schema to disk"""
        schema_file = self.schemas_path / f"{schema.schema_id}.json"
        schema_data = self._schema_to_dict(schema)
        
        with open(schema_file, 'w', encoding='utf-8') as f:
            json.dump(schema_data, f, indent=2)
    
    def export_rules(
        self,
        schema_id: str,
        rule_type: str,
        output_path: Path
    ) -> bool:
        """Export detection rules to file"""
        schema = self.schemas.get(schema_id)
        if not schema:
            return False
        
        rules = [r for r in schema.detection_rules if r.rule_type.value == rule_type]
        
        if not rules:
            # Generate rule if it doesn't exist
            rule = self.generate_detection_rule(schema_id, rule_type)
            if rule:
                rules = [rule]
        
        if not rules:
            return False
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for rule in rules:
                f.write(rule.rule_content)
                f.write('\n\n')
        
        return True
    
    def _generate_default_schemas(self):
        """Generate default attack schemas"""
        # Only generate if no schemas exist
        if self.schemas:
            return
        
        default_schemas = [
            {
                'name': 'PowerShell Empire Attack',
                'description': 'Detection of PowerShell Empire framework usage including payload delivery and C2 communication',
                'attack_phases': ['exploitation', 'command_and_control'],
                'mitre_techniques': ['T1059.001', 'T1071.001', 'T1105'],
                'indicators': [
                    {'type': 'process', 'value': 'powershell.exe', 'confidence': 0.7},
                    {'type': 'command', 'value': '-enc', 'confidence': 0.8},
                    {'type': 'command', 'value': 'IEX', 'confidence': 0.9},
                    {'type': 'network', 'value': 'suspicious_domain.com', 'confidence': 0.95}
                ],
                'likelihood': 'high',
                'impact': 'Complete system compromise possible',
                'tags': ['powershell', 'empire', 'post-exploitation']
            },
            {
                'name': 'Credential Dumping via Mimikatz',
                'description': 'Detection of Mimikatz credential dumping tool usage',
                'attack_phases': ['credential_access'],
                'mitre_techniques': ['T1003.001', 'T1558.003'],
                'indicators': [
                    {'type': 'process', 'value': 'mimikatz.exe', 'confidence': 1.0},
                    {'type': 'command', 'value': 'sekurlsa::logonpasswords', 'confidence': 1.0},
                    {'type': 'file_path', 'value': 'lsass.dmp', 'confidence': 0.9}
                ],
                'likelihood': 'high',
                'impact': 'Credential theft leading to lateral movement',
                'tags': ['mimikatz', 'credentials', 'lsass']
            },
            {
                'name': 'DNS Tunneling Exfiltration',
                'description': 'Data exfiltration using DNS tunneling techniques',
                'attack_phases': ['exfiltration', 'command_and_control'],
                'mitre_techniques': ['T1048.003', 'T1071.004'],
                'indicators': [
                    {'type': 'dns_query', 'value': 'long_subdomain', 'confidence': 0.8},
                    {'type': 'network', 'value': 'high_dns_query_rate', 'confidence': 0.85}
                ],
                'likelihood': 'medium',
                'impact': 'Data theft via covert channel',
                'tags': ['dns', 'exfiltration', 'tunneling']
            },
            {
                'name': 'Lateral Movement via WMI',
                'description': 'Remote code execution using Windows Management Instrumentation',
                'attack_phases': ['lateral_movement', 'execution'],
                'mitre_techniques': ['T1047', 'T1021.006'],
                'indicators': [
                    {'type': 'process', 'value': 'wmic.exe', 'confidence': 0.7},
                    {'type': 'command', 'value': '/node:', 'confidence': 0.8},
                    {'type': 'command', 'value': 'process call create', 'confidence': 0.9}
                ],
                'likelihood': 'high',
                'impact': 'Unauthorized access to remote systems',
                'tags': ['wmi', 'lateral-movement', 'remote-execution']
            }
        ]
        
        for schema_data in default_schemas:
            schema = self.create_schema(
                name=schema_data['name'],
                description=schema_data['description'],
                attack_phases=schema_data['attack_phases'],
                mitre_techniques=schema_data['mitre_techniques']
            )
            
            # Add indicators
            for ind_data in schema_data['indicators']:
                self.add_indicator(
                    schema.schema_id,
                    indicator_type=ind_data['type'],
                    value=ind_data['value'],
                    confidence=ind_data['confidence']
                )
            
            # Update metadata
            schema.likelihood = schema_data['likelihood']
            schema.impact = schema_data['impact']
            schema.tags = schema_data['tags']
            
            self._save_schema(schema)
