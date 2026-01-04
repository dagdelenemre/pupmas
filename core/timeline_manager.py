"""
Timeline Manager - Comprehensive chronology tracking for security operations
Tracks attack timelines, pentest activities, reconnaissance, and exfiltration events
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict


class TimelineType(Enum):
    """Types of timeline tracking"""
    ATTACK = "attack"
    PENTEST = "pentest"
    RECONNAISSANCE = "reconnaissance"
    EXFILTRATION = "exfiltration"
    INCIDENT_RESPONSE = "incident_response"
    GENERAL = "general"


class EventSeverity(Enum):
    """Event severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimelineEvent:
    """Individual timeline event"""
    event_id: str
    timeline_type: TimelineType
    timestamp: datetime
    title: str
    description: str
    severity: EventSeverity
    actor: str = "Unknown"
    target: str = ""
    technique: str = ""  # MITRE technique ID
    tool: str = ""
    indicators: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    parent_event_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert event to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['timeline_type'] = self.timeline_type.value
        data['severity'] = self.severity.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TimelineEvent':
        """Create event from dictionary"""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        data['timeline_type'] = TimelineType(data['timeline_type'])
        data['severity'] = EventSeverity(data['severity'])
        return cls(**data)


@dataclass
class Timeline:
    """Complete timeline with metadata"""
    timeline_id: str
    name: str
    timeline_type: TimelineType
    description: str
    created_at: datetime
    updated_at: datetime
    events: List[TimelineEvent] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class TimelineManager:
    """
    Advanced timeline management system for tracking and analyzing
    security operations chronology
    """
    
    def __init__(self, data_path: Optional[Path] = None):
        """Initialize timeline manager"""
        self.data_path = data_path or Path(__file__).parent.parent / "data"
        self.timelines_path = self.data_path / "timelines"
        self.timelines_path.mkdir(parents=True, exist_ok=True)
        
        self.timelines: Dict[str, Timeline] = {}
        self.event_index: Dict[str, str] = {}  # event_id -> timeline_id
        
        self._load_timelines()
    
    def _load_timelines(self):
        """Load timelines from disk"""
        for timeline_file in self.timelines_path.glob("*.json"):
            try:
                with open(timeline_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                timeline = self._dict_to_timeline(data)
                self.timelines[timeline.timeline_id] = timeline
                
                # Build event index
                for event in timeline.events:
                    self.event_index[event.event_id] = timeline.timeline_id
            except Exception as e:
                print(f"Error loading timeline {timeline_file}: {e}")
    
    def _dict_to_timeline(self, data: Dict) -> Timeline:
        """Convert dictionary to Timeline object"""
        events = [TimelineEvent.from_dict(e) for e in data.get('events', [])]
        
        return Timeline(
            timeline_id=data['timeline_id'],
            name=data['name'],
            timeline_type=TimelineType(data['timeline_type']),
            description=data['description'],
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at']),
            events=events,
            tags=data.get('tags', []),
            metadata=data.get('metadata', {})
        )
    
    def _timeline_to_dict(self, timeline: Timeline) -> Dict:
        """Convert Timeline to dictionary"""
        return {
            'timeline_id': timeline.timeline_id,
            'name': timeline.name,
            'timeline_type': timeline.timeline_type.value,
            'description': timeline.description,
            'created_at': timeline.created_at.isoformat(),
            'updated_at': timeline.updated_at.isoformat(),
            'events': [e.to_dict() for e in timeline.events],
            'tags': timeline.tags,
            'metadata': timeline.metadata
        }
    
    def create_timeline(
        self,
        name: str,
        timeline_type: str,
        description: str = "",
        tags: Optional[List[str]] = None
    ) -> Timeline:
        """Create a new timeline"""
        import hashlib
        
        timeline_id = hashlib.md5(f"{name}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        timeline = Timeline(
            timeline_id=timeline_id,
            name=name,
            timeline_type=TimelineType(timeline_type),
            description=description,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            events=[],
            tags=tags or []
        )
        
        self.timelines[timeline_id] = timeline
        self._save_timeline(timeline)
        
        return timeline
    
    def add_event(
        self,
        timeline_id: str,
        title: str,
        description: str,
        severity: str = "medium",
        timestamp: Optional[datetime] = None,
        **kwargs
    ) -> Optional[TimelineEvent]:
        """Add event to timeline"""
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return None
        
        import hashlib
        event_id = hashlib.md5(
            f"{timeline_id}{title}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        event = TimelineEvent(
            event_id=event_id,
            timeline_type=timeline.timeline_type,
            timestamp=timestamp or datetime.now(),
            title=title,
            description=description,
            severity=EventSeverity(severity),
            actor=kwargs.get('actor', 'Unknown'),
            target=kwargs.get('target', ''),
            technique=kwargs.get('technique', ''),
            tool=kwargs.get('tool', ''),
            indicators=kwargs.get('indicators', []),
            artifacts=kwargs.get('artifacts', []),
            parent_event_id=kwargs.get('parent_event_id'),
            tags=kwargs.get('tags', []),
            metadata=kwargs.get('metadata', {})
        )
        
        timeline.events.append(event)
        timeline.events.sort(key=lambda e: e.timestamp)
        timeline.updated_at = datetime.now()
        
        self.event_index[event_id] = timeline_id
        self._save_timeline(timeline)
        
        return event
    
    def get_event(self, event_id: str) -> Optional[TimelineEvent]:
        """Get event by ID"""
        timeline_id = self.event_index.get(event_id)
        if not timeline_id:
            return None
        
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return None
        
        for event in timeline.events:
            if event.event_id == event_id:
                return event
        
        return None
    
    def update_event(self, event_id: str, **updates) -> bool:
        """Update an existing event"""
        event = self.get_event(event_id)
        if not event:
            return False
        
        for key, value in updates.items():
            if hasattr(event, key):
                setattr(event, key, value)
        
        timeline_id = self.event_index[event_id]
        timeline = self.timelines[timeline_id]
        timeline.updated_at = datetime.now()
        
        self._save_timeline(timeline)
        return True
    
    def delete_event(self, event_id: str) -> bool:
        """Delete an event from timeline"""
        timeline_id = self.event_index.get(event_id)
        if not timeline_id:
            return False
        
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return False
        
        timeline.events = [e for e in timeline.events if e.event_id != event_id]
        timeline.updated_at = datetime.now()
        
        del self.event_index[event_id]
        self._save_timeline(timeline)
        
        return True
    
    def get_timeline(self, timeline_id: str) -> Optional[Timeline]:
        """Get timeline by ID"""
        return self.timelines.get(timeline_id)
    
    def get_timelines_by_type(self, timeline_type: str) -> List[Timeline]:
        """Get all timelines of a specific type"""
        type_enum = TimelineType(timeline_type)
        return [t for t in self.timelines.values() if t.timeline_type == type_enum]
    
    def search_events(
        self,
        query: Optional[str] = None,
        timeline_type: Optional[str] = None,
        severity: Optional[str] = None,
        technique: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        tags: Optional[List[str]] = None
    ) -> List[Tuple[TimelineEvent, str]]:
        """
        Search events across all timelines with filters
        Returns list of (event, timeline_id) tuples
        """
        results = []
        
        for timeline_id, timeline in self.timelines.items():
            # Filter by timeline type
            if timeline_type and timeline.timeline_type.value != timeline_type:
                continue
            
            for event in timeline.events:
                # Apply filters
                if severity and event.severity.value != severity:
                    continue
                
                if technique and event.technique != technique:
                    continue
                
                if date_from and event.timestamp < date_from:
                    continue
                
                if date_to and event.timestamp > date_to:
                    continue
                
                if tags and not any(tag in event.tags for tag in tags):
                    continue
                
                # Text search
                if query:
                    query_lower = query.lower()
                    if not any([
                        query_lower in event.title.lower(),
                        query_lower in event.description.lower(),
                        query_lower in event.actor.lower(),
                        query_lower in event.target.lower(),
                        query_lower in event.tool.lower()
                    ]):
                        continue
                
                results.append((event, timeline_id))
        
        # Sort by timestamp descending
        results.sort(key=lambda x: x[0].timestamp, reverse=True)
        return results
    
    def get_attack_chain(self, timeline_id: str) -> List[List[TimelineEvent]]:
        """
        Analyze timeline and group events into attack chain phases
        Returns list of phases, each containing events
        """
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return []
        
        # Group by MITRE tactics (derived from techniques)
        phases = defaultdict(list)
        
        for event in timeline.events:
            # Simple phase detection based on keywords and techniques
            phase = self._detect_phase(event)
            phases[phase].append(event)
        
        # Order phases by typical attack progression
        phase_order = [
            'reconnaissance', 'weaponization', 'delivery', 'exploitation',
            'installation', 'command_control', 'actions'
        ]
        
        ordered_phases = []
        for phase_name in phase_order:
            if phase_name in phases:
                ordered_phases.append(phases[phase_name])
        
        return ordered_phases
    
    def _detect_phase(self, event: TimelineEvent) -> str:
        """Detect attack phase from event"""
        title_lower = event.title.lower()
        desc_lower = event.description.lower()
        
        if any(kw in title_lower + desc_lower for kw in ['scan', 'recon', 'enum', 'discover']):
            return 'reconnaissance'
        elif any(kw in title_lower + desc_lower for kw in ['payload', 'exploit', 'weaponize']):
            return 'weaponization'
        elif any(kw in title_lower + desc_lower for kw in ['phish', 'deliver', 'email']):
            return 'delivery'
        elif any(kw in title_lower + desc_lower for kw in ['exploit', 'vulnerability', 'rce']):
            return 'exploitation'
        elif any(kw in title_lower + desc_lower for kw in ['install', 'persist', 'backdoor']):
            return 'installation'
        elif any(kw in title_lower + desc_lower for kw in ['c2', 'command', 'control', 'beacon']):
            return 'command_control'
        else:
            return 'actions'
    
    def generate_timeline_summary(self, timeline_id: str) -> Dict:
        """Generate comprehensive timeline summary"""
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return {}
        
        # Calculate statistics
        severity_counts = defaultdict(int)
        technique_counts = defaultdict(int)
        actor_counts = defaultdict(int)
        tool_counts = defaultdict(int)
        
        for event in timeline.events:
            severity_counts[event.severity.value] += 1
            if event.technique:
                technique_counts[event.technique] += 1
            if event.actor:
                actor_counts[event.actor] += 1
            if event.tool:
                tool_counts[event.tool] += 1
        
        # Timeline duration
        if timeline.events:
            first_event = min(timeline.events, key=lambda e: e.timestamp)
            last_event = max(timeline.events, key=lambda e: e.timestamp)
            duration = last_event.timestamp - first_event.timestamp
        else:
            duration = timedelta(0)
        
        return {
            'timeline_id': timeline.timeline_id,
            'name': timeline.name,
            'type': timeline.timeline_type.value,
            'event_count': len(timeline.events),
            'duration': str(duration),
            'duration_hours': duration.total_seconds() / 3600,
            'severity_distribution': dict(severity_counts),
            'techniques_used': dict(technique_counts),
            'actors': dict(actor_counts),
            'tools': dict(tool_counts),
            'first_event': first_event.timestamp.isoformat() if timeline.events else None,
            'last_event': last_event.timestamp.isoformat() if timeline.events else None,
            'tags': timeline.tags
        }
    
    def merge_timelines(
        self,
        timeline_ids: List[str],
        new_name: str,
        new_description: str = ""
    ) -> Optional[Timeline]:
        """Merge multiple timelines into one"""
        timelines_to_merge = [
            self.timelines.get(tid) for tid in timeline_ids
            if tid in self.timelines
        ]
        
        if not timelines_to_merge:
            return None
        
        # Create new timeline
        new_timeline = self.create_timeline(
            name=new_name,
            timeline_type="general",
            description=new_description
        )
        
        # Merge events
        all_events = []
        for timeline in timelines_to_merge:
            all_events.extend(timeline.events)
        
        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        new_timeline.events = all_events
        
        # Rebuild event index
        for event in all_events:
            self.event_index[event.event_id] = new_timeline.timeline_id
        
        self._save_timeline(new_timeline)
        return new_timeline
    
    def export_to_json(self, timeline_id: str, output_path: Path) -> bool:
        """Export timeline to JSON"""
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return False
        
        data = self._timeline_to_dict(timeline)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return True
    
    def export_to_csv(self, timeline_id: str, output_path: Path) -> bool:
        """Export timeline events to CSV"""
        import csv
        
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return False
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Event ID', 'Timestamp', 'Title', 'Description', 'Severity',
                'Actor', 'Target', 'Technique', 'Tool', 'Tags'
            ])
            
            for event in timeline.events:
                writer.writerow([
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.title,
                    event.description,
                    event.severity.value,
                    event.actor,
                    event.target,
                    event.technique,
                    event.tool,
                    ', '.join(event.tags)
                ])
        
        return True
    
    def visualize_timeline(self, timeline_id: str) -> str:
        """Generate ASCII timeline visualization"""
        timeline = self.timelines.get(timeline_id)
        if not timeline or not timeline.events:
            return "Timeline not found or empty"
        
        lines = []
        lines.append(f"\n{'='*80}")
        lines.append(f"Timeline: {timeline.name}")
        lines.append(f"Type: {timeline.timeline_type.value}")
        lines.append(f"Events: {len(timeline.events)}")
        lines.append(f"{'='*80}\n")
        
        for i, event in enumerate(timeline.events):
            severity_icon = {
                'info': 'ℹ',
                'low': '◐',
                'medium': '◕',
                'high': '◉',
                'critical': '⊗'
            }.get(event.severity.value, '•')
            
            timestamp_str = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            lines.append(f"{i+1:3d}. [{timestamp_str}] {severity_icon} {event.title}")
            lines.append(f"     {event.description}")
            
            if event.technique:
                lines.append(f"     MITRE: {event.technique}")
            if event.actor != 'Unknown':
                lines.append(f"     Actor: {event.actor}")
            if event.target:
                lines.append(f"     Target: {event.target}")
            if event.tool:
                lines.append(f"     Tool: {event.tool}")
            
            lines.append("")
        
        return '\n'.join(lines)
    
    def _save_timeline(self, timeline: Timeline):
        """Save timeline to disk"""
        timeline_file = self.timelines_path / f"{timeline.timeline_id}.json"
        data = self._timeline_to_dict(timeline)
        
        with open(timeline_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def delete_timeline(self, timeline_id: str) -> bool:
        """Delete timeline"""
        if timeline_id not in self.timelines:
            return False
        
        # Remove from memory
        timeline = self.timelines.pop(timeline_id)
        
        # Remove event indices
        for event in timeline.events:
            if event.event_id in self.event_index:
                del self.event_index[event.event_id]
        
        # Remove file
        timeline_file = self.timelines_path / f"{timeline_id}.json"
        if timeline_file.exists():
            timeline_file.unlink()
        
        return True
