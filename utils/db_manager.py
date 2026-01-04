"""
Database Manager - Centralized database operations for PUPMAS
Uses SQLAlchemy for ORM and SQLite for storage
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session


Base = declarative_base()


class OperationSession(Base):
    """Database model for operation sessions"""
    __tablename__ = 'operations'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(32), unique=True, nullable=False)
    operation_type = Column(String(50))
    name = Column(String(255))
    status = Column(String(50))
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    metadata_json = Column(Text)


class ScanResult(Base):
    """Database model for scan results"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(32), unique=True)
    target = Column(String(255))
    scan_type = Column(String(50))
    timestamp = Column(DateTime, default=datetime.now)
    results_json = Column(Text)
    severity = Column(String(20))


class VulnerabilityRecord(Base):
    """Database model for identified vulnerabilities"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(32), unique=True)
    cve_id = Column(String(20))
    target = Column(String(255))
    severity = Column(String(20))
    cvss_score = Column(Float)
    description = Column(Text)
    discovered_at = Column(DateTime, default=datetime.now)
    status = Column(String(50))
    remediation = Column(Text)


class ArtifactRecord(Base):
    """Database model for collected artifacts"""
    __tablename__ = 'artifacts'
    
    id = Column(Integer, primary_key=True)
    artifact_id = Column(String(32), unique=True)
    artifact_type = Column(String(50))
    source = Column(String(255))
    data_json = Column(Text)
    file_path = Column(String(512))
    collected_at = Column(DateTime, default=datetime.now)
    tags = Column(Text)


class DatabaseManager:
    """
    Centralized database manager for PUPMAS operations
    Handles all database operations with SQLAlchemy ORM
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database manager"""
        if db_path is None:
            db_path = Path(__file__).parent.parent / "data" / "pupmas.db"
        
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        Base.metadata.create_all(self.engine)
        
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()
    
    # Operation Session methods
    def create_operation(
        self,
        session_id: str,
        operation_type: str,
        name: str,
        metadata: Optional[Dict] = None
    ) -> OperationSession:
        """Create new operation session"""
        session = self.get_session()
        try:
            operation = OperationSession(
                session_id=session_id,
                operation_type=operation_type,
                name=name,
                status='active',
                metadata_json=json.dumps(metadata or {})
            )
            session.add(operation)
            session.commit()
            session.refresh(operation)
            return operation
        finally:
            session.close()
    
    def get_operation(self, session_id: str) -> Optional[OperationSession]:
        """Get operation by session ID"""
        session = self.get_session()
        try:
            return session.query(OperationSession).filter_by(session_id=session_id).first()
        finally:
            session.close()
    
    def list_operations(
        self,
        operation_type: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[OperationSession]:
        """List operations with optional filters"""
        session = self.get_session()
        try:
            query = session.query(OperationSession)
            if operation_type:
                query = query.filter_by(operation_type=operation_type)
            if status:
                query = query.filter_by(status=status)
            return query.all()
        finally:
            session.close()
    
    def update_operation_status(self, session_id: str, status: str) -> bool:
        """Update operation status"""
        session = self.get_session()
        try:
            operation = session.query(OperationSession).filter_by(session_id=session_id).first()
            if operation:
                operation.status = status
                operation.updated_at = datetime.now()
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    # Scan Result methods
    def save_scan_result(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        results: Dict,
        severity: str = "info"
    ) -> ScanResult:
        """Save scan results"""
        session = self.get_session()
        try:
            scan = ScanResult(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type,
                results_json=json.dumps(results),
                severity=severity
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
        finally:
            session.close()
    
    def get_scan_results(
        self,
        target: Optional[str] = None,
        scan_type: Optional[str] = None
    ) -> List[ScanResult]:
        """Get scan results with optional filters"""
        session = self.get_session()
        try:
            query = session.query(ScanResult)
            if target:
                query = query.filter_by(target=target)
            if scan_type:
                query = query.filter_by(scan_type=scan_type)
            return query.order_by(ScanResult.timestamp.desc()).all()
        finally:
            session.close()
    
    # Vulnerability methods
    def save_vulnerability(
        self,
        vuln_id: str,
        cve_id: str,
        target: str,
        severity: str,
        cvss_score: float,
        description: str,
        status: str = "open"
    ) -> VulnerabilityRecord:
        """Save vulnerability record"""
        session = self.get_session()
        try:
            vuln = VulnerabilityRecord(
                vuln_id=vuln_id,
                cve_id=cve_id,
                target=target,
                severity=severity,
                cvss_score=cvss_score,
                description=description,
                status=status
            )
            session.add(vuln)
            session.commit()
            session.refresh(vuln)
            return vuln
        finally:
            session.close()
    
    def get_vulnerabilities(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[VulnerabilityRecord]:
        """Get vulnerabilities with optional filters"""
        session = self.get_session()
        try:
            query = session.query(VulnerabilityRecord)
            if target:
                query = query.filter_by(target=target)
            if severity:
                query = query.filter_by(severity=severity)
            if status:
                query = query.filter_by(status=status)
            return query.order_by(VulnerabilityRecord.cvss_score.desc()).all()
        finally:
            session.close()
    
    def update_vulnerability_status(self, vuln_id: str, status: str, remediation: Optional[str] = None) -> bool:
        """Update vulnerability status"""
        session = self.get_session()
        try:
            vuln = session.query(VulnerabilityRecord).filter_by(vuln_id=vuln_id).first()
            if vuln:
                vuln.status = status
                if remediation:
                    vuln.remediation = remediation
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    # Artifact methods
    def save_artifact(
        self,
        artifact_id: str,
        artifact_type: str,
        source: str,
        data: Dict,
        file_path: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> ArtifactRecord:
        """Save artifact"""
        session = self.get_session()
        try:
            artifact = ArtifactRecord(
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                source=source,
                data_json=json.dumps(data),
                file_path=file_path or '',
                tags=','.join(tags or [])
            )
            session.add(artifact)
            session.commit()
            session.refresh(artifact)
            return artifact
        finally:
            session.close()
    
    def get_artifacts(
        self,
        artifact_type: Optional[str] = None,
        source: Optional[str] = None
    ) -> List[ArtifactRecord]:
        """Get artifacts with optional filters"""
        session = self.get_session()
        try:
            query = session.query(ArtifactRecord)
            if artifact_type:
                query = query.filter_by(artifact_type=artifact_type)
            if source:
                query = query.filter_by(source=source)
            return query.order_by(ArtifactRecord.collected_at.desc()).all()
        finally:
            session.close()
    
    # Statistics and reporting
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        session = self.get_session()
        try:
            stats = {
                'total_operations': session.query(OperationSession).count(),
                'active_operations': session.query(OperationSession).filter_by(status='active').count(),
                'total_scans': session.query(ScanResult).count(),
                'total_vulnerabilities': session.query(VulnerabilityRecord).count(),
                'open_vulnerabilities': session.query(VulnerabilityRecord).filter_by(status='open').count(),
                'critical_vulnerabilities': session.query(VulnerabilityRecord).filter_by(
                    severity='critical', status='open'
                ).count(),
                'total_artifacts': session.query(ArtifactRecord).count()
            }
            return stats
        finally:
            session.close()
    
    def cleanup_old_data(self, days: int = 90) -> int:
        """Clean up data older than specified days"""
        session = self.get_session()
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Delete old completed operations
            deleted = session.query(OperationSession).filter(
                OperationSession.status != 'active',
                OperationSession.updated_at < cutoff_date
            ).delete()
            
            session.commit()
            return deleted
        finally:
            session.close()
    
    def export_to_json(self, output_path: Path) -> bool:
        """Export all data to JSON"""
        session = self.get_session()
        try:
            data = {
                'operations': [
                    {
                        'session_id': op.session_id,
                        'operation_type': op.operation_type,
                        'name': op.name,
                        'status': op.status,
                        'created_at': op.created_at.isoformat(),
                        'metadata': json.loads(op.metadata_json or '{}')
                    }
                    for op in session.query(OperationSession).all()
                ],
                'vulnerabilities': [
                    {
                        'vuln_id': vuln.vuln_id,
                        'cve_id': vuln.cve_id,
                        'target': vuln.target,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'description': vuln.description,
                        'status': vuln.status
                    }
                    for vuln in session.query(VulnerabilityRecord).all()
                ]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error exporting data: {e}")
            return False
        finally:
            session.close()


from datetime import timedelta
