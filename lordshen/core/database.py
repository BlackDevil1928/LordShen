"""Database models and management using SQLAlchemy."""
import uuid
from datetime import datetime
from typing import Optional, List, Any
from sqlalchemy import create_engine, Column, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from contextlib import contextmanager

from lordshen.core.config import CONFIG_DIR

DB_PATH = CONFIG_DIR / "data" / "app.db"
Base = declarative_base()

class Scan(Base):
    """Model representing a pentest scan."""
    __tablename__ = 'scans'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    profile = Column(String, nullable=False)
    scope_name = Column(String, nullable=False)
    status = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    findings_count = Column(Float, default=0)
    
    findings = relationship("Finding", back_populates="scan")
    tools = relationship("ScanTool", back_populates="scan")

class Finding(Base):
    """Model representing a vulnerability finding."""
    __tablename__ = 'findings'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    host = Column(String, nullable=False)
    url = Column(String, nullable=True)
    tool_name = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    confidence = Column(Float, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")

class ScanTool(Base):
    """Model representing a tool executed during a scan."""
    __tablename__ = 'scan_tools'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False)
    tool_name = Column(String, nullable=False)
    status = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    output_file = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="tools")

class AuditLog(Base):
    """Model representing an audit log entry."""
    __tablename__ = 'audit_logs'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    scope_name = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(Text, nullable=True)

def get_engine() -> Any:
    """Get the SQLAlchemy database engine."""
    if not DB_PATH.parent.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{DB_PATH}")

def init_db() -> None:
    """Initialize the database and create tables."""
    engine = get_engine()
    Base.metadata.create_all(engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())

@contextmanager
def get_session():
    """Context manager for database sessions."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def store_finding(session: Any, finding_data: dict[str, Any]) -> Finding:
    """Store a new finding in the database."""
    # Filter to only valid Finding columns
    valid_cols = {c.name for c in Finding.__table__.columns}
    filtered = {k: v for k, v in finding_data.items() if k in valid_cols}
    if "id" not in filtered:
        filtered["id"] = str(uuid.uuid4())
    finding = Finding(**filtered)
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding

def store_scan(session: Any, scan_data: dict[str, Any]) -> Scan:
    """Store or update a scan in the database."""
    scan_id = scan_data.get("id")
    existing = session.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    if existing:
        for key, value in scan_data.items():
            if value and hasattr(existing, key):
                setattr(existing, key, value)
        session.commit()
        session.refresh(existing)
        return existing
    scan = Scan(**scan_data)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan

def get_scan(session: Any, scan_id: str) -> Optional[Scan]:
    """Retrieve a scan by its ID."""
    return session.query(Scan).filter(Scan.id == scan_id).first()

def get_findings(session: Any, scan_id: str, severity: Optional[str] = None) -> List[Finding]:
    """Retrieve findings for a scan, optionally filtered by severity."""
    query = session.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    return query.all()

def log_audit(session: Any, action: str, target: str, scope: str, details: str) -> None:
    """Log an audit action."""
    log = AuditLog(action=action, target=target, scope_name=scope, details=details)
    session.add(log)
    session.commit()
