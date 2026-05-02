# app/models.py
import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Numeric,
    ForeignKey,
    Enum,
    Boolean,
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .db import Base
import enum

class SeverityEnum(str, enum.Enum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Untriaged = "Untriaged"

class StatusEnum(str, enum.Enum):
    Detected = "Detected"
    Resolved = "Resolved"
    Re_emerged = "Re-emerged"

class Manager(Base):
    __tablename__ = "managers"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = Column(String(255), nullable=False)
    api_url = Column(Text, nullable=False)
    
    # El usuario solicitó guardar la contraseña/key directamente en DB y que sea editable
    # Renombrado de api_key_vault_ref a wazuh_password (se guardará encriptada)
    wazuh_user = Column(String(255), nullable=True) # Agregado para soportar Basic Auth si se requiere
    wazuh_password = Column(Text, nullable=False)
    
    assets = relationship("Asset", back_populates="manager", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wazuh_agent_id = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255))
    os_version = Column(String(255))
    ip_address = Column(INET) # Tipo nativo de Postgres para IPs
    
    manager_id = Column(UUID(as_uuid=True), ForeignKey("managers.id"), nullable=False)
    manager = relationship("Manager", back_populates="assets")
    
    detections = relationship("VulnerabilityDetection", back_populates="asset", cascade="all, delete-orphan")


class VulnerabilityCatalog(Base):
    __tablename__ = "vulnerability_catalog"
    
    cve_id = Column(String(50), primary_key=True)
    severity = Column(Enum(SeverityEnum), nullable=True)
    description = Column(Text)
    cvss_score = Column(Numeric(3, 1))
    
    detections = relationship("VulnerabilityDetection", back_populates="vulnerability")


class VulnerabilityDetection(Base):
    __tablename__ = "vulnerability_detections"
    
    # Hypertable abstracta: PK compuesta por timestamp, asset_id, cve_id
    timestamp = Column(DateTime(timezone=True), primary_key=True, default=func.now())
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), primary_key=True)
    cve_id = Column(String(50), ForeignKey("vulnerability_catalog.cve_id"), primary_key=True)
    
    first_seen_at = Column(DateTime(timezone=True), default=func.now())
    status = Column(Enum(StatusEnum), default=StatusEnum.Detected)
    package_name = Column(String(255))
    package_version = Column(String(255))
    
    asset = relationship("Asset", back_populates="detections")
    vulnerability = relationship("VulnerabilityCatalog", back_populates="detections")