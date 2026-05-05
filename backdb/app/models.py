# models.py

from xmlrpc.client import Boolean
from sqlalchemy import Column, String, ForeignKey, DateTime, DECIMAL, Enum as SQLEnum, Text, Numeric, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import datetime
import uuid
import enum
from database import Base

# 1. DEFINICIÓN DE ENUMS (Python side)
class SeverityLevel(str, enum.Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

class VulnStatus(str, enum.Enum):
    Detected = "Detected"
    Resolved = "Resolved"
    Re_emerged = "Re-emerged"

# 2. MODELOS DE TABLAS

# A. Tabla managers
class Manager(Base):
    __tablename__ = "managers"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = Column(String(255), nullable=False)
    api_url = Column(Text, nullable=False)
    api_key_vault_ref = Column(Text)
    
    # Relación inversa: Un manager tiene muchos assets
    assets = relationship("Asset", back_populates="manager")

# B. Tabla Users
class User(Base):
    __tablename__ = "user"

    user_id = Column(Integer, primary_key=True, index=True)
    user_rol = Column(String)
    user_name = Column(String)
    user_email = Column(String, unique=True, index=True)
    user_password = Column(String) # Aquí guardamos el HASH
    user_status = Column(Boolean, default=True)
    user_delete = Column(Boolean, default=False)
    
# C. Tabla assets
class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wazuh_agent_id = Column(String(255), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    os_version = Column(String(255))
    ip_address = Column(INET)
    manager_id = Column(UUID(as_uuid=True), ForeignKey("managers.id"))
    
    manager = relationship("Manager", back_populates="assets")
    detections = relationship("VulnerabilityDetection", back_populates="asset")

# D. Tabla vulnerability_catalog
class VulnerabilityCatalog(Base):
    __tablename__ = "vulnerability_catalog"
    
    cve_id = Column(String(50), primary_key=True)
    # name="severity_level" coincide con el TYPE en init.sql
    # create_type=False evita que SQLAlchemy intente crearlo de nuevo
    severity = Column(
        SQLEnum(SeverityLevel, name="severity_level", create_type=False), 
        nullable=False
    )
    description = Column(Text)
    cvss_score = Column(DECIMAL(3, 1))
    
    detections = relationship("VulnerabilityDetection", back_populates="catalog_entry")

# 4. La Hypertable de TimescaleDB: vulnerability_detections
class VulnerabilityDetection(Base):
    __tablename__ = "vulnerability_detections"
    
    # En TimescaleDB la clave primaria debe incluir la columna de tiempo
    timestamp = Column(DateTime(timezone=True), primary_key=True, default=datetime.datetime.utcnow)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), primary_key=True)
    cve_id = Column(String(50), ForeignKey("vulnerability_catalog.cve_id"), primary_key=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False)
    
    # name="vuln_status" coincide con el TYPE en init.sql
    status = Column(
        SQLEnum(VulnStatus, name="vuln_status", create_type=False), 
        nullable=False
    )
    package_name = Column(String(255))
    package_version = Column(String(255))

    # Relaciones para facilitar navegación de objetos
    asset = relationship("Asset", back_populates="detections")
    catalog_entry = relationship("VulnerabilityCatalog", back_populates="detections")