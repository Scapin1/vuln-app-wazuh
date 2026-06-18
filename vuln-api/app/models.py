# app/models.py

import datetime
import uuid
import enum

from sqlalchemy import (
    Column,
    Integer,
    Boolean,
    String,
    Text,
    DateTime,
    DECIMAL,
    Enum as SQLEnum,
    Numeric,
    UniqueConstraint,
    ForeignKey,
    Table,
    BigInteger
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .db import Base


##          TimeScaleDB-MODELS          ##

# ==========================================================
# 1. ENUMS (Deben coincidir con los TYPE del init.sql)
# ==========================================================
class VulnStatus(enum.Enum):
    Detected = "Detected"
    Resolved = "Resolved"
    Re_emerged = "Re-emerged"

# ==========================================================
# 2. MODELOS DE GESTIÓN (CORE)
# ==========================================================

class User(Base):
    __tablename__ = "user"
    user_id = Column(Integer, primary_key=True, index=True)
    user_rol = Column(String(100))
    user_name = Column(String(255))
    user_email = Column(String(255), unique=True, index=True, nullable=False)
    user_password = Column(String(255))
    user_status = Column(Boolean, default=True)
    user_delete = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    interactions = relationship("UserInteraction", back_populates="user")


class Asset(Base):
    __tablename__ = "assets"
    asset_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wazuh_agent_id = Column(String(255), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    os_version = Column(String(255))
    ip_address = Column(INET)
    wazuh_connection_id = Column(BigInteger, ForeignKey("wazuh_connections.id"), nullable=False)
    
    wazuh_connection = relationship("WazuhConnection", back_populates="assets")
    detections = relationship("VulnerabilityDetection", back_populates="asset")

class UserInteraction(Base):
    __tablename__ = "user_interactions"
    user_interaction_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("user.user_id", ondelete="CASCADE"), nullable=False)
    endpoint = Column(String(255), index=True)
    method = Column(String(50))
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    user = relationship("User", back_populates="interactions")

# ==========================================================
# 3. MODELOS DE WAZUH (INTEGRACIÓN / Antiguos modelos usando para validar la petición de datos a Wazuh / Borrar a futuro)
# ==========================================================

class WazuhConnection(Base):
    __tablename__ = "wazuh_connections"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    indexer_url = Column(String, nullable=False)
    wazuh_user = Column(String, nullable=False)
    wazuh_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    tested = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    assets = relationship("Asset", back_populates="wazuh_connection")


# ==========================================================
# 5. TIMESCALEDB MODELS
# ==========================================================

class VulnerabilityCatalog(Base):
    __tablename__ = "vulnerability_catalog"
    cve_id = Column(Text, primary_key=True)
    severity = Column(Text, nullable=False) # Se mantiene TEXT según init.sql
    description = Column(Text)
    cvss_score = Column(DECIMAL(3, 1))
    
    detections = relationship("VulnerabilityDetection", back_populates="catalog_entry")

class VulnerabilityDetection(Base):
    __tablename__ = "vulnerability_detections"
    timestamp = Column(DateTime(timezone=True), primary_key=True, default=datetime.datetime.utcnow)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.asset_id", ondelete="CASCADE"), primary_key=True)
    cve_id = Column(Text, ForeignKey("vulnerability_catalog.cve_id", ondelete="CASCADE"), primary_key=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(SQLEnum(VulnStatus, name="vuln_status", create_type=False), nullable=False)
    package_name = Column(Text)
    package_version = Column(Text)

    asset = relationship("Asset", back_populates="detections")
    catalog_entry = relationship("VulnerabilityCatalog", back_populates="detections")