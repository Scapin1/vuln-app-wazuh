# app/models.py

import datetime
import uuid
import enum
from xmlrpc.client import Boolean

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
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .db import Base

""""
#class User(Base):
#    __tablename__ = "users"
#    id = Column(Integer, primary_key=True, index=True)
#    username = Column(String, unique=True, index=True, nullable=False)
#    password_hash = Column(String, nullable=False)
#    is_active = Column(Boolean, default=False) 
#    is_default_password = Column(Boolean, nullable=False, default=True)
#    created_at = Column(DateTime(timezone=True), server_default=func.now())
#    interactions = relationship("UserInteraction", back_populates="user")


class WazuhConnection(Base):
    __tablename__ = "wazuh_connections"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    indexer_url = Column(String, nullable=False)
    wazuh_user = Column(String, nullable=False)
    wazuh_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    vulnerabilities = relationship("WazuhVulnerability", back_populates="connection")
    tested = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_ok = Column(Boolean, nullable=True)


#class UserInteraction(Base):
#    __tablename__ = "user_interactions"
#    id = Column(Integer, primary_key=True, index=True)
#    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
#    endpoint = Column(String, index=True)
#    method = Column(String)
#    details = Column(Text, nullable=True)
#    timestamp = Column(DateTime(timezone=True), server_default=func.now())
#    user = relationship("User", back_populates="interactions")


class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(Integer, ForeignKey("wazuh_connections.id"), nullable=False)
    connection = relationship("WazuhConnection", back_populates="vulnerabilities")
    status = Column(String, default="ACTIVE")
    agent_id = Column(String, nullable=False, index=True)
    agent_name = Column(String)
    os_full = Column(Text)
    os_platform = Column(Text)
    os_version = Column(Text)
    package_name = Column(Text)
    package_version = Column(Text)
    package_type = Column(Text)
    package_arch = Column(Text)
    cve_id = Column(Text, nullable=False)
    severity = Column(Text)
    score_base = Column(Numeric)
    score_version = Column(Text)
    detected_at = Column(DateTime(timezone=True))
    published_at = Column(DateTime(timezone=True))
    description = Column(Text)
    reference = Column(Text)
    scanner_vendor = Column(Text)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    history = relationship(
        "VulnerabilityHistory",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    __table_args__ = (
        UniqueConstraint(
            "connection_id",
            "agent_id",
            "package_name",
            "package_version",
            "cve_id",
            name="uniq_wazuh_vuln",
        ),
    )


class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("wazuh_vulnerabilities.id"), nullable=False
    )
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    vulnerability = relationship("WazuhVulnerability", back_populates="history")
"""

##          TimeScaleDB-MODELS          ##

# ==========================================================
# 1. ENUMS (Deben coincidir con los TYPE del init.sql)
# ==========================================================
class VulnStatus(enum.Enum):
    Detected = "Detected"
    Resolved = "Resolved"
    Re_emerged = "Re-emerged"

# ==========================================================
# 2. TABLAS INTERMEDIAS
# ==========================================================
user_manager = Table(
    "user_manager",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("user.user_id", ondelete="CASCADE"), primary_key=True),
    Column("manager_id", UUID(as_uuid=True), ForeignKey("managers.manager_id", ondelete="CASCADE"), primary_key=True),
)

# ==========================================================
# 3. MODELOS DE GESTIÓN (CORE)
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
    # Relación M:N con Managers
    managers = relationship("Manager", secondary=user_manager, back_populates="users")

class Manager(Base):
    __tablename__ = "managers"
    manager_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = Column(String(255), nullable=False)
    api_url = Column(Text, nullable=False)
    api_key_vault_ref = Column(Text)
    
    assets = relationship("Asset", back_populates="manager")
    users = relationship("User", secondary=user_manager, back_populates="managers")

class Asset(Base):
    __tablename__ = "assets"
    asset_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wazuh_agent_id = Column(String(255), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    os_version = Column(String(255))
    ip_address = Column(INET)
    manager_id = Column(UUID(as_uuid=True), ForeignKey("managers.manager_id"), nullable=False)
    
    manager = relationship("Manager", back_populates="assets")
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
# 4. MODELOS DE WAZUH (INTEGRACIÓN)
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
    vulnerabilities = relationship("WazuhVulnerability", back_populates="connection")
    tested = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(Integer, ForeignKey("wazuh_connections.id"), nullable=False)
    connection = relationship("WazuhConnection", back_populates="vulnerabilities")
    status = Column(String, default="ACTIVE")
    agent_id = Column(String, nullable=False, index=True)
    agent_name = Column(String)
    os_full = Column(Text)
    os_platform = Column(Text)
    os_version = Column(Text)
    package_name = Column(Text)
    package_version = Column(Text)
    package_type = Column(Text)
    package_arch = Column(Text)
    cve_id = Column(Text, nullable=False)
    severity = Column(Text)
    score_base = Column(Numeric)
    score_version = Column(Text)
    detected_at = Column(DateTime(timezone=True))
    published_at = Column(DateTime(timezone=True))
    description = Column(Text)
    reference = Column(Text)
    scanner_vendor = Column(Text)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    history = relationship(
        "VulnerabilityHistory",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    __table_args__ = (
        UniqueConstraint(
            "connection_id",
            "agent_id",
            "package_name",
            "package_version",
            "cve_id",
            name="uniq_wazuh_vuln",
        ),
    )

class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("wazuh_vulnerabilities.id"), nullable=False
    )
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    vulnerability = relationship("WazuhVulnerability", back_populates="history")

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