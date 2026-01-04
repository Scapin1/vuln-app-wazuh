# app/models.py
from sqlalchemy import Column, Integer, BigInteger, String, Text, DateTime, Numeric, UniqueConstraint, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    interactions = relationship("UserInteraction", back_populates="user")

class UserInteraction(Base):
    __tablename__ = "user_interactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    endpoint = Column(String, index=True) # La URL o recurso accedido
    method = Column(String)               # GET, POST, DELETE, etc.
    details = Column(Text, nullable=True) # Información adicional opcional
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="interactions")

class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
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
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("agent_id", "package_name", "package_version", "cve_id", name="uniq_wazuh_vuln"),
    )

