# app/models.py
from sqlalchemy import Column, Integer, BigInteger, String, Text, DateTime, Numeric, UniqueConstraint
from sqlalchemy.sql import func
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"

    id = Column(BigInteger, primary_key=True, index=True)
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

