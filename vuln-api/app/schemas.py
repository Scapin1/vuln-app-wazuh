# schemas.py
from pydantic import BaseModel, ConfigDict, EmailStr, IPvAnyAddress
from uuid import UUID
from typing import Dict, Optional, List
from datetime import datetime
from .models import VulnStatus # SeverityLevel lo manejamos como str según init.sql

# --- USER SCHEMAS ---
class UserBase(BaseModel):
    user_email: EmailStr
    user_name: str
    user_rol: str

class UserCreate(UserBase):
    user_email: EmailStr
    user_name: str
    user_rol: str
    user_password: str

class UserOut(UserBase):
    user_id: int
    user_status: bool
    user_delete: bool
    model_config = ConfigDict(from_attributes=True)

# --- ASSET SCHEMAS ---
class AssetBase(BaseModel):
    wazuh_agent_id: str
    hostname: str
    os_version: Optional[str] = None
    ip_address: Optional[IPvAnyAddress] = None
    wazuh_connection_id: UUID

class AssetCreate(AssetBase):
    pass

class AssetOut(AssetBase):
    asset_id: UUID # Coincide con models.py
    model_config = ConfigDict(from_attributes=True)

class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[IPvAnyAddress] = None
    wazuh_connection_id: Optional[UUID] = None

# --- CATALOG SCHEMAS ---
class CatalogCreate(BaseModel):
    cve_id: str
    severity: str # Se mantiene str para coincidir con init.sql
    description: Optional[str] = None
    cvss_score: float

class CatalogOut(CatalogCreate):
    model_config = ConfigDict(from_attributes=True)

class CatalogUpdate(BaseModel):
    severity: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None

# --- DETECTION SCHEMAS ---
class DetectionCreate(BaseModel):
    asset_id: UUID
    cve_id: str
    package_name: str
    package_version: str

class DetectionOut(BaseModel):
    timestamp: datetime
    asset_id: UUID
    cve_id: str
    first_seen_at: datetime
    status: VulnStatus
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class DashboardSummaryResponse(BaseModel):
    severity_distribution: Dict[str, int]
    status_distribution: Dict[str, int]
    total: int

class SnapshotSchema(BaseModel):
    sync_timestamp: str
    agent_count: int
    agents: Optional[List[str]] = None

class TimelineCVESchema(BaseModel):
    cve_id: str
    severity: str
    description: Optional[str] = None
    snapshots: List[SnapshotSchema]
    first_sync: Optional[str] = None
    last_sync: Optional[str] = None
    is_resolved: bool

class GanttTimelineResponse(BaseModel):
    cves: List[TimelineCVESchema]
    total_cves: int
    total_pages: int
    current_page: int
    per_page: int
    min_timestamp: Optional[str] = None
    max_timestamp: Optional[str] = None

class TopAgentSchema(BaseModel):
    agent: str
    count: int

class AnalyticsSummaryResponse(BaseModel):
    severity_distribution: Dict[str, int]
    status_distribution: Dict[str, int]
    top_agents: List[TopAgentSchema]
    critical_count: int
    top_critical_cve: Optional[str] = None

class AgentOptionSchema(BaseModel):
    name: str
    count: int

class CVEOptionSchema(BaseModel):
    id: str
    count: int

class FilterOptionsResponse(BaseModel):
    agents: List[AgentOptionSchema]
    cves: List[CVEOptionSchema]

class TimelineEventItemSchema(BaseModel):
    cve_id: str
    timestamp: str
    agent: str

class TimelineEventsResponse(BaseModel):
    detections: List[TimelineEventItemSchema]
    resolutions: List[TimelineEventItemSchema]

