# schemas.py
from pydantic import BaseModel, ConfigDict, EmailStr, IPvAnyAddress
from uuid import UUID
from typing import Optional, List
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