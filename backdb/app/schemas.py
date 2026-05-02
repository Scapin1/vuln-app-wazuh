# schemas.py

from pydantic import BaseModel, ConfigDict, EmailStr, IPvAnyAddress
from uuid import UUID
from typing import Optional, List
from datetime import datetime
from models import SeverityLevel, VulnStatus


### JWT ###

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

class UserBase(BaseModel):
    user_name: str
    user_email: EmailStr
    user_rol: str

class UserCreate(UserBase):
    user_password: str
    manager_id: UUID  # Pydantic ahora sí sabrá cómo validar esto

class UserOut(UserBase):
    user_id: int
    user_status: bool
    manager_id: UUID
    
    model_config = ConfigDict(from_attributes=True)

# Esquema base (lo que es común a todos)
class UserBase(BaseModel):
    user_email: EmailStr
    user_name: str
    user_rol: str

# Lo que recibes cuando alguien se registra (incluye password)
class UserCreate(UserBase):
    user_password: str

# Lo que devuelves al frontend (¡NUNCA devuelvas el password!)
class UserResponse(UserBase):
    user_id: int
    user_status: bool
    user_delete: bool

    model_config = ConfigDict(from_attributes=True)

class UserOut(UserBase):
    user_id: int
    user_status: bool
    manager_id: UUID
    
    model_config = ConfigDict(
        from_attributes=True,
        arbitrary_types_allowed=True # <--- Esto permite tipos "extraños"
    )

# Esquemas para el Token
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


#############################

# Esquemas para Managers
class ManagerCreate(BaseModel):
    nombre: str
    api_url: str
    api_key_vault_ref: Optional[str] = None

class ManagerOut(ManagerCreate):
    id: UUID
    model_config = ConfigDict(from_attributes=True)

# Esquemas para Assets
class AssetCreate(BaseModel):
    wazuh_agent_id: str
    hostname: str
    os_version: Optional[str] = None
    ip_address: IPvAnyAddress = None
    manager_id: UUID

class AssetOut(AssetCreate):
    id: UUID
    model_config = ConfigDict(from_attributes=True)

# Esquemas para el Catálogo
class CatalogCreate(BaseModel):
    cve_id: str
    severity: SeverityLevel
    description: Optional[str] = None
    cvss_score: float

class CatalogOut(CatalogCreate):
    model_config = ConfigDict(from_attributes=True)

# Esquemas para la Detección (ENTRADA Y SALIDA)
class DetectionCreate(BaseModel):
    asset_id: UUID
    cve_id: str
    package_name: str
    package_version: str

class DetectionOut(BaseModel):
    first_seen_at: datetime
    timestamp: datetime
    asset_id: UUID
    cve_id: str
    status: VulnStatus
    package_name: Optional[str]
    package_version: Optional[str]
    
    # Esto permite que Pydantic lea objetos de SQLAlchemy
    model_config = ConfigDict(from_attributes=True)

#Para actualizar un Manager
class ManagerUpdate(BaseModel):
    nombre: Optional[str] = None
    api_url: Optional[str] = None
    api_key_vault_ref: Optional[str] = None

# Para actualizar un Asset
class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    manager_id: Optional[UUID] = None

# Para actualizar el Catálogo
class CatalogUpdate(BaseModel):
    severity: Optional[SeverityLevel] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None