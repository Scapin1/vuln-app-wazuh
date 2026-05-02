import os
import re
from datetime import datetime, timezone
from typing import List, Annotated, Optional
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import (
    VulnerabilityDetection, Asset, Manager, 
    VulnerabilityCatalog, User, VulnStatus
)
from schemas import (
    ManagerCreate, AssetCreate, CatalogCreate, DetectionCreate, 
    DetectionOut, ManagerOut, AssetOut, CatalogOut, 
    ManagerUpdate, AssetUpdate, CatalogUpdate, 
    UserCreate, UserOut, ChangePasswordRequest
)
from auth import create_access_token, get_current_user
from crypto import verify_password, hash_password

app = FastAPI(title="Evolution Vulnerability API")

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "API de Evolución de Vulnerabilidades activa"}

### JWT CONFIGURATION ###

@app.post(
    "/auth/login", 
    responses={400: {"description": "Email o contraseña incorrectos"}}
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(User).where(User.user_email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.user_password):
        raise HTTPException(status_code=400, detail="Email o contraseña incorrectos")
    
    access_token = create_access_token(data={"sub": user.user_email})
    return {"access_token": access_token, "token_type": "bearer"}

def validate_strong_password(password: str) -> None:
    errors = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errors.append("al menos una letra minúscula")
    if not re.search(r"\d", password):
        errors.append("al menos un número")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        errors.append("al menos un carácter especial")
    
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )

@app.post(
    "/auth/change-password", 
    responses={400: {"description": "Error en la validación de contraseñas"}}
)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not verify_password(request.old_password, current_user.user_password):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")
    if request.old_password == request.new_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser diferente")
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    
    validate_strong_password(request.new_password)
    
    current_user.user_password = hash_password(request.new_password)
    current_user.user_status = True
    db.add(current_user)
    await db.commit()
    return {"message": "Contraseña actualizada exitosamente"}

### CRUD - Create ###

@app.post(
    "/detections/", 
    response_model=DetectionOut,
    responses={404: {"description": "El Asset no existe"}}
)
async def create_detection(
    data: DetectionCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    asset_check = await db.get(Asset, data.asset_id)
    if not asset_check:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == data.asset_id,
        VulnerabilityDetection.cve_id == data.cve_id
    ).order_by(VulnerabilityDetection.timestamp.asc()).limit(1)
    
    result = await db.execute(query)
    first_record = result.scalars().first()

    fecha_primera_vez = first_record.first_seen_at if first_record else datetime.now(timezone.utc)

    nueva_deteccion = VulnerabilityDetection(
        asset_id=data.asset_id,
        cve_id=data.cve_id,
        package_name=data.package_name,
        package_version=data.package_version,
        first_seen_at=fecha_primera_vez,
        status=VulnStatus.Detected
    )
    
    db.add(nueva_deteccion)
    await db.commit()
    await db.refresh(nueva_deteccion)
    return nueva_deteccion

@app.post("/users/", response_model=UserOut)
async def create_user(
    user: UserCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    hashed_password = hash_password(user.user_password)
    db_user = User(
        user_email=user.user_email,
        user_name=user.user_name,
        user_rol=user.user_rol,
        user_password=hashed_password,
        user_status=True,
        user_delete=False
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

@app.post("/managers/", response_model=ManagerOut)
async def create_manager(
    data: ManagerCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_manager = Manager(**data.model_dump())
    db.add(nuevo_manager)
    await db.commit()
    await db.refresh(nuevo_manager)
    return nuevo_manager

@app.post("/assets/", response_model=AssetOut)
async def create_asset(
    data: AssetCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_asset = Asset(**data.model_dump())
    db.add(nuevo_asset)
    await db.commit()
    await db.refresh(nuevo_asset)
    return nuevo_asset

@app.post("/catalog/")
async def create_catalog(
    data: CatalogCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_cve = VulnerabilityCatalog(**data.model_dump())
    db.add(nuevo_cve)
    await db.commit()
    return {"message": "CVE guardado exitosamente"}

### CRUD - Read ###

@app.get("/managers/", response_model=List[ManagerOut])
async def get_managers(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Manager))
    return result.scalars().all()

@app.get("/assets/", response_model=List[AssetOut])
async def get_assets(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Asset))
    return result.scalars().all()

@app.get("/catalog/", response_model=List[CatalogOut])
async def get_catalog(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(VulnerabilityCatalog))
    return result.scalars().all()

@app.get("/detections/", response_model=List[DetectionOut])
async def get_all_detections(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(
        select(VulnerabilityDetection).order_by(VulnerabilityDetection.timestamp.desc())
    )
    return result.scalars().all()

@app.get(
    "/detections/{asset_id}", 
    response_model=List[DetectionOut],
    responses={404: {"description": "No se encontraron detecciones"}}
)
async def get_asset_history(
    asset_id: str, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == asset_id
    ).order_by(VulnerabilityDetection.timestamp.desc()) 
    result = await db.execute(query)
    history = result.scalars().all() 
    if not history:
        raise HTTPException(status_code=404, detail="No se encontraron detecciones para este asset")     
    return history

### CRUD - Update ###

@app.patch(
    "/managers/{manager_id}", 
    response_model=ManagerOut,
    responses={404: {"description": "Manager no encontrado"}}
)
async def update_manager(
    manager_id: UUID, 
    data: ManagerUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Manager).where(Manager.id == manager_id))
    db_manager = result.scalar_one_or_none()
    if not db_manager:
        raise HTTPException(status_code=404, detail="Manager no encontrado")  
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_manager, key, value)
    await db.commit()
    await db.refresh(db_manager)
    return db_manager

@app.patch(
    "/assets/{asset_id}", 
    response_model=AssetOut,
    responses={404: {"description": "Asset no encontrado"}}
)
async def update_asset(
    asset_id: UUID, 
    data: AssetUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    db_asset = result.scalar_one_or_none()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_asset, key, value)
    await db.commit()
    await db.refresh(db_asset)
    return db_asset

@app.patch(
    "/catalog/{cve_id}", 
    response_model=CatalogOut,
    responses={404: {"description": "CVE no encontrado"}}
)
async def update_catalog(
    cve_id: str, 
    data: CatalogUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(VulnerabilityCatalog).where(VulnerabilityCatalog.cve_id == cve_id))
    db_cve = result.scalar_one_or_none()
    if not db_cve:
        raise HTTPException(status_code=404, detail="CVE no encontrado")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_cve, key, value)
    await db.commit()
    await db.refresh(db_cve)
    return db_cve