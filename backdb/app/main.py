# main.py

import os
import re
import jwt
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import VulnerabilityDetection, Asset, Manager, VulnerabilityCatalog, User, VulnStatus, SeverityLevel
from schemas import ManagerCreate, AssetCreate, CatalogCreate, DetectionCreate, DetectionOut, ManagerOut, AssetOut, CatalogOut, ManagerUpdate, AssetUpdate, CatalogUpdate, UserCreate, UserOut, ChangePasswordRequest
from uuid import UUID
from typing import List, Annotated, Optional
# (Se eliminó la segunda importación repetida de datetime aquí)
from auth import create_access_token, get_current_user
from crypto import verify_password, hash_password
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Evolution Vulnerability API")

@app.get("/")
def read_root():
    return {"message": "API de Evolución de Vulnerabilidades activa"}

# Configuración de CORS para tu frontend en Vue.js
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

###  JWT CONFIGURATION ###

@app.post("/auth/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db)
):
    # 1. Buscar por user_email
    result = await db.execute(select(User).where(User.user_email == form_data.username))
    user = result.scalar_one_or_none()

    # 2. Validar contra user_password
    if not user or not verify_password(form_data.password, user.user_password):
        raise HTTPException(status_code=400, detail="Email o contraseña incorrectos")
    
    # 3. El token lleva el email en el campo 'sub'
    access_token = create_access_token(data={"sub": user.user_email})
    return {"access_token": access_token, "token_type": "bearer"}



def validate_strong_password(password: str) -> None:
    """Valida que la contraseña sea robusta. Lanza HTTPException si no cumple."""
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
        errors.append("al menos un carácter especial (!@#$%^&*...)")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )

@app.post("/auth/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    # 1. Comparar con user_password
    if not verify_password(request.old_password, current_user.user_password):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")
    if request.old_password == request.new_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser diferente")
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    # Validamos robustez (tu función actual)
    validate_strong_password(request.new_password)
    # 2. Actualizamos campos según tu tabla
    current_user.user_password = hash_password(request.new_password)
    current_user.user_status = True  # Activamos al usuario al cambiar clave
    db.add(current_user)
    await db.commit() # ¡Await obligatorio!
    return {"message": "Contraseña actualizada exitosamente"}
##########################
###  API CONECTION ###
### CRUD ###
#Create
# 1. Ingresar datos (Detección)
@app.post("/detections/", response_model=DetectionOut)
async def create_detection(data: DetectionCreate, db: AsyncSession = Depends(get_db)):
    # 1. Buscar si ya existe alguna detección previa para este asset y CVE
    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == data.asset_id,
        VulnerabilityDetection.cve_id == data.cve_id
    ).order_by(VulnerabilityDetection.timestamp.asc()).limit(1)
    
    asset_check = await db.get(Asset, data.asset_id)
    if not asset_check:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    result = await db.execute(query)
    first_record = result.scalars().first()

    # 2. Determinar el first_seen_at
    if first_record:
        # Si ya existía, mantenemos la fecha original
        fecha_primera_vez = first_record.first_seen_at
    else:
        # Si es nuevo, la fecha de ahora es la primera vez
        fecha_primera_vez = datetime.now(timezone.utc)

    # 3. Crear el nuevo registro con la lógica de evolución
    nueva_deteccion = VulnerabilityDetection(
        asset_id=data.asset_id,
        cve_id=data.cve_id,
        package_name=data.package_name,
        package_version=data.package_version,
        first_seen_at=fecha_primera_vez,
        status=VulnStatus.Detected # El trigger lo ajustará si es Re-emerged
    )
    
    db.add(nueva_deteccion)
    await db.commit() # Agregado await
    await db.refresh(nueva_deteccion)
    return nueva_deteccion

@app.post("/users/", response_model=UserOut)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # 1. Encriptar la contraseña (CORREGIDO: Usamos hash_password de crypto)
    hashed_password = hash_password(user.user_password)
    
    # 2. Crear el objeto (CORREGIDO: Usamos User directamente)
    db_user = User(
        user_email=user.user_email,
        user_name=user.user_name,
        user_rol=user.user_rol,
        user_password=hashed_password,
        user_status=True,  # Por defecto activo
        user_delete=False  # Por defecto no eliminado
    )
    
    # 3. Guardar en la DB
    db.add(db_user)
    await db.commit() # Agregado await
    await db.refresh(db_user)
    return db_user

@app.post("/managers/")
async def create_manager(data: ManagerCreate, db: AsyncSession = Depends(get_db)):
    nuevo_manager = Manager(
        nombre=data.nombre, 
        api_url=data.api_url,
        api_key_vault_ref=data.api_key_vault_ref
    )
    db.add(nuevo_manager)
    await db.commit()
    await db.refresh(nuevo_manager)
    return nuevo_manager

@app.post("/assets/")
async def create_asset(data: AssetCreate, db: AsyncSession = Depends(get_db)):
    nuevo_asset = Asset(
        wazuh_agent_id=data.wazuh_agent_id,
        hostname=data.hostname,
        os_version=data.os_version,
        ip_address=data.ip_address,
        manager_id=data.manager_id
    )
    db.add(nuevo_asset)
    await db.commit()
    await db.refresh(nuevo_asset)
    return nuevo_asset

@app.post("/catalog/")
async def create_catalog(data: CatalogCreate, db: AsyncSession = Depends(get_db)):
    nuevo_cve = VulnerabilityCatalog(
        cve_id=data.cve_id,
        severity=data.severity,
        description=data.description,
        cvss_score=data.cvss_score
    )
    db.add(nuevo_cve)
    await db.commit() # Agregado await
    return {"message": "CVE guardado exitosamente"}
#Read
# GET - Todos los Managers (Administradores)
@app.get("/managers/", response_model=List[ManagerOut])
async def get_managers(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Manager))
    return result.scalars().all()
# GET - Todos los Assets (PCs)
@app.get("/assets/", response_model=List[AssetOut])
async def get_assets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset))
    return result.scalars().all()
# GET - Todo el Catálogo (CVEs)
@app.get("/catalog/", response_model=List[CatalogOut])
async def get_catalog(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(VulnerabilityCatalog))
    return result.scalars().all()
# GET - Todas las Detecciones (Historial de Evolución)
@app.get("/detections/", response_model=List[DetectionOut])
async def get_all_detections(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(VulnerabilityDetection).order_by(VulnerabilityDetection.timestamp.desc())
    )
    return result.scalars().all()
@app.get("/detections/{asset_id}", response_model=List[DetectionOut])
async def get_asset_history(asset_id: str, db: AsyncSession = Depends(get_db)):
    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == asset_id
    ).order_by(VulnerabilityDetection.timestamp.desc()) 
    result = await db.execute(query)
    history = result.scalars().all() 
    if not history:
        raise HTTPException(status_code=404, detail="No se encontraron detecciones para este asset")     
    return history
#Update
# UPDATE - Manager
@app.patch("/managers/{manager_id}", response_model=ManagerOut)
async def update_manager(manager_id: UUID, data: ManagerUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Manager).where(Manager.id == manager_id))
    db_manager = result.scalar_one_or_none()
    if not db_manager:
        raise HTTPException(status_code=404, detail="Manager no encontrado")  
    # Solo actualizamos los campos que vienen en el JSON
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_manager, key, value)
    await db.commit()
    await db.refresh(db_manager)
    return db_manager
# UPDATE - Asset (PC)
@app.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(asset_id: UUID, data: AssetUpdate, db: AsyncSession = Depends(get_db)):
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
# UPDATE - Catálogo (CVE)
@app.patch("/catalog/{cve_id}", response_model=CatalogOut)
async def update_catalog(cve_id: str, data: CatalogUpdate, db: AsyncSession = Depends(get_db)):
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