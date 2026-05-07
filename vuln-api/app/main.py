# app/main.py
import re
import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import set_key, find_dotenv
from httpx import request
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from uuid import UUID
from typing import List, Annotated, Optional
from pydantic import BaseModel
from sqlalchemy.sql import func
from sqlalchemy import select, insert, update, delete
from .db import Base, engine, get_db
from .models import User, WazuhVulnerability, WazuhConnection
from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .models import User, WazuhVulnerability, WazuhConnection, VulnerabilityHistory
from .wazuh_client import fetch_all_vulns, test_connection
from .crypto import encrypt, decrypt
from .models import Manager, Asset, VulnerabilityCatalog, VulnerabilityDetection
from .schemas import (
    UserCreate, UserOut, ManagerCreate, ManagerOut, AssetCreate, AssetOut, 
    CatalogCreate, CatalogOut, DetectionCreate, DetectionOut, 
    VulnStatus, ManagerUpdate, AssetUpdate, CatalogUpdate,
) 
from sqlalchemy.ext.asyncio import AsyncSession


CONNECTION_NOT_FOUND = "Conexión no encontrada"


class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str


class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    is_active: bool

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str 

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

@app.get("/users/me", tags=["Users"])
async def get_user_me(current_user: Annotated[User, Depends(get_current_user)]):
    return {
        "id": current_user.user_id,
        "username": current_user.user_name,
        "email": current_user.user_email,
        "is_active": current_user.user_status,
        "rol": current_user.user_rol
    }

@app.get("/users", tags=["Users"])
async def list_users(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [{"id": u.user_id, "username": u.user_name} for u in users]

# ==========================================================
# WAZUH CONNECTIONS
# ==========================================================

@app.get("/wazuh-connections", tags=["Wazuh"])
async def list_connections(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(WazuhConnection))
    conns = result.scalars().all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "is_active": c.is_active,
            "tested": c.tested,
            "last_tested_at": c.last_tested_at,
            "last_test_ok": c.last_test_ok,
        }
        for c in conns
    ]

@app.post("/wazuh-connections", status_code=201, tags=["Wazuh"])
async def create_connection(
    request: WazuhConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Verificar nombre único
    query = select(WazuhConnection).where(WazuhConnection.name == request.name)
    existing = (await db.execute(query)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Ya existe una conexión con ese nombre")

    # test_connection debe ser async (usando httpx)
    ok = await test_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
    if not ok:
        raise HTTPException(status_code=400, detail="No se pudo establecer conexión con Wazuh")

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        tested=True,
        last_tested_at=func.now(),
        last_test_ok=True,
    )
    db.add(conn)
    await db.commit()
    await db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}

@app.put("/wazuh-connections/{conn_id}", tags=["Wazuh"])
async def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    
    await db.commit()
    return {"message": "Conexión actualizada"}

@app.post("/wazuh-connections/{conn_id}/test", tags=["Wazuh"])
async def test_existing_wazuh_connection(
    conn_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    ok = await test_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    await db.commit()
    return {"ok": ok, "message": "Conexión exitosa" if ok else "Fallo al conectar"}

@app.delete(
    "/wazuh-connections/{conn_id}",
    responses={
        404: {
            "description": "Conexión no encontrada",
            "content": {
                "application/json": {
                    "example": {"detail": "Conexión no encontrada"}
                }
            },
        }
    },
    tags=["Wazuh"]
)
async def delete_connection(
    conn_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Usamos db.get que es la forma más rápida y limpia en async
    conn = await db.get(WazuhConnection, conn_id)
    
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    
    await db.delete(conn)
    await db.commit()
    
    return {"message": "Conexión eliminada correctamente"}

# ==========================================================
# VULNERABILITIES & SYNC
# ==========================================================

@app.post("/wazuh-connections/{conn_id}/sync", tags=["Sync"])
async def sync_connection(
    conn_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    # fetch_all_vulns DEBE ser async (usando httpx)
    raw_vulns = await fetch_all_vulns(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    count = await process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
    await db.commit()

    return {"synced": count, "connection": conn.name}

async def process_wazuh_vulnerabilities(db: AsyncSession, conn_id: int, raw_vulns: list) -> int:
    count = 0
    seen_vuln_ids = set()

    # Carga masiva de vulnerabilidades activas para evitar N selects
    result = await db.execute(
        select(WazuhVulnerability).where(WazuhVulnerability.connection_id == conn_id, WazuhVulnerability.status == "ACTIVE")
    )
    active_vuln_dict = {v.id: v for v in result.scalars().all()}

    for v in raw_vulns:
        agent = v.get("agent", {})
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        if not vuln.get("id"): continue

        # Buscar si ya existe (Async)
        query = select(WazuhVulnerability).filter_by(
            connection_id=conn_id,
            agent_id=agent.get("id"),
            package_name=pkg.get("name"),
            package_version=pkg.get("version"),
            cve_id=vuln.get("id"),
        )
        existing_res = await db.execute(query)
        existing = existing_res.scalar_one_or_none()

        if existing:
            seen_vuln_ids.add(existing.id)
            await _handle_existing_vuln_async(db, existing, vuln)
        else:
            new_vuln = await _create_new_vuln_async(db, conn_id, agent, pkg, vuln)
            seen_vuln_ids.add(new_vuln.id)

        count += 1

    await _resolve_missing_vulns_async(db, active_vuln_dict, seen_vuln_ids)
    return count

async def _handle_existing_vuln_async(db: AsyncSession, existing: WazuhVulnerability, vuln: dict):
    if existing.status == "RESOLVED":
        existing.status = "ACTIVE"
        db.add(VulnerabilityHistory(vulnerability_id=existing.id, action="REOPENED"))

    if existing.severity != vuln.get("severity"):
        db.add(VulnerabilityHistory(vulnerability_id=existing.id, action="SEVERITY_CHANGED"))
        existing.severity = vuln.get("severity")

    existing.score_base = (vuln.get("score") or {}).get("base")
    existing.last_seen = func.now()

async def _create_new_vuln_async(db: AsyncSession, conn_id: int, agent: dict, pkg: dict, vuln: dict):
    new_vuln = WazuhVulnerability(
        connection_id=conn_id,
        status="ACTIVE",
        agent_id=agent.get("id"),
        agent_name=agent.get("name"),
        package_name=pkg.get("name"),
        package_version=pkg.get("version"),
        cve_id=vuln.get("id"),
        severity=vuln.get("severity"),
        score_base=(vuln.get("score") or {}).get("base"),
    )
    db.add(new_vuln)
    await db.flush() # Flush para obtener el ID antes de insertar el historial
    db.add(VulnerabilityHistory(vulnerability_id=new_vuln.id, action="DETECTED"))
    return new_vuln

async def _resolve_missing_vulns_async(db: AsyncSession, active_dict: dict, seen_ids: set):
    for v_id, db_vuln in active_dict.items():
        if v_id not in seen_ids:
            db_vuln.status = "RESOLVED"
            db.add(VulnerabilityHistory(vulnerability_id=v_id, action="RESOLVED"))

@app.get("/vulns", tags=["Read"])
async def list_vulns(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: Optional[int] = 100,
    connection_id: Optional[int] = None,
):
    query = select(WazuhVulnerability)
    if connection_id:
        query = query.where(WazuhVulnerability.connection_id == connection_id)
    
    query = query.limit(limit).order_by(WazuhVulnerability.last_seen.desc())
    result = await db.execute(query)
    vulns = result.scalars().all()

    # Formateo de respuesta (usando lazy loading o selectinload si es necesario)
    return vulns

@app.post("/vulns/sync-all", tags=["Sync"])
async def sync_all_connections(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    # Buscamos todas las conexiones activas
    query = select(WazuhConnection).where(WazuhConnection.is_active == True)
    result = await db.execute(query)
    conns = result.scalars().all()
    
    results = []

    for conn in conns:
        try:
            # IMPORTANTE: fetch_all_vulns debe ser una función 'async def' 
            # que use httpx.AsyncClient() internamente.
            raw_vulns = await fetch_all_vulns(
                conn.indexer_url,
                conn.wazuh_user,
                decrypt(conn.wazuh_password),
            )

            # Llamamos a la lógica de procesamiento que ya definimos como async
            count = await process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
            
            # Commit parcial por cada conexión exitosa
            await db.commit()

            results.append({
                "connection": conn.name, 
                "synced": count, 
                "ok": True
            })
            
        except Exception as e:
            # Si una falla, hacemos rollback de esa conexión específica y seguimos con la otra
            await db.rollback()
            results.append({
                "connection": conn.name, 
                "ok": False, 
                "error": str(e)
            })

    return results

###  TIMESCALEDB funciones  ###

# ==========================================================
# 1. CREATE
# ==========================================================

@app.post("/users", tags=["Users"])
async def create_user(
    request: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(User).where(User.user_email == request.user_email))
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(status_code=400, detail="El email/usuario ya está ocupado.")

    new_user = User(
        user_name=request.user_name, 
        user_email=request.user_email,
        user_password=hash_password(request.user_password),
        user_status=True,
    )
    db.add(new_user)
    await db.commit()
    return {"message": "Usuario creado"}

@app.post("/managers/", response_model=ManagerOut, tags=["Create"])
async def create_manager(
    data: ManagerCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_manager = Manager(**data.model_dump())
    db.add(nuevo_manager)
    await db.commit()
    await db.refresh(nuevo_manager)
    return nuevo_manager

@app.post("/assets/", response_model=AssetOut, tags=["Create"])
async def create_asset(
    data: AssetCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_asset = Asset(**data.model_dump())
    db.add(nuevo_asset)
    await db.commit()
    await db.refresh(nuevo_asset)
    return nuevo_asset

@app.post("/catalog/", tags=["Create"])
async def create_catalog(
    data: CatalogCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_cve = VulnerabilityCatalog(**data.model_dump())
    db.add(nuevo_cve)
    await db.commit()
    return {"message": "CVE guardado exitosamente"}

@app.post("/detections/", response_model=DetectionOut, tags=["Create"])
async def create_detection(
    data: DetectionCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    # Verificación de existencia del Asset
    asset_check = await db.get(Asset, data.asset_id)
    if not asset_check:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    # Lógica de primera detección en TimescaleDB
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
    return nueva_deteccion

# ==========================================================
# 2. READ
# ==========================================================

@app.get("/managers/", response_model=List[ManagerOut], tags=["Read"])
async def get_managers(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Manager))
    return result.scalars().all()

@app.get("/assets/", response_model=List[AssetOut], tags=["Read"])
async def get_assets(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Asset))
    return result.scalars().all()

@app.get("/catalog/", response_model=List[CatalogOut], tags=["Read"])
async def get_catalog(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(VulnerabilityCatalog))
    return result.scalars().all()

@app.get("/detections/", response_model=List[DetectionOut], tags=["Read"])
async def get_all_detections(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(
        select(VulnerabilityDetection).order_by(VulnerabilityDetection.timestamp.desc())
    )
    return result.scalars().all()

@app.get("/detections/{asset_id}", response_model=List[DetectionOut], tags=["Read"])
async def get_asset_history(
    asset_id: UUID, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == asset_id
    ).order_by(VulnerabilityDetection.timestamp.desc()) 
    
    result = await db.execute(query)
    history = result.scalars().all() 
    if not history:
        raise HTTPException(status_code=404, detail="No se encontraron detecciones")     
    return history

# ==========================================================
# 3. UPDATE
# ==========================================================

@app.patch("/managers/{manager_id}", response_model=ManagerOut, tags=["Update"])
async def update_manager(
    manager_id: UUID, 
    data: ManagerUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Manager).where(Manager.manager_id == manager_id))
    db_manager = result.scalar_one_or_none()
    
    if not db_manager:
        raise HTTPException(status_code=404, detail="Manager no encontrado")  
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_manager, key, value)
        
    await db.commit()
    await db.refresh(db_manager)
    return db_manager

@app.patch("/assets/{asset_id}", response_model=AssetOut, tags=["Update"])
async def update_asset(
    asset_id: UUID, 
    data: AssetUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    db_asset = result.scalar_one_or_none()
    
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_asset, key, value)
        
    await db.commit()
    await db.refresh(db_asset)
    return db_asset

@app.patch("/catalog/{cve_id}", response_model=CatalogOut, tags=["Update"])
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