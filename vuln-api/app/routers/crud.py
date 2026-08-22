# app/routers/crud.py
from datetime import datetime, timezone
from typing import Annotated, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from ..auth import get_current_user, hash_password
from ..db import get_db
from ..models import Asset, User, VulnerabilityCatalog, VulnerabilityDetection
from ..schemas import (
    AssetCreate,
    AssetOut,
    AssetUpdate,
    CatalogCreate,
    CatalogOut,
    CatalogUpdate,
    DetectionCreate,
    DetectionOut,
    UserCreate,
    VulnStatus,
)

router = APIRouter()

###  TIMESCALEDB funciones  ###

# ==========================================================
# 1. CREATE
# ==========================================================

@router.post("/users", tags=["Users"])
async def create_user(
    request: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(User).where(User.user_name == request.user_name))
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está ocupado.")

    new_user = User(
        user_name=request.user_name,
        user_password=hash_password(request.user_password),
        user_status=True,
    )
    db.add(new_user)
    await db.commit()
    return {"message": "Usuario creado"}


@router.delete("/users/{user_id}", tags=["Users"])
async def delete_user(
    user_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")

    result = await db.execute(select(User).where(User.user_id == user_id))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    await db.delete(db_user)
    await db.commit()
    return {"message": "Usuario eliminado correctamente"}


@router.post("/assets/", response_model=AssetOut, tags=["Create"])
async def create_asset(
    data: AssetCreate,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_asset = Asset(**data.model_dump())
    db.add(nuevo_asset)
    await db.commit()
    await db.refresh(nuevo_asset)
    return nuevo_asset

@router.post("/catalog/", tags=["Create"])
async def create_catalog(
    data: CatalogCreate,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_cve = VulnerabilityCatalog(**data.model_dump())
    db.add(nuevo_cve)
    await db.commit()
    return {"message": "CVE guardado exitosamente"}

@router.post("/detections/", response_model=DetectionOut, tags=["Create"])
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


@router.get("/assets/", response_model=List[AssetOut], tags=["Read"])
async def get_assets(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Asset))
    return result.scalars().all()

@router.get("/catalog/", response_model=List[CatalogOut], tags=["Read"])
async def get_catalog(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(VulnerabilityCatalog))
    return result.scalars().all()

@router.get("/detections/", response_model=List[DetectionOut], tags=["Read"])
async def get_all_detections(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(
        select(VulnerabilityDetection)
        .options(
            joinedload(VulnerabilityDetection.asset),
            joinedload(VulnerabilityDetection.catalog_entry)
        )
        .order_by(VulnerabilityDetection.timestamp.desc())
    )
    return result.scalars().all()

@router.get("/detections/{asset_id}", response_model=List[DetectionOut], tags=["Read"])
async def get_asset_history(
    asset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    query = (
        select(VulnerabilityDetection)
        .where(VulnerabilityDetection.asset_id == asset_id)
        .options(
            joinedload(VulnerabilityDetection.asset),
            joinedload(VulnerabilityDetection.catalog_entry)
        )
        .order_by(VulnerabilityDetection.timestamp.desc())
    )

    result = await db.execute(query)
    history = result.scalars().all()
    if not history:
        raise HTTPException(status_code=404, detail="No se encontraron detecciones")
    return history

# ==========================================================
# 3. UPDATE
# ==========================================================


@router.patch("/assets/{asset_id}", response_model=AssetOut, tags=["Update"])
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

@router.patch("/catalog/{cve_id}", response_model=CatalogOut, tags=["Update"])
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
