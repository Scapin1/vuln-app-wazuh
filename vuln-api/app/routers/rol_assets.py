# app/routers/rol_assets.py
from typing import Annotated, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..db import get_db
from ..models import Asset, Rol, RolAsset, User
from ..schemas import AssetOut

router = APIRouter()


@router.post("/roles/{rol_id}/assets/{asset_id}", tags=["Assignments"])
async def assign_asset_to_rol(
    rol_id: int,
    asset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rol = await db.get(Rol, rol_id)
    if not rol:
        raise HTTPException(status_code=404, detail="El rol no existe")

    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    result = await db.execute(
        select(RolAsset).where(RolAsset.rol_id == rol_id, RolAsset.asset_id == asset_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="El Asset ya está asignado al rol")

    nueva_asignacion = RolAsset(rol_id=rol_id, asset_id=asset_id)
    db.add(nueva_asignacion)
    await db.commit()

    return {"message": "Asset asignado al rol correctamente", "rol_id": rol_id, "asset_id": str(asset_id)}


@router.get("/roles/{rol_id}/assets", response_model=List[AssetOut], tags=["Read"])
async def get_rol_assets(
    rol_id: int,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    rol = await db.get(Rol, rol_id)
    if not rol:
        raise HTTPException(status_code=404, detail="El rol no existe")

    result = await db.execute(
        select(Asset)
        .join(RolAsset, Asset.asset_id == RolAsset.asset_id)
        .where(RolAsset.rol_id == rol_id)
        .order_by(Asset.hostname.asc())
    )
    return result.scalars().all()


@router.delete("/roles/{rol_id}/assets/{asset_id}", tags=["Assignments"])
async def unassign_asset_from_rol(
    rol_id: int,
    asset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    rol = await db.get(Rol, rol_id)
    if not rol:
        raise HTTPException(status_code=404, detail="El rol no existe")

    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    result = await db.execute(
        select(RolAsset).where(RolAsset.rol_id == rol_id, RolAsset.asset_id == asset_id)
    )
    asignacion = result.scalar_one_or_none()
    if not asignacion:
        raise HTTPException(status_code=404, detail="La asignación no existe")

    await db.delete(asignacion)
    await db.commit()

    return {"message": "Asset desasignado del rol correctamente"}
