# app/routers/user_assets.py
from typing import Annotated, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..db import get_db
from ..models import Asset, User, UserAsset
from ..schemas import AssetOut

router = APIRouter()


@router.post("/users/{user_id}/assets/{asset_id}", tags=["Assignments"])
async def assign_asset_to_user(
    user_id: int,
    asset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="El usuario no existe")

    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    result = await db.execute(
        select(UserAsset).where(UserAsset.user_id == user_id, UserAsset.asset_id == asset_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="El Asset ya está asignado al usuario")

    nueva_asignacion = UserAsset(user_id=user_id, asset_id=asset_id)
    db.add(nueva_asignacion)
    await db.commit()

    return {"message": "Asset asignado al usuario correctamente", "user_id": user_id, "asset_id": str(asset_id)}


@router.get("/users/{user_id}/assets", response_model=List[AssetOut], tags=["Read"])
async def get_user_assets(
    user_id: int,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="El usuario no existe")

    result = await db.execute(
        select(Asset)
        .join(UserAsset, Asset.asset_id == UserAsset.asset_id)
        .where(UserAsset.user_id == user_id)
        .order_by(Asset.hostname.asc())
    )
    return result.scalars().all()


@router.delete("/users/{user_id}/assets/{asset_id}", tags=["Assignments"])
async def unassign_asset_from_user(
    user_id: int,
    asset_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="El usuario no existe")

    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    result = await db.execute(
        select(UserAsset).where(UserAsset.user_id == user_id, UserAsset.asset_id == asset_id)
    )
    asignacion = result.scalar_one_or_none()
    if not asignacion:
        raise HTTPException(status_code=404, detail="La asignación no existe")

    await db.delete(asignacion)
    await db.commit()

    return {"message": "Asset desasignado del usuario correctamente"}
