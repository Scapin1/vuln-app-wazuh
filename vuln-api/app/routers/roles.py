# app/routers/roles.py
from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..db import get_db
from ..models import Rol, User
from ..schemas import RolCreate, RolOut, RolUpdate

router = APIRouter()


@router.post("/roles/", response_model=RolOut, tags=["Create"])
async def create_rol(
    data: RolCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rol).where(Rol.rol_name == data.rol_name))
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=400, detail="Ya existe un rol con ese nombre")

    nuevo_rol = Rol(**data.model_dump())
    db.add(nuevo_rol)
    await db.commit()
    await db.refresh(nuevo_rol)
    return nuevo_rol


@router.get("/roles/", response_model=List[RolOut], tags=["Read"])
async def get_roles(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Rol).order_by(Rol.rol_id.asc()))
    return result.scalars().all()


@router.get("/roles/{rol_id}", response_model=RolOut, tags=["Read"])
async def get_rol(
    rol_id: int,
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Rol).where(Rol.rol_id == rol_id))
    db_rol = result.scalar_one_or_none()

    if not db_rol:
        raise HTTPException(status_code=404, detail="Rol no encontrado")

    return db_rol


@router.patch("/roles/{rol_id}", response_model=RolOut, tags=["Update"])
async def update_rol(
    rol_id: int,
    data: RolUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rol).where(Rol.rol_id == rol_id))
    db_rol = result.scalar_one_or_none()

    if not db_rol:
        raise HTTPException(status_code=404, detail="Rol no encontrado")

    update_data = data.model_dump(exclude_unset=True)

    if "rol_name" in update_data and update_data["rol_name"] != db_rol.rol_name:
        dup_result = await db.execute(select(Rol).where(Rol.rol_name == update_data["rol_name"]))
        if dup_result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Ya existe un rol con ese nombre")

    for key, value in update_data.items():
        setattr(db_rol, key, value)

    await db.commit()
    await db.refresh(db_rol)
    return db_rol


@router.delete("/roles/{rol_id}", tags=["Delete"])
async def delete_rol(
    rol_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Rol).where(Rol.rol_id == rol_id))
    db_rol = result.scalar_one_or_none()

    if not db_rol:
        raise HTTPException(status_code=404, detail="Rol no encontrado")

    users_check = await db.execute(select(User).where(User.user_rol == rol_id))
    if users_check.scalars().first():
        raise HTTPException(
            status_code=400,
            detail="No se puede eliminar el rol porque tiene usuarios asignados"
        )

    await db.delete(db_rol)
    await db.commit()

    return {"message": "Rol eliminado correctamente"}
