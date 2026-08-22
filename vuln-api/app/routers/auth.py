# app/routers/auth.py
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from ..db import get_db
from ..models import User
from ..service.auth_service import validate_strong_password

router = APIRouter()


@router.post(
    "/auth/login",
    responses={400: {"description": "Usuario o contraseña incorrectos"}}
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(User).where(User.user_name == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.user_password):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")

    access_token = create_access_token(data={"sub": user.user_name})
    return {"access_token": access_token, "token_type": "bearer"}


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

@router.post(
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

@router.get("/users/me", tags=["Users"])
async def get_user_me(current_user: Annotated[User, Depends(get_current_user)]):
    return {
        "id": current_user.user_id,
        "username": current_user.user_name,
        "is_active": current_user.user_status,
        "rol": current_user.role.rol_name if current_user.role else None
    }

@router.get("/users", tags=["Users"])
async def list_users(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [{"id": u.user_id, "username": u.user_name} for u in users]
