# auth.py
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from database import get_db
from models import User
from crypto import verify_password

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

load_dotenv()

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def authenticate_user(db: AsyncSession, email: str, password: str):
    # Buscamos al usuario por su email
    result = await db.execute(select(User).where(User.user_email == email))
    user = result.scalar_one_or_none()

    if not user:
        return None
    
    # CAMBIO AQUÍ: Usamos 'user_password' para coincidir con tu modelo
    if not verify_password(password, user.user_password):
        return None
    
    # CAMBIO AQUÍ: Usamos 'user_delete' (True significa que está borrado)
    if user.user_delete:
        return None
        
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    
    # Mapeo corregido: buscamos por 'user_email'
    result = await db.execute(select(User).where(User.user_email == email))
    user = result.scalar_one_or_none()
    
    if user is None or user.user_delete:
        raise credentials_exception
    return user
