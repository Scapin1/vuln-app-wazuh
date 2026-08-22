# app/routers/wazuh.py
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from ..auth import get_current_user
from ..crypto import decrypt, encrypt
from ..db import get_db
from ..models import User, WazuhConnection
from ..wazuh_client import check_connection

router = APIRouter()


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

# ==========================================================
# WAZUH CONNECTIONS
# ==========================================================

@router.get("/wazuh-connections", tags=["Wazuh"])
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

@router.post("/wazuh-connections", status_code=201, tags=["Wazuh"])
async def create_connection(
    request: WazuhConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    query = select(WazuhConnection).where(WazuhConnection.name == request.name)
    existing = (await db.execute(query)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Ya existe una conexión con ese nombre")

    ok = await check_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
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

@router.put("/wazuh-connections/{conn_id}", tags=["Wazuh"])
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

@router.post("/wazuh-connections/{conn_id}/test", tags=["Wazuh"])
async def test_existing_wazuh_connection(
    conn_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    ok = await check_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    await db.commit()
    return {"ok": ok, "message": "Conexión exitosa" if ok else "Fallo al conectar"}

@router.delete(
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
    conn = await db.get(WazuhConnection, conn_id)

    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    await db.delete(conn)
    await db.commit()

    return {"message": "Conexión eliminada correctamente"}
