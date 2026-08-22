# tests/routers/test_roles.py — cubre app/routers/roles.py
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import Rol, User

REAL_HASH = hash_password("old_password")

mock_user = User(
    user_name="Admin Test",
    user_password=REAL_HASH,
    user_status=True,
    user_delete=False
)
mock_user.user_id = 1


def mock_refresh_side_effect(obj):
    if hasattr(obj, 'user_id') and getattr(obj, 'user_id', None) is None:
        obj.user_id = 1
    elif hasattr(obj, 'id') and getattr(obj, 'id', None) is None:
        obj.id = uuid.uuid4()
    if hasattr(obj, 'rol_id') and getattr(obj, 'rol_id', None) is None:
        obj.rol_id = 1


@pytest.fixture(autouse=True)
def baseline_overrides():
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


def make_client(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_create_rol_success():
    """POST /roles/ crea un rol nuevo y retorna rol_id"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.refresh.side_effect = mock_refresh_side_effect

    res_no_dup = MagicMock()
    res_no_dup.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_no_dup

    async with make_client(mock_db) as ac:
        response = await ac.post("/roles/", json={
            "rol_name": "ANALYST",
            "rol_description": "Solo lectura de vulnerabilidades"
        })

    assert response.status_code == 200
    body = response.json()
    assert body["rol_name"] == "ANALYST"
    assert body["rol_description"] == "Solo lectura de vulnerabilidades"
    assert "rol_id" in body
    assert mock_db.add.called
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_create_rol_duplicate_name():
    """POST /roles/ devuelve 400 si el nombre ya existe"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_dup = MagicMock()
    res_dup.scalar_one_or_none.return_value = Rol(rol_id=1, rol_name="ADMIN")
    mock_db.execute.return_value = res_dup

    async with make_client(mock_db) as ac:
        response = await ac.post("/roles/", json={
            "rol_name": "ADMIN",
            "rol_description": "duplicado"
        })

    assert response.status_code == 400
    assert "ya existe" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_roles_list():
    """GET /roles/ retorna todos los roles ordenados"""
    mock_db = AsyncMock(spec=AsyncSession)

    roles = [
        SimpleNamespace(rol_id=1, rol_name="ADMIN", rol_description="Admin"),
        SimpleNamespace(rol_id=2, rol_name="ANALYST", rol_description="Lectura"),
    ]
    res_roles = MagicMock()
    res_roles.scalars.return_value.all.return_value = roles
    mock_db.execute.return_value = res_roles

    async with make_client(mock_db) as ac:
        response = await ac.get("/roles/")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0]["rol_name"] == "ADMIN"
    assert body[1]["rol_id"] == 2


@pytest.mark.asyncio
async def test_get_rol_by_id_found_and_not_found():
    """GET /roles/{rol_id}: 200 con el rol y 404 cuando no existe"""
    mock_db_ok = AsyncMock(spec=AsyncSession)

    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = SimpleNamespace(
        rol_id=1, rol_name="ADMIN", rol_description="Admin"
    )
    mock_db_ok.execute.return_value = res_found

    async with make_client(mock_db_ok) as ac:
        response = await ac.get("/roles/1")

    assert response.status_code == 200
    assert response.json()["rol_name"] == "ADMIN"

    mock_db_missing = AsyncMock(spec=AsyncSession)
    res_missing = MagicMock()
    res_missing.scalar_one_or_none.return_value = None
    mock_db_missing.execute.return_value = res_missing

    async with make_client(mock_db_missing) as ac:
        response = await ac.get("/roles/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Rol no encontrado"


@pytest.mark.asyncio
async def test_update_rol_success():
    """PATCH /roles/{rol_id} aplica cambios, commitea y refresca"""
    rol = Rol(rol_id=1, rol_name="OLD", rol_description="vieja desc")

    mock_db = AsyncMock(spec=AsyncSession)
    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = rol

    res_no_dup = MagicMock()
    res_no_dup.scalar_one_or_none.return_value = None

    mock_db.execute.side_effect = [res_found, res_no_dup]

    async with make_client(mock_db) as ac:
        response = await ac.patch("/roles/1", json={
            "rol_name": "NEW",
            "rol_description": "nueva desc"
        })

    assert response.status_code == 200
    assert response.json()["rol_name"] == "NEW"
    assert rol.rol_name == "NEW"
    assert rol.rol_description == "nueva desc"
    assert mock_db.commit.called
    assert mock_db.refresh.called


@pytest.mark.asyncio
async def test_update_rol_duplicate_name_rejected():
    """PATCH /roles/{rol_id} rechaza renombrar a un nombre que ya existe"""
    rol = Rol(rol_id=1, rol_name="OLD")

    mock_db = AsyncMock(spec=AsyncSession)

    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = rol

    res_dup = MagicMock()
    res_dup.scalar_one_or_none.return_value = Rol(rol_id=2, rol_name="TAKEN")

    mock_db.execute.side_effect = [res_found, res_dup]

    async with make_client(mock_db) as ac:
        response = await ac.patch("/roles/1", json={"rol_name": "TAKEN"})

    assert response.status_code == 400
    assert "ya existe" in response.json()["detail"].lower()
    assert not mock_db.commit.called


@pytest.mark.asyncio
async def test_update_rol_not_found():
    """PATCH /roles/{rol_id} devuelve 404 para rol inexistente"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_missing = MagicMock()
    res_missing.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_missing

    async with make_client(mock_db) as ac:
        response = await ac.patch("/roles/999", json={"rol_name": "X"})

    assert response.status_code == 404
    assert response.json()["detail"] == "Rol no encontrado"


@pytest.mark.asyncio
async def test_delete_rol_success():
    """DELETE /roles/{rol_id} elimina un rol sin usuarios asignados"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = Rol(rol_id=3, rol_name="UNUSED")

    res_no_users = MagicMock()
    res_no_users.scalars.return_value.first.return_value = None

    mock_db.execute.side_effect = [res_found, res_no_users]

    async with make_client(mock_db) as ac:
        response = await ac.delete("/roles/3")

    assert response.status_code == 200
    assert response.json()["message"] == "Rol eliminado correctamente"
    assert mock_db.delete.called
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_delete_rol_blocked_when_users_assigned():
    """DELETE /roles/{rol_id} devuelve 400 si hay usuarios con ese rol"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = Rol(rol_id=1, rol_name="ADMIN")

    res_users = MagicMock()
    res_users.scalars.return_value.first.return_value = SimpleNamespace(user_id=1)
    mock_db.execute.side_effect = [res_found, res_users]

    async with make_client(mock_db) as ac:
        response = await ac.delete("/roles/1")

    assert response.status_code == 400
    assert "usuarios" in response.json()["detail"]
    assert not mock_db.delete.called


@pytest.mark.asyncio
async def test_delete_rol_not_found():
    """DELETE /roles/{rol_id} devuelve 404 para rol inexistente"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_missing = MagicMock()
    res_missing.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_missing

    async with make_client(mock_db) as ac:
        response = await ac.delete("/roles/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Rol no encontrado"


@pytest.mark.asyncio
async def test_get_user_me_returns_role_name_via_relationship():
    """GET /users/me expone el nombre del rol a través de la relación role"""
    user_with_role = User(
        user_name="RolUser",
        user_password=REAL_HASH,
        user_status=True,
        user_delete=False,
    )
    user_with_role.user_id = 5
    user_with_role.role = Rol(rol_id=1, rol_name="ADMIN", rol_description="Admin")

    app.dependency_overrides[get_current_user] = lambda: user_with_role
    mock_db = AsyncMock(spec=AsyncSession)

    async with make_client(mock_db) as ac:
        response = await ac.get("/users/me")

    assert response.status_code == 200
    assert response.json()["rol"] == "ADMIN"
