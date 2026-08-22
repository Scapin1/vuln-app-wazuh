# tests/routers/test_user_assets.py — cubre app/routers/user_assets.py
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import Asset, User

REAL_HASH = hash_password("old_password")

mock_user = User(
    user_name="Admin Test",
    user_password=REAL_HASH,
    user_status=True,
    user_delete=False
)
mock_user.user_id = 1


def make_asset(hostname="host-1", connection_id=1):
    asset = Asset(wazuh_agent_id=str(uuid4())[:8], hostname=hostname, os_version="Ubuntu", wazuh_connection_id=connection_id)
    asset.asset_id = uuid4()
    return asset


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
async def test_assign_asset_to_user_success():
    """POST /users/{id}/assets/{id} crea la asignación"""
    mock_db = AsyncMock(spec=AsyncSession)

    user = User(user_name="U", user_delete=False)
    user.user_id = 7
    asset = make_asset()

    mock_db.get.side_effect = [user, asset]

    res_no_dup = MagicMock()
    res_no_dup.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_no_dup

    async with make_client(mock_db) as ac:
        response = await ac.post(f"/users/{user.user_id}/assets/{asset.asset_id}")

    assert response.status_code == 200
    assert response.json()["message"] == "Asset asignado al usuario correctamente"
    assert mock_db.add.called
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_assign_asset_duplicate_rejected():
    """POST /users/{id}/assets/{id} devuelve 400 si ya existe la asignación"""
    mock_db = AsyncMock(spec=AsyncSession)

    user = User(user_name="U", user_delete=False)
    user.user_id = 7
    asset = make_asset()

    mock_db.get.side_effect = [user, asset]

    res_dup = MagicMock()
    res_dup.scalar_one_or_none.return_value = object()
    mock_db.execute.return_value = res_dup

    async with make_client(mock_db) as ac:
        response = await ac.post(f"/users/{user.user_id}/assets/{asset.asset_id}")

    assert response.status_code == 400
    assert "ya está asignado" in response.json()["detail"]
    assert not mock_db.add.called


@pytest.mark.asyncio
async def test_assign_asset_missing_user_or_asset():
    """POST /users/{id}/assets/{id} devuelve 404 si usuario o asset no existen"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    random_id = uuid4()
    async with make_client(mock_db) as ac:
        response = await ac.post(f"/users/999/assets/{random_id}")

    assert response.status_code == 404
    assert response.json()["detail"] == "El usuario no existe"

    existing_user = User(user_name="X", user_delete=False)
    existing_user.user_id = 1
    mock_db.get.side_effect = [existing_user, None]

    async with make_client(mock_db) as ac:
        response = await ac.post("/users/1/assets/" + str(random_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "El Asset no existe"


@pytest.mark.asyncio
async def test_get_user_assets_returns_assets():
    """GET /users/{id}/assets retorna los assets asignados"""
    mock_db = AsyncMock(spec=AsyncSession)

    user = User(user_name="U", user_delete=False)
    user.user_id = 7
    assets = [make_asset("alpha"), make_asset("beta")]

    mock_db.get.return_value = user

    res_assets = MagicMock()
    res_assets.scalars.return_value.all.return_value = assets
    mock_db.execute.return_value = res_assets

    async with make_client(mock_db) as ac:
        response = await ac.get(f"/users/{user.user_id}/assets")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0]["hostname"] == "alpha"
    assert body[1]["hostname"] == "beta"


@pytest.mark.asyncio
async def test_get_user_assets_user_not_found():
    """GET /users/{id}/assets devuelve 404 si el usuario no existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    async with make_client(mock_db) as ac:
        response = await ac.get("/users/999/assets")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_unassign_asset_success_and_not_linked():
    """DELETE /users/{id}/assets/{id}: elimina asignación y 404 si no existe"""
    mock_db_ok = AsyncMock(spec=AsyncSession)
    mock_db_ok.delete = AsyncMock()
    mock_db_ok.commit = AsyncMock()

    user = User(user_name="U", user_delete=False)
    user.user_id = 7
    asset = make_asset()

    link = object()
    mock_db_ok.get.side_effect = [user, asset]

    res_link = MagicMock()
    res_link.scalar_one_or_none.return_value = link
    mock_db_ok.execute.return_value = res_link

    async with make_client(mock_db_ok) as ac:
        response = await ac.delete(f"/users/{user.user_id}/assets/{asset.asset_id}")

    assert response.status_code == 200
    assert response.json()["message"] == "Asset desasignado del usuario correctamente"
    assert mock_db_ok.delete.called
    assert mock_db_ok.commit.called

    mock_db_missing = AsyncMock(spec=AsyncSession)
    user2 = User(user_name="U", user_delete=False)
    user2.user_id = 7
    mock_db_missing.get.side_effect = [user2, make_asset()]

    res_no_link = MagicMock()
    res_no_link.scalar_one_or_none.return_value = None
    mock_db_missing.execute.return_value = res_no_link

    async with make_client(mock_db_missing) as ac:
        response = await ac.delete(f"/users/7/assets/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == "La asignación no existe"


@pytest.mark.asyncio
async def test_unassign_asset_missing_asset_404():
    """DELETE /users/{id}/assets/{id} devuelve 404 si el asset no existe"""
    mock_db = AsyncMock(spec=AsyncSession)

    user = User(user_name="U", user_delete=False)
    user.user_id = 7
    mock_db.get.side_effect = [user, None]

    async with make_client(mock_db) as ac:
        response = await ac.delete(f"/users/{user.user_id}/assets/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == "El Asset no existe"


@pytest.mark.asyncio
async def test_unassign_asset_missing_user_404():
    """DELETE /users/{id}/assets/{id} devuelve 404 si el usuario no existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    async with make_client(mock_db) as ac:
        response = await ac.delete(f"/users/999/assets/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == "El usuario no existe"
