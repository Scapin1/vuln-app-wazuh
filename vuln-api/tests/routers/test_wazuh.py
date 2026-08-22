# tests/routers/test_wazuh.py — cubre app/routers/wazuh.py
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import User, WazuhConnection

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
    if hasattr(obj, 'timestamp') and getattr(obj, 'timestamp', None) is None:
        obj.timestamp = datetime.now(timezone.utc)
    if hasattr(obj, 'cve_id') and getattr(obj, 'cve_id', None) is None:
        obj.cve_id = "CVE-2026-MOCK"

async def override_get_db():
    db = AsyncMock(add=MagicMock())

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalars.return_value.first.return_value = None
    mock_result.scalar_one_or_none.return_value = mock_user

    db.execute.return_value = mock_result
    db.refresh.side_effect = mock_refresh_side_effect
    yield db


@pytest.fixture(autouse=True)
def baseline_overrides():
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


def make_client(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_list_connections_success():
    """Cubre GET /wazuh-connections"""
    mock_db = AsyncMock(spec=AsyncSession)

    conn1 = WazuhConnection(id=1, name="Lab 1", indexer_url="http://u1", wazuh_user="u1", is_active=True)
    conn2 = WazuhConnection(id=2, name="Lab 2", indexer_url="http://u2", wazuh_user="u2", is_active=False)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [conn1, conn2]
    mock_db.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/wazuh-connections")

    assert response.status_code == 200
    assert len(response.json()) == 2
    assert response.json()[0]["name"] == "Lab 1"

@pytest.mark.asyncio
async def test_create_connection_success():
    """Cubre POST /wazuh-connections (Ruta exitosa)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    # Simular que no existe conexión previa con ese nombre
    mock_res_exist = MagicMock()
    mock_res_exist.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_res_exist

    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "name": "New Conn",
        "indexer_url": "http://wazuh.local",
        "wazuh_user": "admin",
        "wazuh_password": "password123"
    }

    with patch("app.routers.wazuh.check_connection", return_value=True), \
         patch("app.routers.wazuh.encrypt", return_value="encrypted_string"):

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections", json=payload)

    assert response.status_code == 201
    assert response.json()["message"] == "Conexión creada"
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_update_connection_success():
    """Cubre PUT /wazuh-connections/{conn_id}"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.commit = AsyncMock()

    # Mock de la conexión existente
    existing_conn = WazuhConnection(id=1, name="Old Name")
    mock_db.get.return_value = existing_conn

    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "name": "Updated Name",
        "indexer_url": "http://new.url",
        "wazuh_user": "new_user",
        "wazuh_password": "new_password"
    }

    with patch("app.routers.wazuh.encrypt", return_value="new_encrypted"):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.put("/wazuh-connections/1", json=payload)

    assert response.status_code == 200
    assert existing_conn.name == "Updated Name"
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_update_connection_404():
    """Cubre PUT /wazuh-connections/{conn_id} (No encontrado)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.put("/wazuh-connections/999", json={
            "name": "x", "indexer_url": "x", "wazuh_user": "x", "wazuh_password": "x"
        })
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_test_existing_connection_flow():
    """Cubre POST /wazuh-connections/{conn_id}/test"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.commit = AsyncMock()

    conn = WazuhConnection(id=1, wazuh_password="hash", indexer_url="url", wazuh_user="user")
    mock_db.get.return_value = conn

    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.routers.wazuh.decrypt", return_value="plain"), \
         patch("app.routers.wazuh.check_connection", return_value=True) as mock_check:
        mock_check.return_value = True

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections/1/test")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert conn.last_test_ok is True
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_delete_connection_success():
    """Cubre DELETE /wazuh-connections/{conn_id} (Ruta exitosa)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    conn = WazuhConnection(id=1)
    mock_db.get.return_value = conn

    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.delete("/wazuh-connections/1")

    assert response.status_code == 200
    assert response.json()["message"] == "Conexión eliminada correctamente"
    assert mock_db.delete.called
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_create_connection_already_exists():
    """Cubre el error 400 cuando el nombre de la conexión ya existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = WazuhConnection(name="Lab")
    mock_db.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "name": "Lab",
            "indexer_url": "http://wazuh",
            "wazuh_user": "admin",
            "wazuh_password": "password"
        }
        response = await ac.post("/wazuh-connections", json=payload)

    assert response.status_code == 400
    assert "ya existe" in response.json()["detail"].lower()

@pytest.mark.asyncio
async def test_delete_connection_not_found():
    """Cubre el error 404 en el borrado de conexiones"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None  # No encontrada
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.delete("/wazuh-connections/999")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_connection_unreachable_wazuh():
    """POST /wazuh-connections devuelve 400 si check_connection falla"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_no_dup = MagicMock()
    res_no_dup.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_no_dup

    with patch("app.routers.wazuh.check_connection", return_value=False) as mock_check:
        async with make_client(mock_db) as ac:
            response = await ac.post("/wazuh-connections", json={
                "name": "unreachable",
                "indexer_url": "http://bad",
                "wazuh_user": "admin",
                "wazuh_password": "secret",
            })

    assert response.status_code == 400
    assert response.json()["detail"] == "No se pudo establecer conexión con Wazuh"
    mock_check.assert_called_once()


@pytest.mark.asyncio
async def test_test_existing_connection_not_found():
    """POST /wazuh-connections/{conn_id}/test devuelve 404 si no existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    async with make_client(mock_db) as ac:
        response = await ac.post("/wazuh-connections/999/test")

    assert response.status_code == 404
