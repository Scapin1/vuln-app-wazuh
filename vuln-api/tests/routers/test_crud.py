# tests/routers/test_crud.py — cubre app/routers/crud.py
import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import Asset, User, VulnerabilityCatalog, VulnStatus

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
async def test_crud_and_reads():
    app.dependency_overrides[get_db] = override_get_db

    user_pass_val = os.getenv("TEST_CREATE_USER_PASS", "SafeUserPass_2026!")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        await ac.post("/users/", json={
            "user_name": "U",
            "user_rol": "r",
            "user_password": user_pass_val
        })

        for path in ["/assets/", "/catalog/", "/detections/"]:
            res = await ac.get(path)
            assert res.status_code == 200


@pytest.mark.asyncio
async def test_extra_coverage_posts():
    app.dependency_overrides[get_db] = override_get_db
    safe_pass = os.getenv("TEST_POST_USER_PASS", "Project_Pass_Safe_2026!")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        await ac.post("/catalog/", json={
            "cve_id": "C-2",
            "severity": "H",
            "description": "D",
            "cvss_score": 5.0
        })
        await ac.post("/users/", json={
            "user_name": "U",
            "user_rol": "r",
            "user_password": safe_pass
        })


@pytest.mark.asyncio
async def test_update_catalog_success_path():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_c = VulnerabilityCatalog(cve_id="CVE-2026", severity="Medium", description="D", cvss_score=5.0)

    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = mock_c
    mock_db.execute.return_value = res_mock
    mock_db.refresh.side_effect = mock_refresh_side_effect
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.patch("/catalog/CVE-2026", json={"severity": "High"})
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_update_catalog_success_final():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_c = VulnerabilityCatalog(cve_id="CVE-2026", severity="Low", description="D", cvss_score=1.0)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_c
    mock_db.execute.return_value = mock_result
    mock_db.refresh.side_effect = mock_refresh_side_effect
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.patch("/catalog/CVE-2026", json={"severity": "High"})
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_update_asset_not_found_trigger():
    mock_db = AsyncMock()
    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_mock
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.patch(f"/assets/{uuid.uuid4()}", json={"hostname": "X"})
    assert res.status_code == 404

@pytest.mark.asyncio
async def test_create_user_success():
    """Cubre la creación exitosa de un usuario (POST /users)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_res
    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "user_name": "NewUserTest",
        "user_password": "Password1!",
        "user_rol": "admin"
    }


    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/users", json=payload)

    assert response.status_code == 200, f"Fallo de validación: {response.json()}"
    assert mock_db.add.called

@pytest.mark.asyncio
async def test_create_asset():
    """Cubre la creación exitosa de un asset con el UUID corregido (POST /assets)"""
    import uuid
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.refresh.side_effect = lambda x: setattr(x, 'asset_id', uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "wazuh_agent_id": "100",
        "hostname": "test-server",
        "os_version": "Debian 11",
        "wazuh_connection_id": 1,
        "ip_address": "192.168.1.10"
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/assets/", json=payload)

    assert response.status_code == 200, f"Fallo de validación: {response.json()}"
    assert "asset_id" in response.json()
    assert response.json()["hostname"] == "test-server"

@pytest.mark.asyncio
async def test_validation_errors_coverage():
    """Cubre las ramas de error 422 (Unprocessable Entity) para subir coverage en validaciones"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res_user = await ac.post("/users", json={"bad_field": "error"})

    assert res_user.status_code == 422


@pytest.mark.asyncio
async def test_create_user_duplicate_email():
    """POST /users con email existente devuelve 400"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_existing = MagicMock()
    res_existing.scalar_one_or_none.return_value = User(user_name="ocupado")
    mock_db.execute.return_value = res_existing

    async with make_client(mock_db) as ac:
        response = await ac.post("/users", json={
            "user_name": "ocupado",
            "user_password": "Password1!",
            "user_rol": "admin",
        })

    assert response.status_code == 400
    assert "ocupado" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_detection_asset_not_found():
    """POST /detections/ devuelve 404 si el asset no existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    async with make_client(mock_db) as ac:
        response = await ac.post("/detections/", json={
            "asset_id": str(uuid4()),
            "cve_id": "CVE-2026-0003",
            "package_name": "curl",
            "package_version": "8.0",
        })

    assert response.status_code == 404
    assert response.json()["detail"] == "El Asset no existe"


@pytest.mark.asyncio
async def test_create_detection_reuses_first_seen():
    """POST /detections/ reutiliza first_seen_at del primer registro previo"""
    mock_db = AsyncMock(spec=AsyncSession)
    old_date = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

    first_record = SimpleNamespace(first_seen_at=old_date)

    res_first = MagicMock()
    res_first.scalars.return_value.first.return_value = first_record
    mock_db.execute.return_value = res_first
    mock_db.get.return_value = Asset(wazuh_agent_id="001", hostname="host-1", wazuh_connection_id=1)

    added = {}

    def capture_add(obj):
        added["obj"] = obj

    def fake_commit():
        added["obj"].timestamp = old_date

    mock_db.add.side_effect = capture_add
    mock_db.commit.side_effect = fake_commit

    asset_id = str(uuid4())
    async with make_client(mock_db) as ac:
        response = await ac.post("/detections/", json={
            "asset_id": asset_id,
            "cve_id": "CVE-2026-0004",
            "package_name": "openssl",
            "package_version": "3.0",
        })

    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2026-0004"
    assert body["first_seen_at"].startswith("2026-01-15T10:00:00")
    assert body["status"] == "Detected"


@pytest.mark.asyncio
async def test_get_asset_history_success_and_empty():
    """GET /detections/{asset_id}: 200 con historial y 404 cuando está vacío"""
    now = datetime.now(timezone.utc)

    detection = SimpleNamespace(
        timestamp=now,
        asset_id=uuid4(),
        cve_id="CVE-2026-0005",
        first_seen_at=now,
        status=VulnStatus.Detected,
        package_name="curl",
        package_version="8.0",
    )

    mock_db_ok = AsyncMock(spec=AsyncSession)
    res_history = MagicMock()
    res_history.scalars.return_value.all.return_value = [detection]
    mock_db_ok.execute.return_value = res_history

    target_id = str(uuid4())
    async with make_client(mock_db_ok) as ac:
        response = await ac.get(f"/detections/{target_id}")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["cve_id"] == "CVE-2026-0005"

    mock_db_empty = AsyncMock(spec=AsyncSession)
    res_empty = MagicMock()
    res_empty.scalars.return_value.all.return_value = []
    mock_db_empty.execute.return_value = res_empty

    async with make_client(mock_db_empty) as ac:
        response = await ac.get(f"/detections/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["detail"] == "No se encontraron detecciones"


@pytest.mark.asyncio
async def test_update_asset_success():
    """PATCH /assets/{asset_id}: aplica cambios, commitea y refresca"""
    asset = Asset(wazuh_agent_id="001", hostname="old-host", os_version="OldOS", wazuh_connection_id=1)
    asset.asset_id = uuid4()

    mock_db = AsyncMock(spec=AsyncSession)
    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = asset
    mock_db.execute.return_value = res_found

    async with make_client(mock_db) as ac:
        response = await ac.patch(f"/assets/{asset.asset_id}", json={
            "hostname": "new-host",
            "os_version": "Ubuntu 24.04",
        })

    assert response.status_code == 200
    assert response.json()["hostname"] == "new-host"
    assert asset.hostname == "new-host"
    assert asset.os_version == "Ubuntu 24.04"
    assert mock_db.commit.called
    assert mock_db.refresh.called


@pytest.mark.asyncio
async def test_update_catalog_not_found():
    """PATCH /catalog/{cve_id} devuelve 404 para CVE inexistente"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_missing = MagicMock()
    res_missing.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_missing

    async with make_client(mock_db) as ac:
        response = await ac.patch("/catalog/CVE-NOPE", json={"severity": "LOW"})

    assert response.status_code == 404
    assert response.json()["detail"] == "CVE no encontrado"


@pytest.mark.asyncio
async def test_delete_user_success():
    """DELETE /users/{id} elimina un usuario existente"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.delete = AsyncMock()
    mock_db.commit = AsyncMock()

    target = User(user_name="victim", user_delete=False)
    target.user_id = 9

    res_found = MagicMock()
    res_found.scalar_one_or_none.return_value = target
    mock_db.execute.return_value = res_found

    async with make_client(mock_db) as ac:
        response = await ac.delete("/users/9")

    assert response.status_code == 200
    assert response.json()["message"] == "Usuario eliminado correctamente"
    assert mock_db.delete.called
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_delete_user_self_forbidden():
    """DELETE /users/{id} devuelve 400 si intentas eliminar tu propio usuario"""
    mock_db = AsyncMock(spec=AsyncSession)

    async with make_client(mock_db) as ac:
        response = await ac.delete("/users/1")

    assert response.status_code == 400
    assert "propio" in response.json()["detail"]
    assert not mock_db.execute.called


@pytest.mark.asyncio
async def test_delete_user_not_found():
    """DELETE /users/{id} devuelve 404 si el usuario no existe"""
    mock_db = AsyncMock(spec=AsyncSession)
    res_missing = MagicMock()
    res_missing.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = res_missing

    async with make_client(mock_db) as ac:
        response = await ac.delete("/users/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Usuario no encontrado"
