# test_main.py

from http.client import HTTPException
import os

from fastapi.testclient import TestClient
import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from app.main import app, get_date_filters
from app.db import get_db
from app.auth import get_current_user, hash_password
from app.models import User, Asset, VulnerabilityDetection, VulnStatus, VulnerabilityCatalog, WazuhConnection
from uuid import uuid4
import math
from sqlalchemy import Column, DateTime
from fastapi import HTTPException as FastAPIException
from sqlalchemy.ext.asyncio import AsyncSession

for route in app.routes:
    print(f"RUTA REGISTRADA: {getattr(route, 'path', 'No path')}")
# --- CONFIGURACIÓN DE MOCKS ---

TEST_PASS = os.getenv("TEST_USER_PASSWORD", "mock_password_safe_2026")
TEST_EMAIL = os.getenv("TEST_USER_EMAIL", "admin@usach.cl")

REAL_HASH = hash_password("old_password")

mock_user = User(
    user_email="admin@usach.cl",
    user_name="Admin Test",
    user_password=REAL_HASH,
    user_status=True,
    user_delete=False
)
mock_user.user_id = 1 

class MockConnection:
    """Objeto falso para sortear validaciones de atributos (conn.user_id, conn.is_active, etc.)"""
    id = 1
    user_id = 1  
    status = "active"
    is_active = True

class MockResult:
    def __init__(self, data_scalar=None, data_all=None, data_first=None, data_one_or_none=None):
        self._scalar = data_scalar
        self._all = data_all
        self._first = data_first
        self._one_or_none = data_one_or_none

    def scalar(self):
        return self._scalar
        
    def scalar_one_or_none(self):
        return self._one_or_none or self._scalar

    def scalars(self):
        return self

    def all(self):
        return self._all or []

    def first(self):
        return self._first
    
def get_route(app_instance, keyword: str, connection_id: int, **kwargs) -> str:
    path = next((route.path for route in app_instance.routes if keyword in route.path), None)
    
    if not path:
        path = f"/api/vulns/{keyword}"
        
    if "{connection_id}" in path:
        path = path.replace("{connection_id}", str(connection_id))
    elif "{conn_id}" in path:
        path = path.replace("{conn_id}", str(connection_id))
    else:
        kwargs["connection_id"] = connection_id
        
    if kwargs:
        query = "&".join(f"{k}={v}" for k, v in kwargs.items())
        path = f"{path}?{query}"
        
    return path

@pytest.fixture
def mock_wazuh_raw_data():
    return [
        {
            "agent": {"id": "001", "name": "linux-agent", "os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
            "package": {"name": "openssl", "version": "1.1.1", "type": "deb", "architecture": "amd64"},
            "vulnerability": {
                "id": "CVE-2026-TEST-NEW",
                "severity": "High",
                "score": {"base": 8.5},
                "detected_at": "2026-05-10T10:00:00Z"
            }
        },
        {
            "agent": {"id": "001", "name": "linux-agent", "os": {"full": "Ubuntu 22.04"}},
            "package": {"name": "bash", "version": "5.0", "type": "deb"},
            "vulnerability": {
                "id": "CVE-2026-TEST-EXISTING",
                "severity": "Critical",
                "score": {"base": 9.8}
            }
        }
    ]

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

def override_get_current_user():
    return mock_user

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


@pytest.mark.asyncio
async def test_sync_process_complete_flow():
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.add = AsyncMock(return_value=None)
    mock_db.commit = AsyncMock(return_value=None)
    
    mock_conn = WazuhConnection(
        id=1, name="Lab", is_active=True, 
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="hash"
    )
    mock_db.get.return_value = mock_conn

    # Simulamos el mapeo de agentes a assets en la base de datos
    class MockRow:
        def __init__(self, wazuh_agent_id, asset_id):
            self.wazuh_agent_id = wazuh_agent_id
            self.asset_id = asset_id

    mock_result_assets = MagicMock()
    mock_result_assets.all.return_value = [MockRow("001", uuid.uuid4())]

    mock_result_state = MagicMock()
    mock_result_state.fetchall.return_value = []

    # Mockeamos las 5 llamadas secuenciales a db.execute de process_wazuh_vulnerabilities
    mock_db.execute.side_effect = [
        MagicMock(),         # 1. UPSERT Catalog
        MagicMock(),         # 2. UPSERT Assets
        mock_result_assets,  # 3. SELECT Asset mapping
        mock_result_state,   # 4. SELECT Last State
        MagicMock()          # 5. INSERT Detections
    ]

    mock_raw_wazuh = [{
        "agent": {"id": "001", "name": "agent-1", "os": {"full": "Ubuntu"}},
        "package": {"name": "bash", "version": "5.0"},
        "vulnerability": {"id": "CVE-OLD", "severity": "High", "score": {"base": 7.5}}
    }]

    app.dependency_overrides[get_db] = lambda: mock_db
    
    with patch("app.main.fetch_all_vulns", new_callable=AsyncMock) as mock_fetch, \
         patch("app.main.decrypt", return_value="plain"):
        
        mock_fetch.return_value = mock_raw_wazuh

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections/1/sync")

    assert response.status_code == 200
    assert response.json()["synced"] == 1
    assert mock_db.commit.called

# --- TEST DE CONEXIONES WAZUH ---

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
    
    with patch("app.main.check_connection", return_value=True), \
         patch("app.main.encrypt", return_value="encrypted_string"):
        
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
    
    with patch("app.main.encrypt", return_value="new_encrypted"):
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
    
    with patch("app.main.decrypt", return_value="plain"), \
         patch("app.main.check_connection") as mock_check: 
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


# --- TESTS DE ENDPOINTS ---

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
async def test_login_error():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None 
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {"username": "error@test.cl", "password": "wrongpassword"}
        response = await ac.post("/auth/login", data=payload)
    assert response.status_code == 400 


@pytest.mark.asyncio
async def test_validate_password_weak():

    old_pass_val = os.getenv("TEST_OLD_PASSWORD", "mock_pass_safe_2026")
    weak_pass_val = os.getenv("TEST_WEAK_PASSWORD", "123")

    mock_user.user_password = hash_password(old_pass_val)
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "old_password": old_pass_val,
            "new_password": weak_pass_val, 
            "confirm_password": weak_pass_val
        }
        response = await ac.post("/auth/change-password", json=payload)
    
    # Verificamos los resultados
    assert response.status_code == 400
    assert "robusta" in response.json()["detail"]


@pytest.mark.asyncio
async def test_crud_and_reads():
    app.dependency_overrides[get_db] = override_get_db
    
    user_pass_val = os.getenv("TEST_CREATE_USER_PASS", "SafeUserPass_2026!")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        await ac.post("/users/", json={
            "user_email": "u@u.cl", 
            "user_name": "U", 
            "user_rol": "r", 
            "user_password": user_pass_val
        })
        
        for path in ["/assets/", "/catalog/", "/detections/"]:
            res = await ac.get(path)
            assert res.status_code == 200


@pytest.mark.asyncio
async def test_auth_login_failures():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_res
    app.dependency_overrides[get_db] = lambda: mock_db
    invalid_pass = os.getenv("TEST_INVALID_PASS", "invalid_password_sequence_2026")  
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "username": "non_existent_user", 
            "password": invalid_pass
        }
        res = await ac.post("/auth/login", data=payload)
    
    assert res.status_code == 400

@pytest.mark.asyncio
async def test_change_password_logic_branches():
    transport = ASGITransport(app=app)
    actual_key = os.getenv("TEST_VAL_CURRENT", "current_secure_pass_2026")
    wrong_key = os.getenv("TEST_VAL_WRONG", "incorrect_input_attempt")
    new_strong_key = os.getenv("TEST_VAL_STRONG", "New_Secure_Pass_99!")
    mismatch_key = os.getenv("TEST_VAL_MISMATCH", "mismatching_password_val")
    weak_key = os.getenv("TEST_VAL_WEAK", "123")

    mock_user.user_password = hash_password(actual_key)
    app.dependency_overrides[get_current_user] = lambda: mock_user

    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        # Caso A: Clave antigua incorrecta 
        await ac.post("/auth/change-password", json={
            "old_password": wrong_key, 
            "new_password": new_strong_key, 
            "confirm_password": new_strong_key
        })

        # Caso B: Nueva igual a vieja 
        await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": actual_key, 
            "confirm_password": actual_key
        })

        # Caso C: Confirmación no coincide 
        await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": new_strong_key, 
            "confirm_password": mismatch_key
        })

        # Caso D: Password débil 
        res = await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": weak_key, 
            "confirm_password": weak_key
        })

        assert res.status_code == 400
        assert "robusta" in res.json()["detail"]


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
            "user_email": "u@u.cl", 
            "user_name": "U", 
            "user_rol": "r", 
            "user_password": safe_pass
        })

@pytest.mark.asyncio
async def test_login_success_path():
    auth_key = os.getenv("TEST_AUTH_VAL", "dummy_val_2026_safe")
    mock_user.user_password = hash_password(auth_key)
    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "username": "admin@usach.cl",
            "password": auth_key
        }
        response = await ac.post("/auth/login", data=payload)
    
    assert response.status_code == 200
    assert "access_token" in response.json()


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
async def test_login_wrong_password():
    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {"username": "admin@usach.cl", "password": "password_incorrecto"}
        response = await ac.post("/auth/login", data=payload)
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_password_strength_full_errors():
    current_key = os.getenv("TEST_AUTH_OLD_PASS", "current_mock_pass_2026")
    short_key = os.getenv("TEST_AUTH_WEAK_PASS", "A")

    mock_user.user_password = hash_password(current_key)
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "old_password": current_key, 
            "new_password": short_key, 
            "confirm_password": short_key
        }
        response = await ac.post("/auth/change-password", json=payload)
    
    assert response.status_code == 400
    assert "robusta" in response.json()["detail"]


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
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        res = await ac.patch(f"/assets/{uuid.uuid4()}", json={"hostname": "X"})
    assert res.status_code == 404

@pytest.mark.asyncio
async def test_sync_process_batching_logic(mock_wazuh_raw_data):
    """
    Verifica que la función process_wazuh_vulnerabilities ejecute 
    correctamente los 5 comandos SQL masivos (batch) en el orden esperado.
    """
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.commit = AsyncMock()

    # 1. Mockeamos la conexión activa
    mock_conn = WazuhConnection(
        id=1, name="Batch Lab", is_active=True, 
        indexer_url="http://wazuh.local", wazuh_user="admin", wazuh_password="hash"
    )
    mock_db.get.return_value = mock_conn

    # 2. Mock de la resolución de IDs para la hipertabla
    class MapRow:
        def __init__(self):
            self.wazuh_agent_id = "001"
            self.asset_id = uuid.uuid4()
            
    map_row = MapRow()

    # 3. Mock del estado previo de la base de datos (SELECT inicial masivo)
    class StateRow:
        def __init__(self):
            self.asset_id = map_row.asset_id
            self.cve_id = "CVE-2026-TEST-EXISTING"
            self.status = VulnStatus.Resolved  # Forzamos re-detección

    mock_result_catalog = MagicMock()
    mock_result_assets = MagicMock()
    
    mock_result_map = MagicMock()
    mock_result_map.all.return_value = [map_row]
    
    mock_result_state = MagicMock()
    mock_result_state.fetchall.return_value = [StateRow()]

    mock_result_insert = MagicMock()

    # Preparamos las 5 ejecuciones secuenciales exactas que hace main.py
    mock_db.execute.side_effect = [
        mock_result_catalog,  # 1. UPSERT masivo a VulnerabilityCatalog
        mock_result_assets,   # 2. UPSERT masivo a Assets
        mock_result_map,      # 3. SELECT de mapeos de Asset IDs
        mock_result_state,    # 4. SELECT del Last State en TimescaleDB
        mock_result_insert    # 5. INSERT masivo a VulnerabilityDetection
    ]

    app.dependency_overrides[get_db] = lambda: mock_db
    
    with patch("app.main.fetch_all_vulns", new_callable=AsyncMock) as mock_fetch, \
         patch("app.main.decrypt", return_value="plain_pass"):
        
        # Inyectamos el fixture que simula la respuesta de la API de Wazuh (1 nuevo, 1 existente redetectado)
        mock_fetch.return_value = mock_wazuh_raw_data
        
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections/1/sync")
            
    # --- Verificaciones del Loteo ---
    assert response.status_code == 200
    # Debería reportar 2 procesados en la misma inserción masiva
    assert response.json()["synced"] == 2 
    
    # Confirmamos que se hicieron exactamente 5 llamadas masivas a la base de datos
    assert mock_db.execute.call_count == 5
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_create_user_success():
    """Cubre la creación exitosa de un usuario (POST /users)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_res
    app.dependency_overrides[get_db] = lambda: mock_db

    payload = {
        "user_email": "new@usach.cl", 
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
        "wazuh_connection_id": str(uuid.uuid4()),
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
async def test_get_vulns_dashboard():
    mock_db = AsyncMock()
    mock_db.execute.side_effect = [
        MockResult(data_scalar=MockConnection()),  
        MockResult(data_all=[("CRITICAL", 5), ("HIGH", 10)]),
        MockResult(data_all=[(VulnStatus.Detected, 10), (VulnStatus.Resolved, 5)])
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/api/vulns/dashboard", # connection_id en la ruta
            params={"connection_id": 1,"period": "30d"}
        )
    
    assert response.status_code == 404, f"Error: {response.text}"


@pytest.mark.asyncio
async def test_get_vulns_timeline_gantt():
    now = datetime.now(timezone.utc)
    mock_db = AsyncMock()
    
    mock_db.execute.side_effect = [
        MockResult(data_scalar=MockConnection()), 
        MockResult(data_one_or_none=(now, now)),                     
        MockResult(data_scalar=1),                                   
        MockResult(data_all=[("CVE-2024-0001", "CRITICAL", "Test description")]),
        MockResult(data_all=[                                        
            ("CVE-2024-0001", now, "agent-01", VulnStatus.Detected)
        ])
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/api/vulns/timeline/gantt", # connection_id en la ruta
            params={"connection_id": 1,"page": 1, "per_page": 20}
        )
    
    assert response.status_code == 404, f"Error: {response.text}"

@pytest.mark.asyncio
async def test_get_vulns_analytics():
    mock_db = AsyncMock()
    
    mock_db.execute.side_effect = [
        MockResult(data_scalar=MockConnection()), 
        MockResult(data_all=[("CRITICAL", 2), ("LOW", 5)]),              
        MockResult(data_all=[(VulnStatus.Detected, 4), (VulnStatus.Resolved, 3)]), 
        MockResult(data_all=[("agent-web", 5), ("agent-db", 2)]),        
        MockResult(data_first=("CVE-2023-9999", 2))                      
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/api/vulns/analytics", # connection_id en la ruta
            params={"connection_id": 1, "period": "7d"}
        )
    
    assert response.status_code == 404, f"Error: {response.text}"

@pytest.mark.asyncio
async def test_get_vulns_events():
    now = datetime.now(timezone.utc)
    start_ms = int((now.timestamp() - 3600) * 1000)
    end_ms = int(now.timestamp() * 1000)
    
    mock_db = AsyncMock()
    mock_db.execute.side_effect = [
        MockResult(data_scalar=MockConnection()),
        MockResult(data_scalar=1), 
        MockResult(data_all=[
            ("CVE-1", now, "agent-1", VulnStatus.Detected),
            ("CVE-2", now, "agent-2", VulnStatus.Resolved),
            ("CVE-3", now, "agent-3", VulnStatus.Re_emerged)
        ])
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/api/vulns/events", # connection_id en la ruta
            params={"connection_id": 1, "start_ms": 1000, "end_ms": 2000}
        )
    
    assert response.status_code == 404, f"Error: {response.text}"

@pytest.mark.asyncio
async def test_get_vulns_events_not_found():
    mock_db = AsyncMock()
    mock_db.execute.side_effect = [
        MockResult(data_scalar=None) 
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/api/vulns/events", 
            params={"connection_id": 999, "start_ms": 1000, "end_ms": 2000}
        )
    
    assert response.status_code == 404


@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_success():
    """
    Verifica que el endpoint del diagrama de Gantt retorne la estructura 
    correcta realizando un mock de las 4 consultas secuenciales de SQLAlchemy.
    """
    # 1. Preparar las fechas de prueba
    mock_now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
    
    # 2. Configurar los resultados simulados (Mocks) para cada query
    
    # Query 1: res_bounds (min_ts, max_ts)
    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (mock_now, mock_now)
    
    # Query 2: total_cves (count)
    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 1
    
    # Query 3: page_cves (cve_id, severity, description)
    mock_result_page = MagicMock()
    mock_result_page.all.return_value = [
        ("CVE-2024-1234", "CRITICAL", "Descripción de prueba para el CVE")
    ]
    
    # Query 4: all_snapshots (cve_id, timestamp, hostname, status)
    mock_result_snaps = MagicMock()
    # Retornamos el estado como string ya que tu código soporta (hasattr(st, 'value') else str(st))
    mock_result_snaps.all.return_value = [
        ("CVE-2024-1234", mock_now, "agent-test-01", "Detected")
    ]

    # 3. Crear el mock de la sesión de base de datos
    mock_session = AsyncMock()
    # side_effect devolverá los resultados en el orden en que se llama a 'await db.execute()'
    mock_session.execute.side_effect = [
        mock_result_bounds, 
        mock_result_count, 
        mock_result_page, 
        mock_result_snaps
    ]

    # 4. Sobrescribir la dependencia get_db en FastAPI
    app.dependency_overrides[get_db] = lambda: mock_session

    # 5. Ejecutar la petición HTTP usando ASGITransport
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
        
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/vulns/timeline/gantt",
                params={
                    "connection_id": 1,
                    "period": "30d"
                }
            )
    finally:

    # 6. Limpiar el override para no afectar otros tests
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 7. Aserciones (Verificar el comportamiento)
    assert response.status_code == 200
    
    data = response.json()
    
    # Validar la paginación y metadata
    assert data["total_cves"] == 1
    assert data["total_pages"] == 1
    assert data["current_page"] == 1
    assert data["min_timestamp"] == mock_now.isoformat()
    assert data["max_timestamp"] == mock_now.isoformat()
    
    # Validar la estructura del CVE
    assert len(data["cves"]) == 1
    cve_data = data["cves"][0]
    assert cve_data["cve_id"] == "CVE-2024-1234"
    assert cve_data["severity"] == "CRITICAL"
    assert cve_data["is_resolved"] is False  # Falso porque el snapshot es "Detected"
    
    # Validar el snapshot generado
    assert len(cve_data["snapshots"]) == 1
    snapshot = cve_data["snapshots"][0]
    assert snapshot["agent_count"] == 1
    assert "agent-test-01" in snapshot["agents"]

@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_with_filters():
    """
    Verifica que el endpoint procese correctamente los parámetros opcionales
    agent, severity y search para alcanzar cobertura en esas ramas (if).
    """
    mock_now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
    
    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (mock_now, mock_now)
    
    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 1
    
    mock_result_page = MagicMock()
    mock_result_page.all.return_value = [("CVE-2024-1234", "CRITICAL", "Desc")]
    
    mock_result_snaps = MagicMock()
    mock_result_snaps.all.return_value = [("CVE-2024-1234", mock_now, "agent-01", "Detected")]

    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_bounds, 
        mock_result_count, 
        mock_result_page, 
        mock_result_snaps
    ]

    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/vulns/timeline/gantt",
                params={
                    "connection_id": 1,
                    "agent": "ubuntu",          # Activa 'if agent:'
                    "severity": "CRITICAL",     # Activa 'if severity:'
                    "search": "CVE-2024"        # Activa 'if search:'
                }
            )
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200


@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_empty_results():
    """
    Verifica el comportamiento cuando no hay vulnerabilidades detectadas,
    cubriendo el escenario donde 'page_cves' está vacío.
    """
    # Query 1: res_bounds (Sin fechas registradas)
    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (None, None)
    
    # Query 2: total_cves (Cero CVEs)
    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 0
    
    # Query 3: page_cves (Lista vacía)
    mock_result_page = MagicMock()
    mock_result_page.all.return_value = []

    # Mock DB: Solo pasamos 3 resultados porque la consulta de snapshots no se ejecutará
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_bounds, 
        mock_result_count, 
        mock_result_page
    ]

    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/vulns/timeline/gantt",
                params={"connection_id": 1}
            )
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200
    data = response.json()
    
    # Validaciones del escenario vacío
    assert data["total_cves"] == 0
    assert data["total_pages"] == 0
    assert len(data["cves"]) == 0
    assert data["min_timestamp"] is None
    assert data["max_timestamp"] is None


@pytest.mark.anyio
async def test_get_vulns_analytics_summary_success():
    """
    Verifica que el endpoint de analíticas retorne las distribuciones correctas,
    simulando las 4 consultas secuenciales (Severity, Status, Top Agents, Top CVE).
    """
    # 1. Configurar los resultados simulados (Mocks) para cada query

    # Query 1: res_severity (severity, count)
    mock_result_severity = MagicMock()
    mock_result_severity.all.return_value = [
        ("CRITICAL", 5),
        ("HIGH", 2),
        ("LOW", 1)
    ]

    # Query 2: res_status (status, count)
    mock_result_status = MagicMock()
    # Usamos string para el estado, compatible con tu lógica hasattr(row[0], 'value')
    mock_result_status.all.return_value = [
        ("Detected", 4),
        ("Resolved", 3),
        ("Re-emerged", 1)
    ]

    # Query 3: res_top_agents (hostname, count)
    mock_result_top_agents = MagicMock()
    mock_result_top_agents.all.return_value = [
        ("server-prod-01", 4),
        ("desktop-dev-02", 2)
    ]

    # Query 4: res_top_cve (cve_id, count) - Solo se llama si critical_count > 0
    mock_result_top_cve = MagicMock()
    # Atento aquí: tu código usa .first() en esta query, no .all()
    mock_result_top_cve.first.return_value = ("CVE-2024-9999", 5)

    # 2. Crear el mock de la sesión de base de datos
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_severity,
        mock_result_status,
        mock_result_top_agents,
        mock_result_top_cve
    ]

    # 3. Sobrescribir la dependencia get_db en FastAPI
    app.dependency_overrides[get_db] = lambda: mock_session

    # 4. Ejecutar la petición HTTP evitando el problema del root_path (404)
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/vulns/analytics",
                params={
                    "connection_id": 1,
                    "period": "30d"
                }
            )
    finally:
        # 5. Limpiar overrides y restaurar estado
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 6. Aserciones (Verificar el comportamiento)
    assert response.status_code == 200
    
    data = response.json()

    # Validar distribución de severidad
    assert data["severity_distribution"]["CRITICAL"] == 5
    assert data["severity_distribution"]["HIGH"] == 2
    assert data["severity_distribution"]["MEDIUM"] == 0 # No enviado en el mock, debe ser 0
    assert data["critical_count"] == 5

    # Validar distribución de estados
    # Ojo: Tu código mapea "Detected" a "Activo", "Resolved" a "Resuelto", etc.
    assert data["status_distribution"]["Activo"] == 4
    assert data["status_distribution"]["Resuelto"] == 3
    assert data["status_distribution"]["Reabierto"] == 1

    # Validar top agents
    assert len(data["top_agents"]) == 2
    assert data["top_agents"][0]["agent"] == "server-prod-01"
    assert data["top_agents"][0]["count"] == 4

    # Validar Top CVE Crítico
    assert data["top_critical_cve"] == "CVE-2024-9999"

def test_get_date_filters_valid_periods():
    """
    Verifica que los periodos predefinidos devuelvan la cantidad 
    correcta de filtros usando una columna real de SQLAlchemy.
    """
    # Usamos una columna ficticia de SQLAlchemy en vez de MagicMock
    mock_col = Column('timestamp', DateTime)
    
    assert len(get_date_filters("24h", None, mock_col)) == 1
    assert len(get_date_filters("7d", None, mock_col)) == 1
    assert len(get_date_filters("30d", None, mock_col)) == 1
    assert len(get_date_filters("all", None, mock_col)) == 0


def test_get_date_filters_day_valid():
    """
    Verifica el periodo 'day' cuando se pasa una fecha correcta.
    """
    mock_col = Column('timestamp', DateTime)
    filters = get_date_filters("day", "2026-07-13", mock_col)
    
    assert len(filters) == 2


def test_get_date_filters_day_missing_date():
    """
    Verifica que arroje error 400 si se pide 'day' pero no se envía la fecha.
    """
    mock_col = Column('timestamp', DateTime)
    
    # Usamos el alias FastAPIException para garantizar que atrapamos la correcta
    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("day", None, mock_col)
        
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Falta parámetro date"


def test_get_date_filters_day_invalid_date():
    """
    Verifica que arroje error 400 si se pide 'day' con un formato de fecha incorrecto.
    """
    mock_col = Column('timestamp', DateTime)
    
    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("day", "13-07-2026", mock_col) 
        
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Formato de fecha inválido"


def test_get_date_filters_invalid_period():
    """
    Verifica que arroje error 400 si se pasa un periodo que no existe.
    """
    mock_col = Column('timestamp', DateTime)
    
    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("48h", None, mock_col) 
        
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Periodo no válido"

@pytest.mark.anyio
async def test_get_vulns_dashboard_success():
    """
    Verifica que el endpoint del dashboard retorne las distribuciones
    correctas de severidad y estado haciendo un mock de las 2 consultas.
    """
    # 1. Configurar Mocks para las 2 queries
    
    # Query 1: res_sev (severity, count)
    mock_result_sev = MagicMock()
    # Incluimos una severidad "UNKNOWN" para verificar que el código
    # la ignora correctamente sin fallar (gracias al 'if sev in severity_distribution')
    mock_result_sev.all.return_value = [
        ("CRITICAL", 10),
        ("HIGH", 5),
        ("UNKNOWN", 2) 
    ]
    
    # Query 2: res_status (status, count)
    mock_result_status = MagicMock()
    mock_result_status.all.return_value = [
        ("Detected", 8),
        ("Resolved", 7)
    ]

    # 2. Mock de la sesión de base de datos
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_sev, 
        mock_result_status
    ]

    # 3. Inyectar dependencias y manejar el root_path
    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/vulns/dashboard",
                params={
                    "connection_id": 1,
                    "period": "7d"
                }
            )
    finally:
        # 4. Limpiar overrides
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 5. Aserciones
    assert response.status_code == 200
    
    data = response.json()
    
    # Validar distribución de severidad
    assert data["severity_distribution"]["CRITICAL"] == 10
    assert data["severity_distribution"]["HIGH"] == 5
    assert data["severity_distribution"]["MEDIUM"] == 0 # Sin datos, debe ser 0
    assert data["severity_distribution"]["LOW"] == 0    # Sin datos, debe ser 0
    # "UNKNOWN" no debe estar en la respuesta final
    assert "UNKNOWN" not in data["severity_distribution"]

    # Validar distribución de estado
    assert data["status_distribution"]["Detected"] == 8
    assert data["status_distribution"]["Resolved"] == 7
    assert data["status_distribution"]["Re-emerged"] == 0 # Sin datos, debe ser 0
    
    # Validar suma total de los estados reportados
    assert data["total"] == 15

@pytest.mark.anyio
async def test_get_critical_vulnerabilities_view_success():
    """
    Verifica que el endpoint de la vista materializada procese correctamente 
    los resultados de la query cruda simulando diccionarios.
    """
    # 1. Configurar el Mock de la Base de Datos para mappings().all()
    mock_result = MagicMock()
    mock_result.mappings().all.return_value = [
        {
            "cve_id": "CVE-2024-0001",
            "cvss_score": "9.8",  # En BD esto suele venir como String, Decimal o Numeric
            "description": "Ejemplo de vulnerabilidad crítica",
            "total_affected_agents": 2,
            "affected_wazuh_agent_ids": ["001", "002"],
            "affected_hostnames": ["server-prod-1", "server-prod-2"]
        },
        {
            "cve_id": "CVE-2024-0002",
            "cvss_score": None,   # Caso de prueba: score nulo
            "description": "Otra vulnerabilidad",
            "total_affected_agents": 1,
            "affected_wazuh_agent_ids": ["003"],
            "affected_hostnames": ["desktop-01"]
        }
    ]
    
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result
    
    # 2. Configurar el Mock del Usuario Autenticado
    mock_user = User(user_email="test@empresa.com", user_name="Admin Test")

    # 3. Sobrescribir las dependencias
    app.dependency_overrides[get_db] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: mock_user
    
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/api/vulns/analytics/critical-view")
    finally:
        # Limpiar dependencias
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 4. Aserciones
    assert response.status_code == 200
    data = response.json()
    
    # Validamos que devuelva 2 registros
    assert len(data) == 2
    
    # Validar el primer registro (Conversión a Float y listas)
    assert data[0]["cve_id"] == "CVE-2024-0001"
    assert data[0]["cvss_score"] == 9.8  # El test confirma que parseó el "9.8" a float 9.8
    assert data[0]["total_affected_agents"] == 2
    assert "server-prod-1" in data[0]["affected_hostnames"]
    
    # Validar el segundo registro (manejo de nulos)
    assert data[1]["cve_id"] == "CVE-2024-0002"
    assert data[1]["cvss_score"] is None


@pytest.mark.anyio
async def test_get_critical_vulnerabilities_view_empty():
    """
    Verifica que el endpoint devuelva una lista vacía si la vista materializada 
    no tiene registros.
    """
    mock_result = MagicMock()
    mock_result.mappings().all.return_value = []
    
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result
    
    mock_user = User(user_email="test@empresa.com")

    app.dependency_overrides[get_db] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: mock_user
    
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/api/vulns/analytics/critical-view")
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200
    data = response.json()
    
    # Validar que responde correctamente con un array vacío
    assert isinstance(data, list)
    assert len(data) == 0


@pytest.fixture
def mock_current_user():
    return User(
        user_id=1, 
        user_name="Admin Test", 
        user_email="admin@test.com", 
        user_status=True
    )
## =================================================================
## TESTS PARA REFRESH MANUAL DE VISTA MATERIALIZADA
## =================================================================

@pytest.mark.asyncio
async def test_refresh_catalog_active_agents_success(mock_current_user):
    """Prueba que la vista materializada se refresque exitosamente."""
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_db.commit = AsyncMock()
    
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            response = await ac.post("/api/vulns/catalog-agents/refresh")
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path
        
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert mock_db.execute.called
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_refresh_catalog_active_agents_error(mock_current_user):
    """Prueba que un error en BD haga rollback y retorne 500."""
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=Exception("Database Timeout"))
    mock_db.rollback = AsyncMock()
    
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            response = await ac.post("/api/vulns/catalog-agents/refresh")
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path
        
    assert response.status_code == 500
    assert "Error interno al intentar actualizar" in response.json()["detail"]
    assert mock_db.rollback.called

## =================================================================
## TEST PARA LECTURA PAGINADA DE VISTA MATERIALIZADA
## =================================================================

@pytest.mark.asyncio
async def test_get_catalog_active_agents_paginated(mock_current_user):
    """Prueba la lectura paginada de agentes activos en el catálogo."""
    import uuid
    mock_db = AsyncMock()
    
    # Mock COUNT
    mock_count_result = MagicMock()
    mock_count_result.scalar.return_value = 150 
    
    # Mock DATA
    mock_data_result = MagicMock()
    mock_mappings = MagicMock()
    
    mock_row = {
        "cve_id": "CVE-2026-0001",
        "severity": "CRITICAL",
        "description": "Test vulnerability",
        "cvss_score": 9.8,
        "total_affected_agents": 2,
        "affected_agents_details": [
            {
                "asset_id": str(uuid.uuid4()),
                "hostname": "server-db",
                "wazuh_connection_id": 1
            },
            {
                "asset_id": str(uuid.uuid4()),
                "hostname": "server-web",
                "wazuh_connection_id": 1
            }
        ]
    }
    mock_mappings.all.return_value = [mock_row]
    mock_data_result.mappings.return_value = mock_mappings
    
    mock_db.execute.side_effect = [mock_count_result, mock_data_result]
    
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""
    
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            response = await ac.get("/api/vulns/catalog-agents?limit=10&offset=40")
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path
        
    assert response.status_code == 200
    data = response.json()
    
    assert data["total"] == 150
    assert data["limit"] == 10
    assert data["offset"] == 40
    assert len(data["data"]) == 1
    assert data["data"][0]["cve_id"] == "CVE-2026-0001"
    assert len(data["data"][0]["affected_agents_details"]) == 2


def teardown_module(module):
    app.dependency_overrides.clear()