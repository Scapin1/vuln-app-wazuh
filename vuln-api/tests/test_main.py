# test_main.py

import os
import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from app.main import app
from app.db import get_db
from app.auth import get_current_user, hash_password
from app.models import User, Manager, Asset, VulnerabilityDetection, VulnStatus, VulnerabilityCatalog, WazuhConnection, WazuhVulnerability
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession

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
    if not hasattr(obj, 'manager_id') or getattr(obj, 'manager_id', None) is None:
        obj.manager_id = uuid.uuid4()
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
    mock_db.execute = AsyncMock()
    mock_db.get = AsyncMock()

    mock_conn = WazuhConnection(
        id=1, name="Lab", is_active=True, 
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="hash"
    )
    mock_db.get.return_value = mock_conn

    existing_active = WazuhVulnerability(
        id=10, agent_id="001", cve_id="CVE-OLD", status="ACTIVE", package_name="bash"
    )
    
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [existing_active]
    mock_db.execute.return_value = mock_result

    mock_raw_wazuh = [{
        "agent": {"id": "001", "name": "agent-1", "os": {"full": "Ubuntu"}},
        "package": {"name": "bash", "version": "5.0"},
        "vulnerability": {"id": "CVE-OLD", "severity": "High", "score": {"base": 7.5}}
    }]

    app.dependency_overrides[get_db] = lambda: mock_db
    
    with patch("app.main.fetch_all_vulns", new_callable=AsyncMock) as mock_fetch, \
         patch("app.main.decrypt", return_value="plain"), \
         patch("os.getenv", return_value="una_clave_maestra_muy_larga_de_mas_de_32_bytes"):
        
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
    
    with patch("app.main.test_connection", return_value=True), \
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
         patch("app.main.test_connection", new_callable=AsyncMock) as mock_test:
        
        mock_test.return_value = True
        
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
    
    # 3. Verificamos los resultados
    # Ahora el status seguirá siendo 400, pero el mensaje será el de robustez
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
        
        for path in ["/managers/", "/assets/", "/catalog/", "/detections/"]:
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
        # Caso A: Clave antigua incorrecta (Línea 86)
        # Enviamos 'wrong_key', por lo que rebotará aquí.
        await ac.post("/auth/change-password", json={
            "old_password": wrong_key, 
            "new_password": new_strong_key, 
            "confirm_password": new_strong_key
        })

        # Caso B: Nueva igual a vieja (Línea 89)
        # Aquí 'old' y 'new' son iguales a la del mock.
        await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": actual_key, 
            "confirm_password": actual_key
        })

        # Caso C: Confirmación no coincide (Línea 92)
        await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": new_strong_key, 
            "confirm_password": mismatch_key
        })

        # Caso D: Password débil (Líneas 98-104)
        # Este es el que verificamos con el assert final
        res = await ac.post("/auth/change-password", json={
            "old_password": actual_key, 
            "new_password": weak_key, 
            "confirm_password": weak_key
        })

        assert res.status_code == 400
        assert "robusta" in res.json()["detail"]

@pytest.mark.asyncio
async def test_catalog_patch_and_manager_404():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_c = VulnerabilityCatalog(cve_id="C-1", severity="H", description="D", cvss_score=5.0)
    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = mock_c
    mock_db.execute.return_value = res_mock
    mock_db.refresh.side_effect = mock_refresh_side_effect
    app.dependency_overrides[get_db] = lambda: mock_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        await ac.patch("/catalog/C-1", json={"severity": "Low"})
        res_mock.scalar_one_or_none.return_value = None
        res = await ac.patch(f"/managers/{uuid.uuid4()}", json={"nombre": "X"})
    assert res.status_code == 404

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
        # Esto ejecuta el commit y el refresh de la línea 292
        response = await ac.patch("/catalog/CVE-2026", json={"severity": "High"})
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_update_manager_not_found():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = None # No lo encuentra
    mock_db.execute.return_value = res_mock
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.patch(f"/managers/{uuid.uuid4()}", json={"nombre": "Nuevo"})
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_login_wrong_password():
    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        # Usamos el email del mock_user pero con clave errónea
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
async def test_update_manager_404_path():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_result = MagicMock() # Debe ser MagicMock para que scalar_one_or_none sea síncrono
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.patch(f"/managers/{uuid.uuid4()}", json={"nombre": "X"})
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_update_catalog_success_final():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_c = VulnerabilityCatalog(cve_id="CVE-2026", severity="Low", description="D", cvss_score=1.0)
    
    mock_result = MagicMock() # Sincrónico
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
    res_mock.scalar_one_or_none.return_value = None # No existe
    mock_db.execute.return_value = res_mock
    app.dependency_overrides[get_db] = lambda: mock_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        res = await ac.patch(f"/assets/{uuid.uuid4()}", json={"hostname": "X"})
    assert res.status_code == 404

def teardown_module(module):
    app.dependency_overrides.clear()
