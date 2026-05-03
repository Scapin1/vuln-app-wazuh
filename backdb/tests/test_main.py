# test_main.py

import os
import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from main import app
from database import get_db
from auth import get_current_user
from models import User, Manager, Asset, VulnerabilityDetection, VulnStatus, VulnerabilityCatalog
from crypto import hash_password

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
# Aseguramos que el mock tenga un ID por si el esquema lo pide
mock_user.user_id = 1 

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

# --- TESTS DE ENDPOINTS ---

@pytest.mark.asyncio
async def test_read_root():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "API de Evolución de Vulnerabilidades activa"}

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
async def test_create_manager_success():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    
    def mock_refresh(obj):
        obj.id = uuid.uuid4()
    
    mock_db.refresh.side_effect = mock_refresh
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "nombre": "Wazuh Master",
            "api_url": "https://wazuh.test",
            "api_key_vault_ref": "key-123"
        }
        response = await ac.post("/managers/", json=payload)
    
    assert response.status_code == 200
    assert response.json()["nombre"] == "Wazuh Master"
    assert "id" in response.json()

@pytest.mark.asyncio
async def test_get_asset_history_not_found():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars().all.return_value = [] 
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.get("/detections/asset-inexistente")
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_update_asset_success():
    fixed_id = uuid.uuid4()
    mock_asset = Asset(
        hostname="PC-Viejo",
        wazuh_agent_id="AGENT-001",
        os_version="Ubuntu",
        ip_address="127.0.0.1",
        manager_id=uuid.uuid4()
    )
    mock_asset.id = fixed_id # Asignamos ID para evitar ValidationError
    
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_asset
    mock_db.execute.return_value = mock_result
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.patch(f"/assets/{fixed_id}", json={"hostname": "PC-Nuevo"})
    assert response.status_code == 200

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
async def test_detection_evolution_logic():
    fecha = datetime.now(timezone.utc)
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    
    def mock_refresh_logic(obj):
        obj.id = uuid.uuid4()
        obj.timestamp = fecha
        if hasattr(obj, 'first_seen_at') and obj.first_seen_at is None:
            obj.first_seen_at = fecha
    
    mock_db.refresh.side_effect = mock_refresh_logic
    mock_res = MagicMock()
    mock_res.scalars().first.return_value = None
    mock_db.execute.return_value = mock_res
    
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "asset_id": str(uuid.uuid4()), 
            "cve_id": "CVE-2024-TEST", 
            "package_name": "bash", 
            "package_version": "5.0"
        }
        res = await ac.post("/detections/", json=payload)
        assert res.status_code == 200

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
async def test_patch_updates_and_404():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_obj = Manager(nombre="M", api_url="U", api_key_vault_ref="R")
    mock_obj.id = uuid.uuid4()
    
    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = mock_obj
    mock_db.execute.return_value = res_mock
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        await ac.patch(f"/managers/{mock_obj.id}", json={"nombre": "Nuevo"})
        res_mock.scalar_one_or_none.return_value = None
        res = await ac.patch(f"/assets/{uuid.uuid4()}", json={"hostname": "X"})
        assert res.status_code == 404

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
async def test_detection_evolution_existing_record():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    fecha = datetime.now(timezone.utc)
    existing = VulnerabilityDetection(asset_id=uuid.uuid4(), cve_id="C1", first_seen_at=fecha)
    existing.id, existing.timestamp = uuid.uuid4(), fecha
    
    mock_res = MagicMock()
    mock_res.scalars.return_value.first.return_value = existing
    mock_db.execute.return_value = mock_res
    mock_db.refresh.side_effect = mock_refresh_side_effect
    app.dependency_overrides[get_db] = lambda: mock_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {"asset_id": str(uuid.uuid4()), "cve_id": "C1", "package_name": "x", "package_version": "1"}
        res = await ac.post("/detections/", json=payload)
    assert res.status_code == 200

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
        # Patch exitoso de Catálogo
        await ac.patch("/catalog/C-1", json={"severity": "Low"})
        # Caso 404 (Línea 249)
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
async def test_create_asset_success_logic():
    transport = ASGITransport(app=app)
    test_ip = os.getenv("TEST_ASSET_IP", "127.0.0.1")
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "wazuh_agent_id": "A-001",
            "hostname": "PC-TEST",
            "os_version": "Win11",
            "ip_address": test_ip,
            "manager_id": str(uuid.uuid4())
        }
        response = await ac.post("/assets/", json=payload)
    assert response.status_code == 200
    assert response.json()["hostname"] == "PC-TEST"

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
async def test_create_asset_path_complete():
    transport = ASGITransport(app=app)
    test_ip = os.getenv("TEST_ASSET_IP", "127.0.0.1")
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "wazuh_agent_id": "NEW-001",
            "hostname": "PC-COBERTURA",
            "os_version": "Linux",
            "ip_address": test_ip,
            "manager_id": str(uuid.uuid4())
        }
        response = await ac.post("/assets/", json=payload)
    assert response.status_code == 200

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
async def test_change_password_success():
    mock_db = AsyncMock()
    mock_db.add = MagicMock() 
    app.dependency_overrides[get_db] = lambda: mock_db

    old_key_val = os.getenv("TEST_SUCCESS_OLD_PASS", "OldPass_Secure_123!")
    new_key_val = os.getenv("TEST_SUCCESS_NEW_PASS", "NewPass_Secure_2026!")

    from crypto import hash_password
    mock_user.user_password = hash_password(old_key_val)
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "old_password": old_key_val,
            "new_password": new_key_val,
            "confirm_password": new_key_val
        }
        response = await ac.post("/auth/change-password", json=payload)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Contraseña actualizada exitosamente"
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_create_asset_full_coverage():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    # Importante: side_effect para simular refresh
    def mock_refresh(obj):
        obj.id = uuid.uuid4()
    mock_db.refresh.side_effect = mock_refresh
    
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    test_ip = os.getenv("TEST_ASSET_IP", "127.0.0.1")
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "wazuh_agent_id": "AGT-100",
            "hostname": "PROD-SERVER",
            "os_version": "Debian 12",
            "ip_address": test_ip,
            "manager_id": str(uuid.uuid4())
        }
        response = await ac.post("/assets/", json=payload)
    
    assert response.status_code == 200
    assert mock_db.add.called
    assert mock_db.commit.called

@pytest.mark.asyncio
async def test_get_asset_history_empty_trigger_404():
    mock_db = AsyncMock()
    mock_res = MagicMock()
    # Forzamos una lista vacía explícita
    mock_res.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = mock_res
    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        response = await ac.get(f"/detections/{uuid.uuid4()}")
    
    assert response.status_code == 404
    assert response.json()["detail"] == "No se encontraron detecciones para este asset" 

@pytest.mark.asyncio
async def test_create_detection_new_record_path():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    
    # Simula lo que haría la base de datos: asignar ID y Timestamp al "refrescar"
    def mock_refresh_logic(obj):
        obj.id = uuid.uuid4()
        obj.timestamp = datetime.now(timezone.utc)
        # Si tu esquema pide otros campos obligatorios, asegúralos aquí
        if not hasattr(obj, 'status'):
            obj.status = "Detected"
    
    mock_db.refresh.side_effect = mock_refresh_logic
    
    # Simulamos que la búsqueda inicial no encuentra registros previos
    res_mock = MagicMock()
    res_mock.scalars.return_value.first.return_value = None
    mock_db.execute.return_value = res_mock
    
    app.dependency_overrides[get_db] = lambda: mock_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "asset_id": str(uuid.uuid4()), 
            "cve_id": "CVE-2026-NEW", 
            "package_name": "openssl", 
            "package_version": "3.0.1"
        }
        response = await ac.post("/detections/", json=payload)
    
    # Si llega aquí, es que pasó la validación de Pydantic
    assert response.json()["asset_id"] == payload["asset_id"]
    assert "first_seen_at" in response.json()

@pytest.mark.asyncio
async def test_create_asset_direct_hit():
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_ip_val = os.getenv("TEST_MOCK_IP", "127.0.0.1")
    
    def mock_refresh(obj):
        obj.id = uuid.uuid4()
        if hasattr(obj, 'ip_address') and obj.ip_address is None:
            obj.ip_address = mock_ip_val

    mock_db.refresh.side_effect = mock_refresh
    app.dependency_overrides[get_db] = lambda: mock_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        payload = {
            "wazuh_agent_id": "101", 
            "hostname": "PC-COV", 
            "os_version": "Linux", 
            "ip_address": mock_ip_val,
            "manager_id": str(uuid.uuid4())
        }
        response = await ac.post("/assets/", json=payload)
    
    assert response.status_code == 200
    assert mock_db.commit.called

    res_json = response.json()
    assert "id" in res_json
    assert res_json["ip_address"] == mock_ip_val

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