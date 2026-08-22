# tests/routers/test_auth.py — cubre app/routers/auth.py
import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password, verify_password
from app.db import get_db
from app.main import app
from app.models import User

TEST_PASS = os.getenv("TEST_USER_PASSWORD", "mock_password_safe_2026")

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
async def test_change_password_success_path():
    """Cubre la rama exitosa completa de POST /auth/change-password"""
    current_pass = "Current_Pass_2026"
    new_pass = "Nueva_Clave_99!"

    user = User(
        user_name="Admin Test",
        user_password=hash_password(current_pass),
        user_status=False,
        user_delete=False,
    )
    user.user_id = 7

    mock_db = AsyncMock(spec=AsyncSession)
    app.dependency_overrides[get_current_user] = lambda: user

    async with make_client(mock_db) as ac:
        response = await ac.post("/auth/change-password", json={
            "old_password": current_pass,
            "new_password": new_pass,
            "confirm_password": new_pass,
        })

    assert response.status_code == 200
    assert response.json()["message"] == "Contraseña actualizada exitosamente"
    assert user.user_status is True
    assert verify_password(new_pass, user.user_password)
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_get_user_me_profile():
    """GET /users/me retorna el perfil del usuario autenticado"""
    mock_db = AsyncMock(spec=AsyncSession)

    async with make_client(mock_db) as ac:
        response = await ac.get("/users/me")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == mock_user.user_id
    assert body["username"] == mock_user.user_name
    assert body["is_active"] is True


@pytest.mark.asyncio
async def test_list_users_summary():
    """GET /users retorna id/username de todos los usuarios"""
    mock_db = AsyncMock(spec=AsyncSession)

    users = [
        SimpleNamespace(user_id=1, user_name="alpha"),
        SimpleNamespace(user_id=2, user_name="beta"),
    ]
    res_users = MagicMock()
    res_users.scalars.return_value.all.return_value = users
    mock_db.execute.return_value = res_users

    async with make_client(mock_db) as ac:
        response = await ac.get("/users")

    assert response.status_code == 200
    assert response.json() == [{"id": 1, "username": "alpha"}, {"id": 2, "username": "beta"}]
