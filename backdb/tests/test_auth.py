# test_auth.py

import os
import pytest
import jwt
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException
from auth import (
    create_access_token, 
    get_current_user,
    SECRET_KEY,
    ALGORITHM,
    authenticate_user
)
from models import User
from crypto import hash_password, verify_password
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

SECRET_NAME = "MY-API-KEY"
key_vault_name = os.getenv("KEY_VAULT_NAME", "vault-defecto")
kv_uri = f"https://{key_vault_name}.vault.azure.net"

def get_azure_secret():
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=kv_uri, credential=credential)
        # .value es indispensable para obtener el string de la clave
        retrieved_secret = client.get_secret(SECRET_NAME)
        return retrieved_secret.value
    except Exception:
        # Si falla Azure en el taller, usamos la clave por defecto de auth.py
        return SECRET_KEY

# --- TESTS DE CRIPTOGRAFÍA Y TOKENS ---

def test_crypto_basics():
    """Prueba hashing y verificación de contraseñas (Limpio de duplicados)"""
    test_pass = "secret_password_2026"
    hashed = hash_password(test_pass)
    assert hashed != test_pass
    assert verify_password(test_pass, hashed) is True
    assert verify_password("wrong_password", hashed) is False

@pytest.mark.asyncio
async def test_create_access_token_logic():
    """Verifica la creación y contenido del JWT"""
    data = {"sub": "test@usach.cl"}
    token = create_access_token(data=data)
    
    # Decodificamos para validar el contenido
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == data["sub"]
    assert "exp" in payload

# --- TESTS DE GET_CURRENT_USER (COBERTURA LÍNEAS 62-77) ---

@pytest.mark.asyncio
async def test_get_current_user_all_cases():
    """Cubre éxito y todas las ramas de error de get_current_user"""
    db = AsyncMock()
    email = "admin@test.cl"
    
    # Caso 1: Éxito
    token = create_access_token(data={"sub": email})
    mock_u = User(user_email=email, user_delete=False)
    res = MagicMock()
    res.scalar_one_or_none.return_value = mock_u
    db.execute.return_value = res
    
    user = await get_current_user(token=token, db=db)
    assert user.user_email == email

    # Caso 2: Token inválido (401)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token="token_mal_formado", db=db)
    assert exc.value.status_code == 401

    # Caso 3: Payload sin 'sub' o sub None
    token_no_sub = jwt.encode({"data": "none"}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token_no_sub, db=db)
    assert exc.value.status_code == 401

    # Caso 4: Usuario no existe en DB
    res.scalar_one_or_none.return_value = None
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token, db=db)
    assert exc.value.status_code == 401

    # Caso 5: Usuario marcado como borrado
    mock_u.user_delete = True
    res.scalar_one_or_none.return_value = mock_u
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token, db=db)
    assert exc.value.status_code == 401

# --- TESTS DE AUTHENTICATE_USER ---

@pytest.mark.asyncio
async def test_authenticate_user_full_logic():
    #Cubre éxito y fallos de autenticación (Líneas 59, 63)
    db = AsyncMock()
    
    # Caso 1: Usuario no existe (Línea 59)
    mock_res_none = MagicMock()
    mock_res_none.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_res_none
    assert await authenticate_user(db, "no@test.cl", "pass") is None

    # Caso 2: Existe pero clave incorrecta (Línea 63 aprox)
    hashed = hash_password("clave123")
    mock_user = User(user_email="si@test.cl", user_password=hashed, user_delete=False)
    mock_res_user = MagicMock()
    mock_res_user.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = mock_res_user
    
    assert await authenticate_user(db, "si@test.cl", "clave_erronea") is None
    
    # Caso 3: Éxito total
    assert await authenticate_user(db, "si@test.cl", "clave123") == mock_user

# --- TESTS DE AUTHENTICATE_USER ---

@pytest.mark.asyncio
async def test_authenticate_user_logic():
    """Cubre el flujo de autenticación éxito/fallo"""
    db = AsyncMock()
    valid_pass = "clave123"
    hashed = hash_password(valid_pass)
    email = "si@test.cl"
    
    mock_user = User(user_email=email, user_password=hashed, user_delete=False)
    mock_res = MagicMock()
    
    # Caso 1: Usuario no encontrado
    mock_res.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_res
    assert await authenticate_user(db, "no@test.cl", "pass") is None

    # Caso 2: Contraseña incorrecta
    mock_res.scalar_one_or_none.return_value = mock_user
    assert await authenticate_user(db, email, "incorrecta") is None
    
    # Caso 3: Éxito
    assert await authenticate_user(db, email, valid_pass) == mock_user

    # Caso 4: Usuario borrado
    mock_user.user_delete = True
    assert await authenticate_user(db, email, valid_pass) is None

# --- TESTS DE GET_CURRENT_USER (COBERTURA LÍNEAS 63 Y 77) ---

@pytest.mark.asyncio
async def test_get_current_user_logic():
    db = AsyncMock()
    email = "admin@test.cl"
    
    # Caso 1: Éxito
    token = create_access_token({"sub": email})
    mock_u = User(user_email=email, user_delete=False)
    res = MagicMock()
    res.scalar_one_or_none.return_value = mock_u
    db.execute.return_value = res
    assert await get_current_user(token, db) == mock_u

    # Caso 2: Token inválido (JWTError)
    with pytest.raises(HTTPException) as ex:
        await get_current_user("token_invalido", db)
    assert ex.value.status_code == 401

    # Caso 3: Payload sin campo 'sub' (Cubre Línea 63)
    token_no_sub = jwt.encode({"some": "data"}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as ex:
        await get_current_user(token_no_sub, db)
    assert ex.value.status_code == 401

    # Caso 4: Usuario no encontrado en DB (Cubre Línea 77)
    res.scalar_one_or_none.return_value = None
    with pytest.raises(HTTPException) as ex:
        await get_current_user(token, db)
    assert ex.value.status_code == 401

    # Caso 5: Usuario existe pero está borrado (Cubre Línea 77 - user_delete)
    mock_u.user_delete = True
    res.scalar_one_or_none.return_value = mock_u
    with pytest.raises(HTTPException) as ex:
        await get_current_user(token, db)
    assert ex.value.status_code == 401

@pytest.mark.asyncio
async def test_get_current_user_errors():
    """Cubre excepciones de validación de token"""
    db = AsyncMock()

    # Token sin el campo 'sub'
    token_no_sub = jwt.encode({"data": "random"}, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token_no_sub, db=db)
    assert exc.value.status_code == 401
    
    # Token expirado o mal formado
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token="token-invalido", db=db)
    assert exc.value.status_code == 401
