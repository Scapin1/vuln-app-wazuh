# test_auth.py

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

# --- TESTS DE CRIPTOGRAFÍA Y TOKENS ---

def test_crypto_basics1():
    #Prueba hashing y verificación de contraseñas
    password = "secret_password"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

@pytest.mark.asyncio
async def test_create_access_token_logic1():
    """Verifica la creación y contenido del JWT"""
    data = {"sub": "test@usach.cl"}
    token = create_access_token(data=data)
    
    # Decodificamos para validar el contenido
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == data["sub"]
    assert "exp" in payload

# --- TESTS DE GET_CURRENT_USER (COBERTURA LÍNEAS 62-77) ---

@pytest.mark.asyncio
async def test_get_current_user_success():
    #Prueba obtención exitosa de usuario
    db = AsyncMock()
    email = "admin@test.cl"
    token = create_access_token(data={"sub": email})
    
    mock_user = User(user_email=email, user_delete=False)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = mock_result

    user = await get_current_user(token=token, db=db)
    assert user.user_email == email

@pytest.mark.asyncio
async def test_get_current_user_errors1():
    #Cubre errores de validación de token y usuario (Líneas 63, 70, 77)
    db = AsyncMock()

    # Caso 1: Token inválido
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token="token_totalmente_invalido", db=db)
    assert exc.value.status_code == 401

    # Caso 2: sub es None (Línea 63)
    token_no_sub = create_access_token(data={"sub": None})
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token_no_sub, db=db)
    assert exc.value.status_code == 401

    # Caso 3: Usuario no encontrado en DB (Línea 77)
    token_valid = create_access_token(data={"sub": "no_existe@test.cl"})
    mock_res_none = MagicMock()
    mock_res_none.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_res_none
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token_valid, db=db)
    assert exc.value.status_code == 401

    # Caso 4: Usuario borrado (Líneas 70-71)
    mock_user_del = User(user_email="borrado@test.cl", user_delete=True)
    mock_res_del = MagicMock()
    mock_res_del.scalar_one_or_none.return_value = mock_user_del
    db.execute.return_value = mock_res_del
    with pytest.raises(HTTPException) as exc:
        await get_current_user(token=token_valid, db=db)
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

# --- TESTS DE CRIPTOGRAFÍA ---

def test_crypto_basics():
    #Prueba hashing y verificación de contraseñas
    password = "secret_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_create_access_token_logic():
    #Prueba creación de tokens con y sin delta
    data = {"sub": "test@usach.cl"}
    token = create_access_token(data=data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == data["sub"]

# --- TESTS DE AUTHENTICATE_USER ---

@pytest.mark.asyncio
async def test_authenticate_user_logic():
    """Prueba el flujo de autenticación contra Mock de DB"""
    db = AsyncMock()
    password = "password123"
    hashed = hash_password(password)
    email = "test@usach.cl"
    
    mock_user = User(user_email=email, user_password=hashed, user_delete=False)
    
    # Caso 1: Éxito
    res = MagicMock()
    res.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = res
    
    user = await authenticate_user(db, email, password)
    assert user == mock_user

    # Caso 2: Usuario borrado
    mock_user.user_delete = True
    assert await authenticate_user(db, email, password) is None

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
