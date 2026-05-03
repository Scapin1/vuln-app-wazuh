# test_crypto.py

import pytest
import os
import importlib
from cryptography.fernet import InvalidToken, Fernet
import crypto
from crypto import (
    hash_password, 
    verify_password, 
    encrypt_data, 
    decrypt_data
)
from unittest.mock import patch

# --- TESTS DE CONTRASEÑAS (BCRYPT) ---

def test_password_hashing_workflow():
    """Verifica que el hash sea seguro y validable"""
    password = "password_usach_2026"
    hashed = hash_password(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("otra_clave", hashed) is False

def test_password_salt_is_random():
    """Verifica que dos hashes de la misma clave sean distintos (salting)"""
    password = "secret_password"
    assert hash_password(password) != hash_password(password)


# --- TESTS DE ENCRIPTACIÓN DE DATOS (FERNET) ---

def test_data_encryption_roundtrip():
    """Verifica el flujo completo de encriptar y desencriptar"""
    sensitive_data = "api_key_wazuh_12345"
    
    encrypted = encrypt_data(sensitive_data)
    assert isinstance(encrypted, str)
    assert encrypted != sensitive_data
    
    decrypted = decrypt_data(encrypted)
    assert decrypted == sensitive_data

def test_decryption_with_invalid_token():
    """Verifica que lance InvalidToken si el dato es corrupto"""
    # Un token de Fernet válido debe tener una estructura específica.
    # Usamos uno que no corresponda a nuestra llave.
    otra_llave = Fernet.generate_key().decode()
    token_ajeno = Fernet(otra_llave.encode()).encrypt(b"datos").decode()
    
    with pytest.raises(InvalidToken):
        decrypt_data(token_ajeno)

def test_crypto_runtime_error_no_key():
    """Verifica que el sistema se proteja si falta la llave en el entorno"""
    with patch.dict(os.environ, {"ENCRYPTION_KEY": ""}):
        with pytest.raises(RuntimeError) as exc:
            importlib.reload(crypto)
        assert "ENCRYPTION_KEY no está definida" in str(exc.value)
    
    # Restaurar el estado del módulo para los demás tests
    importlib.reload(crypto)