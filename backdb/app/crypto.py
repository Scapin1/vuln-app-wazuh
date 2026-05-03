# crypto.py
import os
from cryptography.fernet import Fernet

import bcrypt
# --- CONFIGURACIÓN DE CONTRASEÑAS (Bcrypt) ---

def verify_password(plain_password: str, hashed_password: str)-> bool:
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password_bytes)

def hash_password(password: str) -> str:
    # El password debe ser bytes para bcrypt
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')


# --- CONFIGURACIÓN DE DATOS SENSIBLES (Fernet) ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

# Validación preventiva
if not ENCRYPTION_KEY:
    # Para desarrollo podrías usar una llave fija, pero en producción/taller 
    # es mejor que falle si no está configurada.
    raise RuntimeError("ERROR: ENCRYPTION_KEY no está definida en el entorno.")

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(value: str) -> str:
    """Encripta un texto (ej. API Key) para guardarlo en la DB"""
    return fernet.encrypt(value.encode()).decode()

def decrypt_data(value: str) -> str:
    """Desencripta un texto de la DB para usarlo en una petición"""
    return fernet.decrypt(value.encode()).decode()