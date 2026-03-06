# app/main.py
import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import set_key, find_dotenv
from sqlalchemy.orm import Session
from typing import List, Annotated
from pydantic import BaseModel
from sqlalchemy.sql import func
from .db import Base, engine, get_db, SessionLocal
from .models import User, WazuhVulnerability, WazuhConnection
from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)

from .wazuh_client import fetch_all_vulns, test_connection
from .crypto import encrypt, decrypt

Base.metadata.create_all(bind=engine)

class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str
    version: str = None

class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    version: str | None
    is_active: bool

def create_default_admin():
    db = SessionLocal()
    try:
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            print("Creando usuario admin default...")
            default_admin = User(username="admin", password_hash=hash_password("admin"))
            db.add(default_admin)
            db.commit()
    finally:
        db.close()


create_default_admin()

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@app.post("/auth/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    # 1. Verificar que la contraseña antigua sea correcta
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(
            status_code=400, detail="La contraseña antigua es incorrecta"
        )

    # 2. Validar que la nueva contraseña no sea igual a la antigua (opcional pero recomendado)
    if request.old_password == request.new_password:
        raise HTTPException(
            status_code=400,
            detail="La nueva contraseña debe ser diferente a la anterior",
        )

    # 3. Hashear la nueva contraseña y actualizar el modelo
    current_user.password_hash = hash_password(request.new_password)

    # 4. Guardar los cambios en la base de datos
    db.add(current_user)
    db.commit()

    return {"message": "Contraseña actualizada exitosamente"}

@app.get("/users/me")
def get_user_me(current_user: User = Depends(get_current_user)):
    # Check if this is admin and has default password
    is_default = current_user.username == "admin" and verify_password(
        "admin", current_user.password_hash
    )
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_default_password": is_default,
    }


class NewUserRequest(BaseModel):
    username: str
    password: str


@app.post("/users")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuario ya existe")

    new_user = User(
        username=request.username, password_hash=hash_password(request.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}


@app.get("/users")
def list_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users]


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado"}


class WazuhConfigRequest(BaseModel):
    indexer_url: str
    user: str
    password: str


@app.get("/wazuh-config")
def get_wazuh_config(current_user: User = Depends(get_current_user)):
    return {
        "indexer_url": os.getenv("WAZUH_INDEXER_URL", ""),
        "user": os.getenv("WAZUH_USER", ""),
        "password": "",  # Don't return password directly for security, or return masked
    }


@app.put("/wazuh-config")
def update_wazuh_config(
    request: WazuhConfigRequest, current_user: User = Depends(get_current_user)
):
    env_file = find_dotenv()
    if not env_file:
        env_file = ".env"
        # Create if not exists
        with open(env_file, "a") as f:
            pass

    set_key(env_file, "WAZUH_INDEXER_URL", request.indexer_url)
    set_key(env_file, "WAZUH_USER", request.user)
    if request.password:
        set_key(env_file, "WAZUH_PASSWORD", request.password)

    # Reload environment variables to update current process
    os.environ["WAZUH_INDEXER_URL"] = request.indexer_url
    os.environ["WAZUH_USER"] = request.user
    if request.password:
        os.environ["WAZUH_PASSWORD"] = request.password

    return {
        "message": "Configuración actualizada. Puede requerir reiniciar el backend si wazuh_client.py la carga estáticamente al importar."
    }


@app.get("/wazuh-connections")
def list_connections(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    conns = db.query(WazuhConnection).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "version": c.version,
            "is_active": c.is_active,
        }
        for c in conns
    ]


@app.post("/wazuh-connections", status_code=201)
def create_connection(
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.query(WazuhConnection).filter(WazuhConnection.name == request.name).first():
        raise HTTPException(
            status_code=400, detail="Ya existe una conexión con ese nombre"
        )

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        version=request.version,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}


@app.put("/wazuh-connections/{conn_id}")
def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    conn.version = request.version
    db.commit()
    return {"message": "Conexión actualizada"}


@app.delete("/wazuh-connections/{conn_id}")
def delete_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    db.delete(conn)
    db.commit()
    return {"message": "Conexión eliminada"}


@app.post("/wazuh-connections/{conn_id}/test")
def test_wazuh_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    ok = test_connection(
        conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password)
    )
    return {"ok": ok, "message": "Conexión exitosa" if ok else "No se pudo conectar"}


@app.post("/wazuh-connections/{conn_id}/sync")
def sync_connection(
    conn_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    raw_vulns = fetch_all_vulns(
        conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password), conn.version
    )
    count = 0

    for v in raw_vulns:
        agent = v.get("agent", {})
        host = v.get("host", {})
        osinfo = host.get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        if not vuln.get("id"):
            continue

        existing = (
            db.query(WazuhVulnerability)
            .filter_by(
                connection_id=conn.id,
                agent_id=agent.get("id"),
                package_name=pkg.get("name"),
                package_version=pkg.get("version"),
                cve_id=vuln.get("id"),
            )
            .first()
        )

        if existing:
            existing.severity = vuln.get("severity")
            existing.score_base = (vuln.get("score") or {}).get("base")
            existing.detected_at = vuln.get("detected_at")
            existing.last_seen = func.now()
        else:
            db.add(
                WazuhVulnerability(
                    connection_id=conn.id,
                    agent_id=agent.get("id"),
                    agent_name=agent.get("name"),
                    os_full=osinfo.get("full"),
                    os_platform=osinfo.get("platform"),
                    os_version=osinfo.get("version"),
                    package_name=pkg.get("name"),
                    package_version=pkg.get("version"),
                    package_type=pkg.get("type"),
                    package_arch=pkg.get("architecture"),
                    cve_id=vuln.get("id"),
                    severity=vuln.get("severity"),
                    score_base=(vuln.get("score") or {}).get("base"),
                    score_version=(vuln.get("score") or {}).get("version"),
                    detected_at=vuln.get("detected_at"),
                    published_at=vuln.get("published_at"),
                    description=vuln.get("description"),
                    reference=vuln.get("reference"),
                    scanner_vendor=(vuln.get("scanner") or {}).get("vendor"),
                )
            )
        count += 1

    db.commit()
    return {"synced": count, "connection": conn.name}


@app.post("/vulns/sync-all")
def sync_all_connections(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    # Buscamos todas las conexiones activas
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    results = []

    for conn in conns:
        try:
            # 1. Obtenemos las vulnerabilidades usando la contraseña desencriptada
            raw_vulns = fetch_all_vulns(
                conn.indexer_url,
                conn.wazuh_user,
                decrypt(conn.wazuh_password),
                conn.version,
            )
            count = 0

            # 2. Iteramos sobre cada vulnerabilidad
            for v in raw_vulns:
                agent = v.get("agent", {})
                host = v.get("host", {})
                osinfo = host.get("os") or {}
                pkg = v.get("package", {})
                vuln = v.get("vulnerability", {})

                if not vuln.get("id"):
                    continue

                # 3. Verificamos si ya existe para ESTA conexión específica
                existing = (
                    db.query(WazuhVulnerability)
                    .filter_by(
                        connection_id=conn.id,
                        agent_id=agent.get("id"),
                        package_name=pkg.get("name"),
                        package_version=pkg.get("version"),
                        cve_id=vuln.get("id"),
                    )
                    .first()
                )

                if existing:
                    # Actualizamos si ya existe
                    existing.severity = vuln.get("severity")
                    existing.score_base = (vuln.get("score") or {}).get("base")
                    existing.detected_at = vuln.get("detected_at")
                    existing.last_seen = func.now()
                else:
                    # Insertamos si es nueva
                    db.add(
                        WazuhVulnerability(
                            connection_id=conn.id,
                            agent_id=agent.get("id"),
                            agent_name=agent.get("name"),
                            os_full=osinfo.get("full"),
                            os_platform=osinfo.get("platform"),
                            os_version=osinfo.get("version"),
                            package_name=pkg.get("name"),
                            package_version=pkg.get("version"),
                            package_type=pkg.get("type"),
                            package_arch=pkg.get("architecture"),
                            cve_id=vuln.get("id"),
                            severity=vuln.get("severity"),
                            score_base=(vuln.get("score") or {}).get("base"),
                            score_version=(vuln.get("score") or {}).get("version"),
                            detected_at=vuln.get("detected_at"),
                            published_at=vuln.get("published_at"),
                            description=vuln.get("description"),
                            reference=vuln.get("reference"),
                            scanner_vendor=(vuln.get("scanner") or {}).get("vendor"),
                        )
                    )
                count += 1

            # 4. Guardamos los cambios de esta conexión específica en la BD
            db.commit()
            results.append({"connection": conn.name, "synced": count, "ok": True})

        except Exception as e:
            # Si algo falla con esta conexión (ej. credenciales malas), revertimos sus cambios
            db.rollback()
            results.append({"connection": conn.name, "ok": False, "error": str(e)})

    return results



@app.get("/vulns")
def list_vulns(
    limit: int = 100,
    connection_id: int = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vulns = db.query(WazuhVulnerability).limit(limit).all()
    return vulns


@app.get("/users/me")
def get_user_me(current_user: User = Depends(get_current_user)):
    # Check if this is admin and has default password
    is_default = current_user.username == "admin" and verify_password(
        "admin", current_user.password_hash
    )
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_default_password": is_default,
    }


class NewUserRequest(BaseModel):
    username: str
    password: str


@app.post("/users")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuario ya existe")

    new_user = User(
        username=request.username, password_hash=hash_password(request.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}


class WazuhConfigRequest(BaseModel):
    indexer_url: str
    user: str
    password: str


@app.get("/wazuh-config")
def get_wazuh_config(current_user: User = Depends(get_current_user)):
    return {
        "indexer_url": os.getenv("WAZUH_INDEXER_URL", ""),
        "user": os.getenv("WAZUH_USER", ""),
        "password": "",  # Don't return password directly for security, or return masked
    }


@app.put("/wazuh-config")
def update_wazuh_config(
    request: WazuhConfigRequest, current_user: User = Depends(get_current_user)
):
    env_file = find_dotenv()
    if not env_file:
        env_file = ".env"
        # Create if not exists
        with open(env_file, "a") as f:
            pass

    set_key(env_file, "WAZUH_INDEXER_URL", request.indexer_url)
    set_key(env_file, "WAZUH_USER", request.user)
    if request.password:
        set_key(env_file, "WAZUH_PASSWORD", request.password)

    # Reload environment variables to update current process
    os.environ["WAZUH_INDEXER_URL"] = request.indexer_url
    os.environ["WAZUH_USER"] = request.user
    if request.password:
        os.environ["WAZUH_PASSWORD"] = request.password

    return {
        "message": "Configuración actualizada. Puede requerir reiniciar el backend si wazuh_client.py la carga estáticamente al importar."
    }

