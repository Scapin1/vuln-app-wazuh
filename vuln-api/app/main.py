# app/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Annotated
from pydantic import BaseModel

from .db import Base, engine, get_db, SessionLocal
from .models import User, WazuhVulnerability
from .auth import authenticate_user, create_access_token, get_current_user, hash_password, verify_password
from .wazuh_client import fetch_all_vulns

Base.metadata.create_all(bind=engine)

def create_default_admin():
    db = SessionLocal()
    try:
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            print("Creando usuario admin default...")
            default_admin = User(
                    username="admin",
                    password_hash=hash_password("admin")
                    )
            db.add(default_admin)
            db.commit()
    finally:
        db.close()

create_default_admin()

app = FastAPI(title="Vulnerability Aggregator API")

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
    db: Session = Depends(get_db), 
    current_user: Annotated[User, Depends(get_current_user)]
):
    # 1. Verificar que la contraseña antigua sea correcta
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(
            status_code=400, 
            detail="La contraseña antigua es incorrecta"
        )
    
    # 2. Validar que la nueva contraseña no sea igual a la antigua (opcional pero recomendado)
    if request.old_password == request.new_password:
        raise HTTPException(
            status_code=400, 
            detail="La nueva contraseña debe ser diferente a la anterior"
        )

    # 3. Hashear la nueva contraseña y actualizar el modelo
    current_user.password_hash = hash_password(request.new_password)
    
    # 4. Guardar los cambios en la base de datos
    db.add(current_user)
    db.commit()
    
    return {"message": "Contraseña actualizada exitosamente"}

@app.post("/vulns/sync")
def sync_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    raw_vulns = fetch_all_vulns()
    count = 0

    for v in raw_vulns:
        agent = v.get("agent", {})
        host = v.get("host", {})
        osinfo = host.get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        if not vuln.get("id"):
            continue

        existing = db.query(WazuhVulnerability).filter_by(
            agent_id=agent.get("id"),
            package_name=pkg.get("name"),
            package_version=pkg.get("version"),
            cve_id=vuln.get("id"),
        ).first()

        if existing:
            existing.severity = vuln.get("severity")
            existing.score_base = (vuln.get("score") or {}).get("base")
            existing.score_version = (vuln.get("score") or {}).get("version")
            existing.detected_at = vuln.get("detected_at")
            existing.published_at = vuln.get("published_at")
            existing.description = vuln.get("description")
            existing.reference = vuln.get("reference")
            existing.scanner_vendor = (vuln.get("scanner") or {}).get("vendor")
        else:
            item = WazuhVulnerability(
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
            db.add(item)
        count += 1

    db.commit()
    return {"synced": count}

@app.get("/vulns")
def list_vulns(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    vulns = db.query(WazuhVulnerability).limit(limit).all()
    return vulns


