# app/main.py
from collections import defaultdict
import math
from operator import and_, or_
import re
import os
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import set_key, find_dotenv
from httpx import request
from sqlalchemy.orm import Session, joinedload
from datetime import datetime, time, timedelta, timezone
from uuid import UUID
from typing import List, Annotated, Literal, Optional, Dict, Set, Any, Tuple
from pydantic import BaseModel
from sqlalchemy.sql import func
from sqlalchemy import select, insert, update, delete, text
from .db import Base, engine, get_db
from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .wazuh_client import fetch_all_vulns, check_connection
from .crypto import encrypt, decrypt
from .models import Asset, VulnerabilityCatalog, VulnerabilityDetection, User, WazuhConnection
from .schemas import (
    AnalyticsSummaryResponse, DashboardSummaryResponse, FilterOptionsResponse, GanttTimelineResponse, SnapshotSchema, TimelineCVESchema, TimelineEventsResponse, UserCreate, UserOut, AssetCreate, AssetOut, 
    CatalogCreate, CatalogOut, DetectionCreate, DetectionOut, 
    VulnStatus, AssetUpdate, CatalogUpdate,
) 
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert
from datetime import datetime

CONNECTION_NOT_FOUND = "Conexión no encontrada"


class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str


class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    is_active: bool

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post(
    "/auth/login", 
    responses={400: {"description": "Email o contraseña incorrectos"}}
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(User).where(User.user_email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.user_password):
        raise HTTPException(status_code=400, detail="Email o contraseña incorrectos")
    
    access_token = create_access_token(data={"sub": user.user_email})
    return {"access_token": access_token, "token_type": "bearer"}


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str 

def validate_strong_password(password: str) -> None:
    errors = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errors.append("al menos una letra minúscula")
    if not re.search(r"\d", password):
        errors.append("al menos un número")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        errors.append("al menos un carácter especial")
    
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )

@app.post(
    "/auth/change-password", 
    responses={400: {"description": "Error en la validación de contraseñas"}}
)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not verify_password(request.old_password, current_user.user_password):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")
    if request.old_password == request.new_password:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe ser diferente")
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    
    validate_strong_password(request.new_password)
    
    current_user.user_password = hash_password(request.new_password)
    current_user.user_status = True
    db.add(current_user)
    await db.commit()
    return {"message": "Contraseña actualizada exitosamente"}

@app.get("/users/me", tags=["Users"])
async def get_user_me(current_user: Annotated[User, Depends(get_current_user)]):
    return {
        "id": current_user.user_id,
        "username": current_user.user_name,
        "email": current_user.user_email,
        "is_active": current_user.user_status,
        "rol": current_user.user_rol
    }

@app.get("/users", tags=["Users"])
async def list_users(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return [{"id": u.user_id, "username": u.user_name} for u in users]

# ==========================================================
# WAZUH CONNECTIONS
# ==========================================================

@app.get("/wazuh-connections", tags=["Wazuh"])
async def list_connections(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(WazuhConnection))
    conns = result.scalars().all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "is_active": c.is_active,
            "tested": c.tested,
            "last_tested_at": c.last_tested_at,
            "last_test_ok": c.last_test_ok,
        }
        for c in conns
    ]

@app.post("/wazuh-connections", status_code=201, tags=["Wazuh"])
async def create_connection(
    request: WazuhConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    query = select(WazuhConnection).where(WazuhConnection.name == request.name)
    existing = (await db.execute(query)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Ya existe una conexión con ese nombre")

    ok = check_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
    if not ok:
        raise HTTPException(status_code=400, detail="No se pudo establecer conexión con Wazuh")

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        tested=True,
        last_tested_at=func.now(),
        last_test_ok=True,
    )
    db.add(conn)
    await db.commit()
    await db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}

@app.put("/wazuh-connections/{conn_id}", tags=["Wazuh"])
async def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    
    await db.commit()
    return {"message": "Conexión actualizada"}

@app.post("/wazuh-connections/{conn_id}/test", tags=["Wazuh"])
async def test_existing_wazuh_connection(
    conn_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    ok = check_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))

    conn.tested = True
    conn.last_tested_at = func.now()
    conn.last_test_ok = ok
    await db.commit()
    return {"ok": ok, "message": "Conexión exitosa" if ok else "Fallo al conectar"}

@app.delete(
    "/wazuh-connections/{conn_id}",
    responses={
        404: {
            "description": "Conexión no encontrada",
            "content": {
                "application/json": {
                    "example": {"detail": "Conexión no encontrada"}
                }
            },
        }
    },
    tags=["Wazuh"]
)
async def delete_connection(
    conn_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    conn = await db.get(WazuhConnection, conn_id)
    
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    
    await db.delete(conn)
    await db.commit()
    
    return {"message": "Conexión eliminada correctamente"}

# ==========================================================
# VULNERABILITIES & SYNC
# ==========================================================

def get_date_filters(period: str, date: Optional[str], model_col):
    now = datetime.now(timezone.utc)
    if period == "24h":
        return [model_col >= (now - timedelta(hours=24))]
    elif period == "7d":
        return [model_col >= (now - timedelta(days=7))]
    elif period == "30d":
        return [model_col >= (now - timedelta(days=30))]
    elif period == "day":
        if not date:
            raise HTTPException(status_code=400, detail={"error": "Falta parámetro date"})
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
            start_of_day = datetime.combine(target_date, time.min).replace(tzinfo=timezone.utc)
            return [model_col >= start_of_day, model_col < start_of_day + timedelta(days=1)]
        except ValueError:
            raise HTTPException(status_code=400, detail={"error": "Formato de fecha inválido"})
    elif period == "all":
        return []
    else:
        raise HTTPException(status_code=400, detail={"error": "Periodo no válido"})


@app.get("/api/vulns/dashboard", response_model=DashboardSummaryResponse)
async def get_vulns_dashboard(
    connection_id: int = Query(..., description="ID de conexión Wazuh (requerido)"),
    period: Literal["24h", "7d", "30d", "day", "all"] = Query("30d"),
    date: Optional[str] = Query(None, description="Si period=day, fecha YYYY-MM-DD"),
    db: AsyncSession = Depends(get_db)
):

    where_clauses = [Asset.wazuh_connection_id == connection_id]
    where_clauses.extend(get_date_filters(period, date, VulnerabilityDetection.timestamp))
    
    stmt_sev = (
        select(VulnerabilityCatalog.severity, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
        .where(and_(*where_clauses))
        .group_by(VulnerabilityCatalog.severity)
    )
    res_sev = await db.execute(stmt_sev)

    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in res_sev.all():
        sev = (row[0] or "").upper()
        if sev in severity_distribution:
            severity_distribution[sev] += row[1]

    stmt_status = (
        select(VulnerabilityDetection.status, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .where(and_(*where_clauses))
        .group_by(VulnerabilityDetection.status)
    )
    res_status = await db.execute(stmt_status)

    status_distribution = {"Detected": 0, "Resolved": 0, "Re-emerged": 0}
    total = 0
    for row in res_status.all():
        status_val = row[0].value if hasattr(row[0], 'value') else str(row[0])
        if status_val in status_distribution:
            status_distribution[status_val] += row[1]
        total += row[1]

    return {
        "severity_distribution": severity_distribution,
        "status_distribution": status_distribution,
        "total": total
    }

@app.get("/api/vulns/timeline/gantt", response_model=GanttTimelineResponse)
async def get_vulns_timeline_gantt(
    connection_id: int = Query(..., description="ID de conexión (requerido)"),
    period: Literal["24h", "7d", "30d", "day", "all"] = Query("all"),
    date: Optional[str] = Query(None, description="Si period=day, fecha YYYY-MM-DD"),
    agent: Optional[str] = Query(None, description="Filtrar por agent_name"),
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = Query(None),
    search: Optional[str] = Query(None, description="Búsqueda parcial en cve_id o description"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):

    where_clauses = [Asset.wazuh_connection_id == connection_id]
    where_clauses.extend(get_date_filters(period, date, VulnerabilityDetection.timestamp))

    if agent:
        where_clauses.append(Asset.hostname.ilike(f"%{agent}%"))
    if severity:
        where_clauses.append(VulnerabilityCatalog.severity.ilike(severity))
    if search:
        where_clauses.append(or_(
            VulnerabilityCatalog.cve_id.ilike(f"%{search}%"),
            VulnerabilityCatalog.description.ilike(f"%{search}%")
        ))

    stmt_bounds = (
        select(func.min(VulnerabilityDetection.timestamp), func.max(VulnerabilityDetection.timestamp))
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
        .where(and_(*where_clauses))
    )
    res_bounds = await db.execute(stmt_bounds)
    min_ts, max_ts = res_bounds.one_or_none() or (None, None)

    stmt_count = (
        select(func.count(func.distinct(VulnerabilityDetection.cve_id)))
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
        .where(and_(*where_clauses))
    )
    total_cves = (await db.execute(stmt_count)).scalar() or 0
    total_pages = math.ceil(total_cves / per_page) if total_cves > 0 else 0

    stmt_page_cves = (
        select(VulnerabilityCatalog.cve_id, VulnerabilityCatalog.severity, VulnerabilityCatalog.description)
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
        .where(and_(*where_clauses))
        .distinct()
        .order_by(VulnerabilityCatalog.cve_id)
        .limit(per_page)
        .offset((page - 1) * per_page)
    )
    page_cves = (await db.execute(stmt_page_cves)).all()

    cves_response = []
    if page_cves:
        target_cve_ids = [row[0] for row in page_cves]
 
        stmt_snaps = (
            select(
                VulnerabilityDetection.cve_id,
                VulnerabilityDetection.timestamp,
                Asset.hostname,
                VulnerabilityDetection.status
            )
            .select_from(VulnerabilityDetection)
            .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
            .where(and_(VulnerabilityDetection.cve_id.in_(target_cve_ids), *where_clauses))
            .order_by(VulnerabilityDetection.cve_id, VulnerabilityDetection.timestamp.asc())
        )
        all_snapshots = (await db.execute(stmt_snaps)).all()

        grouped_data = defaultdict(lambda: defaultdict(list))
        for c_id, ts, ag_name, st in all_snapshots:
            st_val = st.value if hasattr(st, 'value') else str(st)
            grouped_data[c_id][ts].append((ag_name, st_val))

        for cve_id, sev, desc in page_cves:
            cve_map = grouped_data[cve_id]
            sorted_ts = sorted(cve_map.keys())

            snapshots_list = []
            for ts in sorted_ts:
                active_agents = [a for a, st in cve_map[ts] if st in ("Detected", "Re-emerged")]
                agent_count = len(active_agents)
                agents_payload = active_agents if agent_count <= 500 else None

                snapshots_list.append({
                    "sync_timestamp": ts.isoformat(),
                    "agent_count": agent_count,
                    "agents": agents_payload
                })

            is_resolved = snapshots_list[-1]["agent_count"] == 0 if snapshots_list else False

            cves_response.append({
                "cve_id": cve_id,
                "severity": (sev or "").upper(),
                "description": desc,
                "snapshots": snapshots_list,
                "first_sync": sorted_ts[0].isoformat() if sorted_ts else None,
                "last_sync": sorted_ts[-1].isoformat() if sorted_ts else None,
                "is_resolved": is_resolved
            })

    return {
        "cves": cves_response,
        "total_cves": total_cves,
        "total_pages": total_pages,
        "current_page": page,
        "per_page": per_page,
        "min_timestamp": min_ts.isoformat() if min_ts else None,
        "max_timestamp": max_ts.isoformat() if max_ts else None
    }

@app.get("/api/vulns/analytics", response_model=AnalyticsSummaryResponse)
async def get_vulns_analytics_summary(
    connection_id: int = Query(..., description="ID de conexión (requerido)"),
    period: Literal["24h", "7d", "30d", "day", "all"] = Query("30d"),
    date: Optional[str] = Query(None, description="Si period=day, fecha YYYY-MM-DD"),
    db: AsyncSession = Depends(get_db)
):
    where_clauses = [Asset.wazuh_connection_id == connection_id]
    where_clauses.extend(get_date_filters(period, date, VulnerabilityDetection.timestamp))

    stmt_severity = (
        select(VulnerabilityCatalog.severity, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
        .where(and_(*where_clauses))
        .group_by(VulnerabilityCatalog.severity)
    )
    res_severity = await db.execute(stmt_severity)
 
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in res_severity.all():
        sev_label = (row[0] or "").upper()
        if sev_label in severity_distribution:
            severity_distribution[sev_label] += row[1]

    critical_count = severity_distribution["CRITICAL"]


    stmt_status = (
        select(VulnerabilityDetection.status, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .where(and_(*where_clauses))
        .group_by(VulnerabilityDetection.status)
    )
    res_status = await db.execute(stmt_status)

    status_distribution = {"Activo": 0, "Resuelto": 0, "Reabierto": 0}
    for row in res_status.all():
        status_val = row[0].value if hasattr(row[0], 'value') else str(row[0])
        if status_val == "Detected":
            status_distribution["Activo"] += row[1]
        elif status_val == "Resolved":
            status_distribution["Resuelto"] += row[1]
        elif status_val == "Re-emerged":
            status_distribution["Reabierto"] += row[1]

    stmt_top_agents = (
        select(Asset.hostname, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .where(and_(*where_clauses))
        .group_by(Asset.hostname)
        .order_by(func.count().desc())
        .limit(10)
    )
    res_top_agents = await db.execute(stmt_top_agents)
    top_agents = [{"agent": row[0] or "Unknown", "count": row[1]} for row in res_top_agents.all()]

    top_critical_cve = None
    if critical_count > 0:
        stmt_top_cve = (
            select(VulnerabilityDetection.cve_id, func.count())
            .select_from(VulnerabilityDetection)
            .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
            .join(VulnerabilityCatalog, VulnerabilityDetection.cve_id == VulnerabilityCatalog.cve_id)
            .where(and_(*where_clauses, VulnerabilityCatalog.severity.ilike("CRITICAL")))
            .group_by(VulnerabilityDetection.cve_id)
            .order_by(func.count().desc())
            .limit(1)
        )
        res_top_cve = await db.execute(stmt_top_cve)
        top_cve_row = res_top_cve.first()
        if top_cve_row:
            top_critical_cve = top_cve_row[0]

    return {
        "severity_distribution": severity_distribution,
        "status_distribution": status_distribution,
        "top_agents": top_agents,
        "critical_count": critical_count,
        "top_critical_cve": top_critical_cve
    }

@app.get("/api/vulns/filter-options", response_model=FilterOptionsResponse)
async def get_vulns_filter_options(
    connection_id: int = Query(..., description="ID de conexión (requerido)"),
    db: AsyncSession = Depends(get_db)
):
    stmt_agents = (
        select(Asset.hostname, func.count())
        .select_from(Asset)
        .join(VulnerabilityDetection, Asset.asset_id == VulnerabilityDetection.asset_id)
        .where(Asset.wazuh_connection_id == connection_id)
        .group_by(Asset.hostname)
        .order_by(Asset.hostname.asc())
    )
    res_agents = await db.execute(stmt_agents)
    agents_list = [{"name": row[0], "count": row[1]} for row in res_agents.all() if row[0]]

    stmt_cves = (
        select(VulnerabilityDetection.cve_id, func.count())
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .where(Asset.wazuh_connection_id == connection_id)
        .group_by(VulnerabilityDetection.cve_id)
        .order_by(VulnerabilityDetection.cve_id.asc())
    )
    res_cves = await db.execute(stmt_cves)
    cves_list = [{"id": row[0], "count": row[1]} for row in res_cves.all() if row[0]]

    return {
        "agents": agents_list,
        "cves": cves_list
    }

@app.get("/api/vulns/events", response_model=TimelineEventsResponse)
async def get_vulns_timeline_events(
    connection_id: int = Query(..., description="ID de conexión (requerido)"),
    start_ms: int = Query(..., description="Unix ms del inicio del rango"),
    end_ms: int = Query(..., description="Unix ms del fin del rango"),
    db: AsyncSession = Depends(get_db)
):
    stmt_conn = select(WazuhConnection.id).where(WazuhConnection.id == connection_id)
    conn_exists = (await db.execute(stmt_conn)).scalar()
    if not conn_exists:
        raise HTTPException(status_code=404, detail={"error": "Conexión no encontrada"})

    try:
        start_dt = datetime.fromtimestamp(start_ms / 1000.0, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end_ms / 1000.0, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        raise HTTPException(status_code=400, detail={"error": "Rango de tiempo inválido"})


    stmt = (
        select(
            VulnerabilityDetection.cve_id,
            VulnerabilityDetection.timestamp,
            Asset.hostname,
            VulnerabilityDetection.status
        )
        .select_from(VulnerabilityDetection)
        .join(Asset, VulnerabilityDetection.asset_id == Asset.asset_id)
        .where(and_(
            Asset.wazuh_connection_id == connection_id,
            VulnerabilityDetection.timestamp >= start_dt,
            VulnerabilityDetection.timestamp <= end_dt
        ))
        .order_by(VulnerabilityDetection.timestamp.asc())
    )
    
    result = await db.execute(stmt)

    detections_list = []
    resolutions_list = []
    
    for cve_id, ts, hostname, status in result.all():
        status_val = status.value if hasattr(status, 'value') else str(status)
        event_data = {
            "cve_id": cve_id,
            "timestamp": ts.isoformat(),
            "agent": hostname or "Desconocido"
        }
        
        if status_val in ("Detected", "Re-emerged"):
            detections_list.append(event_data)
        elif status_val == "Resolved":
            resolutions_list.append(event_data)

    return {
        "detections": detections_list,
        "resolutions": resolutions_list
    }


@app.post("/wazuh-connections/{conn_id}/sync", tags=["Sync"])
async def sync_connection(
    conn_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    conn = await db.get(WazuhConnection, conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    raw_vulns = await fetch_all_vulns(
        conn.indexer_url, 
        conn.wazuh_user, 
        decrypt(conn.wazuh_password)
    )

    count = await process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
    await db.commit()

    return {"synced": count, "connection": conn.name}

def chunk_list(data_list: list, chunk_size: int):
    for i in range(0, len(data_list), chunk_size):
        yield data_list[i:i + chunk_size]

async def process_wazuh_vulnerabilities(db: AsyncSession, conn_id: int, raw_vulns: list) -> int:
    if not raw_vulns:
        return 0

    assets_data: Dict[str, dict] = {}
    catalog_data: Dict[str, dict] = {}

    for v in raw_vulns:
        agent = v.get("agent", {})
        vuln = v.get("vulnerability", {})

        agent_id = str(agent.get("id"))
        cve_id = vuln.get("id")

        if not agent_id or not cve_id: 
            continue

        if agent_id not in assets_data:
            assets_data[agent_id] = {
                "wazuh_agent_id": agent_id,
                "hostname": agent.get("name", "Unknown"),
                "os_version": agent.get("os", {}).get("full"),
                "wazuh_connection_id": conn_id  # Enlazado directamente al ID de WazuhConnection
            }

        if cve_id not in catalog_data:
            catalog_data[cve_id] = {
                "cve_id": cve_id,
                "severity": vuln.get("severity", "Unknown"),
                "description": vuln.get("description"),
                "cvss_score": (vuln.get("score") or {}).get("base")
            }

    if catalog_data:
        catalog_items = list(catalog_data.values())
        for chunk in chunk_list(catalog_items, 1000):
            stmt_catalog = pg_insert(VulnerabilityCatalog).values(chunk)
            stmt_catalog = stmt_catalog.on_conflict_do_nothing(index_elements=['cve_id'])
            await db.execute(stmt_catalog)

    if assets_data:
        assets_items = list(assets_data.values())
        for chunk in chunk_list(assets_items, 1000):
            stmt_assets = pg_insert(Asset).values(chunk)
            stmt_assets = stmt_assets.on_conflict_do_nothing(index_elements=['wazuh_agent_id'])
            await db.execute(stmt_assets)

    agent_wazuh_ids = list(assets_data.keys())
    result_assets = await db.execute(
        select(Asset.asset_id, Asset.wazuh_agent_id).where(Asset.wazuh_agent_id.in_(agent_wazuh_ids))
    )
    asset_map = {row.wazuh_agent_id: row.asset_id for row in result_assets.all()}

    if not asset_map:
        return 0

    query_last_state = """
        SELECT DISTINCT ON (d.asset_id, d.cve_id)
            d.asset_id, d.cve_id, d.status
        FROM vulnerability_detections d
        JOIN assets a ON d.asset_id = a.asset_id
        WHERE a.wazuh_connection_id = :conn_id
        ORDER BY d.asset_id, d.cve_id, d.timestamp DESC
    """
    
    result_state = await db.execute(
        text(query_last_state), 
        {"conn_id": conn_id}
    )
    
    current_state: Dict[Tuple[UUID, str], VulnStatus] = {
        (row.asset_id, row.cve_id): row.status for row in result_state.fetchall()
    }

    detections_to_insert: List[Dict[str, Any]] = []
    seen_in_payload: Set[Tuple[UUID, str]] = set()
    inserted_in_loop: Set[Tuple[UUID, str]] = set()
    current_timestamp = datetime.now(timezone.utc)

    for v in raw_vulns:
        agent_id = str(v.get("agent", {}).get("id"))
        cve_id = v.get("vulnerability", {}).get("id")
        pkg = v.get("package", {})

        asset_uuid = asset_map.get(agent_id)
        if not asset_uuid or not cve_id:
            continue

        pair_key = (asset_uuid, cve_id)
        seen_in_payload.add(pair_key)

        if pair_key in inserted_in_loop:
            continue

        detected_at_str = v.get("vulnerability", {}).get("detected_at")
        first_seen = parse_wazuh_date(detected_at_str) if detected_at_str else current_timestamp

        detections_to_insert.append({
            "timestamp": current_timestamp,
            "asset_id": asset_uuid,
            "cve_id": cve_id,
            "status": VulnStatus.Detected,
            "first_seen_at": first_seen,
            "package_name": pkg.get("name"),
            "package_version": pkg.get("version")
        })
        inserted_in_loop.add(pair_key)

    # Si en la BD el último estado era 'Detected' pero ya no existe en este payload, insertamos un registro de tipo 'Resolved'.
    for (asset_uuid, cve_id), status in current_state.items():
        if status == VulnStatus.Detected and (asset_uuid, cve_id) not in seen_in_payload:
            pair_key = (asset_uuid, cve_id)
            if pair_key in inserted_in_loop:
                continue
            
            detections_to_insert.append({
                "timestamp": current_timestamp,
                "asset_id": asset_uuid,
                "cve_id": cve_id,
                "status": VulnStatus.Resolved,
                "first_seen_at": current_timestamp, 
                "package_name": None,
                "package_version": None
            })
            inserted_in_loop.add(pair_key)

    if detections_to_insert:
        for chunk in chunk_list(detections_to_insert, 1000):
            await db.execute(pg_insert(VulnerabilityDetection).values(chunk))

    return len(detections_to_insert)

def parse_wazuh_date(date_str: str):
    if not date_str or date_str == "not defined":
        return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except Exception:
        return None


@app.get("/vulns", tags=["Read"])
async def list_vulns(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=10000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    connection_id: Optional[int] = None,
):
    query = select(VulnerabilityDetection).options(
        joinedload(VulnerabilityDetection.asset),
        joinedload(VulnerabilityDetection.catalog_entry)
    )

    count_query = select(func.count()).select_from(VulnerabilityDetection)

    if connection_id:
        query = query.join(Asset).where(Asset.wazuh_connection_id == connection_id)
        count_query = count_query.join(Asset).where(Asset.wazuh_connection_id == connection_id)
    
    query = query.order_by(VulnerabilityDetection.timestamp.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    vulns = result.scalars().all()

    total_result = await db.execute(count_query)
    total_count = total_result.scalar() or 0

    data = [
        {
            "id": f"{v.asset_id}-{v.cve_id}", 
            "connection_id": v.asset.wazuh_connection_id if v.asset else None,
            "status": v.status.value if hasattr(v.status, 'value') else v.status,
            "agent_id": v.asset.wazuh_agent_id if v.asset else None,
            "agent_name": v.asset.hostname if v.asset else None,
            "os_full": v.asset.os_version if v.asset else None,
            "package_name": v.package_name,
            "package_version": v.package_version,
            "cve_id": v.cve_id,
            "severity": v.catalog_entry.severity if v.catalog_entry else None,
            "score_base": float(v.catalog_entry.cvss_score) if v.catalog_entry and v.catalog_entry.cvss_score else None,
            "description": v.catalog_entry.description if v.catalog_entry else None,
            "first_seen": v.first_seen_at,
            "last_seen": v.timestamp
        }
        for v in vulns
    ]

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "data": data
    }

@app.post("/vulns/sync-all", tags=["Sync"])
async def sync_all_connections(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    query = select(WazuhConnection).where(WazuhConnection.is_active == True)
    result = await db.execute(query)
    conns = result.scalars().all()
    
    results = []

    for conn in conns:
        conn_id = conn.id
        conn_name = conn.name
        conn_indexer_url = conn.indexer_url
        conn_wazuh_user = conn.wazuh_user
        wazuh_password_plain = decrypt(conn.wazuh_password)

        try:

            total_count = 0

            async for vulns_batch in fetch_all_vulns(
                conn_indexer_url, 
                conn_wazuh_user, 
                wazuh_password_plain
            ):
                batch_count = await process_wazuh_vulnerabilities(db, conn_id, vulns_batch)
                total_count += batch_count
                await db.commit()
            
            results.append({
                "connection": conn_name,
                "synced": total_count, 
                "ok": True
            })
            
        except Exception as e:
            await db.rollback()
            results.append({
                "connection": conn_name,
                "ok": False, 
                "synced_before_error": total_count,
                "error": str(e)
            })
            continue

    return results

###  TIMESCALEDB funciones  ###

# ==========================================================
# 1. CREATE
# ==========================================================

@app.post("/users", tags=["Users"])
async def create_user(
    request: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(User).where(User.user_email == request.user_email))
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(status_code=400, detail="El email/usuario ya está ocupado.")

    new_user = User(
        user_name=request.user_name, 
        user_email=request.user_email,
        user_password=hash_password(request.user_password),
        user_status=True,
    )
    db.add(new_user)
    await db.commit()
    return {"message": "Usuario creado"}


@app.post("/assets/", response_model=AssetOut, tags=["Create"])
async def create_asset(
    data: AssetCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_asset = Asset(**data.model_dump())
    db.add(nuevo_asset)
    await db.commit()
    await db.refresh(nuevo_asset)
    return nuevo_asset

@app.post("/catalog/", tags=["Create"])
async def create_catalog(
    data: CatalogCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    nuevo_cve = VulnerabilityCatalog(**data.model_dump())
    db.add(nuevo_cve)
    await db.commit()
    return {"message": "CVE guardado exitosamente"}

@app.post("/detections/", response_model=DetectionOut, tags=["Create"])
async def create_detection(
    data: DetectionCreate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    # Verificación de existencia del Asset
    asset_check = await db.get(Asset, data.asset_id)
    if not asset_check:
        raise HTTPException(status_code=404, detail="El Asset no existe")

    # Lógica de primera detección en TimescaleDB
    query = select(VulnerabilityDetection).where(
        VulnerabilityDetection.asset_id == data.asset_id,
        VulnerabilityDetection.cve_id == data.cve_id
    ).order_by(VulnerabilityDetection.timestamp.asc()).limit(1)
    
    result = await db.execute(query)
    first_record = result.scalars().first()

    fecha_primera_vez = first_record.first_seen_at if first_record else datetime.now(timezone.utc)

    nueva_deteccion = VulnerabilityDetection(
        asset_id=data.asset_id,
        cve_id=data.cve_id,
        package_name=data.package_name,
        package_version=data.package_version,
        first_seen_at=fecha_primera_vez,
        status=VulnStatus.Detected
    )
    
    db.add(nueva_deteccion)
    await db.commit()
    return nueva_deteccion

# ==========================================================
# 2. READ
# ==========================================================


@app.get("/assets/", response_model=List[AssetOut], tags=["Read"])
async def get_assets(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(Asset))
    return result.scalars().all()

@app.get("/catalog/", response_model=List[CatalogOut], tags=["Read"])
async def get_catalog(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(VulnerabilityCatalog))
    return result.scalars().all()

@app.get("/detections/", response_model=List[DetectionOut], tags=["Read"])
async def get_all_detections(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(
        select(VulnerabilityDetection)
        .options(
            joinedload(VulnerabilityDetection.asset),
            joinedload(VulnerabilityDetection.catalog_entry)
        )
        .order_by(VulnerabilityDetection.timestamp.desc())
    )
    return result.scalars().all()

@app.get("/detections/{asset_id}", response_model=List[DetectionOut], tags=["Read"])
async def get_asset_history(
    asset_id: UUID, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    query = (
        select(VulnerabilityDetection)
        .where(VulnerabilityDetection.asset_id == asset_id)
        .options(
            joinedload(VulnerabilityDetection.asset),
            joinedload(VulnerabilityDetection.catalog_entry)
        )
        .order_by(VulnerabilityDetection.timestamp.desc()) 
    ) 
    
    result = await db.execute(query)
    history = result.scalars().all() 
    if not history:
        raise HTTPException(status_code=404, detail="No se encontraron detecciones")     
    return history

# ==========================================================
# 3. UPDATE
# ==========================================================


@app.patch("/assets/{asset_id}", response_model=AssetOut, tags=["Update"])
async def update_asset(
    asset_id: UUID, 
    data: AssetUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    db_asset = result.scalar_one_or_none()
    
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_asset, key, value)
        
    await db.commit()
    await db.refresh(db_asset)
    return db_asset

@app.patch("/catalog/{cve_id}", response_model=CatalogOut, tags=["Update"])
async def update_catalog(
    cve_id: str, 
    data: CatalogUpdate, 
    db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(VulnerabilityCatalog).where(VulnerabilityCatalog.cve_id == cve_id))
    db_cve = result.scalar_one_or_none()
    
    if not db_cve:
        raise HTTPException(status_code=404, detail="CVE no encontrado")
    
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_cve, key, value)
        
    await db.commit()
    await db.refresh(db_cve)
    return db_cve