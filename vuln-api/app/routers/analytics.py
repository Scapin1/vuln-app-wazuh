# app/routers/analytics.py
import logging
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..db import get_db
from ..service.analytics_service import get_date_filters
from ..models import Asset, User, VulnerabilityCatalog, VulnerabilityDetection, WazuhConnection
from ..schemas import (
    AnalyticsSummaryResponse,
    CriticalVulnViewDTO,
    DashboardSummaryResponse,
    FilterOptionsResponse,
    GanttTimelineResponse,
    TimelineEventsResponse,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter()


@router.get("/vulns/dashboard", response_model=DashboardSummaryResponse)
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

@router.get("/vulns/timeline/gantt", response_model=GanttTimelineResponse)
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

@router.get("/vulns/analytics", response_model=AnalyticsSummaryResponse)
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

@router.get("/vulns/filter-options", response_model=FilterOptionsResponse)
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

@router.get("/vulns/events", response_model=TimelineEventsResponse)
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
        .where(
            Asset.wazuh_connection_id == connection_id,
            VulnerabilityDetection.timestamp >= start_dt,
            VulnerabilityDetection.timestamp <= end_dt
        )
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


# ===================================================================
# Vistas Materializadas
# ===================================================================

@router.post("/vulns/analytics/refresh-critical", tags=["Analytics"])
async def refresh_critical_view(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db)
):
    try:
        await db.execute(text("SELECT refresh_critical_vulns_view();"))
        await db.commit()

        return {
            "status": "success",
            "message": "Analíticas críticas actualizadas correctamente."
        }
    except Exception as e:
        await db.rollback()
        logger.error(f"Error actualizando la vista materializada: {e}")

        raise HTTPException(
            status_code=500,
            detail="Error interno al intentar actualizar las analíticas. Contacte al administrador."
        )

@router.get(
    "/vulns/analytics/critical-view",
    response_model=List[CriticalVulnViewDTO],
    tags=["Analytics"]
)
async def get_critical_vulnerabilities_view(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db)
):
    query = """
        SELECT
            cve_id,
            cvss_score,
            description,
            total_affected_agents,
            affected_wazuh_agent_ids,
            affected_hostnames
        FROM mv_critical_vulnerabilities
        ORDER BY total_affected_agents DESC;
    """

    result = await db.execute(text(query))
    rows = result.mappings().all()
    response_data = []
    for row in rows:
        response_data.append({
            "cve_id": row["cve_id"],
            "cvss_score": float(row["cvss_score"]) if row["cvss_score"] else None,
            "description": row["description"],
            "total_affected_agents": row["total_affected_agents"],
            "affected_wazuh_agent_ids": row["affected_wazuh_agent_ids"] or [],
            "affected_hostnames": row["affected_hostnames"] or []
        })

    return response_data
