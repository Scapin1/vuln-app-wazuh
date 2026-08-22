# app/routers/sync.py
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from ..auth import get_current_user
from ..crypto import decrypt
from ..db import get_db
from ..models import Asset, User, VulnerabilityDetection, WazuhConnection
from ..service.sync_service import chunk_list, parse_wazuh_date, process_wazuh_vulnerabilities
from ..wazuh_client import fetch_all_vulns

router = APIRouter()


@router.post("/wazuh-connections/{conn_id}/sync", tags=["Sync"])
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

    total_synced = 0

    try:
        async for batch in fetch_all_vulns(
            conn.indexer_url,
            conn.wazuh_user,
            decrypt(conn.wazuh_password)
        ):
            count = await process_wazuh_vulnerabilities(db, conn.id, batch)
            total_synced += count

        await db.commit()
        return {"synced": total_synced, "connection": conn.name, "ok": True}
    except Exception as e:
        await db.rollback()
        return {"synced": 0, "connection": conn.name, "ok": False, "error": str(e)}


@router.get("/vulns", tags=["Read"])
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

@router.post("/vulns/sync-all", tags=["Sync"])
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
