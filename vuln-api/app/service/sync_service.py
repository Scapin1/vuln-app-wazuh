# app/services/sync_service.py
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Asset, VulnerabilityCatalog, VulnerabilityDetection
from ..schemas import VulnStatus


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

        estado_anterior = current_state.get(pair_key)
        if estado_anterior == VulnStatus.Resolved:
            nuevo_estado = VulnStatus.Re_emerged
        else:
            nuevo_estado = VulnStatus.Detected

        detections_to_insert.append({
            "timestamp": current_timestamp,
            "asset_id": asset_uuid,
            "cve_id": cve_id,
            "status": nuevo_estado,
            "first_seen_at": first_seen,
            "package_name": pkg.get("name"),
            "package_version": pkg.get("version")
        })
        inserted_in_loop.add(pair_key)

    # Si en la BD el último estado era 'Detected' pero ya no existe en este payload, insertamos un registro de tipo 'Resolved'.
    for (asset_uuid, cve_id), status in current_state.items():
        if status in (VulnStatus.Detected, VulnStatus.Re_emerged) and (asset_uuid, cve_id) not in seen_in_payload:
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
