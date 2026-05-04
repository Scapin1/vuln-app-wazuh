# app/main.py
import contextlib
import os
import logging

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .db import engine, get_db, SessionLocal
from .models import Manager, Asset, VulnerabilityCatalog, VulnerabilityDetection, SeverityEnum, StatusEnum
from .wazuh_client import fetch_all_vulns
from .crypto import decrypt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_sync_job,
        trigger=CronTrigger(hour=3, minute=0),
        id='daily_wazuh_sync',
        name='Sincronización diaria de Wazuh',
        replace_existing=True
    )
    scheduler.start()
    logger.info("Scheduler iniciado. Tarea programada a las 03:00 AM.")
    yield
    scheduler.shutdown()


app = FastAPI(title="Vulnerability Middleware", root_path="/api", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGINS", "*").split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Sync Job ---

def run_sync_job():
    """Función de extracción invocada por el Scheduler."""
    logger.info("Iniciando sincronización masiva programada...")
    db = SessionLocal()
    try:
        managers = db.query(Manager).all()
        for manager in managers:
            try:
                sync_manager(db, manager)
            except Exception as e:
                logger.error(f"Error sincronizando manager {manager.nombre}: {e}")
    finally:
        db.close()


# --- Sync Logic (refactored to reduce cognitive complexity) ---

def _parse_severity(vuln: dict) -> SeverityEnum:
    """Mapea el string de severidad de Wazuh al Enum."""
    severity_str = vuln.get("severity", "Untriaged").capitalize()
    return getattr(SeverityEnum, severity_str, SeverityEnum.Untriaged)


def _parse_score(vuln: dict):
    """Extrae y valida el score CVSS."""
    score = (vuln.get("score") or {}).get("base")
    if score is None:
        return None
    try:
        return float(score)
    except (ValueError, TypeError):
        return None


def _parse_raw_vulns(raw_vulns: list, manager_id):
    """Parsea el payload de Wazuh en diccionarios de assets, catálogo y detecciones."""
    assets_data = {}
    catalog_data = {}
    detections_data = []

    for v in raw_vulns:
        agent = v.get("agent", {})
        osinfo = (v.get("host") or {}).get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        cve_id = vuln.get("id")
        if not cve_id:
            continue

        agent_id = agent.get("id")

        if agent_id and agent_id not in assets_data:
            assets_data[agent_id] = {
                "wazuh_agent_id": agent_id,
                "hostname": agent.get("name"),
                "os_version": osinfo.get("version"),
                "ip_address": agent.get("ip") or None,
                "manager_id": manager_id,
            }

        if cve_id not in catalog_data:
            catalog_data[cve_id] = {
                "cve_id": cve_id,
                "severity": _parse_severity(vuln),
                "description": vuln.get("description"),
                "cvss_score": _parse_score(vuln),
            }

        detections_data.append({
            "wazuh_agent_id": agent_id,
            "cve_id": cve_id,
            "status": StatusEnum.Detected,
            "package_name": pkg.get("name"),
            "package_version": pkg.get("version"),
        })

    return assets_data, catalog_data, detections_data


def _upsert_catalog(db: Session, catalog_data: dict):
    """Bulk upsert de CVEs en el catálogo."""
    if not catalog_data:
        return
    stmt = insert(VulnerabilityCatalog).values(list(catalog_data.values()))
    stmt = stmt.on_conflict_do_update(
        index_elements=["cve_id"],
        set_={
            "severity": stmt.excluded.severity,
            "description": stmt.excluded.description,
            "cvss_score": stmt.excluded.cvss_score,
        },
    )
    db.execute(stmt)


def _upsert_assets(db: Session, assets_data: dict, manager_id):
    """Upsert de assets y retorna mapeo wazuh_agent_id -> UUID de postgres."""
    asset_pg_ids = {}
    for ag_id, a_data in assets_data.items():
        db_asset = db.query(Asset).filter_by(
            manager_id=manager_id, wazuh_agent_id=ag_id
        ).first()
        if db_asset:
            db_asset.hostname = a_data["hostname"]
            db_asset.os_version = a_data["os_version"]
        else:
            db_asset = Asset(**a_data)
            db.add(db_asset)
        db.flush()
        asset_pg_ids[ag_id] = db_asset.id
    return asset_pg_ids


def _insert_detections(db: Session, detections_data: list, asset_pg_ids: dict):
    """Inserta detecciones masivas ignorando duplicados."""
    final_detections = []
    for d in detections_data:
        pg_asset_id = asset_pg_ids.get(d["wazuh_agent_id"])
        if not pg_asset_id:
            continue
        final_detections.append({
            "asset_id": pg_asset_id,
            "cve_id": d["cve_id"],
            "status": d["status"],
            "package_name": d["package_name"],
            "package_version": d["package_version"],
        })

    if final_detections:
        stmt = insert(VulnerabilityDetection).values(final_detections)
        stmt = stmt.on_conflict_do_nothing()
        db.execute(stmt)

    return len(final_detections)


def sync_manager(db: Session, manager: Manager):
    """Sincroniza todas las vulnerabilidades de un Manager."""
    logger.info(f"Obteniendo datos de Wazuh Indexer para el manager {manager.nombre}...")

    pwd = decrypt(manager.wazuh_password) if manager.wazuh_password else ""
    raw_vulns = fetch_all_vulns(manager.api_url, manager.wazuh_user, pwd)

    if not raw_vulns:
        logger.info(f"No se encontraron vulnerabilidades para {manager.nombre}.")
        return 0

    logger.info(f"Recibidos {len(raw_vulns)} registros. Procesando batch upserts...")

    assets_data, catalog_data, detections_data = _parse_raw_vulns(raw_vulns, manager.id)

    _upsert_catalog(db, catalog_data)
    asset_pg_ids = _upsert_assets(db, assets_data, manager.id)
    count = _insert_detections(db, detections_data, asset_pg_ids)

    db.commit()
    logger.info(f"Sincronización de {manager.nombre} completada. {count} detecciones.")
    return count


# --- Endpoints ---

@app.post("/sync", summary="Gatilla la extracción manualmente")
def trigger_sync(background_tasks: BackgroundTasks):
    """
    Endpoint para gatillar la sincronización de manera manual.
    Se ejecuta en background para no bloquear la respuesta HTTP.
    """
    background_tasks.add_task(run_sync_job)
    return {"message": "Sincronización iniciada en segundo plano."}


@app.get("/status")
def health_check():
    return {"status": "ok", "service": "Vulnerability Middleware Extraction API"}
