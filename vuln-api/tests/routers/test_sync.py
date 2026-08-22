# tests/routers/test_sync.py — cubre app/routers/sync.py
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import User, VulnStatus, WazuhConnection
from app.routers.sync import chunk_list, parse_wazuh_date, process_wazuh_vulnerabilities

REAL_HASH = hash_password("old_password")

mock_user = User(
    user_name="Admin Test",
    user_password=REAL_HASH,
    user_status=True,
    user_delete=False
)
mock_user.user_id = 1


def mock_refresh_side_effect(obj):
    if hasattr(obj, 'user_id') and getattr(obj, 'user_id', None) is None:
        obj.user_id = 1
    elif hasattr(obj, 'id') and getattr(obj, 'id', None) is None:
        obj.id = uuid.uuid4()
    if hasattr(obj, 'timestamp') and getattr(obj, 'timestamp', None) is None:
        obj.timestamp = datetime.now(timezone.utc)
    if hasattr(obj, 'cve_id') and getattr(obj, 'cve_id', None) is None:
        obj.cve_id = "CVE-2026-MOCK"

async def override_get_db():
    db = AsyncMock(add=MagicMock())

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalars.return_value.first.return_value = None
    mock_result.scalar_one_or_none.return_value = mock_user

    db.execute.return_value = mock_result
    db.refresh.side_effect = mock_refresh_side_effect
    yield db


@pytest.fixture(autouse=True)
def baseline_overrides():
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


def make_client(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def mock_wazuh_raw_data():
    return [
        {
            "agent": {"id": "001", "name": "linux-agent", "os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
            "package": {"name": "openssl", "version": "1.1.1", "type": "deb", "architecture": "amd64"},
            "vulnerability": {
                "id": "CVE-2026-TEST-NEW",
                "severity": "High",
                "score": {"base": 8.5},
                "detected_at": "2026-05-10T10:00:00Z"
            }
        },
        {
            "agent": {"id": "001", "name": "linux-agent", "os": {"full": "Ubuntu 22.04"}},
            "package": {"name": "bash", "version": "5.0", "type": "deb"},
            "vulnerability": {
                "id": "CVE-2026-TEST-EXISTING",
                "severity": "Critical",
                "score": {"base": 9.8}
            }
        }
    ]


@pytest.mark.asyncio
async def test_sync_process_complete_flow():
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.add = AsyncMock(return_value=None)
    mock_db.commit = AsyncMock(return_value=None)

    mock_conn = WazuhConnection(
        id=1, name="Lab", is_active=True,
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="hash"
    )
    mock_db.get.return_value = mock_conn

    # Simulamos el mapeo de agentes a assets en la base de datos
    class MockRow:
        def __init__(self, wazuh_agent_id, asset_id):
            self.wazuh_agent_id = wazuh_agent_id
            self.asset_id = asset_id

    mock_result_assets = MagicMock()
    mock_result_assets.all.return_value = [MockRow("001", uuid.uuid4())]

    mock_result_state = MagicMock()
    mock_result_state.fetchall.return_value = []

    # Mockeamos las 5 llamadas secuenciales a db.execute de process_wazuh_vulnerabilities
    mock_db.execute.side_effect = [
        MagicMock(),         # 1. UPSERT Catalog
        MagicMock(),         # 2. UPSERT Assets
        mock_result_assets,  # 3. SELECT Asset mapping
        mock_result_state,   # 4. SELECT Last State
        MagicMock()          # 5. INSERT Detections
    ]

    mock_raw_wazuh = [{
        "agent": {"id": "001", "name": "agent-1", "os": {"full": "Ubuntu"}},
        "package": {"name": "bash", "version": "5.0"},
        "vulnerability": {"id": "CVE-OLD", "severity": "High", "score": {"base": 7.5}}
    }]

    app.dependency_overrides[get_db] = lambda: mock_db

    async def mock_fetch_generator(*args, **kwargs):
            yield mock_raw_wazuh

    with patch("app.routers.sync.fetch_all_vulns", side_effect=mock_fetch_generator) as mock_fetch, \
             patch("app.routers.sync.decrypt", return_value="plain"):

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections/1/sync")

    assert response.status_code == 200
    assert response.json()["synced"] == 1
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_sync_connection_not_found():
    """Cubre el 404 de POST /wazuh-connections/{conn_id}/sync"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = None

    async with make_client(mock_db) as ac:
        response = await ac.post("/wazuh-connections/999/sync")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_sync_connection_inactive():
    """Cubre el 400 cuando la conexión está inactiva"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = WazuhConnection(id=1, name="Off", is_active=False)

    async with make_client(mock_db) as ac:
        response = await ac.post("/wazuh-connections/1/sync")

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_list_vulns_with_and_without_connection_filter():
    """Cubre GET /vulns con y sin connection_id (join opcional y campos nulos)"""
    now = datetime.now(timezone.utc)

    vuln_full = SimpleNamespace(
        asset_id=uuid4(),
        cve_id="CVE-2026-0001",
        status=VulnStatus.Detected,
        asset=SimpleNamespace(wazuh_connection_id=1, wazuh_agent_id="001", hostname="host-1", os_version="Ubuntu"),
        catalog_entry=SimpleNamespace(severity="HIGH", cvss_score=7.5, description="desc"),
        package_name="curl",
        package_version="8.0",
        first_seen_at=now,
        timestamp=now,
    )
    vuln_bare = SimpleNamespace(
        asset_id=uuid4(),
        cve_id="CVE-2026-0002",
        status=VulnStatus.Resolved,
        asset=None,
        catalog_entry=None,
        package_name=None,
        package_version=None,
        first_seen_at=now,
        timestamp=now,
    )

    mock_db_a = AsyncMock(spec=AsyncSession)
    res_q = MagicMock()
    res_q.scalars.return_value.all.return_value = [vuln_full]
    res_count = MagicMock()
    res_count.scalar.return_value = 1
    mock_db_a.execute.side_effect = [res_q, res_count]

    async with make_client(mock_db_a) as ac:
        response = await ac.get("/vulns", params={"connection_id": 1, "limit": 50, "offset": 10})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["limit"] == 50
    assert body["offset"] == 10
    item = body["data"][0]
    assert item["cve_id"] == "CVE-2026-0001"
    assert item["status"] == "Detected"
    assert item["severity"] == "HIGH"
    assert item["score_base"] == 7.5
    assert item["agent_name"] == "host-1"

    mock_db_b = AsyncMock(spec=AsyncSession)
    res_q2 = MagicMock()
    res_q2.scalars.return_value.all.return_value = [vuln_bare]
    res_count2 = MagicMock()
    res_count2.scalar.return_value = 1
    mock_db_b.execute.side_effect = [res_q2, res_count2]

    async with make_client(mock_db_b) as ac:
        response = await ac.get("/vulns")

    assert response.status_code == 200
    item = response.json()["data"][0]
    assert item["connection_id"] is None
    assert item["severity"] is None
    assert item["score_base"] is None


@pytest.mark.asyncio
async def test_sync_all_connections_success():
    """POST /vulns/sync-all sincroniza TODAS las conexiones activas (más de una)"""
    mock_db = AsyncMock(spec=AsyncSession)

    conn_a = WazuhConnection(
        id=1, name="Conn-A", is_active=True,
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="enc-pass",
    )
    conn_b = WazuhConnection(
        id=2, name="Conn-B", is_active=True,
        indexer_url="http://wazuh2", wazuh_user="admin", wazuh_password="enc-pass",
    )
    res_conns = MagicMock()
    res_conns.scalars.return_value.all.return_value = [conn_a, conn_b]
    mock_db.execute.return_value = res_conns

    async def fake_fetch(*args, **kwargs):
        yield [{"vuln": 1}]
        yield [{"vuln": 2}]

    with patch("app.routers.sync.fetch_all_vulns", side_effect=fake_fetch) as mock_fetch, \
         patch("app.routers.sync.decrypt", return_value="plain") as mock_decrypt, \
         patch("app.routers.sync.process_wazuh_vulnerabilities", new=AsyncMock(return_value=3)):

        async with make_client(mock_db) as ac:
            response = await ac.post("/vulns/sync-all")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0] == {"connection": "Conn-A", "synced": 6, "ok": True}
    assert body[1] == {"connection": "Conn-B", "synced": 6, "ok": True}
    assert mock_fetch.call_count == 2
    assert mock_decrypt.call_count == 2
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_sync_connection_fetch_failure_returns_ok_false():
    """Si el indexer falla al forzar sync individual, responde JSON limpio (no 500)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.get.return_value = WazuhConnection(
        id=1, name="Lab", is_active=True,
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="hash"
    )

    async def boom(*args, **kwargs):
        raise RuntimeError("indexer down")
        yield

    with patch("app.routers.sync.fetch_all_vulns", side_effect=boom), \
         patch("app.routers.sync.decrypt", return_value="plain"):

        async with make_client(mock_db) as ac:
            response = await ac.post("/wazuh-connections/1/sync")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["synced"] == 0
    assert "indexer down" in body["error"]
    assert mock_db.rollback.called


@pytest.mark.asyncio
async def test_sync_all_connections_partial_failure():
    """Cubre el except de sync-all: rollback, ok False y synced_before_error"""
    mock_db = AsyncMock(spec=AsyncSession)

    conn = WazuhConnection(
        id=1, name="Bad-Conn", is_active=True,
        indexer_url="http://wazuh", wazuh_user="admin", wazuh_password="enc-pass",
    )
    res_conns = MagicMock()
    res_conns.scalars.return_value.all.return_value = [conn]
    mock_db.execute.return_value = res_conns

    async def boom(*args, **kwargs):
        raise RuntimeError("boom")
        yield

    with patch("app.routers.sync.fetch_all_vulns", side_effect=boom), \
         patch("app.routers.sync.decrypt", return_value="plain"), \
         patch("app.routers.sync.process_wazuh_vulnerabilities", new=AsyncMock(return_value=0)):

        async with make_client(mock_db) as ac:
            response = await ac.post("/vulns/sync-all")

    assert response.status_code == 200
    result = response.json()[0]
    assert result["ok"] is False
    assert result["synced_before_error"] == 0
    assert "boom" in result["error"]
    assert mock_db.rollback.called


@pytest.mark.asyncio
async def test_sync_all_connections_without_active_conns():
    """Cubre sync-all cuando no hay conexiones activas"""
    mock_db = AsyncMock(spec=AsyncSession)
    res_conns = MagicMock()
    res_conns.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = res_conns

    async with make_client(mock_db) as ac:
        response = await ac.post("/vulns/sync-all")

    assert response.status_code == 200
    assert response.json() == []


# ==========================================================
# SYNC: process_wazuh_vulnerabilities y helpers
# ==========================================================

def test_chunk_list_splits_in_equal_parts():
    assert list(chunk_list([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]
    assert list(chunk_list([], 100)) == []


def test_parse_wazuh_date_variants():
    assert parse_wazuh_date(None) is None
    assert parse_wazuh_date("") is None
    assert parse_wazuh_date("not defined") is None
    assert parse_wazuh_date("fecha-invalida") is None

    parsed = parse_wazuh_date("2026-01-02T03:04:05Z")
    assert parsed.year == 2026
    assert parsed.utcoffset() == timedelta(0)


@pytest.mark.asyncio
async def test_process_wazuh_empty_payload_returns_zero():
    mock_db = AsyncMock(spec=AsyncSession)
    assert await process_wazuh_vulnerabilities(mock_db, 1, []) == 0
    assert not mock_db.execute.called


class MapRow:
    def __init__(self, agent_id, asset_uuid):
        self.wazuh_agent_id = agent_id
        self.asset_id = asset_uuid


class StateRow:
    def __init__(self, asset_uuid, cve, status):
        self.asset_id = asset_uuid
        self.cve_id = cve
        self.status = status


def raw_vuln(agent_id, cve, detected_at=None):
    return {
        "agent": {"id": agent_id, "name": f"agent-{agent_id}", "os": {"full": "Ubuntu"}},
        "package": {"name": "curl", "version": "8.0"},
        "vulnerability": {
            "id": cve, "severity": "High",
            "score": {"base": 7.0}, "detected_at": detected_at,
        },
    }


@pytest.mark.asyncio
async def test_process_wazuh_returns_zero_when_asset_map_empty():
    """Si ningún agente mapea a un asset existente, no se insertan detecciones"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_map = MagicMock()
    res_map.all.return_value = []

    mock_db.execute.side_effect = [
        MagicMock(),   # UPSERT catalog
        MagicMock(),   # UPSERT assets
        res_map,       # SELECT mapping
    ]

    count = await process_wazuh_vulnerabilities(mock_db, 1, [raw_vuln("001", "CVE-A")])

    assert count == 0
    assert mock_db.execute.call_count == 3


@pytest.mark.asyncio
async def test_process_wazuh_dedupes_same_pair_in_payload():
    """El mismo par (asset, cve) repetido en el payload solo genera una detección"""
    mock_db = AsyncMock(spec=AsyncSession)
    asset_uuid = uuid4()

    res_map = MagicMock()
    res_map.all.return_value = [MapRow("001", asset_uuid)]

    res_state = MagicMock()
    res_state.fetchall.return_value = [StateRow(asset_uuid, "CVE-A", VulnStatus.Detected)]

    mock_db.execute.side_effect = [
        MagicMock(),
        MagicMock(),
        res_map,
        res_state,
        MagicMock(),
    ]

    count = await process_wazuh_vulnerabilities(
        mock_db, 1, [raw_vuln("001", "CVE-A"), raw_vuln("001", "CVE-A")]
    )

    assert count == 1
    assert mock_db.execute.call_count == 5


@pytest.mark.asyncio
async def test_process_wazuh_skips_entries_without_agent_or_cve():
    """Entradas sin agent.id o sin vulnerability.id se descartan antes de tocar la BD"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_map = MagicMock()
    res_map.all.return_value = []

    mock_db.execute.side_effect = [res_map]

    raw = [
        raw_vuln("", "CVE-A"),
        {"agent": {"id": "002"}, "vulnerability": {"id": None}},
    ]

    count = await process_wazuh_vulnerabilities(mock_db, 1, raw)

    assert count == 0
    assert mock_db.execute.call_count == 1


@pytest.mark.asyncio
async def test_process_wazuh_skips_payload_agents_missing_from_map():
    """Agentes del payload que no mapean a ningún asset existente se omiten"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_catalog = MagicMock()
    res_assets = MagicMock()

    res_map = MagicMock()
    res_map.all.return_value = [MapRow("777", uuid4())]

    res_state = MagicMock()
    res_state.fetchall.return_value = []

    mock_db.execute.side_effect = [res_catalog, res_assets, res_map, res_state]

    count = await process_wazuh_vulnerabilities(mock_db, 1, [raw_vuln("001", "CVE-A")])

    assert count == 0
    assert mock_db.execute.call_count == 4


@pytest.mark.asyncio
async def test_process_wazuh_inserts_resolved_for_absent_pairs():
    """Pares ausentes del payload con estado Detected/Re-emerged generan registros Resolved"""
    mock_db = AsyncMock(spec=AsyncSession)
    asset_uuid = uuid4()

    call_log = []

    async def scripted_execute(stmt, *args, **kwargs):
        call_log.append(stmt)
        result = MagicMock()
        if len(call_log) == 3:
            result.all.return_value = [MapRow("001", asset_uuid)]
        elif len(call_log) == 4:
            result.fetchall.return_value = [
                StateRow(asset_uuid, "CVE-GONE", VulnStatus.Detected),
                StateRow(asset_uuid, "CVE-RE", VulnStatus.Re_emerged),
            ]
        else:
            result.all.return_value = []
            result.fetchall.return_value = []
        return result

    mock_db.execute.side_effect = scripted_execute

    count = await process_wazuh_vulnerabilities(mock_db, 1, [raw_vuln("001", "CVE-B")])

    assert count == 3
    assert mock_db.execute.call_count == 5


@pytest.mark.asyncio
async def test_sync_process_batching_logic(mock_wazuh_raw_data):
    """
    Verifica que la función process_wazuh_vulnerabilities ejecute
    correctamente los 5 comandos SQL masivos (batch) en el orden esperado.
    """
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.commit = AsyncMock()

    # 1. Mockeamos la conexión activa
    mock_conn = WazuhConnection(
        id=1, name="Batch Lab", is_active=True,
        indexer_url="http://wazuh.local", wazuh_user="admin", wazuh_password="hash"
    )
    mock_db.get.return_value = mock_conn

    # 2. Mock de la resolución de IDs para la hipertabla
    class MapRow:
        def __init__(self):
            self.wazuh_agent_id = "001"
            self.asset_id = uuid.uuid4()

    map_row = MapRow()

    # 3. Mock del estado previo de la base de datos (SELECT inicial masivo)
    class StateRow:
        def __init__(self):
            self.asset_id = map_row.asset_id
            self.cve_id = "CVE-2026-TEST-EXISTING"
            self.status = VulnStatus.Resolved  # Forzamos re-detección

    mock_result_catalog = MagicMock()
    mock_result_assets = MagicMock()

    mock_result_map = MagicMock()
    mock_result_map.all.return_value = [map_row]

    mock_result_state = MagicMock()
    mock_result_state.fetchall.return_value = [StateRow()]

    mock_result_insert = MagicMock()

    # Preparamos las 5 ejecuciones secuenciales exactas que hace main.py
    mock_db.execute.side_effect = [
        mock_result_catalog,  # 1. UPSERT masivo a VulnerabilityCatalog
        mock_result_assets,   # 2. UPSERT masivo a Assets
        mock_result_map,      # 3. SELECT de mapeos de Asset IDs
        mock_result_state,    # 4. SELECT del Last State en TimescaleDB
        mock_result_insert    # 5. INSERT masivo a VulnerabilityDetection
    ]

    app.dependency_overrides[get_db] = lambda: mock_db

    async def mock_fetch_generator(*args, **kwargs):
            yield mock_wazuh_raw_data

    with patch("app.routers.sync.fetch_all_vulns", side_effect=mock_fetch_generator) as mock_fetch, \
             patch("app.routers.sync.decrypt", return_value="plain_pass"):

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/wazuh-connections/1/sync")

    # --- Verificaciones del Loteo ---
    assert response.status_code == 200
    # Debería reportar 2 procesados en la misma inserción masiva
    assert response.json()["synced"] == 2

    # Confirmamos que se hicieron exactamente 5 llamadas masivas a la base de datos
    assert mock_db.execute.call_count == 5
    assert mock_db.commit.called
